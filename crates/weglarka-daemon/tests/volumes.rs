//! Volume endpoints and `apps remove --purge-volumes` on `FakePodman`, over the real admin socket.

use std::path::PathBuf;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::net::UnixStream;
use weglarka_core::config::HostConfig;
use weglarka_core::testing::{Call, FakePodman};
use weglarka_daemon::{Running, Settings, start};

const IMAGE: &str = "ghcr.io/jpalczewski/ntfy.zig:latest";

struct Harness {
    _dir: tempfile::TempDir,
    fake: FakePodman,
    running: Running<FakePodman>,
}

async fn harness() -> Harness {
    // Short path: `sun_path` is limited to ~104 characters.
    let dir = tempfile::Builder::new()
        .prefix("wg")
        .tempdir_in("/tmp")
        .unwrap();
    let root: PathBuf = dir.path().to_owned();
    std::fs::write(root.join("traefik.yml"), "").unwrap();
    let host = HostConfig::from_toml_str(&format!(
        r#"
[ingress]
mode = "behind"
bind = "127.0.0.1:18080"
traefik_dynamic_file = "{root}/traefik.yml"

[admin]
socket = "{root}/run/admin.sock"

[webhook]
listen = "127.0.0.1:0"
domain = "hooks.example.eu"

[state]
dir = "{root}/state"
"#,
        root = root.display()
    ))
    .unwrap();
    let fake = FakePodman::new();
    let settings = Settings::from_host(host, root.join("weglarka.toml"));
    let running = start(settings, fake.clone()).await.unwrap();
    Harness {
        _dir: dir,
        fake,
        running,
    }
}

async fn send<S>(stream: S, req: Request<Full<Bytes>>) -> (StatusCode, Bytes)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(conn);
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    (status, resp.into_body().collect().await.unwrap().to_bytes())
}

async fn admin(h: &Harness, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
    let stream = UnixStream::connect(&h.running.admin_socket).await.unwrap();
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "weglarka")
        .body(Full::new(Bytes::from(
            body.map(|b| b.to_string()).unwrap_or_default(),
        )))
        .unwrap();
    let (status, bytes) = send(stream, req).await;
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, value)
}

/// Raw admin call: returns the status and the body bytes.
async fn raw(h: &Harness, method: &str, path: &str, body: Vec<u8>) -> (StatusCode, Bytes) {
    let stream = UnixStream::connect(&h.running.admin_socket).await.unwrap();
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "weglarka")
        .body(Full::new(Bytes::from(body)))
        .unwrap();
    send(stream, req).await
}

fn app_with_volume() -> Value {
    json!({
        "name": "szklana",
        "spec": {
            "image": IMAGE,
            "domains": ["pogoda.example.eu"],
            "port": 8085,
            "health": { "attempts": 1, "window_secs": 1 },
            "volumes": [{ "name": "data", "target": "/data" }]
        }
    })
}

async fn deployed() -> Harness {
    let h = harness().await;
    let (s, _) = admin(&h, "POST", "/v1/apps", Some(app_with_volume())).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = admin(&h, "POST", "/v1/apps/szklana/deploy", Some(json!({}))).await;
    assert_eq!(s, StatusCode::OK);
    h
}

#[tokio::test]
async fn list_export_and_own_import_use_the_raw_volume_endpoints() {
    let h = deployed().await;

    let (s, v) = admin(&h, "GET", "/v1/apps/szklana/volumes", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        v,
        json!({"volumes": [{"name": "data", "target": "/data", "podman_name": "szklana.data", "exists": true}]})
    );

    let (s, _) = raw(
        &h,
        "PUT",
        "/v1/apps/szklana/volumes/data/import",
        b"own-tar".to_vec(),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, tar) = raw(&h, "GET", "/v1/apps/szklana/volumes/data/export", vec![]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(&tar[..], b"own-tar");

    let calls = h.fake.calls();
    assert!(calls.contains(&Call::VolumeImport("szklana.data".into())));
    assert!(
        !calls
            .iter()
            .any(|c| matches!(c, Call::ContainerArchivePut { .. }))
    );
    h.running.stop().await;
}

#[tokio::test]
async fn foreign_import_maps_ids_through_a_helper_container() {
    let h = deployed().await;
    let (s, _) = raw(
        &h,
        "PUT",
        "/v1/apps/szklana/volumes/data/import?foreign=true",
        b"coolify-tar".to_vec(),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    let calls = h.fake.calls();
    assert!(calls.contains(&Call::ContainerArchivePut {
        name: "wg-import.szklana".into(),
        path: "/data".into()
    }));
    assert!(!calls.iter().any(|c| matches!(c, Call::VolumeImport(_))));
    assert!(
        h.fake
            .containers()
            .iter()
            .all(|c| c.name != "wg-import.szklana"),
        "helper cleaned up"
    );
    h.running.stop().await;
}

#[tokio::test]
async fn undeclared_or_unknown_targets_are_rejected() {
    let h = deployed().await;
    for (method, path) in [
        ("PUT", "/v1/apps/szklana/volumes/other/import"),
        ("GET", "/v1/apps/szklana/volumes/other/export"),
        ("PUT", "/v1/apps/nope/volumes/data/import"),
        ("GET", "/v1/apps/nope/volumes"),
    ] {
        let (s, _) = raw(&h, method, path, vec![]).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{method} {path}");
    }
    h.running.stop().await;
}

#[tokio::test]
async fn import_before_the_first_deploy_is_a_clear_error() {
    let h = harness().await;
    h.fake.fail_pull(IMAGE, "registry down"); // the background reconcile cannot deploy it
    admin(&h, "POST", "/v1/apps", Some(app_with_volume())).await;
    let (s, v) = admin(&h, "GET", "/v1/apps/szklana/volumes", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["volumes"][0]["exists"], false);
    let (s, _) = raw(&h, "PUT", "/v1/apps/szklana/volumes/data/import", vec![]).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, body) = raw(
        &h,
        "PUT",
        "/v1/apps/szklana/volumes/data/import?foreign=true",
        vec![],
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(&body).contains("not deployed"));
    h.running.stop().await;
}

#[tokio::test]
async fn remove_keeps_volumes_unless_purge_is_requested() {
    let h = deployed().await;
    let (s, _) = admin(&h, "DELETE", "/v1/apps/szklana", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(h.fake.volumes().len(), 1, "plain remove keeps the data");

    // Add it back, then remove it for good.
    admin(&h, "POST", "/v1/apps", Some(app_with_volume())).await;
    let (s, _) = admin(&h, "DELETE", "/v1/apps/szklana?purge_volumes=true", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(h.fake.volumes().is_empty());
    assert!(h.fake.containers().iter().all(|c| c.name != "szklana"));
    h.running.stop().await;
}
