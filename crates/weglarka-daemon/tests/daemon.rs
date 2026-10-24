//! Daemon tests on `FakePodman`: admin API over a real unix socket, webhooks over TCP.

use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::net::{TcpStream, UnixStream};
use weglarka_core::config::HostConfig;
use weglarka_core::testing::{Call, FakePodman};
use weglarka_daemon::github::{DELIVERY_HEADER, EVENT_HEADER, SIGNATURE_HEADER, sign};
use weglarka_daemon::{Running, Settings, start};

const SECRET: &str = "hunter2-webhook";
const IMAGE: &str = "ghcr.io/jpalczewski/ntfy.zig:latest";

struct Harness {
    _dir: tempfile::TempDir,
    root: PathBuf,
    fake: FakePodman,
    running: Running<FakePodman>,
}

async fn harness() -> Harness {
    // Short path: `sun_path` is limited to ~104 characters.
    let dir = tempfile::Builder::new()
        .prefix("wg")
        .tempdir_in("/tmp")
        .unwrap();
    let root = dir.path().to_owned();
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
        root,
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

async fn hook(
    addr: SocketAddr,
    instance: &str,
    event: &str,
    delivery: &str,
    body: &[u8],
    signature: Option<String>,
) -> StatusCode {
    let stream = TcpStream::connect(addr).await.unwrap();
    let mut req = Request::builder()
        .method("POST")
        .uri(format!("/webhook/github/{instance}"))
        .header("host", "hooks.example.eu")
        .header(EVENT_HEADER, event)
        .header(DELIVERY_HEADER, delivery);
    if let Some(sig) = signature {
        req = req.header(SIGNATURE_HEADER, sig);
    }
    send(
        stream,
        req.body(Full::new(Bytes::from(body.to_vec()))).unwrap(),
    )
    .await
    .0
}

fn app_body(name: &str, domain: &str) -> Value {
    json!({
        "name": name,
        "spec": {
            "image": IMAGE,
            "domains": [domain],
            "port": 8085,
            "health": { "attempts": 1, "window_secs": 1 }
        }
    })
}

async fn eventually<F: Fn() -> Fut, Fut: Future<Output = bool>>(what: &str, f: F) {
    for _ in 0..100 {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for: {what}");
}

async fn current_digest(h: &Harness, name: &str) -> Option<String> {
    let (status, v) = admin(h, "GET", &format!("/v1/apps/{name}"), None).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    v["state"]["current"].as_str().map(str::to_owned)
}

fn published(tag: &str) -> Vec<u8> {
    json!({
        "action": "published",
        "registry_package": {
            "name": "ntfy.zig", "namespace": "jpalczewski", "package_type": "CONTAINER",
            "package_version": {
                "package_url": format!("ghcr.io/jpalczewski/ntfy.zig:{tag}"),
                "container_metadata": { "tag": { "name": tag } }
            }
        }
    })
    .to_string()
    .into_bytes()
}

fn pulls(fake: &FakePodman) -> usize {
    fake.calls()
        .iter()
        .filter(|c| matches!(c, Call::ImagePull(r) if r == IMAGE))
        .count()
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

#[tokio::test]
async fn admin_lifecycle_add_deploy_status_remove() {
    let h = harness().await;

    let mode = std::fs::metadata(&h.running.admin_socket)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);

    let (s, v) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(app_body("ntfy", "nz.example.eu")),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["name"], "ntfy");
    let (s, v) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(app_body("ntfy", "nz.example.eu")),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(v["code"], "already_exists");

    // A domain taken by another app fails ingress validation.
    let (s, v) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(app_body("other", "nz.example.eu")),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let (s, _) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(json!({"name": "Bad_Name", "spec": {"image": "x"}})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // `add` wakes the reconcile, which performs the first deploy.
    eventually("first deploy", || async {
        current_digest(&h, "ntfy").await.is_some()
    })
    .await;

    let (s, v) = admin(&h, "POST", "/v1/apps/ntfy/deploy", Some(json!({}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(matches!(
        v["outcome"].as_str(),
        Some("deployed" | "unchanged")
    ));
    let (s, v) = admin(
        &h,
        "POST",
        "/v1/apps/ntfy/deploy",
        Some(json!({"image_ref": "x"})),
    )
    .await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_request"))
    );
    let (s, v) = admin(&h, "POST", "/v1/apps/ghost/deploy", None).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("not_found"))
    );

    let (s, v) = admin(&h, "GET", "/v1/apps/ntfy", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["runtime"], "running");
    let (_, v) = admin(&h, "GET", "/v1/apps", None).await;
    assert_eq!(v["apps"][0]["name"], "ntfy");
    assert_eq!(v["apps"][0]["runtime"], "running");
    let (_, v) = admin(&h, "GET", "/v1/status", None).await;
    assert_eq!(v["api_version"], "v1");
    assert_eq!(v["apps"].as_array().unwrap().len(), 1);

    // Secrets: name and value validation, no values in responses.
    let (s, v) = admin(
        &h,
        "PUT",
        "/v1/apps/ntfy/secrets/config",
        Some(json!({"value": "s3cr3t"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(!v.to_string().contains("s3cr3t"));
    let (s, _) = admin(
        &h,
        "PUT",
        "/v1/apps/ntfy/secrets/bad.name",
        Some(json!({"value": "x"})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = admin(
        &h,
        "PUT",
        "/v1/apps/ntfy/secrets/config",
        Some(json!({"value": ""})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = admin(
        &h,
        "PUT",
        "/v1/apps/ghost/secrets/config",
        Some(json!({"value": "x"})),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, v) = admin(&h, "GET", "/v1/apps/ntfy/secrets", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["secrets"][0]["name"], "config");
    assert!(!v.to_string().contains("s3cr3t"));
    let secrets_file = h.root.join("state/secrets.toml");
    assert_eq!(
        std::fs::metadata(&secrets_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    // Ingress: nginx.conf, the Traefik file and the nginx container appear after the app set changes.
    eventually("ingress applied", || async {
        read(&h.root.join("state/nginx/nginx.conf")).contains("nz.example.eu")
            && read(&h.root.join("traefik.yml")).contains("nz.example.eu")
            && h.fake
                .containers()
                .iter()
                .any(|c| c.name == "weglarka-nginx")
    })
    .await;
    assert!(h.fake.networks().contains(&"net-weglarka".to_owned()));
    assert!(h.fake.networks().contains(&"net-ntfy".to_owned()));

    let (s, v) = admin(&h, "GET", "/v1/doctor", None).await;
    assert_eq!(s, StatusCode::OK);
    let ids: Vec<&str> = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    for want in [
        "runtime.socket",
        "state.apps_file",
        "state.secrets_file",
        "state.webhook_secrets",
        "state.drift",
        "webhook.listener",
        "ingress.traefik_file",
    ] {
        assert!(ids.contains(&want), "missing check {want}: {ids:?}");
    }
    let hmac = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "state.webhook_secrets")
        .unwrap();
    assert_eq!(hmac["status"], "warn");

    let (s, _) = admin(&h, "DELETE", "/v1/apps/ntfy", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, v) = admin(&h, "DELETE", "/v1/apps/ntfy", None).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("not_found"))
    );
    eventually("app removed from ingress and runtime", || async {
        !read(&h.root.join("traefik.yml")).contains("nz.example.eu")
            && !h.fake.containers().iter().any(|c| c.name == "ntfy")
    })
    .await;

    let (s, _) = admin(&h, "GET", "/v1/nope", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    h.running.stop().await;
}

#[tokio::test]
async fn provision_only_add_creates_no_container_and_deploy_provisions() {
    let h = harness().await;
    let mut body = app_body("ntfy", "nz.example.eu");
    body["spec"]["start"] = json!(false);
    body["spec"]["volumes"] = json!([{"name": "data", "target": "/data"}]);

    // `start = false`: `add` provisions synchronously and the response already has the pinned digest.
    let (s, v) = admin(&h, "POST", "/v1/apps", Some(body)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["runtime"], "not_started");
    assert_eq!(v["spec"]["start"], json!(false));
    let digest = v["state"]["current"].clone();
    assert!(digest.is_string(), "digest pinned: {v}");
    let digest = digest.as_str().unwrap().to_owned();

    // Nothing runs, but the network and the declared volume are ready.
    assert!(h.fake.containers().iter().all(|c| c.name != "ntfy"));
    assert!(h.fake.networks().contains(&"net-ntfy".to_owned()));
    assert!(h.fake.volumes().iter().any(|v| v.name == "ntfy.data"));

    // Reads agree: `show` and the list report `not_started`.
    let (s, v) = admin(&h, "GET", "/v1/apps/ntfy", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["runtime"], "not_started");
    assert_eq!(v["state"]["current"], json!(digest));
    let (_, v) = admin(&h, "GET", "/v1/apps", None).await;
    assert_eq!(v["apps"][0]["runtime"], "not_started");

    // A manual deploy of a `start = false` app provisions again instead of starting it.
    let (s, v) = admin(&h, "POST", "/v1/apps/ntfy/deploy", Some(json!({}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["outcome"], "provisioned");
    assert_eq!(v["digest"], json!(digest));
    assert!(h.fake.containers().iter().all(|c| c.name != "ntfy"));

    // Wakes from `add`/`deploy` settle without bringing the container back.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(h.fake.containers().iter().all(|c| c.name != "ntfy"));
    h.running.stop().await;
}

#[tokio::test]
async fn webhook_flow() {
    let h = harness().await;
    let addr = h.running.webhook_addr;
    admin(
        &h,
        "POST",
        "/v1/apps",
        Some(app_body("ntfy", "nz.example.eu")),
    )
    .await;
    eventually("first deploy", || async {
        current_digest(&h, "ntfy").await.is_some()
    })
    .await;
    let (s, _) = admin(
        &h,
        "PUT",
        "/v1/apps/ntfy/secrets/webhook-hmac",
        Some(json!({"value": SECRET})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let body = published("latest");
    let good = Some(sign(SECRET.as_bytes(), &body));

    // Bad signature, no signature, wrong secret, unknown app, app without a secret → 401.
    let bad = Some(sign(b"wrong", &body));
    assert_eq!(
        hook(addr, "ntfy", "registry_package", "d0", &body, bad).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        hook(addr, "ntfy", "registry_package", "d0", &body, None).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        hook(addr, "ghost", "registry_package", "d0", &body, good.clone()).await,
        StatusCode::UNAUTHORIZED
    );

    // Irrelevant events (correctly signed) → 204.
    let ping = b"{}".to_vec();
    let ping_sig = Some(sign(SECRET.as_bytes(), &ping));
    assert_eq!(
        hook(addr, "ntfy", "ping", "d1", &ping, ping_sig.clone()).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        hook(addr, "ntfy", "push", "d2", &ping, ping_sig).await,
        StatusCode::NO_CONTENT
    );
    let other = published("sha-abc123");
    assert_eq!(
        hook(
            addr,
            "ntfy",
            "registry_package",
            "d3",
            &other,
            Some(sign(SECRET.as_bytes(), &other))
        )
        .await,
        StatusCode::NO_CONTENT
    );

    // Good signature → 202 right away; the deploy runs in a separate task.
    let before = pulls(&h.fake);
    assert_eq!(
        hook(addr, "ntfy", "registry_package", "d4", &body, good.clone()).await,
        StatusCode::ACCEPTED
    );
    eventually("webhook deploy pulled", || async {
        pulls(&h.fake) > before
    })
    .await;
    let after_first = pulls(&h.fake);

    // Duplicate delivery: 202, but no redeploy (dedup by X-GitHub-Delivery).
    assert_eq!(
        hook(addr, "ntfy", "registry_package", "d4", &body, good.clone()).await,
        StatusCode::ACCEPTED
    );
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(pulls(&h.fake), after_first);

    // Body over the limit → 413.
    let huge = vec![b'x'; 1024 * 1024 + 1];
    assert_eq!(
        hook(
            addr,
            "ntfy",
            "registry_package",
            "d5",
            &huge,
            Some(sign(SECRET.as_bytes(), &huge))
        )
        .await,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    h.running.stop().await;
}

#[tokio::test]
async fn refuses_loose_secrets_permissions() {
    let dir = tempfile::Builder::new()
        .prefix("wg")
        .tempdir_in("/tmp")
        .unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("state")).unwrap();
    std::fs::write(root.join("state/secrets.toml"), "").unwrap();
    std::fs::set_permissions(
        root.join("state/secrets.toml"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let host = HostConfig::from_toml_str(&format!(
        "[ingress]\nmode=\"behind\"\nbind=\"127.0.0.1:18081\"\n[admin]\nsocket=\"{r}/a.sock\"\n[webhook]\nlisten=\"127.0.0.1:0\"\ndomain=\"h.example.eu\"\n[state]\ndir=\"{r}/state\"\n",
        r = root.display()
    ))
    .unwrap();
    let res = start(
        Settings::from_host(host, root.join("weglarka.toml")),
        FakePodman::new(),
    )
    .await;
    assert!(res.is_err());
}
