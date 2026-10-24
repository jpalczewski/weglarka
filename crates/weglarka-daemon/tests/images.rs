//! Image retention through the admin API (issue #40): `POST /v1/images/prune` and the `doctor`
//! warning. Real unix socket, `FakePodman`.

use std::time::Duration;

use futures_util::StreamExt;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::net::UnixStream;
use weglarka_core::app::Digest;
use weglarka_core::config::HostConfig;
use weglarka_core::podman::PodmanClient;
use weglarka_core::testing::{DEFAULT_IMAGE_SIZE_BYTES, FakePodman};
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
        fake,
        running,
    }
}

fn digest(c: char) -> Digest {
    Digest::new(format!("sha256:{}", c.to_string().repeat(64))).unwrap()
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

async fn eventually<F: Fn() -> Fut, Fut: Future<Output = bool>>(what: &str, f: F) {
    for _ in 0..100 {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for: {what}");
}

/// The `runtime.images` check of a `GET /v1/doctor`.
async fn image_check(h: &Harness) -> Value {
    let (status, report) = admin(h, "GET", "/v1/doctor", None).await;
    assert_eq!(status, StatusCode::OK, "{report}");
    report["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .find(|c| c["id"] == "runtime.images")
        .cloned()
        .expect("every report carries the image check")
}

#[tokio::test]
async fn prune_dry_run_then_removes_and_doctor_reports_it() {
    let h = harness().await;
    h.fake.set_pull_digest(IMAGE, digest('a'));
    let (status, value) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(json!({
            "name": "ntfy",
            "spec": {
                "image": IMAGE,
                "domains": ["nz.example.eu"],
                "port": 8085,
                "health": { "attempts": 1, "window_secs": 1 }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    eventually("first deploy", || async {
        let (_, app) = admin(&h, "GET", "/v1/apps/ntfy", None).await;
        app["state"]["current"].is_string()
    })
    .await;

    // What an earlier deploy left behind: an image of the app's repository that `state.toml` does
    // not know (the daemon used to keep every pulled image).
    // The ingress nginx image sits in the same store, so counts are relative to it.
    let seeded = h.fake.images().len() + 1;
    let stale = format!("ghcr.io/jpalczewski/ntfy.zig@{}", digest('e'));
    h.fake.set_pull_digest(&stale, digest('e'));
    h.fake.image_pull(&stale).collect::<Vec<_>>().await;
    assert_eq!(h.fake.images().len(), seeded);

    let check = image_check(&h).await;
    assert_eq!(check["status"], "warn", "{check}");
    assert!(
        check["message"]
            .as_str()
            .unwrap()
            .contains("1 unused image(s)"),
        "{check}"
    );
    assert!(
        check["hint"]
            .as_str()
            .unwrap()
            .contains("weglarka images prune"),
        "{check}"
    );

    let (status, value) = admin(
        &h,
        "POST",
        "/v1/images/prune",
        Some(json!({ "dry_run": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(value["dry_run"], true);
    assert_eq!(value["removed"].as_array().unwrap().len(), 1, "{value}");
    assert_eq!(value["reclaimed_bytes"], json!(DEFAULT_IMAGE_SIZE_BYTES));
    assert_eq!(h.fake.images().len(), seeded, "a dry run removes nothing");

    // No body = an actual prune.
    let (status, value) = admin(&h, "POST", "/v1/images/prune", None).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(value["dry_run"], false);
    assert_eq!(value["removed"][0]["digests"], json!([stale]));
    assert_eq!(value["reclaimed_bytes"], json!(DEFAULT_IMAGE_SIZE_BYTES));
    assert!(value.get("failed").is_none(), "nothing failed: {value}");
    assert_eq!(h.fake.images().len(), seeded - 1, "the leftover is gone");

    let check = image_check(&h).await;
    assert_eq!(check["status"], "ok", "{check}");
}

/// An image a container still uses is never removed, not even when nothing in `state.toml` protects
/// it: the planner only removes what is provably dead weight, and Podman is the backstop.
#[tokio::test]
async fn an_image_used_by_a_container_survives_a_prune() {
    let h = harness().await;
    h.fake.set_pull_digest(IMAGE, digest('a'));
    let (status, value) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(json!({
            "name": "ntfy",
            "spec": {
                "image": IMAGE,
                "domains": ["nz.example.eu"],
                "port": 8085,
                "health": { "attempts": 1, "window_secs": 1 }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    eventually("first deploy", || async {
        let (_, app) = admin(&h, "GET", "/v1/apps/ntfy", None).await;
        app["state"]["current"].is_string()
    })
    .await;

    // The ingress nginx image lives in the same store; only the app image is interesting here.
    let before = h.fake.images().len();
    let (status, value) = admin(&h, "POST", "/v1/images/prune", None).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(value["removed"], json!([]), "{value}");
    assert_eq!(h.fake.images().len(), before);

    // Nothing was removed, so the doctor reports no leftovers either.
    let check = image_check(&h).await;
    assert_eq!(check["status"], "ok", "{check}");
}
