//! `depends_on` through the admin API (real unix socket, FakePodman): graph validation, the
//! removal refusal, the deploy gate and the `doctor` check (issue #35).

use std::path::{Path, PathBuf};
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::net::UnixStream;
use weglarka_core::config::HostConfig;
use weglarka_core::testing::FakePodman;
use weglarka_daemon::{Running, Settings, start};

const IMAGE: &str = "ghcr.io/jpalczewski/ntfy.zig:latest";

struct Harness {
    _dir: tempfile::TempDir,
    root: PathBuf,
    _fake: FakePodman,
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
        _fake: fake,
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

async fn eventually<F: Fn() -> Fut, Fut: Future<Output = bool>>(what: &str, f: F) {
    for _ in 0..100 {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for: {what}");
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

fn spec(domain: &str) -> Value {
    json!({
        "image": IMAGE,
        "domains": [domain],
        "port": 8085,
        "health": { "attempts": 1, "window_secs": 1 }
    })
}

fn with_deps(mut spec: Value, deps: &[&str]) -> Value {
    if !deps.is_empty() {
        spec["depends_on"] = json!(deps);
    }
    spec
}

fn stopped(mut spec: Value) -> Value {
    spec["start"] = json!(false);
    spec
}

async fn add(h: &Harness, name: &str, spec: Value) {
    let (s, v) = admin(
        h,
        "POST",
        "/v1/apps",
        Some(json!({"name": name, "spec": spec})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

async fn put(h: &Harness, name: &str, spec: Value) -> (StatusCode, Value) {
    admin(
        h,
        "PUT",
        &format!("/v1/apps/{name}"),
        Some(json!({ "spec": spec })),
    )
    .await
}

async fn show(h: &Harness, name: &str) -> Value {
    let (s, v) = admin(h, "GET", &format!("/v1/apps/{name}"), None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v
}

async fn deployed(h: &Harness, name: &str) {
    eventually("first deploy", || async {
        show(h, name).await["state"]["current"].is_string()
    })
    .await;
}

#[tokio::test]
async fn invalid_dependency_graphs_are_rejected_with_400() {
    let h = harness().await;
    add(&h, "db", spec("db.example.eu")).await;
    add(&h, "api", spec("api.example.eu")).await;

    // A dependency on an existing app is accepted and is not a container change (`deploy` absent).
    let (s, v) = put(&h, "api", with_deps(spec("api.example.eu"), &["db"])).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(
        v.get("deploy").is_none(),
        "depends_on must not redeploy: {v}"
    );
    assert!(read(&h.root.join("state/apps.toml")).contains("depends_on = [\"db\"]"));

    // An unknown target is rejected, naming it.
    let (s, v) = put(&h, "api", with_deps(spec("api.example.eu"), &["ghost"])).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert!(v["message"].as_str().unwrap().contains("ghost"), "{v}");

    // A cycle is rejected with the path.
    let (s, v) = put(&h, "db", with_deps(spec("db.example.eu"), &["api"])).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert!(v["message"].as_str().unwrap().contains("cycle"), "{v}");

    // Self-reference is caught by the per-app rules.
    let (s, v) = put(&h, "api", with_deps(spec("api.example.eu"), &["api"])).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");

    // None of the rejected graphs reached apps.toml.
    let toml = read(&h.root.join("state/apps.toml"));
    assert_eq!(toml.matches("depends_on").count(), 1, "{toml}");
}

#[tokio::test]
async fn deleting_a_dependency_is_refused_with_409() {
    let h = harness().await;
    add(&h, "db", spec("db.example.eu")).await;
    deployed(&h, "db").await;
    add(&h, "api", with_deps(spec("api.example.eu"), &["db"])).await;
    deployed(&h, "api").await;

    let (s, v) = admin(&h, "DELETE", "/v1/apps/db?purge_volumes=true", None).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::CONFLICT, Some("conflict")),
        "{v}"
    );
    assert!(v["message"].as_str().unwrap().contains("api"), "{v}");
    assert!(
        read(&h.root.join("state/apps.toml")).contains("[apps.db]"),
        "a refused removal must not touch apps.toml"
    );

    let (s, _) = admin(&h, "DELETE", "/v1/apps/api", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = admin(&h, "DELETE", "/v1/apps/db", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn a_dependent_does_not_deploy_while_its_dependency_is_stopped() {
    let h = harness().await;
    add(&h, "db", spec("db.example.eu")).await;
    deployed(&h, "db").await;
    add(&h, "api", with_deps(spec("api.example.eu"), &["db"])).await;
    deployed(&h, "api").await;

    // Stop the dependency: `start = false` removes its container but keeps the app declared.
    let (s, v) = put(&h, "db", stopped(spec("db.example.eu"))).await;
    assert_eq!(s, StatusCode::OK, "{v}");

    let (s, v) = admin(&h, "POST", "/v1/apps/api/deploy", None).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::CONFLICT, Some("conflict")),
        "{v}"
    );
    assert!(v["message"].as_str().unwrap().contains("db"), "{v}");
    // The refusal left the running dependent untouched.
    assert_eq!(show(&h, "api").await["runtime"], json!("running"));

    // An image change runs a deploy right after the spec write; the same gate answers 409, not 500.
    let mut bumped = with_deps(spec("api.example.eu"), &["db"]);
    bumped["image"] = json!("ghcr.io/jpalczewski/ntfy.zig:v2");
    let (s, v) = put(&h, "api", bumped).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::CONFLICT, Some("conflict")),
        "{v}"
    );
    assert!(v["message"].as_str().unwrap().contains("db"), "{v}");

    // `doctor` calls the configuration out instead of silently leaving the app in place.
    let (s, v) = admin(&h, "GET", "/v1/doctor", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let check = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "state.dependencies")
        .expect("state.dependencies check");
    assert_eq!(check["status"], json!("warn"), "{check}");
    assert!(
        check["message"].as_str().unwrap().contains("api"),
        "{check}"
    );
}
