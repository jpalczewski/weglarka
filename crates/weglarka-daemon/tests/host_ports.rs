//! `host_ports` (issue #34) through the admin API and at startup: the rules that need the host
//! (privileged ports, two apps on one socket, the ingress bind) are enforced wherever the daemon
//! reads or writes `apps.toml` (`docs/decisions/0013-host-ports.md`).

use std::path::{Path, PathBuf};

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
    running: Running<FakePodman>,
}

/// `weglarka.toml` for a test daemon; `allow_privileged` toggles
/// `[runtime] allow_privileged_host_ports`.
fn host_toml(root: &Path, allow_privileged: bool) -> String {
    format!(
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

[runtime]
allow_privileged_host_ports = {allow_privileged}
"#,
        root = root.display()
    )
}

/// Short path: `sun_path` is limited to ~104 characters.
fn tempdir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::Builder::new()
        .prefix("wg")
        .tempdir_in("/tmp")
        .unwrap();
    let root = dir.path().to_owned();
    std::fs::write(root.join("traefik.yml"), "").unwrap();
    (dir, root)
}

async fn harness_with(allow_privileged: bool) -> Harness {
    let (dir, root) = tempdir();
    let host = HostConfig::from_toml_str(&host_toml(&root, allow_privileged)).unwrap();
    let running = start(
        Settings::from_host(host, root.join("weglarka.toml")),
        FakePodman::new(),
    )
    .await
    .unwrap();
    Harness {
        _dir: dir,
        root,
        running,
    }
}

async fn harness() -> Harness {
    harness_with(false).await
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

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// A valid spec for `domain`; `start = false` keeps the test free of background deploys.
fn spec(domain: &str) -> Value {
    json!({
        "image": IMAGE,
        "domains": [domain],
        "port": 8085,
        "start": false,
        "health": { "attempts": 1, "window_secs": 1 }
    })
}

fn with_ports(mut spec: Value, ports: Value) -> Value {
    spec["host_ports"] = ports;
    spec
}

fn app_body(name: &str, spec: Value) -> Value {
    json!({ "name": name, "spec": spec })
}

/// The `apps.toml` the daemon writes next to its state; `[state] dir = "<root>/state"`.
fn apps_file(h: &Harness) -> PathBuf {
    h.root.join("state/apps.toml")
}

#[tokio::test]
async fn add_persists_host_ports_and_show_returns_them() {
    let h = harness().await;
    let ports = json!([
        { "host": 2222, "container": 22 },
        { "host": 2223, "container": 22, "ip": "0.0.0.0" }
    ]);
    let (s, v) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(app_body(
            "git",
            with_ports(spec("git.example.eu"), ports.clone()),
        )),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["spec"]["host_ports"], ports);

    // `show` reads the spec back, loopback included as the effective default.
    let (s, v) = admin(&h, "GET", "/v1/apps/git", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["spec"]["host_ports"], ports);
    assert_eq!(v["spec"]["host_ports"][0]["ip"], Value::Null);

    // Persisted in `apps.toml`; an omitted `ip` (loopback) stays omitted on the way out.
    let apps = read(&apps_file(&h));
    assert!(apps.contains("host = 2222"), "{apps}");
    assert!(apps.contains("container = 22"), "{apps}");
    assert!(apps.contains("ip = \"0.0.0.0\""), "{apps}");
    assert!(
        !apps.contains("127.0.0.1"),
        "loopback is implicit, not serialized: {apps}"
    );

    let (s, v) = admin(&h, "GET", "/v1/apps", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["apps"][0]["name"], "git");
    h.running.stop().await;
}

#[tokio::test]
async fn a_second_app_on_the_same_host_port_is_rejected() {
    let h = harness().await;
    let ports = json!([{ "host": 2222, "container": 22 }]);
    let (s, v) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(app_body(
            "git",
            with_ports(spec("git.example.eu"), ports.clone()),
        )),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let before = read(&apps_file(&h));

    let (s, v) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(app_body(
            "other",
            with_ports(spec("other.example.eu"), ports.clone()),
        )),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["code"], "invalid_request");
    let message = v["message"].as_str().unwrap_or_default();
    assert!(message.contains("already published"), "{message}");
    assert!(message.contains("git"), "{message}");

    // The rejected candidate was not saved: the first app still holds the port.
    assert_eq!(read(&apps_file(&h)), before);
    let (s, _) = admin(&h, "GET", "/v1/apps/other", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, v) = admin(&h, "GET", "/v1/apps/git", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["spec"]["host_ports"], ports);
    h.running.stop().await;
}

#[tokio::test]
async fn update_onto_the_ingress_bind_is_rejected() {
    let h = harness().await;
    let (s, v) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(app_body("web", spec("web.example.eu"))),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let before = read(&apps_file(&h));

    // The ingress bind is 127.0.0.1:18080; a wildcard on the same port also collides.
    let mut bad = spec("web.example.eu");
    bad["host_ports"] = json!([{ "host": 18080, "container": 80, "ip": "0.0.0.0" }]);
    let (s, v) = admin(&h, "PUT", "/v1/apps/web", Some(json!({ "spec": bad }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["code"], "invalid_request");
    let message = v["message"].as_str().unwrap_or_default();
    assert!(message.contains("ingress bind"), "{message}");

    // Full-replacement semantics: the spec that was there is unchanged.
    assert_eq!(read(&apps_file(&h)), before);
    let (s, v) = admin(&h, "GET", "/v1/apps/web", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["spec"].get("host_ports").is_none(), "{v}");
    h.running.stop().await;
}

#[tokio::test]
async fn a_privileged_host_port_needs_the_explicit_opt_in() {
    let body = || {
        app_body(
            "git",
            with_ports(
                spec("git.example.eu"),
                json!([{ "host": 222, "container": 22 }]),
            ),
        )
    };

    let h = harness().await;
    let (s, v) = admin(&h, "POST", "/v1/apps", Some(body())).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let message = v["message"].as_str().unwrap_or_default();
    assert!(message.contains("below 1024"), "{message}");
    assert!(message.contains("allow_privileged_host_ports"), "{message}");
    assert!(!apps_file(&h).exists() || !read(&apps_file(&h)).contains("git"));
    h.running.stop().await;

    let h = harness_with(true).await;
    let (s, v) = admin(&h, "POST", "/v1/apps", Some(body())).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["spec"]["host_ports"][0]["host"], 222);
    h.running.stop().await;
}

#[tokio::test]
async fn startup_refuses_an_apps_file_that_breaks_host_port_rules() {
    let conflict = r#"
[apps.a]
image = "i"
host_ports = [{ host = 2222, container = 22 }]

[apps.b]
image = "j"
host_ports = [{ host = 2222, container = 22 }]
"#;
    let privileged = r#"
[apps.git]
image = "i"
start = false
host_ports = [{ host = 222, container = 22 }]
"#;

    let start_err = |apps: &'static str, allow_privileged: bool| async move {
        let (_dir, root) = tempdir();
        std::fs::create_dir_all(root.join("state")).unwrap();
        std::fs::write(root.join("state/apps.toml"), apps).unwrap();
        let host = HostConfig::from_toml_str(&host_toml(&root, allow_privileged)).unwrap();
        start(
            Settings::from_host(host, root.join("weglarka.toml")),
            FakePodman::new(),
        )
        .await
        .err()
        .expect("invalid host_ports must stop the daemon")
        .to_string()
    };

    let message = start_err(conflict, false).await;
    assert!(message.contains("already published"), "{message}");

    let message = start_err(privileged, false).await;
    assert!(message.contains("below 1024"), "{message}");

    // The opt-in makes the same file valid and the daemon starts.
    let (_dir, root) = tempdir();
    std::fs::create_dir_all(root.join("state")).unwrap();
    std::fs::write(root.join("state/apps.toml"), privileged).unwrap();
    let host = HostConfig::from_toml_str(&host_toml(&root, true)).unwrap();
    let running = start(
        Settings::from_host(host, root.join("weglarka.toml")),
        FakePodman::new(),
    )
    .await
    .expect("allow_privileged_host_ports makes port 222 valid");
    running.stop().await;
}
