//! Shared harness for the daemon's integration tests: the daemon runs for real (its admin unix
//! socket answers) while Podman is a [`FakePodman`].
//!
//! All integration tests live in one binary (`tests/it/main.rs`, one module per area), so the
//! generic `Daemon<FakePodman>` and the HTTP stack are compiled and linked once instead of once per
//! file. Modules pull the helpers in with `use crate::common::*;`.

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

/// The image reference most tests deploy; only its name matters to [`FakePodman`].
pub const IMAGE: &str = "ghcr.io/jpalczewski/ntfy.zig:latest";

/// A started daemon on a temp dir, with the handle of the [`FakePodman`] behind it.
pub struct Harness {
    /// Kept only so the temp dir outlives the daemon: dropping it removes everything.
    pub _dir: tempfile::TempDir,
    /// The daemon's root: `weglarka.toml`, `traefik.yml`, `run/` and `state/` live here.
    pub root: PathBuf,
    /// `<root>/config`: the directory tests use as `config_root` when they set it in the config.
    pub config_root: PathBuf,
    pub fake: FakePodman,
    pub running: Running<FakePodman>,
}

/// A temp dir under `/tmp` (a unix socket path is limited to ~104 characters) with `traefik.yml`
/// written, i.e. everything a [`Settings`] needs except the daemon's state.
pub fn tempdir(prefix: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in("/tmp")
        .unwrap();
    let root = dir.path().to_owned();
    std::fs::write(root.join("traefik.yml"), "").unwrap();
    (dir, root)
}

/// The `weglarka.toml` the tests start from.
///
/// `top_level` lines land **before** the first table (that is where `config_root` lives) and
/// `sections` after `[state]`, so a test can add `[runtime]`, `[notify.*]`, `[self_update]` and so
/// on without copying the whole file.
pub fn host_toml(root: &Path, top_level: &str, sections: &str) -> String {
    format!(
        "{top_level}
[ingress]
mode = \"behind\"
bind = \"127.0.0.1:18080\"
traefik_dynamic_file = \"{root}/traefik.yml\"

[admin]
socket = \"{root}/run/admin.sock\"

[webhook]
listen = \"127.0.0.1:0\"
domain = \"hooks.example.eu\"

[state]
dir = \"{root}/state\"
{sections}",
        root = root.display()
    )
}

/// Daemon settings for `root` without starting anything (`root` must already exist): for tests
/// that drive [`start`] themselves to observe a startup error.
pub fn settings(root: &Path, top_level: &str, sections: &str) -> Settings {
    let host = HostConfig::from_toml_str(&host_toml(root, top_level, sections)).unwrap();
    Settings::from_host(host, root.join("weglarka.toml"))
}

/// Builds a [`Harness`] whose config differs from [`host_toml`]'s default.
pub struct Builder {
    dir: tempfile::TempDir,
    root: PathBuf,
    top_level: String,
    sections: String,
    apps: Option<String>,
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl Builder {
    /// A fresh [`tempdir`]; use [`root`](Self::root) to prepare files under it before the start.
    pub fn new() -> Self {
        let (dir, root) = tempdir("wg");
        Self {
            dir,
            root,
            top_level: String::new(),
            sections: String::new(),
            apps: None,
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Extra `weglarka.toml` lines before the first table (`config_root = "…"`).
    pub fn top_level(mut self, toml: &str) -> Self {
        self.top_level.push_str(toml);
        self
    }

    /// Extra `weglarka.toml` sections appended after `[state]`.
    pub fn sections(mut self, toml: &str) -> Self {
        self.sections.push_str(toml);
        self
    }

    /// Writes `<root>/state/apps.toml` before the daemon starts (startup validation reads it).
    pub fn apps(mut self, apps_toml: &str) -> Self {
        self.apps = Some(apps_toml.to_owned());
        self
    }

    pub async fn build(self) -> Harness {
        if let Some(apps) = &self.apps {
            std::fs::create_dir_all(self.root.join("state")).unwrap();
            std::fs::write(self.root.join("state/apps.toml"), apps).unwrap();
        }
        let fake = FakePodman::new();
        let running = start(
            settings(&self.root, &self.top_level, &self.sections),
            fake.clone(),
        )
        .await
        .unwrap();
        Harness {
            _dir: self.dir,
            config_root: self.root.join("config"),
            root: self.root,
            fake,
            running,
        }
    }
}

/// The default daemon: [`host_toml`] with no extras.
pub async fn harness() -> Harness {
    Builder::new().build().await
}

/// One HTTP/1 request over `stream`, returning the status and the whole body.
pub async fn send<S>(stream: S, req: Request<Full<Bytes>>) -> (StatusCode, Bytes)
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

/// An admin API call with an optional JSON body: returns the status and the decoded answer (`Null`
/// for an empty body).
pub async fn admin(
    h: &Harness,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    admin_running(&h.running, method, path, body).await
}

/// [`admin`] against a raw [`Running`]: for tests that drive [`start`] without a [`Harness`].
pub async fn admin_running(
    running: &Running<FakePodman>,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let stream = UnixStream::connect(&running.admin_socket).await.unwrap();
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

/// A raw admin call: returns the status and the body bytes (tars, error messages).
pub async fn raw(h: &Harness, method: &str, path: &str, body: Vec<u8>) -> (StatusCode, Bytes) {
    let stream = UnixStream::connect(&h.running.admin_socket).await.unwrap();
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "weglarka")
        .body(Full::new(Bytes::from(body)))
        .unwrap();
    send(stream, req).await
}

/// Retries `f` for up to ten seconds.
///
/// `apps add` with `start = true` only writes the spec: the deploy (network, container, digest in
/// the state) runs in the background reconcile pass, so a test that looks at that state must poll
/// instead of asserting right after the 200.
pub async fn eventually<F: Fn() -> Fut, Fut: Future<Output = bool>>(what: &str, f: F) {
    for _ in 0..100 {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for: {what}");
}

/// A file the daemon wrote, or the empty string when it does not exist yet.
pub fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// The spec most tests deploy: the ntfy image on `domain` with a single-attempt health gate.
pub fn spec(domain: &str) -> Value {
    json!({
        "image": IMAGE,
        "domains": [domain],
        "port": 8085,
        "health": { "attempts": 1, "window_secs": 1 }
    })
}

/// `POST /v1/apps` with `{ "name", "spec" }`; the status is not asserted (negative tests need it).
pub async fn post_app(h: &Harness, name: &str, spec: Value) -> (StatusCode, Value) {
    admin(
        h,
        "POST",
        "/v1/apps",
        Some(json!({ "name": name, "spec": spec })),
    )
    .await
}

/// [`post_app`], asserting the daemon accepted the app.
pub async fn add(h: &Harness, name: &str, spec: Value) {
    let (status, body) = post_app(h, name, spec).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// `GET /v1/apps/{name}`, asserting a 200.
pub async fn show(h: &Harness, name: &str) -> Value {
    let (status, value) = admin(h, "GET", &format!("/v1/apps/{name}"), None).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    value
}

/// Waits until the background deploy recorded a digest for `name`.
pub async fn deployed(h: &Harness, name: &str) {
    eventually("first deploy", || async {
        show(h, name).await["state"]["current"].is_string()
    })
    .await;
}
