//! Self-update through the real admin socket (issue #99, decision 0027): the startup confirmation of
//! the digest a switch requested and the `self_update` doctor check (off, applied, pending, stale
//! timer).

use std::path::PathBuf;

use futures_util::StreamExt;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use tokio::net::UnixStream;
use weglarka_core::app::Digest;
use weglarka_core::config::HostConfig;
use weglarka_core::podman::PodmanClient;
use weglarka_core::self_update::{self, SelfUpdateState};
use weglarka_core::testing::FakePodman;
use weglarka_daemon::{Running, Settings, start};

const IMAGE: &str = "ghcr.io/jpalczewski/weglarka:latest";
const SELF_UPDATE: &str = r#"
[self_update]
image = "ghcr.io/jpalczewski/weglarka:latest"
interval_secs = 300
"#;

struct Env {
    _dir: tempfile::TempDir,
    fake: FakePodman,
    settings: Settings,
}

impl Env {
    fn new(extra: &str) -> Self {
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
bind = "127.0.0.1:18081"
traefik_dynamic_file = "{root}/traefik.yml"

[admin]
socket = "{root}/run/admin.sock"

[webhook]
listen = "127.0.0.1:0"
domain = "hooks.example.eu"

[state]
dir = "{root}/state"
{extra}
"#,
            root = root.display()
        ))
        .unwrap();
        let settings = Settings::from_host(host, root.join("weglarka.toml"));
        std::fs::create_dir_all(&settings.paths.state_dir).unwrap();
        Env {
            _dir: dir,
            fake: FakePodman::new(),
            settings,
        }
    }

    fn state_dir(&self) -> PathBuf {
        self.settings.paths.state_dir.clone()
    }

    /// Pulls `reference` into the fake store (moving its digest) and returns the digest.
    async fn pull(&self, reference: &str) -> Digest {
        let digest = digest('a');
        self.fake.set_pull_digest(reference, digest.clone());
        let mut stream = std::pin::pin!(self.fake.image_pull(reference));
        while let Some(event) = stream.next().await {
            event.unwrap();
        }
        digest
    }

    /// Models the daemon's own container: unlabelled, named `weglarka`, running `reference`.
    fn own_container(&self, reference: &str) {
        self.fake.add_foreign_container("weglarka", reference);
    }

    async fn start(&self) -> Running<FakePodman> {
        start(self.settings.clone(), self.fake.clone())
            .await
            .unwrap()
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

async fn doctor(running: &Running<FakePodman>) -> Value {
    let stream = UnixStream::connect(&running.admin_socket).await.unwrap();
    let req = Request::builder()
        .method("GET")
        .uri("/v1/doctor")
        .header("host", "weglarka")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (status, bytes) = send(stream, req).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    serde_json::from_slice(&bytes).unwrap()
}

fn check<'a>(report: &'a Value, id: &str) -> &'a Value {
    report["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .find(|c| c["id"] == id)
        .unwrap_or_else(|| panic!("no {id} check in {report}"))
}

fn status(check: &Value) -> &str {
    check["status"].as_str().unwrap_or_default()
}

#[tokio::test]
async fn startup_confirms_the_pending_digest_and_keeps_the_previous_one() {
    let env = Env::new(SELF_UPDATE);
    let pulled = env.pull(IMAGE).await;
    env.own_container(IMAGE);
    let previous = digest('b');
    let now = self_update::secs(std::time::SystemTime::now());
    self_update::save(
        &env.state_dir(),
        &SelfUpdateState {
            current: Some(previous.clone()),
            pending: Some(pulled.clone()),
            pending_at: Some(now),
            checked_at: Some(now),
            ..SelfUpdateState::default()
        },
    )
    .unwrap();

    let running = env.start().await;
    let state = self_update::load(&env.state_dir()).unwrap();
    assert_eq!(state.current, Some(pulled.clone()), "confirmed at startup");
    assert_eq!(state.previous, Some(previous.clone()), "rollback target");
    assert_eq!(state.pending, None, "a confirmed request is cleared");

    let report = doctor(&running).await;
    let su = check(&report, "self_update");
    assert_eq!(status(su), "ok", "{su}");
    let message = su["message"].as_str().unwrap();
    assert!(message.contains("running"), "{message}");
    assert!(message.contains("previous"), "{message}");
    running.stop().await;
}

#[tokio::test]
async fn a_switch_that_did_not_take_effect_is_reported_not_assumed() {
    let env = Env::new(SELF_UPDATE);
    let running_digest = env.pull(IMAGE).await;
    env.own_container(IMAGE);
    let pending = digest('e');
    let now = self_update::secs(std::time::SystemTime::now());
    self_update::save(
        &env.state_dir(),
        &SelfUpdateState {
            current: Some(running_digest.clone()),
            pending: Some(pending.clone()),
            pending_at: Some(now),
            checked_at: Some(now),
            ..SelfUpdateState::default()
        },
    )
    .unwrap();

    let running = env.start().await;
    // The daemon really runs `running_digest`, so the requested switch did not happen.
    let state = self_update::load(&env.state_dir()).unwrap();
    assert_eq!(state.current, Some(running_digest.clone()));
    assert_eq!(state.pending, Some(pending), "kept for doctor and rollback");
    let report = doctor(&running).await;
    let su = check(&report, "self_update");
    assert_eq!(status(su), "warn", "{su}");
    let message = su["message"].as_str().unwrap();
    assert!(message.contains("pending"), "{message}");
    let hint = su["hint"].as_str().unwrap_or_default();
    assert!(hint.contains("--rollback"), "{hint}");
    running.stop().await;
}

#[tokio::test]
async fn a_configured_self_update_without_a_recent_check_warns_about_the_timer() {
    let env = Env::new(SELF_UPDATE);
    let running = env.start().await;
    let report = doctor(&running).await;
    let su = check(&report, "self_update");
    assert_eq!(status(su), "warn", "{su}");
    let hint = su["hint"].as_str().unwrap_or_default();
    assert!(hint.contains("platform install"), "{hint}");
    running.stop().await;
}

#[tokio::test]
async fn without_the_section_the_check_says_off() {
    let env = Env::new("");
    let running = env.start().await;
    let report = doctor(&running).await;
    let su = check(&report, "self_update");
    assert_eq!(status(su), "ok", "{su}");
    assert!(su["message"].as_str().unwrap().contains("off"), "{su}");
    running.stop().await;
}

#[tokio::test]
async fn an_unusable_self_update_section_stops_the_daemon() {
    let env = Env::new("[self_update]\nimage = \"ghcr.io/o/w\"\n");
    let err = match start(env.settings.clone(), env.fake.clone()).await {
        Ok(_) => panic!("[self_update] without a tag must stop the daemon"),
        Err(e) => e,
    };
    let message = err.to_string();
    assert!(message.contains("no tag"), "{message}");
}

/// Issue #100: `GET /v1/health` is the readiness signal the host-side watchdog probes. It must answer
/// on the admin socket without touching Podman.
#[tokio::test]
async fn health_answers_once_the_admin_api_serves() {
    let env = Env::new(SELF_UPDATE);
    let running = env.start().await;
    let stream = UnixStream::connect(&running.admin_socket).await.unwrap();
    let req = Request::builder()
        .method("GET")
        .uri("/v1/health")
        .header("host", "weglarka")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (status, bytes) = send(stream, req).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["status"], "ok");
    assert!(
        body["daemon_version"]
            .as_str()
            .is_some_and(|v| !v.is_empty()),
        "{body}"
    );
    assert!(body["uptime_secs"].as_u64().is_some(), "{body}");
    running.stop().await;
}

/// Issue #100: a fallback recorded by the watchdog is confirmed at startup, the failed digest never
/// becomes the rollback target, and `doctor` reports what happened.
#[tokio::test]
async fn a_fallback_is_confirmed_and_reported_by_doctor() {
    let env = Env::new(SELF_UPDATE);
    // The container really runs the restored image: that is what the fallback pinned.
    let restored = env.pull(IMAGE).await;
    env.own_container(IMAGE);
    let failed = digest('f');
    let mut state = SelfUpdateState {
        current: Some(failed.clone()),
        ..SelfUpdateState::default()
    };
    state.begin_switch(
        Some(restored.clone()),
        failed.clone(),
        std::time::SystemTime::now() - std::time::Duration::from_secs(600),
    );
    state.record_fallback(
        failed.clone(),
        restored.clone(),
        std::time::SystemTime::now() - std::time::Duration::from_secs(300),
    );
    state.record_error(
        "the switch to the new image did not become healthy",
        Some(failed.clone()),
        std::time::SystemTime::now() - std::time::Duration::from_secs(300),
    );
    self_update::save(&env.state_dir(), &state).unwrap();

    let running = env.start().await;
    let state = self_update::load(&env.state_dir()).unwrap();
    assert_eq!(state.current, Some(restored.clone()));
    assert_eq!(
        state.previous, None,
        "the failed image is not a rollback target"
    );
    assert!(state.pending.is_none(), "the fallback is confirmed");

    let report = doctor(&running).await;
    let su = check(&report, "self_update");
    assert_eq!(status(su), "warn", "{su}");
    let message = su["message"].as_str().unwrap();
    assert!(message.contains("automatic fallback"), "{message}");
    assert!(message.contains("failed"), "{message}");
    running.stop().await;
}
