//! The opt-in `/metrics` listener (ADR 0061) on `FakePodman`: off by default, on creates and joins the
//! network and serves one route, and a network failure leaves the daemon running.

use crate::common::*;

use futures_util::StreamExt;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, StatusCode};
use serde_json::Value;
use tokio::net::TcpStream;
use weglarka_daemon::Running;
use weglarka_daemon::service::SERVICE_NAME;
use weglarka_engine::testing::{Call, FakePodman};
use weglarka_model::podman::PodmanClient;

const ON: &str = "\n[metrics]\nlisten = \"127.0.0.1:0\"\nnetwork = \"scrape\"\n";

/// Models the daemon's own container: unlabelled, named like the service.
async fn own_container(fake: &FakePodman) {
    let mut pull = std::pin::pin!(fake.image_pull(IMAGE));
    while let Some(event) = pull.next().await {
        event.unwrap();
    }
    fake.add_foreign_container(SERVICE_NAME, IMAGE);
}

async fn start_daemon(
    sections: &str,
    own_container: bool,
) -> (tempfile::TempDir, FakePodman, Running<FakePodman>) {
    let (dir, root) = tempdir("wg");
    let fake = FakePodman::new();
    if own_container {
        self::own_container(&fake).await;
    }
    let running = weglarka_daemon::start(settings(&root, "", sections), fake.clone())
        .await
        .unwrap();
    (dir, fake, running)
}

async fn get(addr: std::net::SocketAddr, method: &str, path: &str) -> (StatusCode, String) {
    let stream = TcpStream::connect(addr).await.unwrap();
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "metrics")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (status, body) = send(stream, req).await;
    (status, String::from_utf8_lossy(&body).into_owned())
}

fn connects(fake: &FakePodman) -> usize {
    fake.calls()
        .iter()
        .filter(|c| matches!(c, Call::NetworkConnect { .. }))
        .count()
}

async fn doctor(running: &Running<FakePodman>) -> Vec<Value> {
    let (status, body) = admin_running(running, "GET", "/v1/doctor", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["checks"].as_array().unwrap().clone()
}

#[tokio::test]
async fn off_by_default_binds_nothing_and_touches_no_network() {
    let (_dir, fake, running) = start_daemon("", true).await;
    assert!(running.metrics_addr.is_none());
    assert_eq!(connects(&fake), 0);
    assert!(
        !fake
            .calls()
            .iter()
            .any(|c| matches!(c, Call::NetworkCreate(n) if n == "scrape" || n == "metrics")),
    );
    let checks = doctor(&running).await;
    assert!(
        checks.iter().all(|c| c["id"] != "metrics.listener"),
        "{checks:?}"
    );
    let (_, config) = admin_running(&running, "GET", "/v1/config", None).await;
    assert!(config.get("metrics").is_none());
    running.stop().await;
}

#[tokio::test]
async fn on_creates_and_joins_the_network_and_serves_only_metrics() {
    let (_dir, fake, running) = start_daemon(ON, true).await;
    let addr = running.metrics_addr.expect("listening");
    joined(&running).await;

    assert!(fake.networks().contains(&"scrape".to_owned()));
    assert_eq!(
        fake.network_members("scrape"),
        vec![SERVICE_NAME.to_owned()]
    );
    let spec = fake.network_spec("scrape").unwrap();
    assert_eq!(spec.labels["weglarka.managed"], "metrics");
    assert!(spec.internal, "nothing needs egress through this network");

    let (status, body) = get(addr, "GET", "/metrics").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("# TYPE weglarka_build_info gauge"), "{body}");
    assert!(
        body.contains(&format!(
            "weglarka_build_info{{version=\"{}\"}} 1",
            env!("CARGO_PKG_VERSION")
        )),
        "{body}"
    );

    for path in [
        "/",
        "/v1/apps",
        "/v1/doctor",
        "/v1/health",
        "/webhook/github/x",
        "/metrics/",
    ] {
        let (status, _) = get(addr, "GET", path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }
    let (status, _) = get(addr, "POST", "/metrics").await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);

    let checks = doctor(&running).await;
    let check = checks
        .iter()
        .find(|c| c["id"] == "metrics.listener")
        .unwrap();
    assert_eq!(check["status"], "ok", "{check}");

    let (_, config) = admin_running(&running, "GET", "/v1/config", None).await;
    assert_eq!(config["metrics"]["network"], "scrape");
    running.stop().await;
}

#[tokio::test]
async fn a_second_start_does_not_connect_again() {
    let (_dir, root) = tempdir("wg");
    let fake = FakePodman::new();
    own_container(&fake).await;
    for _ in 0..2 {
        let running = weglarka_daemon::start(settings(&root, "", ON), fake.clone())
            .await
            .unwrap();
        assert!(running.metrics_addr.is_some());
        joined(&running).await;
        running.stop().await;
    }
    assert_eq!(connects(&fake), 1);
}

/// Waits for the background join to finish.
async fn joined(running: &Running<FakePodman>) {
    eventually("the metrics network join", || async {
        listener_check(running).await["status"] == "ok"
    })
    .await;
}

async fn listener_check(running: &Running<FakePodman>) -> Value {
    doctor(running)
        .await
        .into_iter()
        .find(|c| c["id"] == "metrics.listener")
        .unwrap()
}

#[tokio::test(start_paused = true)]
async fn a_network_failure_keeps_serving_retries_and_recovers_without_a_restart() {
    // No container named like the service yet: joining the network is impossible.
    let (_dir, fake, running) = start_daemon(ON, false).await;
    // Bound and serving from the start; the daemon itself is up.
    let addr = running.metrics_addr.expect("bound without the network");
    let (status, _) = get(addr, "GET", "/metrics").await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = admin_running(&running, "GET", "/v1/health", None).await;
    assert_eq!(status, StatusCode::OK);

    let check = listener_check(&running).await;
    assert_eq!(check["status"], "warn", "{check}");
    assert!(
        check["message"]
            .as_str()
            .unwrap()
            .contains("not on network scrape yet")
    );
    assert_eq!(connects(&fake), 0);

    // Podman recovers; the next retry joins without a restart.
    own_container(&fake).await;
    tokio::time::sleep(std::time::Duration::from_secs(70)).await;
    let check = listener_check(&running).await;
    assert_eq!(check["status"], "ok", "{check}");
    assert_eq!(
        fake.network_members("scrape"),
        vec![SERVICE_NAME.to_owned()]
    );
    running.stop().await;
}

#[tokio::test]
async fn a_bind_failure_is_permanent_and_reported_without_stopping_the_daemon() {
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let sections = format!(
        "\n[metrics]\nlisten = \"{}\"\nnetwork = \"scrape\"\n",
        taken.local_addr().unwrap()
    );
    let (_dir, _fake, running) = start_daemon(&sections, true).await;
    assert!(running.metrics_addr.is_none());
    let check = listener_check(&running).await;
    assert_eq!(check["status"], "fail", "{check}");
    assert!(check["message"].as_str().unwrap().contains("not started"));
    let (status, _) = admin_running(&running, "GET", "/v1/health", None).await;
    assert_eq!(status, StatusCode::OK);
    running.stop().await;
}

#[test]
fn an_invalid_network_name_is_rejected() {
    for bad in ["net-foo", "Bad", "-x", ""] {
        let toml = format!("listen = \"127.0.0.1:1\"\nnetwork = \"{bad}\"");
        let cfg: weglarka_model::config::MetricsConfig = toml::from_str(&toml).unwrap();
        assert!(cfg.validate().is_err(), "{bad}");
    }
    let cfg: weglarka_model::config::MetricsConfig =
        toml::from_str("listen = \"127.0.0.1:1\"").unwrap();
    assert_eq!(cfg.network, "metrics");
    assert!(cfg.validate().is_ok());
}

// Daemon metrics (issue #352): counters from events, certificate expiry, self-update state.

fn digest(c: char) -> weglarka_model::app::Digest {
    weglarka_model::app::Digest::new(format!("sha256:{}", c.to_string().repeat(64))).unwrap()
}

async fn scrape(running: &Running<FakePodman>) -> String {
    let (status, body) = get(running.metrics_addr.expect("listening"), "GET", "/metrics").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body
}

/// No family-specific line leaks anything but names and fixed enums.
fn assert_no_free_text(body: &str) {
    for leak in ["sha256", "ghcr.io", "DISTINCTIVE"] {
        assert!(!body.contains(leak), "{leak} in {body}");
    }
}

#[tokio::test]
async fn deploys_and_failed_deploys_move_their_counters_and_no_reason_reaches_a_label() {
    let h = Builder::new().sections(ON).build().await;
    add(&h, "web", spec("web.example.com")).await;
    deployed(&h, "web").await;

    let bad = "ghcr.io/jpalczewski/bad:latest";
    h.fake
        .fail_pull(bad, "DISTINCTIVE \"reason\"\nwith a newline");
    let mut failing = spec("bad.example.com");
    failing["image"] = bad.into();
    add(&h, "bad", failing).await;

    eventually("the failed deploy is counted", || async {
        scrape(&h.running)
            .await
            .contains("weglarka_deploys_total{app=\"bad\",result=\"failed\"}")
    })
    .await;
    let body = scrape(&h.running).await;
    assert!(
        body.contains("# TYPE weglarka_deploys_total counter"),
        "{body}"
    );
    assert!(
        body.contains("weglarka_deploys_total{app=\"web\",result=\"ok\"} 1\n"),
        "{body}"
    );
    assert!(
        !body.contains("weglarka_deploys_total{app=\"web\",result=\"failed\"}"),
        "{body}"
    );
    assert!(!body.contains("# TYPE weglarka_rollbacks_total"), "{body}");
    // Neither ACME nor self-update is configured.
    assert!(!body.contains("weglarka_certificate_"), "{body}");
    assert!(!body.contains("weglarka_self_update_"), "{body}");
    assert_no_free_text(&body);
    h.running.stop().await;
}

#[tokio::test]
async fn a_rollback_counts() {
    let h = Builder::new().sections(ON).build().await;
    h.fake.set_pull_digest(IMAGE, digest('a'));
    h.fake
        .script_health("web", [weglarka_model::podman::HealthStatus::Healthy]);
    add(&h, "web", spec("web.example.com")).await;
    deployed(&h, "web").await;

    // The next version fails its gate; the container restored after it is healthy again.
    h.fake.set_pull_digest(IMAGE, digest('b'));
    h.fake.script_health(
        "web",
        [
            weglarka_model::podman::HealthStatus::Unhealthy,
            weglarka_model::podman::HealthStatus::Healthy,
        ],
    );
    let (status, body) = admin(
        &h,
        "POST",
        "/v1/apps/web/deploy",
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["outcome"], "rolled_back", "{body}");

    let body = scrape(&h.running).await;
    assert!(
        body.contains("weglarka_rollbacks_total{app=\"web\",result=\"ok\"} 1\n"),
        "{body}"
    );
    assert!(
        body.contains("weglarka_deploys_total{app=\"web\",result=\"ok\"} 1\n"),
        "{body}"
    );
    assert_no_free_text(&body);
    h.running.stop().await;
}

#[tokio::test]
async fn self_update_state_appears_only_with_the_section_and_an_unreadable_file_omits_it() {
    let state = weglarka_model::self_update::SelfUpdateState {
        pending: Some(digest('c')),
        pending_at: Some(1_700_000_000),
        checked_at: Some(1_700_000_100),
        error: Some(weglarka_model::self_update::SelfUpdateError {
            message: "DISTINCTIVE signature refused".into(),
            digest: Some(digest('d')),
            at: 1_700_000_200,
        }),
        ..Default::default()
    };
    let section = "\n[self_update]\nimage = \"ghcr.io/jpalczewski/weglarka:latest\"\n";
    let h = Builder::new()
        .sections(&format!("{ON}{section}"))
        .build()
        .await;
    weglarka_model::self_update::save(&h.root.join("state"), &state).unwrap();
    let body = scrape(&h.running).await;
    assert!(body.contains("weglarka_self_update_pending 1\n"), "{body}");
    assert!(
        body.contains("weglarka_self_update_last_check_timestamp_seconds 1700000100\n"),
        "{body}"
    );
    assert!(
        body.contains("weglarka_self_update_last_error_timestamp_seconds 1700000200\n"),
        "{body}"
    );
    assert_no_free_text(&body);

    // A broken state file: the family goes, the page stays.
    std::fs::write(h.root.join("state/self-update.toml"), "pending = [").unwrap();
    let body = scrape(&h.running).await;
    assert!(!body.contains("weglarka_self_update_"), "{body}");
    assert!(body.contains("weglarka_build_info"), "{body}");
    h.running.stop().await;

    // Without `[self_update]` the same file adds nothing.
    let h = Builder::new().sections(ON).build().await;
    weglarka_model::self_update::save(&h.root.join("state"), &state).unwrap();
    let body = scrape(&h.running).await;
    assert!(!body.contains("weglarka_self_update_"), "{body}");
    h.running.stop().await;
}

fn edge_settings(root: &std::path::Path, extra: &str) -> weglarka_daemon::Settings {
    let host = weglarka_model::config::HostConfig::from_toml_str(&format!(
        r#"
[ingress]
mode = "edge"
bind = "127.0.0.1:18080"
https_bind = "127.0.0.1:18443"

[admin]
socket = "{root}/run/admin.sock"

[webhook]
listen = "127.0.0.1:0"
domain = "hooks.example.com"

[state]
dir = "{root}/state"
{extra}"#,
        root = root.display()
    ))
    .unwrap();
    weglarka_daemon::Settings::from_host(host, root.join("weglarka.toml"))
}

#[tokio::test]
async fn certificate_expiry_is_a_timestamp_per_routed_domain_only_with_acme() {
    // `openssl x509 -enddate` of the fixture: Oct  1 07:51:01 2126 GMT.
    const LEAF: &[u8] = include_bytes!("../../../weglarka-acme/tests/fixtures/leaf.crt");
    const NOT_AFTER: u64 = 4_946_514_661;
    let acme = "[acme]\naccept_terms = true\ndirectory_url = \"https://acme.invalid/directory\"\n";

    let (_dir, root) = tempdir("wg");
    let running = weglarka_daemon::start(
        edge_settings(&root, &format!("{ON}{acme}")),
        FakePodman::new(),
    )
    .await
    .unwrap();
    let tls = running.daemon.ingress.tls_dir();
    std::fs::create_dir_all(&tls).unwrap();
    std::fs::write(tls.join("hooks.example.com.crt"), LEAF).unwrap();
    std::fs::write(tls.join("hooks.example.com.key"), "key").unwrap();
    // Not routed: a stray certificate gets no line.
    std::fs::write(tls.join("stray.example.org.crt"), LEAF).unwrap();
    std::fs::write(tls.join("stray.example.org.key"), "key").unwrap();

    let body = scrape(&running).await;
    assert!(
        body.contains("# TYPE weglarka_certificate_not_after_seconds gauge"),
        "{body}"
    );
    assert!(
        body.contains(&format!(
            "weglarka_certificate_not_after_seconds{{domain=\"hooks.example.com\"}} {NOT_AFTER}\n"
        )),
        "{body}"
    );
    assert!(!body.contains("stray.example.org"), "{body}");
    running.stop().await;

    // The same files without `[acme]`: no family.
    let running = weglarka_daemon::start(edge_settings(&root, ON), FakePodman::new())
        .await
        .unwrap();
    let body = scrape(&running).await;
    assert!(!body.contains("weglarka_certificate_"), "{body}");
    running.stop().await;
}
