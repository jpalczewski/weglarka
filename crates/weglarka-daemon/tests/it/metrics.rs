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
