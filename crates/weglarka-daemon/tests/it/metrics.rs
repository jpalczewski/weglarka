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

    assert!(fake.networks().contains(&"scrape".to_owned()));
    assert_eq!(
        fake.network_members("scrape"),
        vec![SERVICE_NAME.to_owned()]
    );
    assert_eq!(
        fake.network_spec("scrape").unwrap().labels["weglarka.managed"],
        "metrics"
    );

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
        running.stop().await;
    }
    assert_eq!(connects(&fake), 1);
}

#[tokio::test]
async fn a_network_failure_leaves_the_daemon_running_and_doctor_reports_it() {
    // No container named like the service: joining the network is impossible.
    let (_dir, _fake, running) = start_daemon(ON, false).await;
    assert!(running.metrics_addr.is_none());

    let checks = doctor(&running).await;
    let check = checks
        .iter()
        .find(|c| c["id"] == "metrics.listener")
        .unwrap();
    assert_eq!(check["status"], "fail", "{check}");
    assert!(check["message"].as_str().unwrap().contains("not started"));

    // The other listeners are up.
    let (status, _) = get(running.webhook_addr, "GET", "/nothing").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
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
