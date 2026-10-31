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
    for bad in ["net-foo", "metrics-foo", "metrics-", "Bad", "-x", ""] {
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

#[tokio::test]
async fn certificate_expiry_is_a_timestamp_per_routed_domain_only_with_acme() {
    // `openssl x509 -enddate` of the fixture: Oct  1 07:51:01 2126 GMT.
    const LEAF: &[u8] = include_bytes!("../../../weglarka-acme/tests/fixtures/leaf.crt");
    const NOT_AFTER: u64 = 4_946_514_661;
    let acme = "[acme]\naccept_terms = true\ndirectory_url = \"https://acme.invalid/directory\"\n";

    let (_dir, root) = tempdir("wg");
    let running = weglarka_daemon::start(
        crate::daemon::edge_settings_with(&root, &format!("{ON}{acme}")),
        FakePodman::new(),
    )
    .await
    .unwrap();
    let tls = running.daemon.ingress.tls_dir();
    std::fs::create_dir_all(&tls).unwrap();
    std::fs::write(tls.join("hooks.example.eu.crt"), LEAF).unwrap();
    std::fs::write(tls.join("hooks.example.eu.key"), "key").unwrap();
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
            "weglarka_certificate_not_after_seconds{{domain=\"hooks.example.eu\"}} {NOT_AFTER}\n"
        )),
        "{body}"
    );
    assert!(!body.contains("stray.example.org"), "{body}");
    running.stop().await;

    // The same files without `[acme]`: no family.
    let running = weglarka_daemon::start(
        crate::daemon::edge_settings_with(&root, ON),
        FakePodman::new(),
    )
    .await
    .unwrap();
    let body = scrape(&running).await;
    assert!(!body.contains("weglarka_certificate_"), "{body}");
    running.stop().await;
}

// ---- per-app resources (#351) ----

mod resources {
    use std::collections::BTreeMap;

    use super::*;
    use weglarka_daemon::ingress::NGINX_CONTAINER;
    use weglarka_model::podman::{ContainerStats, NetworkIo};

    /// A daemon with `[metrics]` on and the daemon's own container present.
    async fn metrics_harness() -> Harness {
        let h = Builder::new().sections(ON).build().await;
        own_container(&h.fake).await;
        h
    }

    async fn scrape(h: &Harness) -> String {
        let addr = h.running.metrics_addr.expect("listening");
        let (status, body) = get(addr, "GET", "/metrics").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    /// The value of the series `name{app="…",role="…"}`, if the page has it.
    fn sample(body: &str, name: &str, app: &str, role: &str) -> Option<f64> {
        let series = format!("{name}{{app=\"{app}\",role=\"{role}\"}} ");
        body.lines()
            .find_map(|line| line.strip_prefix(&series))
            .map(|v| v.parse().unwrap())
    }

    fn unlabelled(body: &str, name: &str) -> Option<f64> {
        body.lines()
            .find_map(|line| line.strip_prefix(&format!("{name} ")))
            .map(|v| v.parse().unwrap())
    }

    /// Every `app` label value on the page.
    fn apps(body: &str) -> Vec<String> {
        let mut apps: Vec<String> = body
            .lines()
            .filter_map(|line| line.split("app=\"").nth(1))
            .filter_map(|rest| rest.split('"').next())
            .map(str::to_owned)
            .collect();
        apps.sort();
        apps.dedup();
        apps
    }

    fn stat(name: &str, mib: u64) -> ContainerStats {
        ContainerStats {
            name: name.to_owned(),
            memory_usage: mib << 20,
            cpu_nanos: 1_000_000_000,
            pids: 1,
            ..Default::default()
        }
    }

    /// A running container with `labels`, as a deploy, `run`, `forward` or an import leaves it.
    fn labelled(fake: &FakePodman, name: &str, labels: &[(&str, &str)]) {
        fake.add_foreign_container(name, IMAGE);
        fake.set_container_labels(
            name,
            labels
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect::<BTreeMap<_, _>>(),
        );
    }

    async fn app(h: &Harness, name: &str, memory: Option<&str>) {
        let mut spec = spec(&format!("{name}.example.com"));
        if let Some(memory) = memory {
            spec["resources"] = serde_json::json!({ "memory": memory });
        }
        add(h, name, spec).await;
        deployed(h, name).await;
    }

    fn stats_calls(fake: &FakePodman) -> usize {
        fake.calls()
            .iter()
            .filter(|c| matches!(c, Call::ContainerStats))
            .count()
    }

    const MEMORY: &str = "weglarka_container_memory_usage_bytes";

    #[tokio::test]
    async fn the_role_comes_from_the_blue_green_container_name() {
        let h = metrics_harness().await;
        app(&h, "alpha", None).await;
        labelled(&h.fake, "alpha.next", &[("weglarka.instance", "alpha")]);
        labelled(&h.fake, "alpha.prev", &[("weglarka.instance", "alpha")]);
        h.fake.script_stats([
            stat("alpha", 1),
            stat("alpha.next", 2),
            stat("alpha.prev", 3),
        ]);

        let body = scrape(&h).await;
        assert_eq!(sample(&body, MEMORY, "alpha", "active"), Some(1048576.0));
        assert_eq!(
            sample(&body, MEMORY, "alpha", "challenger"),
            Some(2097152.0)
        );
        assert_eq!(sample(&body, MEMORY, "alpha", "retiring"), Some(3145728.0));
        assert_eq!(unlabelled(&body, "weglarka_resource_metrics_up"), Some(1.0));
        h.running.stop().await;
    }

    #[tokio::test]
    async fn one_off_containers_and_unlabelled_strangers_get_no_series() {
        let h = metrics_harness().await;
        app(&h, "alpha", None).await;
        // Names of one-off containers carry tokens; they also carry the instance as `*-for`.
        labelled(
            &h.fake,
            "wg-run.alpha.3f9a2c",
            &[("weglarka.run", "true"), ("weglarka.run-for", "alpha")],
        );
        labelled(
            &h.fake,
            "wg-fwd.alpha.77ab01",
            &[
                ("weglarka.forward", "true"),
                ("weglarka.forward-for", "alpha"),
            ],
        );
        labelled(
            &h.fake,
            "wg-import.alpha",
            &[("weglarka.import-for", "alpha")],
        );
        // Even with the instance label, a run marker wins.
        labelled(
            &h.fake,
            "wg-run.alpha.b0b0",
            &[("weglarka.run", "true"), ("weglarka.instance", "alpha")],
        );
        h.fake.add_foreign_container("hand-started", IMAGE);
        h.fake.script_stats(
            [
                "alpha",
                "wg-run.alpha.3f9a2c",
                "wg-fwd.alpha.77ab01",
                "wg-import.alpha",
                "wg-run.alpha.b0b0",
                "hand-started",
            ]
            .map(|n| stat(n, 1)),
        );

        let body = scrape(&h).await;
        assert!(!body.contains("wg-run."), "{body}");
        assert!(!body.contains("wg-fwd."), "{body}");
        assert!(!body.contains("wg-import."), "{body}");
        assert!(!body.contains("hand-started"), "{body}");
        assert!(sample(&body, MEMORY, "alpha", "active").is_some(), "{body}");
        assert!(
            body.lines()
                .filter(|l| l.starts_with(MEMORY))
                .all(|l| !l.contains("role=\"challenger\"")),
            "{body}"
        );
        h.running.stop().await;
    }

    /// The forwarder exists only in `edge` mode (the `behind` harness removes it on every ingress
    /// pass); its naming is covered by the unit tests of `metrics::resources`.
    #[tokio::test]
    async fn the_ingress_and_the_daemon_are_reported_by_their_names() {
        let h = metrics_harness().await;
        if h.fake.container_inspect(NGINX_CONTAINER).await.is_err() {
            h.fake.add_foreign_container(NGINX_CONTAINER, IMAGE);
        }
        h.fake
            .script_stats([stat(NGINX_CONTAINER, 4), stat(SERVICE_NAME, 6)]);

        let body = scrape(&h).await;
        assert_eq!(
            sample(&body, MEMORY, NGINX_CONTAINER, "active"),
            Some(4.0 * 1048576.0)
        );
        assert_eq!(
            sample(&body, MEMORY, SERVICE_NAME, "active"),
            Some(6.0 * 1048576.0)
        );
        assert_eq!(
            apps(&body),
            vec![SERVICE_NAME.to_owned(), NGINX_CONTAINER.to_owned()]
        );
        h.running.stop().await;
    }

    #[tokio::test]
    async fn every_field_libpod_supplies_becomes_a_sample() {
        let h = metrics_harness().await;
        app(&h, "alpha", None).await;
        h.fake.set_restarts("alpha", 3);
        h.fake.set_oom_killed("alpha", true);
        h.fake.script_stats([ContainerStats {
            name: "alpha".into(),
            memory_usage: 4096,
            cpu_nanos: 2_500_000_000,
            pids: 7,
            block_read_bytes: 8192,
            block_write_bytes: 0,
            network: Some(NetworkIo {
                rx_bytes: 1024,
                tx_bytes: 206,
            }),
        }]);

        let body = scrape(&h).await;
        let alpha = |name| sample(&body, name, "alpha", "active");
        assert_eq!(alpha(MEMORY), Some(4096.0));
        assert_eq!(alpha("weglarka_container_cpu_seconds_total"), Some(2.5));
        assert_eq!(alpha("weglarka_container_pids"), Some(7.0));
        assert_eq!(
            alpha("weglarka_container_block_read_bytes_total"),
            Some(8192.0)
        );
        assert_eq!(
            alpha("weglarka_container_block_write_bytes_total"),
            Some(0.0),
            "a real zero next to a non-zero read is data"
        );
        assert_eq!(
            alpha("weglarka_container_network_receive_bytes_total"),
            Some(1024.0)
        );
        assert_eq!(
            alpha("weglarka_container_network_transmit_bytes_total"),
            Some(206.0)
        );
        assert_eq!(alpha("weglarka_container_restarts_total"), Some(3.0));
        assert_eq!(alpha("weglarka_container_oom_killed"), Some(1.0));
        assert!(
            body.contains("# TYPE weglarka_container_cpu_seconds_total counter"),
            "{body}"
        );
        assert!(
            body.contains("# TYPE weglarka_container_memory_usage_bytes gauge"),
            "{body}"
        );
        h.running.stop().await;
    }

    #[tokio::test]
    async fn the_memory_limit_is_reported_only_when_one_is_set() {
        let h = metrics_harness().await;
        app(&h, "alpha", Some("64m")).await;
        app(&h, "beta", None).await;
        h.fake.script_stats([stat("alpha", 1), stat("beta", 1)]);

        let body = scrape(&h).await;
        let limit = "weglarka_container_memory_limit_bytes";
        assert_eq!(sample(&body, limit, "alpha", "active"), Some(67108864.0));
        assert_eq!(sample(&body, limit, "beta", "active"), None, "{body}");
        assert!(sample(&body, MEMORY, "beta", "active").is_some());
        h.running.stop().await;
    }

    #[tokio::test]
    async fn missing_data_is_no_sample_not_zero() {
        let h = metrics_harness().await;
        app(&h, "alpha", None).await;
        app(&h, "beta", None).await;
        // alpha: libpod answered with zeros (no controller delegation); beta: no stats entry at all.
        h.fake.script_stats([ContainerStats {
            name: "alpha".into(),
            ..Default::default()
        }]);

        let body = scrape(&h).await;
        for app in ["alpha", "beta"] {
            for name in [
                MEMORY,
                "weglarka_container_cpu_seconds_total",
                "weglarka_container_pids",
                "weglarka_container_block_read_bytes_total",
                "weglarka_container_block_write_bytes_total",
                "weglarka_container_network_receive_bytes_total",
                "weglarka_container_network_transmit_bytes_total",
            ] {
                assert_eq!(sample(&body, name, app, "active"), None, "{name} {app}");
            }
            // What inspect knows is still there.
            assert_eq!(
                sample(&body, "weglarka_container_restarts_total", app, "active"),
                Some(0.0)
            );
        }
        assert_eq!(unlabelled(&body, "weglarka_resource_metrics_up"), Some(1.0));
        h.running.stop().await;
    }

    #[tokio::test]
    async fn a_failed_stats_call_drops_the_families_and_reports_down() {
        let h = metrics_harness().await;
        app(&h, "alpha", None).await;
        h.fake.fail_stats(Some("cgroup stats unavailable"));

        let body = scrape(&h).await;
        assert_eq!(unlabelled(&body, "weglarka_resource_metrics_up"), Some(0.0));
        assert!(!body.contains("weglarka_container_"), "{body}");
        assert!(body.contains("weglarka_build_info"), "{body}");
        assert!(!body.contains("cgroup stats unavailable"), "no free text");
        h.running.stop().await;
    }

    #[tokio::test]
    async fn concurrent_and_repeated_scrapes_share_one_stats_call() {
        let h = metrics_harness().await;
        app(&h, "alpha", None).await;
        h.fake.script_stats([stat("alpha", 1)]);
        let before = stats_calls(&h.fake);

        let bodies = futures_util::future::join_all((0..4).map(|_| scrape(&h))).await;
        assert!(bodies.windows(2).all(|w| w[0] == w[1]));
        // Inside the TTL, a later change is not seen and costs no call.
        h.fake.script_stats([stat("alpha", 9)]);
        assert_eq!(scrape(&h).await, bodies[0]);
        assert_eq!(stats_calls(&h.fake) - before, 1);
        h.running.stop().await;
    }
}
