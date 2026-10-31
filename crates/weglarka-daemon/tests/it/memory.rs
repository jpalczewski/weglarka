//! The `runtime.memory` doctor check (issues #208, #416): severity per condition, on `FakePodman`.

use crate::common::*;

use hyper::StatusCode;
use serde_json::{Value, json};
use weglarka_engine::testing::Call;
use weglarka_engine::testing::FakePodman;
use weglarka_model::podman::{ContainerStats, PodmanClient};

const MIB: u64 = 1 << 20;
const NGINX: &str = "weglarka-nginx";

fn doctor_check<'a>(v: &'a Value, id: &str) -> Option<&'a Value> {
    v["checks"]
        .as_array()?
        .iter()
        .find(|check| check["id"] == id)
}

fn stat(name: &str, mib: u64) -> ContainerStats {
    ContainerStats {
        name: name.to_owned(),
        memory_usage: mib * MIB,
        ..Default::default()
    }
}

/// Deploys `name` with an optional memory limit and returns its container name.
async fn app(h: &Harness, name: &str, limit: Option<&str>) -> String {
    let mut spec = spec(&format!("{name}.example.com"));
    if let Some(limit) = limit {
        spec["resources"] = json!({ "memory": limit });
    }
    add(h, name, spec).await;
    deployed(h, name).await;
    container_of(&h.fake, name).await
}

async fn container_of(fake: &FakePodman, instance: &str) -> String {
    let all = fake.container_list(&Default::default()).await.unwrap();
    all.into_iter()
        .find(|c| c.labels.get("weglarka.instance").map(String::as_str) == Some(instance))
        .unwrap_or_else(|| panic!("no container for {instance}"))
        .name
}

/// Drops nginx so only the apps under test are running containers.
async fn without_nginx(h: &Harness) {
    let _ = h.fake.container_remove(NGINX, true).await;
}

/// Every `runtime.memory` line of a doctor report.
fn memory_lines(v: &Value) -> Vec<&Value> {
    v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["id"] == "runtime.memory")
        .collect()
}

async fn memory_lines_of(h: &Harness) -> Vec<Value> {
    let (status, report) = admin(h, "GET", "/v1/doctor", None).await;
    assert_eq!(status, StatusCode::OK, "{report}");
    memory_lines(&report).into_iter().cloned().collect()
}

#[tokio::test]
async fn below_the_threshold_is_one_ok_summary_line() {
    let h = harness().await;
    let a = app(&h, "alpha", Some("100m")).await;
    let b = app(&h, "beta", Some("200m")).await;
    without_nginx(&h).await;
    h.fake.script_stats([stat(&a, 50), stat(&b, 40)]);

    let lines = memory_lines_of(&h).await;
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["status"], "ok", "{}", lines[0]);
    let message = lines[0]["message"].as_str().unwrap();
    assert!(message.contains("2 container(s)"), "{message}");
    assert!(message.contains("90.0 MiB in use"), "{message}");
    assert!(
        message.contains("highest against a limit: alpha (active) 50.0 MiB of 100.0 MiB"),
        "{message}"
    );
}

#[tokio::test]
async fn eighty_five_percent_of_the_limit_warns_with_app_role_usage_and_limit() {
    let h = harness().await;
    let a = app(&h, "alpha", Some("100m")).await;
    let b = app(&h, "beta", Some("100m")).await;
    without_nginx(&h).await;
    h.fake.script_stats([stat(&a, 85), stat(&b, 79)]);

    let lines = memory_lines_of(&h).await;
    assert_eq!(
        lines.len(),
        1,
        "only the container over the line: {lines:?}"
    );
    assert_eq!(lines[0]["status"], "warn", "{}", lines[0]);
    assert_eq!(
        lines[0]["message"],
        "alpha (active) uses 85.0 MiB of its 100.0 MiB memory limit (85%)"
    );
    assert!(lines[0]["hint"].is_string(), "{}", lines[0]);
}

#[tokio::test]
async fn the_ingress_without_a_limit_warns() {
    let h = harness().await;
    let a = app(&h, "alpha", Some("100m")).await;
    if h.fake.container_inspect(NGINX).await.is_err() {
        h.fake.add_foreign_container(NGINX, crate::common::IMAGE);
    }
    h.fake.script_stats([stat(&a, 50), stat(NGINX, 20)]);

    let lines = memory_lines_of(&h).await;
    let warn = lines
        .iter()
        .find(|l| l["status"] == "warn")
        .unwrap_or_else(|| panic!("no warn in {lines:?}"));
    assert_eq!(warn["message"], "weglarka-nginx has no memory limit");
    assert!(warn["hint"].is_string(), "{warn}");
    assert!(
        lines.iter().any(|l| l["status"] == "ok"),
        "the app below the line still gets its summary: {lines:?}"
    );
}

#[tokio::test]
async fn no_memory_data_is_info_with_the_delegation_hint() {
    let h = harness().await;
    let a = app(&h, "alpha", Some("100m")).await;
    without_nginx(&h).await;
    h.fake.script_stats([stat(&a, 0)]);

    let lines = memory_lines_of(&h).await;
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["status"], "info", "{}", lines[0]);
    assert!(
        lines[0]["hint"].as_str().unwrap().contains("memory pids"),
        "{}",
        lines[0]
    );
}

#[tokio::test]
async fn a_libpod_failure_is_info_and_doctor_continues() {
    let h = harness().await;
    app(&h, "alpha", Some("100m")).await;
    h.fake.fail_stats(Some("boom"));

    let (status, report) = admin(&h, "GET", "/v1/doctor", None).await;
    assert_eq!(status, StatusCode::OK, "{report}");
    let check = doctor_check(&report, "runtime.memory").expect("reported");
    assert_eq!(check["status"], "info", "{check}");
    assert!(
        check["message"].as_str().unwrap().contains("boom"),
        "a full caller sees the text: {check}"
    );
    assert!(check["hint"].as_str().unwrap().contains("memory pids"));
    assert!(
        doctor_check(&report, "state.drift").is_some(),
        "the rest of doctor still runs"
    );
}

#[tokio::test]
async fn a_read_caller_sees_the_redaction_marker_instead_of_the_libpod_error() {
    use crate::token_api::{call, setup};
    let s = setup().await;
    s.h.fake.fail_stats(Some("secret=hunter2"));

    let reader = s.issuer.token("rita", &["viewers"]);
    let (status, _, body) = call(&s.token_socket, "GET", "/v1/doctor", Some(&reader), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let check = doctor_check(&body, "runtime.memory").expect("reported");
    assert_eq!(check["status"], "info", "{check}");
    assert!(
        check["message"]
            .as_str()
            .unwrap()
            .contains("<details withheld>"),
        "{check}"
    );
    assert!(!body.to_string().contains("hunter2"), "{body}");
}

#[tokio::test]
async fn doctor_after_a_stats_read_asks_libpod_once() {
    let h = harness().await;
    let a = app(&h, "alpha", Some("100m")).await;
    h.fake.script_stats([stat(&a, 10)]);
    let stats_calls = || {
        h.fake
            .calls()
            .iter()
            .filter(|c| matches!(c, Call::ContainerStats))
            .count()
    };
    let before = stats_calls();

    let (status, _) = admin(&h, "GET", "/v1/stats", None).await;
    assert_eq!(status, StatusCode::OK);
    memory_lines_of(&h).await;
    assert_eq!(stats_calls() - before, 1, "the shared snapshot is reused");
}

#[tokio::test]
async fn a_stopped_container_has_no_figure_and_is_not_counted() {
    let h = harness().await;
    let a = app(&h, "alpha", Some("100m")).await;
    let b = app(&h, "beta", Some("100m")).await;
    without_nginx(&h).await;
    h.fake.container_stop(&a, 1).await.unwrap();
    h.fake.script_stats([stat(&a, 99), stat(&b, 10)]);

    let lines = memory_lines_of(&h).await;
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["status"], "ok", "{}", lines[0]);
    assert!(
        lines[0]["message"]
            .as_str()
            .unwrap()
            .contains("1 container(s)"),
        "{}",
        lines[0]
    );
}
