//! The `runtime.memory` doctor check (issue #208): severity per condition, on `FakePodman`.

use crate::common::*;

use hyper::StatusCode;
use serde_json::{Value, json};
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

async fn memory_check(h: &Harness) -> Value {
    let (status, report) = admin(h, "GET", "/v1/doctor", None).await;
    assert_eq!(status, StatusCode::OK, "{report}");
    doctor_check(&report, "runtime.memory")
        .cloned()
        .unwrap_or_else(|| panic!("no runtime.memory in {report}"))
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

#[tokio::test]
async fn all_below_the_threshold_is_ok_with_totals() {
    let h = harness().await;
    let a = app(&h, "alpha", Some("100m")).await;
    let b = app(&h, "beta", Some("200m")).await;
    without_nginx(&h).await;
    h.fake.script_stats([stat(&a, 50), stat(&b, 40)]);

    let check = memory_check(&h).await;
    assert_eq!(check["status"], "ok", "{check}");
    let message = check["message"].as_str().unwrap();
    assert!(message.contains("2 running container(s)"), "{message}");
    assert!(message.contains("90.0 MiB in use"), "{message}");
    assert!(
        message.contains(&format!("highest against a limit: {a}")),
        "{message}"
    );
}

#[tokio::test]
async fn at_eighty_percent_warns_with_names_percentages_and_a_hint() {
    let h = harness().await;
    let a = app(&h, "alpha", Some("100m")).await;
    let b = app(&h, "beta", Some("100m")).await;
    without_nginx(&h).await;
    h.fake.script_stats([stat(&a, 80), stat(&b, 79)]);

    let check = memory_check(&h).await;
    assert_eq!(check["status"], "warn", "{check}");
    let message = check["message"].as_str().unwrap();
    assert!(message.contains(&format!("{a} (80%)")), "{message}");
    assert!(!message.contains(&format!("{b} (")), "{message}");
    assert!(check["hint"].is_string(), "{check}");
}

#[tokio::test]
async fn nginx_without_a_limit_is_info_and_named() {
    let h = harness().await;
    let a = app(&h, "alpha", Some("100m")).await;
    // Give the (possibly absent) nginx a running container with usage and no limit.
    if h.fake.container_inspect(NGINX).await.is_err() {
        h.fake.add_foreign_container(NGINX, crate::common::IMAGE);
    }
    h.fake.script_stats([stat(&a, 10), stat(NGINX, 20)]);

    let check = memory_check(&h).await;
    assert_eq!(check["status"], "info", "{check}");
    assert!(
        check["message"]
            .as_str()
            .unwrap()
            .contains("weglarka-nginx has no memory limit"),
        "{check}"
    );
}

#[tokio::test]
async fn zero_usage_is_no_data_not_idle() {
    let h = harness().await;
    let a = app(&h, "alpha", Some("100m")).await;
    without_nginx(&h).await;
    h.fake.script_stats([stat(&a, 0)]);

    let check = memory_check(&h).await;
    assert_eq!(check["status"], "info", "{check}");
    let message = check["message"].as_str().unwrap();
    assert!(
        message.contains(&format!("no memory data for {a}")),
        "{message}"
    );
    assert!(
        message.contains("cgroup controller delegation"),
        "{message}"
    );
    assert!(message.contains("0.0 MiB in use"), "{message}");
}

#[tokio::test]
async fn a_failing_stats_call_is_info_and_doctor_continues() {
    let h = harness().await;
    app(&h, "alpha", Some("100m")).await;
    h.fake.fail_stats(Some("boom"));

    let (status, report) = admin(&h, "GET", "/v1/doctor", None).await;
    assert_eq!(status, StatusCode::OK, "{report}");
    let check = doctor_check(&report, "runtime.memory").expect("reported");
    assert_eq!(check["status"], "info", "{check}");
    assert!(
        check["message"].as_str().unwrap().contains("unavailable"),
        "{check}"
    );
    assert!(
        doctor_check(&report, "state.drift").is_some(),
        "the rest of doctor still runs"
    );
}

#[tokio::test]
async fn the_highest_severity_wins_and_every_condition_is_mentioned() {
    let h = harness().await;
    let a = app(&h, "alpha", Some("100m")).await;
    let b = app(&h, "beta", Some("100m")).await;
    without_nginx(&h).await;
    h.fake.add_foreign_container(NGINX, crate::common::IMAGE);
    h.fake
        .script_stats([stat(&a, 95), stat(&b, 0), stat(NGINX, 5)]);

    let check = memory_check(&h).await;
    assert_eq!(check["status"], "warn", "{check}");
    let message = check["message"].as_str().unwrap();
    assert!(message.contains(&format!("{a} (95%)")), "{message}");
    assert!(
        message.contains(&format!("no memory data for {b}")),
        "{message}"
    );
    assert!(
        message.contains("weglarka-nginx has no memory limit"),
        "{message}"
    );
}

#[tokio::test]
async fn a_stopped_container_is_not_counted() {
    let h = harness().await;
    let a = app(&h, "alpha", Some("100m")).await;
    without_nginx(&h).await;
    h.fake.container_stop(&a, 1).await.unwrap();
    h.fake.script_stats([stat(&a, 99)]);

    let check = memory_check(&h).await;
    assert!(
        check["message"]
            .as_str()
            .unwrap()
            .contains("0 running container(s)"),
        "{check}"
    );
}
