//! Shared services in `apps list` and `doctor` (#592 D, ADR 0079): the summary JSON, the `read`
//! projection and the doctor check. Declarations are rejected by the per-kind gate, which these
//! tests open through `weglarka_model`'s `testing` feature — the engine and daemon need a file that
//! loads before any kind is released.

use crate::common::*;
use crate::token_api;

use std::collections::BTreeMap;

use hyper::StatusCode;
use serde_json::{Value, json};
use weglarka_model::labels;
use weglarka_model::podman::{NetworkSpec, PodmanClient};
use weglarka_model::shared_services::testing::open_kind_gates;

/// A service, its instance and two members; `worker` is declared before `api` so the member order
/// in the answer proves it is the model's (name order), not the file's.
const APPS: &str = r#"
[shared_services.cache]
kind = "redis"
instance = "cache-redis"
profile = "cache"
maxmemory = "64mb"

[apps.cache-redis]
image = "docker.io/library/redis:7.4"
auto_update = false
start = false

[apps.worker]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
start = false
shared_services = ["cache"]

[apps.api]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
start = false
shared_services = ["cache"]
"#;

/// The same file with nothing declared: today's JSON, unchanged.
const PLAIN_APPS: &str = r#"
[apps.api]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
start = false
"#;

fn summary() -> Value {
    json!([{
        "name": "cache",
        "kind": "redis",
        "profile": "cache",
        "instance": "cache-redis",
        "members": ["api", "worker"],
    }])
}

fn doctor_check<'a>(report: &'a Value, id: &str) -> &'a Value {
    report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap_or_else(|| panic!("{id} check exists"))
}

#[tokio::test]
async fn apps_list_shows_a_service_with_its_members() {
    open_kind_gates();
    let h = Builder::new().apps(APPS).build().await;

    let (status, body) = admin(&h, "GET", "/v1/apps", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["shared_services"], summary());
    // The allowlist itself: a new declaration field has to be decided here before it can reach a
    // caller (`profile`/`kind` are names, `maxmemory` is a sizing value and stays out).
    let keys: Vec<&String> = body["shared_services"][0]
        .as_object()
        .expect("one service object")
        .keys()
        .collect();
    assert_eq!(keys, ["instance", "kind", "members", "name", "profile"]);

    // Nothing the `read` scope must not see: no sizing value, no derived secret name.
    let (_, raw_body) = raw(&h, "GET", "/v1/apps", vec![]).await;
    let text = String::from_utf8_lossy(&raw_body);
    for absent in ["maxmemory", "64mb", "svc-cache", "secret", "pgpass"] {
        assert!(!text.contains(absent), "{absent} in the answer: {text}");
    }
    h.running.stop().await;
}

#[tokio::test]
async fn apps_list_without_declarations_has_no_shared_services_key() {
    let h = Builder::new().apps(PLAIN_APPS).build().await;
    let (status, raw_body) = raw(&h, "GET", "/v1/apps", vec![]).await;
    assert_eq!(status, StatusCode::OK);
    // `skip_serializing_if` keeps the answer of a host without services byte-for-byte what it was.
    let text = String::from_utf8_lossy(&raw_body);
    assert!(!text.contains("shared_services"), "{text}");
    h.running.stop().await;
}

#[tokio::test]
async fn a_read_token_gets_the_same_projection() {
    open_kind_gates();
    let s = token_api::setup_with(Builder::new().sections(token_api::SECTIONS).apps(APPS)).await;
    let reader = s.issuer.token("rita", &["viewers"]);

    let (status, _, body) =
        token_api::call(&s.token_socket, "GET", "/v1/apps", Some(&reader), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // `APPS_LIST` is a `read` endpoint, and this is already its allowlist: the two callers cannot
    // drift, because one constructor serves both.
    assert_eq!(body["shared_services"], summary());
    let text = body.to_string();
    for absent in ["maxmemory", "64mb", "svc-cache", "secret"] {
        assert!(!text.contains(absent), "{absent} in the answer: {text}");
    }
    s.h.running.stop().await;
}

#[tokio::test]
async fn doctor_lists_each_service_with_its_member_count() {
    open_kind_gates();
    let h = Builder::new().apps(APPS).build().await;

    let (status, report) = admin(&h, "GET", "/v1/doctor", None).await;
    assert_eq!(status, StatusCode::OK);
    let check = doctor_check(&report, "state.shared_services");
    assert_eq!(check["status"], "ok", "{check}");
    assert_eq!(check["message"], "cache (redis) on cache-redis: 2 members");
    h.running.stop().await;
}

#[tokio::test]
async fn doctor_says_when_no_service_is_declared() {
    let h = Builder::new().apps(PLAIN_APPS).build().await;
    let (_, report) = admin(&h, "GET", "/v1/doctor", None).await;
    let check = doctor_check(&report, "state.shared_services");
    assert_eq!(check["status"], "ok", "{check}");
    assert_eq!(check["message"], "no shared services declared");
    h.running.stop().await;
}

#[tokio::test]
async fn doctor_knows_a_service_network_without_a_shared_networks_entry() {
    open_kind_gates();
    let h = Builder::new().apps(APPS).build().await;
    // Both namespaces become `net-shared-<name>` (ADR 0079), so the service's group must not be
    // reported as an undeclared one. Created here, after the startup pass: reconcile removes a
    // group network it does not know, and this one is known.
    h.fake
        .network_create(&NetworkSpec {
            name: "net-shared-cache".to_owned(),
            internal: true,
            labels: BTreeMap::from([(labels::SHARED_NETWORK.to_owned(), "cache".to_owned())]),
        })
        .await
        .unwrap();

    let (_, report) = admin(&h, "GET", "/v1/doctor", None).await;
    let check = doctor_check(&report, "state.shared_networks");
    let message = check["message"].as_str().unwrap_or_default();
    assert!(!message.contains("net-shared-cache"), "{check}");
    assert!(!message.contains("does not declare it"), "{check}");
    h.running.stop().await;
}
