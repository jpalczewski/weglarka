//! `depends_on` through the admin API (real unix socket, FakePodman): graph validation, the
//! removal refusal, the deploy gate and the `doctor` check (issue #35).

use crate::common::*;

use hyper::StatusCode;
use serde_json::{Value, json};

/// A daemon whose dependency gate waits 1 s instead of the production 10 s, so the tests that hit
/// the full budget stay fast.
async fn short_gate() -> Harness {
    Builder::new()
        .sections("\n[runtime]\ndependency_wait_secs = 1\n")
        .build()
        .await
}

fn with_deps(mut spec: Value, deps: &[&str]) -> Value {
    if !deps.is_empty() {
        spec["depends_on"] = json!(deps);
    }
    spec
}

fn stopped(mut spec: Value) -> Value {
    spec["start"] = json!(false);
    spec
}
async fn put(h: &Harness, name: &str, spec: Value) -> (StatusCode, Value) {
    admin(
        h,
        "PUT",
        &format!("/v1/apps/{name}"),
        Some(json!({ "spec": spec })),
    )
    .await
}

#[tokio::test]
async fn invalid_dependency_graphs_are_rejected_with_400() {
    let h = short_gate().await;
    add(&h, "db", spec("db.example.eu")).await;
    add(&h, "api", spec("api.example.eu")).await;

    // A dependency on an existing app is accepted and is not a container change (`deploy` absent).
    let (s, v) = put(&h, "api", with_deps(spec("api.example.eu"), &["db"])).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(
        v.get("deploy").is_none(),
        "depends_on must not redeploy: {v}"
    );
    assert!(read(&h.root.join("state/apps.toml")).contains("depends_on = [\"db\"]"));

    // An unknown target is rejected, naming it.
    let (s, v) = put(&h, "api", with_deps(spec("api.example.eu"), &["ghost"])).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert!(v["message"].as_str().unwrap().contains("ghost"), "{v}");

    // A cycle is rejected with the path.
    let (s, v) = put(&h, "db", with_deps(spec("db.example.eu"), &["api"])).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert!(v["message"].as_str().unwrap().contains("cycle"), "{v}");

    // Self-reference is caught by the per-app rules.
    let (s, v) = put(&h, "api", with_deps(spec("api.example.eu"), &["api"])).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");

    // None of the rejected graphs reached apps.toml.
    let toml = read(&h.root.join("state/apps.toml"));
    assert_eq!(toml.matches("depends_on").count(), 1, "{toml}");
}

#[tokio::test]
async fn deleting_a_dependency_is_refused_with_409() {
    let h = short_gate().await;
    add(&h, "db", spec("db.example.eu")).await;
    deployed(&h, "db").await;
    add(&h, "api", with_deps(spec("api.example.eu"), &["db"])).await;
    deployed(&h, "api").await;

    let (s, v) = admin(&h, "DELETE", "/v1/apps/db?purge_volumes=true", None).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::CONFLICT, Some("conflict")),
        "{v}"
    );
    assert!(v["message"].as_str().unwrap().contains("api"), "{v}");
    assert!(
        read(&h.root.join("state/apps.toml")).contains("[apps.db]"),
        "a refused removal must not touch apps.toml"
    );

    let (s, _) = admin(&h, "DELETE", "/v1/apps/api", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = admin(&h, "DELETE", "/v1/apps/db", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn a_dependent_does_not_deploy_while_its_dependency_is_stopped() {
    let h = short_gate().await;
    add(&h, "db", spec("db.example.eu")).await;
    deployed(&h, "db").await;
    add(&h, "api", with_deps(spec("api.example.eu"), &["db"])).await;
    deployed(&h, "api").await;

    // Stop the dependency: `start = false` removes its container but keeps the app declared.
    let (s, v) = put(&h, "db", stopped(spec("db.example.eu"))).await;
    assert_eq!(s, StatusCode::OK, "{v}");

    let (s, v) = admin(&h, "POST", "/v1/apps/api/deploy", None).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::CONFLICT, Some("conflict")),
        "{v}"
    );
    assert!(v["message"].as_str().unwrap().contains("db"), "{v}");
    // The refusal left the running dependent untouched.
    assert_eq!(show(&h, "api").await["runtime"], json!("running"));

    // An image change runs a deploy right after the spec write; the same gate answers 409, not 500.
    let mut bumped = with_deps(spec("api.example.eu"), &["db"]);
    bumped["image"] = json!("ghcr.io/jpalczewski/ntfy.zig:v2");
    let (s, v) = put(&h, "api", bumped).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::CONFLICT, Some("conflict")),
        "{v}"
    );
    assert!(v["message"].as_str().unwrap().contains("db"), "{v}");

    // `doctor` calls the configuration out instead of silently leaving the app in place.
    let (s, v) = admin(&h, "GET", "/v1/doctor", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let check = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "state.dependencies")
        .expect("state.dependencies check");
    assert_eq!(check["status"], json!("warn"), "{check}");
    assert!(
        check["message"].as_str().unwrap().contains("api"),
        "{check}"
    );
}
