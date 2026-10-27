//! Sites with environments (issue #205, `docs/decisions/0050-site-environments.md`) on `FakePodman`,
//! over the real admin socket: declaring a site, the instances it expands into, the guards that keep
//! them out of `apps update/remove`, promotion errors and the doctor check.

use crate::common::*;

use hyper::StatusCode;
use serde_json::{Value, json};
use weglarka_model::state;

fn blog() -> Value {
    json!({ "spec": {
        "kind": "static",
        "image": "registry.example.com/me/blog",
        "env": {
            "dev": { "track": "main", "domains": ["dev.example.com"] },
            "prod": { "promote_from": "dev", "domains": ["example.com"] },
        }
    }})
}

async fn declare_blog(h: &Harness) {
    let (status, body) = admin(h, "PUT", "/v1/sites/blog", Some(blog())).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
}

#[tokio::test]
async fn a_declared_site_expands_into_instances_but_apps_toml_keeps_only_the_site() {
    let h = harness().await;
    declare_blog(&h).await;

    let (status, list) = admin(&h, "GET", "/v1/sites", None).await;
    assert_eq!(status, StatusCode::OK);
    let envs = &list["sites"][0]["envs"];
    assert_eq!(envs[0]["instance"], "blog-dev");
    assert_eq!(envs[1]["promote_from"], "dev");
    assert!(envs[1]["current"].is_null());

    let (_, apps) = admin(&h, "GET", "/v1/apps", None).await;
    let names: Vec<_> = apps["apps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| (a["name"].as_str().unwrap(), a["site"].as_str().unwrap()))
        .collect();
    assert_eq!(
        names,
        [("blog-dev", "blog/dev"), ("blog-prod", "blog/prod")]
    );

    let text = std::fs::read_to_string(h.root.join("state/apps.toml")).unwrap();
    assert!(!text.contains("[apps."), "{text}");
    assert!(text.contains("[sites.blog.env.prod]"), "{text}");
    assert!(state::load_apps(&h.root.join("state/apps.toml")).is_ok());
    h.running.stop().await;
}

#[tokio::test]
async fn expanded_instances_cannot_be_edited_or_removed_through_apps() {
    let h = harness().await;
    declare_blog(&h).await;
    let (status, body) = admin(&h, "DELETE", "/v1/apps/blog-prod", None).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body["message"].as_str().unwrap().contains("site blog"));
    let (status, body) = admin(
        &h,
        "PUT",
        "/v1/apps/blog-dev",
        Some(json!({ "spec": { "image": "x:1" } })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    // Adding an app under an expanded name is refused as well.
    let (status, _) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(json!({ "name": "blog-dev", "spec": { "image": "x:1" } })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    h.running.stop().await;
}

#[tokio::test]
async fn a_site_whose_expansion_collides_with_an_app_is_rejected() {
    let h = harness().await;
    let (status, _) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(json!({ "name": "blog-dev", "spec": { "image": "x:1" } })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = admin(&h, "PUT", "/v1/sites/blog", Some(blog())).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body["message"].as_str().unwrap().contains("[apps]"));
    h.running.stop().await;
}

#[tokio::test]
async fn promote_errors_and_the_unpromoted_doctor_warning() {
    let h = harness().await;
    declare_blog(&h).await;
    let promote = |env: &str| format!("/v1/sites/blog/envs/{env}/promote");

    // The source has no release yet.
    let (status, _) = admin(&h, "POST", &promote("prod"), Some(json!({}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // A tracking environment is deployed by the webhook, not promoted into.
    let (status, _) = admin(&h, "POST", &promote("dev"), Some(json!({}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = admin(&h, "POST", &promote("nope"), Some(json!({}))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = admin(
        &h,
        "POST",
        &promote("prod"),
        Some(json!({ "rollback": true, "digest": format!("sha256:{}", "a".repeat(64)) })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // `apps deploy` on a promote-only environment is refused.
    let (status, body) = admin(&h, "POST", "/v1/apps/blog-prod/deploy", Some(json!({}))).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body["message"].as_str().unwrap().contains("promote"));

    let (_, report) = admin(&h, "GET", "/v1/doctor", None).await;
    let check = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "sites.unpromoted")
        .expect("sites.unpromoted check exists");
    assert_eq!(check["status"], "warn", "{check}");
    assert!(check["message"].as_str().unwrap().contains("blog/prod"));
    h.running.stop().await;
}

#[tokio::test]
async fn removing_a_site_drops_its_instances() {
    let h = harness().await;
    declare_blog(&h).await;
    let (status, _) = admin(&h, "DELETE", "/v1/sites/blog", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, apps) = admin(&h, "GET", "/v1/apps", None).await;
    assert!(apps["apps"].as_array().unwrap().is_empty());
    let (status, _) = admin(&h, "DELETE", "/v1/sites/blog", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    h.running.stop().await;
}
