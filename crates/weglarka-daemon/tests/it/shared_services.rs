//! Shared services on the admin socket (ADR 0079, issue #592): `apps remove` of the instance of a
//! `[shared_services.<name>]` declaration is a 409 that touches nothing, both while members list the
//! service and with no members (the declaration has to go first). Removing a member still works.
//!
//! The declarations are behind the rollout gate, which only the model's `testing` feature can open.

use crate::common::*;

use hyper::StatusCode;
use serde_json::Value;
use weglarka_daemon::start;
use weglarka_engine::testing::FakePodman;
use weglarka_model::app::{AppsFile, InstanceName};
use weglarka_model::shared_services;
use weglarka_model::state;

/// The `service-has-members` fixture of the managed-Redis contract (#593): one declaration, its
/// instance and two members.
const HAS_MEMBERS: &str = r#"[shared_services.cache]
kind = "redis"
instance = "cache-redis"
profile = "cache"
maxmemory = "64mb"

[apps.cache-redis]
image = "docker.io/library/redis:7.4"
auto_update = false

[apps.api]
image = "ghcr.io/example/api:1"
shared_services = ["cache"]

[apps.worker]
image = "ghcr.io/example/worker:1"
shared_services = ["cache"]
"#;

/// The same declaration with no members left: the instance is still named by it.
const NO_MEMBERS: &str = r#"[shared_services.cache]
kind = "redis"
instance = "cache-redis"
profile = "cache"
maxmemory = "64mb"

[apps.cache-redis]
image = "docker.io/library/redis:7.4"
auto_update = false
"#;

/// The three images of [`HAS_MEMBERS`] and [`NO_MEMBERS`].
const IMAGES: [&str; 3] = [
    "docker.io/library/redis:7.4",
    "ghcr.io/example/api:1",
    "ghcr.io/example/worker:1",
];

fn instance(s: &str) -> InstanceName {
    InstanceName::new(s).unwrap()
}

fn cache() -> shared_services::ServiceName {
    shared_services::ServiceName::new("cache").unwrap()
}

fn apps_path(h: &Harness) -> std::path::PathBuf {
    h.root.join("state/apps.toml")
}

fn apps_file(h: &Harness) -> AppsFile {
    state::load_apps(&apps_path(h)).unwrap()
}

fn message(body: &Value) -> String {
    body["message"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| body.to_string())
}

/// A daemon whose `apps.toml` is `apps`, with the shared-service gate open (the declarations would
/// otherwise be rejected at startup).
///
/// The fixture's apps are not deployed here, and their pulls fail on purpose: a deploy below holds
/// the engine lock through the spec's health gate (30 s by default), so the background reconcile
/// pass would otherwise answer the removal with `503 busy` instead of the guard's 409. The guard
/// reads `apps.toml` only.
async fn harness_with(apps: &str) -> Harness {
    shared_services::testing::open_kind_gates();
    let (dir, root) = tempdir("wg");
    std::fs::create_dir_all(root.join("state")).unwrap();
    std::fs::write(root.join("state/apps.toml"), apps).unwrap();
    let fake = FakePodman::new();
    for image in IMAGES {
        fake.fail_pull(image, "not deployed in this test");
    }
    let running = start(settings(&root, "", ""), fake.clone()).await.unwrap();
    Harness {
        config_root: root.join("config"),
        _dir: dir,
        root,
        fake,
        running,
    }
}

#[tokio::test]
async fn removing_the_instance_of_a_service_with_members_is_a_conflict() {
    let h = harness_with(HAS_MEMBERS).await;
    let before = read(&apps_path(&h));
    assert!(
        before.contains("[shared_services.cache]")
            && before.contains(r#"shared_services = ["cache"]"#),
        "{before}"
    );

    // Every shape of the request is refused, including both purge flags.
    for query in [
        "",
        "?purge_volumes=true",
        "?purge_secrets=true",
        "?purge_volumes=true&purge_secrets=true",
    ] {
        let (status, body) =
            admin(&h, "DELETE", &format!("/v1/apps/cache-redis{query}"), None).await;
        assert_eq!(status, StatusCode::CONFLICT, "{query}: {body}");
        let text = message(&body);
        assert!(
            text.contains("cache-redis runs [shared_services.cache]"),
            "{query}: {text}"
        );
        assert!(
            text.contains("still used by: api, worker"),
            "{query}: {text}"
        );
        assert_eq!(
            read(&apps_path(&h)),
            before,
            "{query}: apps.toml is byte-for-byte untouched"
        );
    }

    // Nothing was touched: the declaration, its instance and both members are still desired state.
    let apps = apps_file(&h);
    assert_eq!(apps.apps.len(), 3, "{:?}", apps.apps.keys());
    assert!(apps.shared_services.contains_key(&cache()));
    h.running.stop().await;
}

#[tokio::test]
async fn removing_the_instance_of_a_service_without_members_is_a_conflict() {
    let h = harness_with(NO_MEMBERS).await;
    let before = read(&apps_path(&h));

    let (status, body) = admin(&h, "DELETE", "/v1/apps/cache-redis", None).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let text = message(&body);
    assert!(
        text.contains("cache-redis runs [shared_services.cache]"),
        "{text}"
    );
    assert!(
        text.contains("remove the declaration from apps.toml first"),
        "{text}"
    );
    assert!(!text.contains("still used by"), "no members: {text}");
    assert_eq!(
        read(&apps_path(&h)),
        before,
        "apps.toml is byte-for-byte untouched"
    );
    assert!(apps_file(&h).apps.contains_key(&instance("cache-redis")));
    h.running.stop().await;
}

#[tokio::test]
async fn removing_a_member_is_allowed_and_keeps_the_service() {
    let h = harness_with(HAS_MEMBERS).await;

    let (status, body) = admin(&h, "DELETE", "/v1/apps/api", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let apps = apps_file(&h);
    assert!(!apps.apps.contains_key(&instance("api")));
    assert!(
        apps.apps.contains_key(&instance("worker")),
        "the other member stays"
    );
    assert!(
        apps.apps.contains_key(&instance("cache-redis")),
        "the service stays"
    );
    assert!(apps.shared_services.contains_key(&cache()));

    // The surviving member still lists the service, so the refusal narrowed to it.
    let (status, body) = admin(&h, "DELETE", "/v1/apps/cache-redis", None).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let text = message(&body);
    assert!(text.contains("still used by: worker"), "{text}");
    h.running.stop().await;
}
