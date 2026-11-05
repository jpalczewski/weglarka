//! Sites with environments (issue #205, `docs/decisions/0050-site-environments.md`) on `FakePodman`,
//! over the real admin socket: declaring a site, the instances it expands into, the guards that keep
//! them out of `apps update/remove`, promotion errors and the doctor check.

use crate::common::*;

use hyper::StatusCode;
use serde_json::{Value, json};
use weglarka_engine::sites::release_id;
use weglarka_model::app::{Digest, InstanceName};
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

/// A site whose static options are declared once for every environment, with `robots` overridden in
/// the preview only (#545/#548, ADR 0075).
fn docs() -> Value {
    json!({ "spec": {
        "kind": "static",
        "image": "registry.example.com/me/docs",
        "ingress": { "static": {
            "not_found_page": "/404.html",
            "cache_immutable_paths": ["/_astro"],
        }},
        "env": {
            "dev": { "track": "main", "domains": ["dev.example.com"], "robots": "noindex" },
            "prod": { "promote_from": "dev", "domains": ["example.com"] },
        }
    }})
}

#[tokio::test]
async fn a_declared_site_shares_its_static_options_and_overrides_robots_per_environment() {
    let h = harness().await;
    let (status, body) = admin(&h, "PUT", "/v1/sites/docs", Some(docs())).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let static_options = |app: &Value| app["spec"]["ingress"]["static"].clone();
    let (status, dev) = admin(&h, "GET", "/v1/apps/docs-dev", None).await;
    assert_eq!(status, StatusCode::OK, "{dev}");
    let (status, prod) = admin(&h, "GET", "/v1/apps/docs-prod", None).await;
    assert_eq!(status, StatusCode::OK, "{prod}");
    for app in [&dev, &prod] {
        let opts = static_options(app);
        assert_eq!(opts["not_found_page"], "/404.html");
        assert_eq!(opts["cache_immutable_paths"], json!(["/_astro"]));
    }
    assert_eq!(static_options(&dev)["robots"], "noindex");
    assert!(
        static_options(&prod).get("robots").is_none(),
        "the preview's robots is not inherited by production: {prod}"
    );

    // The site table is what `apps.toml` keeps: no expanded instance, options under `[sites]`.
    let text = std::fs::read_to_string(h.root.join("state/apps.toml")).unwrap();
    assert!(text.contains("[sites.docs.ingress.static]"), "{text}");
    assert!(text.contains("[sites.docs.env.dev]"), "{text}");
    assert!(!text.contains("[apps."), "{text}");
    h.running.stop().await;
}

#[tokio::test]
async fn an_invalid_shared_static_option_is_refused() {
    let h = harness().await;
    let mut bad = docs();
    bad["spec"]["ingress"]["static"]["not_found_page"] = json!("/404.txt");
    let (status, body) = admin(&h, "PUT", "/v1/sites/docs", Some(bad)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let message = body["message"].as_str().unwrap();
    // The error names the table the operator edited, not only the expanded instance.
    assert!(message.contains("site docs, environment dev"), "{body}");
    assert!(message.contains("not_found_page"), "{body}");
    let (status, _) = admin(&h, "GET", "/v1/sites/docs", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "nothing was written");
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

/// The static-site doctor checks (`sites.directory`, `sites.current`, ADR 0049, #101): silent
/// without a `kind = "static"` app, and report-only.
const BLOG_SITE: &str = r#"
[apps.blog]
kind = "static"
image = "registry.example.com/me/blog:latest"
domains = ["blog.example.com"]
"#;

fn blog_digest() -> String {
    blog_digest_for('a')
}

fn blog_digest_for(c: char) -> String {
    format!("sha256:{}", c.to_string().repeat(64))
}

/// `<sites root>/blog/releases` (the daemon's default under `<state>/nginx`).
fn blog_site(h: &Harness) -> std::path::PathBuf {
    h.root.join("state/nginx/sites/blog")
}

fn install_release_at(root: &std::path::Path, c: char, body: &str) -> String {
    let raw = blog_digest_for(c);
    let id = release_id(&Digest::new(&raw).unwrap());
    let release = root.join("state/nginx/sites/blog/releases").join(&id);
    std::fs::create_dir_all(&release).unwrap();
    std::fs::write(release.join("index.html"), body).unwrap();
    id
}

fn point_current_at(root: &std::path::Path, id: &str) {
    let site = root.join("state/nginx/sites/blog");
    let _ = std::fs::remove_file(site.join("current"));
    std::os::unix::fs::symlink(
        std::path::Path::new("releases").join(id),
        site.join("current"),
    )
    .unwrap();
}

fn write_blog_state(root: &std::path::Path, current: Option<char>, previous: Option<char>) {
    let mut text = String::from("[apps.blog]\n");
    if let Some(c) = current {
        text.push_str(&format!("current = \"{}\"\n", blog_digest_for(c)));
    }
    if let Some(c) = previous {
        text.push_str(&format!("previous = \"{}\"\n", blog_digest_for(c)));
    }
    std::fs::create_dir_all(root.join("state")).unwrap();
    std::fs::write(root.join("state/state.toml"), text).unwrap();
}

/// A static site serving `b` with `a` retained as `previous`, both releases complete on disk.
async fn rollback_harness() -> Harness {
    let builder = Builder::new().apps(BLOG_SITE);
    let root = builder.root().to_owned();
    install_release_at(&root, 'a', "one");
    let current = install_release_at(&root, 'b', "two");
    write_blog_state(&root, Some('b'), Some('a'));
    point_current_at(&root, &current);
    builder.build().await
}

/// A static site with a current release but no `previous` in `state.toml`.
async fn no_previous_harness() -> Harness {
    let builder = Builder::new().apps(BLOG_SITE);
    let root = builder.root().to_owned();
    let current = install_release_at(&root, 'b', "two");
    write_blog_state(&root, Some('b'), None);
    point_current_at(&root, &current);
    builder.build().await
}

async fn static_harness() -> Harness {
    let builder = Builder::new().apps(BLOG_SITE);
    std::fs::create_dir_all(builder.root().join("state")).unwrap();
    std::fs::write(
        builder.root().join("state/state.toml"),
        format!("[apps.blog]\ncurrent = \"{}\"\n", blog_digest()),
    )
    .unwrap();
    builder.build().await
}

fn doctor_check<'a>(report: &'a Value, id: &str) -> Option<&'a Value> {
    report["checks"]
        .as_array()?
        .iter()
        .find(|check| check["id"] == id)
}

#[tokio::test]
async fn doctor_is_quiet_about_static_sites_without_a_static_app() {
    let h = harness().await;
    let (_, report) = admin(&h, "GET", "/v1/doctor", None).await;
    assert!(
        doctor_check(&report, "sites.directory").is_none(),
        "{report}"
    );
    assert!(doctor_check(&report, "sites.current").is_none(), "{report}");
    h.running.stop().await;
}

#[tokio::test]
async fn doctor_reports_the_sites_directory() {
    let h = static_harness().await;
    let (_, report) = admin(&h, "GET", "/v1/doctor", None).await;
    let check = doctor_check(&report, "sites.directory").expect("sites.directory reported");
    assert_eq!(check["status"], "fail", "{check}");
    assert!(check["hint"].is_string(), "{check}");

    let root = h.root.join("state/nginx/sites");
    std::fs::create_dir_all(&root).unwrap();
    // Group-writable: anyone in the group could plant what nginx serves.
    std::fs::set_permissions(
        &root,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o775),
    )
    .unwrap();
    let (_, report) = admin(&h, "GET", "/v1/doctor", None).await;
    let check = doctor_check(&report, "sites.directory").expect("sites.directory reported");
    assert_eq!(check["status"], "warn", "{check}");

    // Explicit, so the result does not depend on the test runner's umask.
    std::fs::set_permissions(
        &root,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
    )
    .unwrap();
    let (_, report) = admin(&h, "GET", "/v1/doctor", None).await;
    let check = doctor_check(&report, "sites.directory").expect("sites.directory reported");
    assert_eq!(check["status"], "ok", "{check}");
    assert!(
        check["message"]
            .as_str()
            .unwrap()
            .contains(&root.display().to_string()),
        "{check}"
    );
    h.running.stop().await;
}

#[tokio::test]
async fn doctor_warns_about_a_current_release_that_does_not_match_state() {
    let h = static_harness().await;
    let (_, report) = admin(&h, "GET", "/v1/doctor", None).await;
    let check = doctor_check(&report, "sites.current").expect("sites.current reported");
    assert_eq!(check["status"], "warn", "{check}");
    assert!(
        check["message"].as_str().unwrap().contains("blog"),
        "{check}"
    );

    // A complete release plus the relative `current` link makes the check pass.
    let id = release_id(&Digest::new(blog_digest()).unwrap());
    let site = h.root.join("state/nginx/sites/blog");
    let release = site.join("releases").join(&id);
    std::fs::create_dir_all(&release).unwrap();
    std::fs::write(release.join("index.html"), "<h1>hi</h1>").unwrap();
    std::os::unix::fs::symlink(
        std::path::Path::new("releases").join(&id),
        site.join("current"),
    )
    .unwrap();

    let (_, report) = admin(&h, "GET", "/v1/doctor", None).await;
    let check = doctor_check(&report, "sites.current").expect("sites.current reported");
    assert_eq!(check["status"], "ok", "{check}");
    h.running.stop().await;
}

// ── `runtime` and drift of a static site (issue #547) ─────────────────────────

/// A static site has no container by design, so after a successful deploy `apps show`/`apps list`
/// report `serving` and `doctor` sees no drift.
#[tokio::test]
async fn a_static_site_that_serves_its_pinned_release_is_serving() {
    let h = served_release_harness(false).await;
    let (status, show) = admin(&h, "GET", "/v1/apps/blog", None).await;
    assert_eq!(status, StatusCode::OK, "{show}");
    assert_eq!(show["runtime"], "serving", "{show}");
    // `health` is rejected in a static spec, so the default gate must not show up as if it were one.
    assert!(show["spec"].get("health").is_none(), "{show}");
    assert!(show["health"].is_null(), "{show}");

    let (status, list) = admin(&h, "GET", "/v1/apps", None).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(list["apps"][0]["runtime"], "serving", "{list}");

    let (_, report) = admin(&h, "GET", "/v1/doctor", None).await;
    let drift = doctor_check(&report, "state.drift").expect("state.drift reported");
    assert_eq!(drift["status"], "ok", "{drift}");
    let current = doctor_check(&report, "sites.current").expect("sites.current reported");
    assert_eq!(current["status"], "ok", "{current}");
    h.running.stop().await;
}

/// A pinned static site whose `current` is gone (or points elsewhere) is `missing`, and doctor says
/// so once: in `sites.current`, not again as drift.
#[tokio::test]
async fn a_static_site_that_does_not_serve_its_pinned_release_is_missing() {
    let h = served_release_harness(false).await;
    std::fs::remove_file(blog_site(&h).join("current")).unwrap();

    let (_, show) = admin(&h, "GET", "/v1/apps/blog", None).await;
    assert_eq!(show["runtime"], "missing", "{show}");
    let (_, list) = admin(&h, "GET", "/v1/apps", None).await;
    assert_eq!(list["apps"][0]["runtime"], "missing", "{list}");
    let (_, report) = admin(&h, "GET", "/v1/doctor", None).await;
    let drift = doctor_check(&report, "state.drift").expect("state.drift reported");
    assert_eq!(drift["status"], "ok", "{drift}");
    let current = doctor_check(&report, "sites.current").expect("sites.current reported");
    assert_eq!(current["status"], "warn", "{current}");
    assert!(
        current["message"].as_str().unwrap().contains("blog"),
        "{current}"
    );

    // `current` pointing at another (complete) release is the same verdict.
    let other = install_release_at(&h.root, 'c', "three");
    point_current_at(&h.root, &other);
    let (_, show) = admin(&h, "GET", "/v1/apps/blog", None).await;
    assert_eq!(show["runtime"], "missing", "{show}");
    let (_, report) = admin(&h, "GET", "/v1/doctor", None).await;
    let current = doctor_check(&report, "sites.current").expect("sites.current reported");
    assert_eq!(current["status"], "warn", "{current}");
    assert!(
        current["message"].as_str().unwrap().contains("expected"),
        "{current}"
    );
    h.running.stop().await;
}

/// `GET /v1/apps` tells a standalone static app from a container app with `kind` (issue #548, the
/// panel's sites page): a container omits the field, so its JSON is what it always was.
#[tokio::test]
async fn the_apps_list_names_a_static_kind_and_omits_it_for_a_container() {
    let apps_toml = "[apps.web]\nimage = \"registry.example.com/me/web:1\"\ndomains = [\"web.example.com\"]\n\
                     \n[apps.blog]\nkind = \"static\"\nimage = \"registry.example.com/me/blog:latest\"\n\
                     domains = [\"blog.example.com\"]\n";
    let h = Builder::new().apps(apps_toml).build().await;
    let (status, list) = admin(&h, "GET", "/v1/apps", None).await;
    assert_eq!(status, StatusCode::OK, "{list}");
    let apps = list["apps"].as_array().unwrap();
    let web = apps
        .iter()
        .find(|a| a["name"] == "web")
        .expect("the container app is listed");
    let blog = apps
        .iter()
        .find(|a| a["name"] == "blog")
        .expect("the static app is listed");
    assert!(web.get("kind").is_none(), "{web}");
    assert_eq!(blog["kind"], "static", "{blog}");
    h.running.stop().await;
}

// ── `apps rollback` (issue #103) ─────────────────────────────────────────────────

fn digest_of(c: char) -> Digest {
    Digest::new(blog_digest_for(c)).unwrap()
}

#[tokio::test]
async fn apps_rollback_switches_a_static_site_to_its_previous_release() {
    let h = rollback_harness().await;
    let (status, body) = admin(&h, "POST", "/v1/apps/blog/rollback", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["from"], json!(blog_digest_for('b')));
    assert_eq!(body["to"], json!(blog_digest_for('a')));
    assert_eq!(body["reused_release"], true);
    assert_eq!(
        std::fs::read_to_string(blog_site(&h).join("current/index.html")).unwrap(),
        "one"
    );

    let st = state::load_state(&h.root.join("state/state.toml")).unwrap();
    let blog = st.apps.get(&InstanceName::new("blog").unwrap()).unwrap();
    assert_eq!(blog.current, Some(digest_of('a')));
    assert_eq!(blog.previous, Some(digest_of('b')));
    let failed = blog.failed.as_ref().expect("the left digest is recorded");
    assert_eq!(failed.digest, digest_of('b'));
    assert_eq!(failed.reason, "rolled back by the operator");
    h.running.stop().await;
}

#[tokio::test]
async fn apps_rollback_maps_every_refusal() {
    // An unknown instance is a 404.
    let h = harness().await;
    let (status, body) = admin(&h, "POST", "/v1/apps/ghost/rollback", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["code"], "not_found");
    h.running.stop().await;

    // A container app is a 400 that points at the rollback that applies to it. `start = false`
    // keeps the first reconcile a quick provision, so the engine lock is free for the request.
    let h = Builder::new()
        .apps("[apps.ntfy]\nimage = \"ghcr.io/jpalczewski/ntfy.zig:latest\"\nstart = false\n")
        .build()
        .await;
    deployed(&h, "ntfy").await;
    let (status, body) = admin(&h, "POST", "/v1/apps/ntfy/rollback", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "invalid_request");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("weglarka apps update ntfy"),
        "{body}"
    );
    h.running.stop().await;

    // A static site without a previous release is a 409 and nothing changes.
    let h = no_previous_harness().await;
    let (status, body) = admin(&h, "POST", "/v1/apps/blog/rollback", None).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "conflict");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("no previous release to return to"),
        "{body}"
    );
    assert_eq!(
        std::fs::read_to_string(blog_site(&h).join("current/index.html")).unwrap(),
        "two"
    );
    let st = state::load_state(&h.root.join("state/state.toml")).unwrap();
    let blog = st.apps.get(&InstanceName::new("blog").unwrap()).unwrap();
    assert_eq!(blog.current, Some(digest_of('b')));
    assert_eq!(blog.previous, None);
    h.running.stop().await;

    // A site environment is a 400 that points at `promote --rollback`.
    let h = harness().await;
    declare_blog(&h).await;
    let (status, body) = admin(&h, "POST", "/v1/apps/blog-dev/rollback", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("weglarka promote blog dev --rollback"),
        "{body}"
    );
    let st = state::load_state(&h.root.join("state/state.toml")).unwrap();
    assert_eq!(
        st.apps
            .get(&InstanceName::new("blog-dev").unwrap())
            .and_then(|a| a.current.clone()),
        None
    );
    h.running.stop().await;
}

// ── `apps update` against the served release (issue #501) ─────────────────────

/// A static site whose served release is complete for its current spec: `index.html`, plus the
/// `404.html` an added `not_found_page` names when `with_page` — `current` and `state.toml` agree.
async fn served_release_harness(with_page: bool) -> Harness {
    let builder = Builder::new().apps(BLOG_SITE);
    let root = builder.root().to_owned();
    let current = install_release_at(&root, 'b', "two");
    if with_page {
        let release = root.join("state/nginx/sites/blog/releases").join(&current);
        std::fs::write(release.join("404.html"), "not found").unwrap();
    }
    write_blog_state(&root, Some('b'), None);
    point_current_at(&root, &current);
    builder.build().await
}

/// The `BLOG_SITE` spec as a full replacement (what `apps update` takes) adding `not_found_page`.
fn blog_update_with_not_found_page() -> Value {
    json!({ "spec": {
        "kind": "static",
        "image": "registry.example.com/me/blog:latest",
        "domains": ["blog.example.com"],
        "ingress": { "static": { "not_found_page": "/404.html" } }
    }})
}

#[tokio::test]
async fn an_ingress_only_update_is_refused_when_the_served_release_lacks_the_page() {
    let h = served_release_harness(false).await;
    let apps_toml = h.root.join("state/apps.toml");
    let before = read(&apps_toml);

    let (status, body) = admin(
        &h,
        "PUT",
        "/v1/apps/blog",
        Some(blog_update_with_not_found_page()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "invalid_request");
    let message = body["message"].as_str().unwrap();
    assert!(message.contains("404.html"), "{body}");
    assert!(message.contains("weglarka deploy blog"), "{body}");

    // A refused update persists nothing: the spec is unchanged and the served release is untouched.
    assert_eq!(read(&apps_toml), before);
    let apps = state::load_apps(&apps_toml).unwrap();
    let blog = apps.apps.get(&InstanceName::new("blog").unwrap()).unwrap();
    assert!(blog.ingress.static_.is_none(), "{:?}", blog.ingress);
    assert_eq!(
        std::fs::read_to_string(blog_site(&h).join("current/index.html")).unwrap(),
        "two"
    );
    h.running.stop().await;
}

#[tokio::test]
async fn an_ingress_only_update_is_accepted_when_the_served_release_has_the_page() {
    let h = served_release_harness(true).await;
    let (status, body) = admin(
        &h,
        "PUT",
        "/v1/apps/blog",
        Some(blog_update_with_not_found_page()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let apps = state::load_apps(&h.root.join("state/apps.toml")).unwrap();
    let blog = apps.apps.get(&InstanceName::new("blog").unwrap()).unwrap();
    assert_eq!(
        blog.ingress
            .static_
            .as_ref()
            .and_then(|s| s.not_found_page.as_deref()),
        Some("/404.html")
    );
    h.running.stop().await;
}

// ── `sites declare` against the releases the environments serve (issue #572) ──

const DECLARED_BLOG: &str = r#"
[sites.blog]
kind = "static"
image = "registry.example.com/me/blog"

[sites.blog.env.dev]
track = "main"
domains = ["dev.example.com"]

[sites.blog.env.prod]
promote_from = "dev"
domains = ["example.com"]
"#;

/// The `blog()` declaration as a whole replacement, with the shared table every environment
/// inherits (#570, ADR 0075).
fn blog_with_not_found_page() -> Value {
    let mut site = blog();
    site["spec"]["ingress"] = json!({ "static": { "not_found_page": "/404.html" } });
    site
}

/// A complete release for one site environment (`<sites root>/<instance>/releases/<id>` plus the
/// relative `current` link), with the `404.html` an added `not_found_page` names when `with_page`.
fn install_environment_release(root: &std::path::Path, instance: &str, c: char, with_page: bool) {
    let id = release_id(&Digest::new(blog_digest_for(c)).unwrap());
    let site = root.join("state/nginx/sites").join(instance);
    let release = site.join("releases").join(&id);
    std::fs::create_dir_all(&release).unwrap();
    std::fs::write(release.join("index.html"), "served").unwrap();
    if with_page {
        std::fs::write(release.join("404.html"), "not found").unwrap();
    }
    std::os::unix::fs::symlink(
        std::path::Path::new("releases").join(&id),
        site.join("current"),
    )
    .unwrap();
}

/// `state.toml` for a site whose environments serve `(instance, release digit)` — the pin and the
/// `current` link have to agree for the release code.
fn write_environment_state(root: &std::path::Path, served: &[(&str, char)]) {
    let text: String = served
        .iter()
        .map(|(instance, c)| {
            format!(
                "[apps.{instance}]\ncurrent = \"{}\"\n\n",
                blog_digest_for(*c)
            )
        })
        .collect();
    std::fs::create_dir_all(root.join("state")).unwrap();
    std::fs::write(root.join("state/state.toml"), text).unwrap();
}

/// A declared site whose `dev` serves `b` — a complete release, with `404.html` when `with_page` —
/// so `current`, `state.toml` and the release on disk agree. `prod` has no release yet.
async fn declared_site_harness(with_page: bool) -> Harness {
    let builder = Builder::new().apps(DECLARED_BLOG);
    let root = builder.root().to_owned();
    install_environment_release(&root, "blog-dev", 'b', with_page);
    write_environment_state(&root, &[("blog-dev", 'b')]);
    builder.build().await
}

#[tokio::test]
async fn a_re_declare_adding_a_shared_static_option_the_served_release_lacks_is_refused() {
    let h = declared_site_harness(false).await;
    let apps_toml = h.root.join("state/apps.toml");
    let before = read(&apps_toml);

    let (status, body) = admin(
        &h,
        "PUT",
        "/v1/sites/blog",
        Some(blog_with_not_found_page()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "invalid_request");
    let message = body["message"].as_str().unwrap();
    // The operator edited a shared table: the message names the site, environment and file, and a
    // tracking environment is fixed by a deploy.
    assert!(
        message.contains("site blog, environment dev (instance blog-dev)"),
        "{body}"
    );
    assert!(message.contains("404.html"), "{body}");
    assert!(message.contains("weglarka deploy blog-dev"), "{body}");

    // A refused declare writes nothing and leaves the served release alone.
    assert_eq!(read(&apps_toml), before);
    assert_eq!(
        std::fs::read_to_string(h.root.join("state/nginx/sites/blog-dev/current/index.html"))
            .unwrap(),
        "served"
    );
    h.running.stop().await;
}

#[tokio::test]
async fn a_re_declare_that_also_changes_the_tracked_tag_is_still_checked() {
    // A new `track` changes the instance's `image`, which exempts an `apps update` (a deploy
    // follows). A declare deploys nothing, so `dev` keeps serving the release without the page.
    let h = declared_site_harness(false).await;
    let apps_toml = h.root.join("state/apps.toml");
    let before = read(&apps_toml);

    let mut site = blog_with_not_found_page();
    site["spec"]["env"]["dev"]["track"] = json!("next");
    let (status, body) = admin(&h, "PUT", "/v1/sites/blog", Some(site)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("site blog, environment dev (instance blog-dev)"),
        "{body}"
    );
    assert_eq!(read(&apps_toml), before);
    h.running.stop().await;
}

#[tokio::test]
async fn a_re_declare_adding_a_shared_static_option_the_served_release_has_is_accepted() {
    let h = declared_site_harness(true).await;
    let (status, body) = admin(
        &h,
        "PUT",
        "/v1/sites/blog",
        Some(blog_with_not_found_page()),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    // Persisted once, in the site table; every environment inherits it.
    let text = read(&h.root.join("state/apps.toml"));
    assert!(text.contains("[sites.blog.ingress.static]"), "{text}");
    assert!(text.contains("not_found_page = \"/404.html\""), "{text}");
    let (status, dev) = admin(&h, "GET", "/v1/apps/blog-dev", None).await;
    assert_eq!(status, StatusCode::OK, "{dev}");
    assert_eq!(
        dev["spec"]["ingress"]["static"]["not_found_page"],
        "/404.html"
    );

    // A new environment has no stored spec and serves nothing yet, so it passes the same check
    // while the unchanged shared options of `dev` are not checked again.
    let mut added = blog_with_not_found_page();
    added["spec"]["env"]["staging"] = json!({
        "track": "main",
        "domains": ["staging.example.com"],
    });
    let (status, body) = admin(&h, "PUT", "/v1/sites/blog", Some(added)).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let text = read(&h.root.join("state/apps.toml"));
    assert!(text.contains("[sites.blog.env.staging]"), "{text}");
    h.running.stop().await;
}

#[tokio::test]
async fn a_re_declare_names_a_promote_only_environment_and_points_at_promote() {
    // `dev` already serves a release with the page, `prod` was promoted from an older one without
    // it: only the promote-only environment fails, and its fix is a promotion, not a deploy.
    let builder = Builder::new().apps(DECLARED_BLOG);
    let root = builder.root().to_owned();
    install_environment_release(&root, "blog-dev", 'b', true);
    install_environment_release(&root, "blog-prod", 'a', false);
    write_environment_state(&root, &[("blog-dev", 'b'), ("blog-prod", 'a')]);
    let h = builder.build().await;

    let (status, body) = admin(
        &h,
        "PUT",
        "/v1/sites/blog",
        Some(blog_with_not_found_page()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let message = body["message"].as_str().unwrap();
    assert!(
        message.contains("site blog, environment prod (instance blog-prod)"),
        "{body}"
    );
    assert!(message.contains("404.html"), "{body}");
    assert!(message.contains("weglarka promote blog prod"), "{body}");
    h.running.stop().await;
}
