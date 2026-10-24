//! Host config mounts and `apps reload` (issue #118, ADR 0022) over the admin API: startup
//! validation, reload/show/doctor on `FakePodman` with a real `config_root` in the temp dir.

mod common;

use common::*;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use hyper::StatusCode;
use serde_json::{Value, json};
use weglarka_core::testing::{Call, FakePodman};
use weglarka_daemon::{Running, StartError, start};

const IMAGE: &str = "ghcr.io/jpalczewski/prometheus:latest";
const CONFIG_SOURCE: &str = "prometheus/prometheus.yml";
const CONFIG_TARGET: &str = "/etc/prometheus/prometheus.yml";

/// The `config_root` line of `weglarka.toml` when the test asks for one.
fn config_root_line(config_root: Option<&Path>) -> String {
    config_root
        .map(|root| format!("config_root = {:?}\n", root.display().to_string()))
        .unwrap_or_default()
}

/// A `config_root` with one real config file, and a daemon that mounts it when `with_config_root`.
async fn harness(with_config_root: bool) -> Harness {
    harness_with_apps(with_config_root, "").await
}

/// [`harness`] with `apps.toml` written **before** startup: the per-source tolerance is only
/// observable when the broken mount is already declared when the daemon starts.
async fn harness_with_apps(with_config_root: bool, apps: &str) -> Harness {
    let mut builder = Builder::new();
    let config_root = builder.root().join("config");
    std::fs::create_dir_all(config_root.join("prometheus")).unwrap();
    std::fs::write(
        config_root.join(CONFIG_SOURCE),
        "global:\n  scrape_interval: 30s\n",
    )
    .unwrap();
    builder = builder.top_level(&config_root_line(
        with_config_root.then_some(config_root.as_path()),
    ));
    if !apps.is_empty() {
        builder = builder.apps(apps);
    }
    builder.build().await
}

/// Daemon startup for the rejection tests: `apps.toml` already written, `start` decides.
async fn start_result(
    root: &Path,
    config_root: Option<&Path>,
    apps_toml: &str,
) -> Result<Running<FakePodman>, StartError> {
    std::fs::create_dir_all(root.join("state")).unwrap();
    std::fs::write(root.join("state/apps.toml"), apps_toml).unwrap();
    std::fs::write(root.join("traefik.yml"), "").unwrap();
    let settings = settings(root, &config_root_line(config_root), "");
    start(settings, FakePodman::new()).await
}

fn apps_toml(configs: &str) -> String {
    format!("[apps.prometheus]\nimage = {IMAGE:?}\ndomains = [\"prom.example.eu\"]\n{configs}\n")
}

fn startup_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("wgs")
        .tempdir_in("/tmp")
        .unwrap()
}

fn app_body(name: &str, domain: &str, extra: Value) -> Value {
    let mut spec = json!({
        "image": IMAGE,
        "domains": [domain],
        "port": 8085,
        "health": { "attempts": 1, "window_secs": 1 },
    });
    if let Value::Object(extra) = extra {
        let spec = spec.as_object_mut().unwrap();
        for (key, value) in extra {
            spec.insert(key, value);
        }
    }
    json!({ "name": name, "spec": spec })
}

fn configs_field() -> Value {
    json!([{ "source": CONFIG_SOURCE, "target": CONFIG_TARGET }])
}

async fn current_digest(h: &Harness, name: &str) -> Option<String> {
    let (status, v) = admin(h, "GET", &format!("/v1/apps/{name}"), None).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    v["state"]["current"].as_str().map(str::to_owned)
}

async fn add_deployed(h: &Harness, body: Value) -> String {
    let (s, v) = admin(h, "POST", "/v1/apps", Some(body)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let name = v["name"].as_str().unwrap().to_owned();
    eventually("first deploy", || async {
        current_digest(h, &name).await.is_some()
    })
    .await;
    current_digest(h, &name).await.unwrap()
}

fn doctor_check<'a>(v: &'a Value, id: &str) -> Option<&'a Value> {
    v["checks"]
        .as_array()?
        .iter()
        .find(|check| check["id"] == id)
}

// ── Startup (before any socket is bound) ─────────────────────────────────────────

#[tokio::test]
async fn startup_rejects_configs_without_a_config_root() {
    let dir = startup_dir();
    let root = dir.path();
    let err = start_result(
        root,
        None,
        &apps_toml(&format!(
            "configs = [{{ source = \"{CONFIG_SOURCE}\", target = \"{CONFIG_TARGET}\" }}]"
        )),
    )
    .await
    .err()
    .expect("startup must refuse an app with configs when config_root is unset");
    let message = err.to_string();
    assert!(message.contains("config mounts"), "{message}");
    assert!(message.contains("config_root"), "{message}");
    assert!(
        message.contains("prometheus"),
        "the app is named: {message}"
    );
}

#[tokio::test]
async fn startup_tolerates_a_missing_or_escaping_source() {
    let outside = startup_dir();
    std::fs::write(outside.path().join("secret.yml"), "secret\n").unwrap();
    // Declared before the files exist: startup must not refuse them — reconcile blocks the instance
    // and `doctor` reports the mounts instead.
    let apps = format!(
        "[apps.prometheus]\nimage = {IMAGE:?}\n\
         configs = [{{ source = \"missing.yml\", target = \"/missing.yml\" }}]\n\
         [apps.escaping]\nimage = {IMAGE:?}\n\
         configs = [{{ source = \"escape\", target = \"/escape\" }}]\n"
    );
    let h = harness_with_apps(true, &apps).await;
    std::os::unix::fs::symlink(outside.path(), h.config_root.join("escape")).unwrap();

    let (s, v) = admin(&h, "GET", "/v1/doctor", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let mounts = doctor_check(&v, "configs.mounts").expect("configs.mounts reported");
    assert_eq!(mounts["status"], "warn", "{mounts}");
    let message = mounts["message"].as_str().unwrap_or_default();
    assert!(message.contains("missing.yml"), "{message}");
    assert!(message.contains("does not exist"), "{message}");
    assert!(message.contains("escape"), "{message}");
    assert!(message.contains("outside config_root"), "{message}");

    // Nothing was deployed: the instance is blocked, not silently shipped without its config.
    let drift = doctor_check(&v, "state.drift").expect("state.drift reported");
    assert_eq!(drift["status"], "warn", "{drift}");
    let drift_message = drift["message"].as_str().unwrap_or_default();
    assert!(drift_message.contains("prometheus"), "{drift_message}");
    assert!(drift_message.contains("not deployed"), "{drift_message}");
    assert!(h.fake.containers().iter().all(|c| c.name != "prometheus"));
    h.running.stop().await;
}

#[tokio::test]
async fn startup_rejects_an_unusable_config_root() {
    let dir = startup_dir();
    let root = dir.path();

    // A configured but missing directory would hide every config: the daemon refuses to start.
    let missing = root.join("config");
    let err = start_result(
        root,
        Some(&missing),
        &apps_toml("configs = [{ source = \"app.yml\", target = \"/app.yml\" }]"),
    )
    .await
    .err()
    .expect("startup must refuse a missing config_root");
    let message = err.to_string();
    assert!(message.contains("config mounts"), "{message}");
    assert!(message.contains("unavailable"), "{message}");

    // The same for a path that is not a directory, even with no app declaring configs.
    let file = root.join("config-file");
    std::fs::write(&file, "x").unwrap();
    let err = start_result(root, Some(&file), &apps_toml(""))
        .await
        .err()
        .expect("startup must refuse a config_root that is not a directory");
    assert!(err.to_string().contains("not a directory"), "{err}");
}

// ── `apps reload` ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn reload_sends_the_signal_and_reports_the_mounts() {
    let h = harness(true).await;
    add_deployed(
        &h,
        app_body(
            "prometheus",
            "prom.example.eu",
            json!({ "configs": configs_field(), "reload_signal": "SIGHUP" }),
        ),
    )
    .await;

    // The mount reaches the container read-only.
    let container = h
        .fake
        .container_spec("prometheus")
        .expect("container created");
    assert!(
        container
            .mounts
            .iter()
            .any(|m| m.target == CONFIG_TARGET && m.read_only),
        "{:?}",
        container.mounts
    );

    // `show` reports the mount with an ok status and a content fingerprint.
    let (s, v) = admin(&h, "GET", "/v1/apps/prometheus", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["configs"][0]["source"], CONFIG_SOURCE);
    assert_eq!(v["configs"][0]["target"], CONFIG_TARGET);
    assert_eq!(v["configs"][0]["status"], "ok");
    assert!(
        v["configs"][0]["fingerprint"].is_string(),
        "a real config file is fingerprinted: {v}"
    );

    // An empty body means `recreate = false`.
    let (s, v) = admin(&h, "POST", "/v1/apps/prometheus/reload", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["action"], "signalled");
    assert_eq!(v["signal"], "HUP");
    assert_eq!(v["configs"][0]["status"], "ok", "{v}");
    assert!(
        h.fake.calls().iter().any(|call| matches!(
            call,
            Call::ContainerKill { name, signal } if name == "prometheus" && signal == "HUP"
        )),
        "no SIGHUP was sent: {:?}",
        h.fake.calls()
    );
    h.running.stop().await;
}

#[tokio::test]
async fn reload_without_a_signal_restarts_the_container() {
    let h = harness(true).await;
    add_deployed(
        &h,
        app_body(
            "prometheus",
            "prom.example.eu",
            json!({ "configs": configs_field() }),
        ),
    )
    .await;
    let before = h.fake.calls().len();

    let (s, v) = admin(&h, "POST", "/v1/apps/prometheus/reload", Some(json!({}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["action"], "restarted");
    assert!(v.get("signal").is_none(), "no signal in {v}");

    let calls = h.fake.calls()[before..].to_vec();
    let stop = calls
        .iter()
        .position(|call| matches!(call, Call::ContainerStop(name) if name == "prometheus"))
        .expect("container stopped");
    let start = calls
        .iter()
        .position(|call| matches!(call, Call::ContainerStart(name) if name == "prometheus"))
        .expect("container started again");
    assert!(stop < start, "stop then start: {calls:?}");
    assert!(
        !calls
            .iter()
            .any(|call| matches!(call, Call::ContainerKill { name, .. } if name == "prometheus")),
        "no signal without `reload_signal`: {calls:?}"
    );
    h.running.stop().await;
}

#[tokio::test]
async fn reload_of_an_app_that_is_not_running_is_a_conflict() {
    let h = harness(true).await;
    // `start = false`: provisioned (digest pinned), no container to signal or restart.
    let (s, v) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(app_body(
            "prometheus",
            "prom.example.eu",
            json!({ "start": false }),
        )),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["runtime"], "not_started");

    let (s, v) = admin(&h, "POST", "/v1/apps/prometheus/reload", None).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["code"], "conflict");
    let message = v["message"].as_str().unwrap_or_default();
    assert!(message.contains("apps start"), "{message}");

    let (s, v) = admin(&h, "POST", "/v1/apps/ghost/reload", None).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("not_found"))
    );
    h.running.stop().await;
}

#[tokio::test]
async fn reload_recreate_of_a_provisioned_app_is_a_conflict() {
    let h = harness(true).await;
    // `start = false`: provisioned, no container to replace.
    let (s, v) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(app_body(
            "prometheus",
            "prom.example.eu",
            json!({ "start": false, "configs": configs_field() }),
        )),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["runtime"], "not_started");
    let before = h.fake.created_specs().len();

    let (s, v) = admin(
        &h,
        "POST",
        "/v1/apps/prometheus/reload",
        Some(json!({ "recreate": true })),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["code"], "conflict");
    let message = v["message"].as_str().unwrap_or_default();
    assert!(message.contains("apps start"), "{message}");
    assert_eq!(
        h.fake.created_specs().len(),
        before,
        "nothing was recreated or started"
    );
    assert!(h.fake.containers().iter().all(|c| c.name != "prometheus"));
    h.running.stop().await;
}

#[tokio::test]
async fn reload_recreate_recreates_from_the_pinned_digest() {
    let h = harness(true).await;
    let digest = add_deployed(
        &h,
        app_body(
            "prometheus",
            "prom.example.eu",
            json!({ "configs": configs_field(), "reload_signal": "SIGHUP" }),
        ),
    )
    .await;
    let created_containers = |h: &Harness| -> Vec<weglarka_core::podman::ContainerSpec> {
        h.fake
            .created_specs()
            .into_iter()
            .filter(|spec| spec.name == "prometheus")
            .collect()
    };
    let first = created_containers(&h);
    assert_eq!(first.len(), 1, "{first:?}");
    let pinned = first[0].image.clone();
    assert!(pinned.ends_with(&digest), "{pinned} / {digest}");

    let (s, v) = admin(
        &h,
        "POST",
        "/v1/apps/prometheus/reload",
        Some(json!({ "recreate": true })),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["action"], "recreated");
    assert!(v.get("signal").is_none(), "no signal in {v}");
    assert_eq!(v["configs"][0]["status"], "ok", "{v}");

    let created = created_containers(&h);
    assert_eq!(created.len(), 2, "the container was recreated: {created:?}");
    assert_eq!(
        created[1].image, pinned,
        "recreated from the pinned digest, not a new one"
    );
    assert_eq!(
        h.fake
            .containers()
            .iter()
            .find(|c| c.name == "prometheus")
            .expect("container back")
            .state,
        weglarka_core::podman::ContainerState::Running
    );
    assert_eq!(
        current_digest(&h, "prometheus").await.as_deref(),
        Some(digest.as_str())
    );
    h.running.stop().await;
}

// ── Validation at write time ────────────────────────────────────────────────────

#[tokio::test]
async fn add_and_update_reject_configs_without_a_config_root() {
    let h = harness(false).await;

    let (s, v) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(app_body(
            "prometheus",
            "prom.example.eu",
            json!({ "configs": configs_field() }),
        )),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["code"], "invalid_request");
    let message = v["message"].as_str().unwrap_or_default();
    assert!(message.contains("config_root"), "{message}");
    assert!(message.contains("platform install"), "{message}");

    // The same app without configs is accepted; adding configs later is rejected the same way.
    add_deployed(&h, app_body("prometheus", "prom.example.eu", json!({}))).await;
    let (s, v) = admin(
        &h,
        "PUT",
        "/v1/apps/prometheus",
        Some(json!({
            "spec": {
                "image": IMAGE,
                "domains": ["prom.example.eu"],
                "port": 8085,
                "configs": configs_field(),
            }
        })),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["code"], "invalid_request");
    // Nothing was persisted: the app still has no configs.
    let (_, v) = admin(&h, "GET", "/v1/apps/prometheus", None).await;
    assert!(v.get("configs").is_none(), "{v}");
    assert!(v["spec"].get("configs").is_none(), "{v}");
    h.running.stop().await;
}

#[tokio::test]
async fn add_accepts_a_config_source_that_does_not_exist_yet() {
    let h = harness(true).await;
    // `apps add` only checks that the feature is on: the files may follow (reconcile blocks the
    // instance and `doctor` warns until they do).
    let (s, v) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(app_body(
            "prometheus",
            "prom.example.eu",
            json!({ "configs": [{ "source": "later.yml", "target": "/later.yml" }] }),
        )),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["name"], "prometheus");

    let (s, v) = admin(&h, "GET", "/v1/apps/prometheus", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["configs"][0]["status"], "missing", "{v}");
    assert!(v["configs"][0].get("fingerprint").is_none(), "{v}");
    assert!(
        v["configs"][0]["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("does not exist"),
        "{v}"
    );

    // As soon as the file exists the same spec resolves — nothing has to be re-saved.
    std::fs::write(h.config_root.join("later.yml"), "a: 1\n").unwrap();
    let (s, v) = admin(&h, "GET", "/v1/apps/prometheus", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["configs"][0]["status"], "ok", "{v}");
    assert!(v["configs"][0]["fingerprint"].is_string(), "{v}");
    h.running.stop().await;
}

// ── Doctor ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn doctor_reports_a_healthy_config_root() {
    let h = harness(true).await;
    add_deployed(
        &h,
        app_body(
            "prometheus",
            "prom.example.eu",
            json!({ "configs": configs_field() }),
        ),
    )
    .await;

    let (s, v) = admin(&h, "GET", "/v1/doctor", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let root = doctor_check(&v, "configs.root").expect("configs.root reported");
    assert_eq!(root["status"], "ok", "{root}");
    let mounts = doctor_check(&v, "configs.mounts").expect("configs.mounts reported");
    assert_eq!(mounts["status"], "ok", "{mounts}");
    h.running.stop().await;
}

#[tokio::test]
async fn doctor_warns_about_a_missing_source_and_a_writable_root() {
    let h = harness(true).await;
    // Hand-edited `apps.toml`: the daemon is already running, doctor re-reads the file every time.
    let mut apps = std::fs::read_to_string(h.root.join("state/apps.toml")).unwrap_or_default();
    apps.push_str(&format!(
        "[apps.broken]\nimage = {IMAGE:?}\nconfigs = [{{ source = \"missing.yml\", target = \"/missing.yml\" }}]\n"
    ));
    std::fs::write(h.root.join("state/apps.toml"), apps).unwrap();
    std::fs::set_permissions(&h.config_root, std::fs::Permissions::from_mode(0o777)).unwrap();

    let (s, v) = admin(&h, "GET", "/v1/doctor", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let root = doctor_check(&v, "configs.root").expect("configs.root reported");
    assert_eq!(root["status"], "warn", "{root}");
    assert!(
        root["message"]
            .as_str()
            .unwrap_or_default()
            .contains("group/world-writable"),
        "{root}"
    );
    let mounts = doctor_check(&v, "configs.mounts").expect("configs.mounts reported");
    assert_eq!(mounts["status"], "warn", "{mounts}");
    let message = mounts["message"].as_str().unwrap_or_default();
    assert!(message.contains("broken"), "{message}");
    assert!(message.contains("does not exist"), "{message}");
    assert!(mounts["hint"].is_string(), "{mounts}");
    h.running.stop().await;
}

#[tokio::test]
async fn doctor_warns_when_the_app_cannot_read_a_config() {
    let h = harness(true).await;
    add_deployed(
        &h,
        app_body(
            "prometheus",
            "prom.example.eu",
            json!({ "configs": configs_field() }),
        ),
    )
    .await;
    // The runtime user's 0600 file is `nobody` in the app's uid range (ADR 0009).
    std::fs::set_permissions(
        h.config_root.join(CONFIG_SOURCE),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    let (s, v) = admin(&h, "GET", "/v1/doctor", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let mounts = doctor_check(&v, "configs.mounts").expect("configs.mounts reported");
    assert_eq!(mounts["status"], "warn", "{mounts}");
    let message = mounts["message"].as_str().unwrap_or_default();
    assert!(message.contains("not readable by the app"), "{message}");
    assert!(message.contains("600"), "the mode is reported: {message}");
    assert!(
        mounts["hint"].as_str().unwrap_or_default().contains("0644"),
        "the fix is spelled out: {mounts}"
    );
    h.running.stop().await;
}

#[tokio::test]
async fn doctor_is_quiet_about_configs_when_the_feature_is_off() {
    let h = harness(false).await;
    let (s, v) = admin(&h, "GET", "/v1/doctor", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(doctor_check(&v, "configs.root").is_none(), "{v}");
    assert!(doctor_check(&v, "configs.mounts").is_none(), "{v}");

    // A hand-edited `apps.toml` that declares configs without a `config_root`: a warning, not a
    // failed report.
    std::fs::write(
        h.root.join("state/apps.toml"),
        apps_toml("configs = [{ source = \"missing.yml\", target = \"/missing.yml\" }]"),
    )
    .unwrap();
    let (s, v) = admin(&h, "GET", "/v1/doctor", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let root = doctor_check(&v, "configs.root").expect("configs.root reported");
    assert_eq!(root["status"], "warn", "{root}");
    assert!(
        root["message"]
            .as_str()
            .unwrap_or_default()
            .contains("config_root is not set"),
        "{root}"
    );
    h.running.stop().await;
}
