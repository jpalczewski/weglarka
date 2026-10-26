//! `host_ports` (issue #34) through the admin API and at startup: the rules that need the host
//! (privileged ports, two apps on one socket, the ingress bind) are enforced wherever the daemon
//! reads or writes `apps.toml` (`docs/decisions/0013-host-ports.md`).

use crate::common::*;
use std::path::PathBuf;

use hyper::StatusCode;
use serde_json::{Value, json};
use weglarka_core::testing::FakePodman;
use weglarka_daemon::start;

const IMAGE: &str = "ghcr.io/jpalczewski/ntfy.zig:latest";

/// The `[runtime]` section that toggles `allow_privileged_host_ports`.
fn allow_privileged(allow: bool) -> String {
    format!("\n[runtime]\nallow_privileged_host_ports = {allow}\n")
}

async fn harness_with(allow: bool) -> Harness {
    Builder::new()
        .sections(&allow_privileged(allow))
        .build()
        .await
}

async fn harness() -> Harness {
    harness_with(false).await
}

/// A valid spec for `domain`; `start = false` keeps the test free of background deploys.
fn spec(domain: &str) -> Value {
    json!({
        "image": IMAGE,
        "domains": [domain],
        "port": 8085,
        "start": false,
        "health": { "attempts": 1, "window_secs": 1 }
    })
}

fn with_ports(mut spec: Value, ports: Value) -> Value {
    spec["host_ports"] = ports;
    spec
}

fn app_body(name: &str, spec: Value) -> Value {
    json!({ "name": name, "spec": spec })
}

/// The `apps.toml` the daemon writes next to its state; `[state] dir = "<root>/state"`.
fn apps_file(h: &Harness) -> PathBuf {
    h.root.join("state/apps.toml")
}

#[tokio::test]
async fn add_persists_host_ports_and_show_returns_them() {
    let h = harness().await;
    let ports = json!([
        { "host": 2222, "container": 22 },
        { "host": 2223, "container": 22, "ip": "0.0.0.0" }
    ]);
    let (s, v) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(app_body(
            "git",
            with_ports(spec("git.example.eu"), ports.clone()),
        )),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["spec"]["host_ports"], ports);

    // `show` reads the spec back, loopback included as the effective default.
    let (s, v) = admin(&h, "GET", "/v1/apps/git", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["spec"]["host_ports"], ports);
    assert_eq!(v["spec"]["host_ports"][0]["ip"], Value::Null);

    // Persisted in `apps.toml`; an omitted `ip` (loopback) stays omitted on the way out.
    let apps = read(&apps_file(&h));
    assert!(apps.contains("host = 2222"), "{apps}");
    assert!(apps.contains("container = 22"), "{apps}");
    assert!(apps.contains("ip = \"0.0.0.0\""), "{apps}");
    assert!(
        !apps.contains("127.0.0.1"),
        "loopback is implicit, not serialized: {apps}"
    );

    let (s, v) = admin(&h, "GET", "/v1/apps", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["apps"][0]["name"], "git");
    h.running.stop().await;
}

#[tokio::test]
async fn a_second_app_on_the_same_host_port_is_rejected() {
    let h = harness().await;
    let ports = json!([{ "host": 2222, "container": 22 }]);
    let (s, v) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(app_body(
            "git",
            with_ports(spec("git.example.eu"), ports.clone()),
        )),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let before = read(&apps_file(&h));

    let (s, v) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(app_body(
            "other",
            with_ports(spec("other.example.eu"), ports.clone()),
        )),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["code"], "invalid_request");
    let message = v["message"].as_str().unwrap_or_default();
    assert!(message.contains("already published"), "{message}");
    assert!(message.contains("git"), "{message}");

    // The rejected candidate was not saved: the first app still holds the port.
    assert_eq!(read(&apps_file(&h)), before);
    let (s, _) = admin(&h, "GET", "/v1/apps/other", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, v) = admin(&h, "GET", "/v1/apps/git", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["spec"]["host_ports"], ports);
    h.running.stop().await;
}

#[tokio::test]
async fn update_onto_the_ingress_bind_is_rejected() {
    let h = harness().await;
    let (s, v) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(app_body("web", spec("web.example.eu"))),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let before = read(&apps_file(&h));

    // The ingress bind is 127.0.0.1:18080; a wildcard on the same port also collides.
    let mut bad = spec("web.example.eu");
    bad["host_ports"] = json!([{ "host": 18080, "container": 80, "ip": "0.0.0.0" }]);
    let (s, v) = admin(&h, "PUT", "/v1/apps/web", Some(json!({ "spec": bad }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["code"], "invalid_request");
    let message = v["message"].as_str().unwrap_or_default();
    assert!(message.contains("ingress bind"), "{message}");

    // Full-replacement semantics: the spec that was there is unchanged.
    assert_eq!(read(&apps_file(&h)), before);
    let (s, v) = admin(&h, "GET", "/v1/apps/web", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["spec"].get("host_ports").is_none(), "{v}");
    h.running.stop().await;
}

#[tokio::test]
async fn a_privileged_host_port_needs_the_explicit_opt_in() {
    let body = || {
        app_body(
            "git",
            with_ports(
                spec("git.example.eu"),
                json!([{ "host": 222, "container": 22 }]),
            ),
        )
    };

    let h = harness().await;
    let (s, v) = admin(&h, "POST", "/v1/apps", Some(body())).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let message = v["message"].as_str().unwrap_or_default();
    assert!(message.contains("below 1024"), "{message}");
    assert!(message.contains("allow_privileged_host_ports"), "{message}");
    assert!(!apps_file(&h).exists() || !read(&apps_file(&h)).contains("git"));
    h.running.stop().await;

    let h = harness_with(true).await;
    let (s, v) = admin(&h, "POST", "/v1/apps", Some(body())).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["spec"]["host_ports"][0]["host"], 222);
    h.running.stop().await;
}

#[tokio::test]
async fn startup_refuses_an_apps_file_that_breaks_host_port_rules() {
    let conflict = r#"
[apps.a]
image = "i"
host_ports = [{ host = 2222, container = 22 }]

[apps.b]
image = "j"
host_ports = [{ host = 2222, container = 22 }]
"#;
    let privileged = r#"
[apps.git]
image = "i"
start = false
host_ports = [{ host = 222, container = 22 }]
"#;

    let start_err = |apps: &'static str, allow: bool| async move {
        let (_dir, root) = tempdir("wg");
        std::fs::create_dir_all(root.join("state")).unwrap();
        std::fs::write(root.join("state/apps.toml"), apps).unwrap();
        start(
            settings(&root, "", &allow_privileged(allow)),
            FakePodman::new(),
        )
        .await
        .err()
        .expect("invalid host_ports must stop the daemon")
        .to_string()
    };

    let message = start_err(conflict, false).await;
    assert!(message.contains("already published"), "{message}");

    let message = start_err(privileged, false).await;
    assert!(message.contains("below 1024"), "{message}");

    // The opt-in makes the same file valid and the daemon starts.
    let (_dir, root) = tempdir("wg");
    std::fs::create_dir_all(root.join("state")).unwrap();
    std::fs::write(root.join("state/apps.toml"), privileged).unwrap();
    let running = start(
        settings(&root, "", &allow_privileged(true)),
        FakePodman::new(),
    )
    .await
    .expect("allow_privileged_host_ports makes port 222 valid");
    running.stop().await;
}
