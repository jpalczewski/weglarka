//! Daemon tests on `FakePodman`: admin API over a real unix socket, webhooks over TCP.

mod common;

use common::*;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, StatusCode};
use serde_json::{Value, json};
use tokio::net::TcpStream;
use weglarka_core::config::HostConfig;
use weglarka_core::testing::{Call, FakePodman};
use weglarka_daemon::github::{DELIVERY_HEADER, EVENT_HEADER, SIGNATURE_HEADER, sign};
use weglarka_daemon::{Settings, start};

const SECRET: &str = "hunter2-webhook";
const IMAGE: &str = "ghcr.io/jpalczewski/ntfy.zig:latest";

async fn hook(
    addr: SocketAddr,
    instance: &str,
    event: &str,
    delivery: &str,
    body: &[u8],
    signature: Option<String>,
) -> StatusCode {
    let stream = TcpStream::connect(addr).await.unwrap();
    let mut req = Request::builder()
        .method("POST")
        .uri(format!("/webhook/github/{instance}"))
        .header("host", "hooks.example.eu")
        .header(EVENT_HEADER, event)
        .header(DELIVERY_HEADER, delivery);
    if let Some(sig) = signature {
        req = req.header(SIGNATURE_HEADER, sig);
    }
    send(
        stream,
        req.body(Full::new(Bytes::from(body.to_vec()))).unwrap(),
    )
    .await
    .0
}

fn app_body(name: &str, domain: &str) -> Value {
    json!({
        "name": name,
        "spec": {
            "image": IMAGE,
            "domains": [domain],
            "port": 8085,
            "health": { "attempts": 1, "window_secs": 1 }
        }
    })
}

async fn current_digest(h: &Harness, name: &str) -> Option<String> {
    let (status, v) = admin(h, "GET", &format!("/v1/apps/{name}"), None).await;
    assert_eq!(status, StatusCode::OK, "{v}");
    v["state"]["current"].as_str().map(str::to_owned)
}

fn published(tag: &str) -> Vec<u8> {
    json!({
        "action": "published",
        "registry_package": {
            "name": "ntfy.zig", "namespace": "jpalczewski", "package_type": "CONTAINER",
            "package_version": {
                "package_url": format!("ghcr.io/jpalczewski/ntfy.zig:{tag}"),
                "container_metadata": { "tag": { "name": tag } }
            }
        }
    })
    .to_string()
    .into_bytes()
}

fn pulls(fake: &FakePodman) -> usize {
    fake.calls()
        .iter()
        .filter(|c| matches!(c, Call::ImagePull(r) if r == IMAGE))
        .count()
}

#[tokio::test]
async fn admin_lifecycle_add_deploy_status_remove() {
    let h = harness().await;

    let mode = std::fs::metadata(&h.running.admin_socket)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);

    let (s, v) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(app_body("ntfy", "nz.example.eu")),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["name"], "ntfy");
    let (s, v) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(app_body("ntfy", "nz.example.eu")),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(v["code"], "already_exists");

    // A domain taken by another app fails ingress validation.
    let (s, v) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(app_body("other", "nz.example.eu")),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let (s, _) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(json!({"name": "Bad_Name", "spec": {"image": "x"}})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // `add` wakes the reconcile, which performs the first deploy.
    eventually("first deploy", || async {
        current_digest(&h, "ntfy").await.is_some()
    })
    .await;

    let (s, v) = admin(&h, "POST", "/v1/apps/ntfy/deploy", Some(json!({}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(matches!(
        v["outcome"].as_str(),
        Some("deployed" | "unchanged")
    ));
    let (s, v) = admin(
        &h,
        "POST",
        "/v1/apps/ntfy/deploy",
        Some(json!({"image_ref": "x"})),
    )
    .await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_request"))
    );
    let (s, v) = admin(&h, "POST", "/v1/apps/ghost/deploy", None).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("not_found"))
    );

    let (s, v) = admin(&h, "GET", "/v1/apps/ntfy", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["runtime"], "running");
    let (_, v) = admin(&h, "GET", "/v1/apps", None).await;
    assert_eq!(v["apps"][0]["name"], "ntfy");
    assert_eq!(v["apps"][0]["runtime"], "running");
    let (_, v) = admin(&h, "GET", "/v1/status", None).await;
    assert_eq!(v["api_version"], "v1");
    assert_eq!(v["apps"].as_array().unwrap().len(), 1);

    // Secrets: name and value validation, no values in responses.
    let (s, v) = admin(
        &h,
        "PUT",
        "/v1/apps/ntfy/secrets/config",
        Some(json!({"value": "s3cr3t"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(!v.to_string().contains("s3cr3t"));
    let (s, _) = admin(
        &h,
        "PUT",
        "/v1/apps/ntfy/secrets/bad.name",
        Some(json!({"value": "x"})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = admin(
        &h,
        "PUT",
        "/v1/apps/ntfy/secrets/config",
        Some(json!({"value": ""})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = admin(
        &h,
        "PUT",
        "/v1/apps/ghost/secrets/config",
        Some(json!({"value": "x"})),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, v) = admin(&h, "GET", "/v1/apps/ntfy/secrets", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["secrets"][0]["name"], "config");
    assert!(!v.to_string().contains("s3cr3t"));
    let secrets_file = h.root.join("state/secrets.toml");
    assert_eq!(
        std::fs::metadata(&secrets_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    // Ingress: nginx.conf, the Traefik file and the nginx container appear after the app set changes.
    eventually("ingress applied", || async {
        read(&h.root.join("state/nginx/nginx.conf")).contains("nz.example.eu")
            && read(&h.root.join("traefik.yml")).contains("nz.example.eu")
            && h.fake
                .containers()
                .iter()
                .any(|c| c.name == "weglarka-nginx")
    })
    .await;
    assert!(h.fake.networks().contains(&"net-weglarka".to_owned()));
    assert!(h.fake.networks().contains(&"net-ntfy".to_owned()));

    let (s, v) = admin(&h, "GET", "/v1/doctor", None).await;
    assert_eq!(s, StatusCode::OK);
    let ids: Vec<&str> = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    for want in [
        "runtime.socket",
        "state.apps_file",
        "state.secrets_file",
        "state.webhook_secrets",
        "state.drift",
        "webhook.listener",
        "ingress.traefik_file",
    ] {
        assert!(ids.contains(&want), "missing check {want}: {ids:?}");
    }
    let hmac = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "state.webhook_secrets")
        .unwrap();
    assert_eq!(hmac["status"], "warn");

    let (s, _) = admin(&h, "DELETE", "/v1/apps/ntfy", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, v) = admin(&h, "DELETE", "/v1/apps/ntfy", None).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("not_found"))
    );
    eventually("app removed from ingress and runtime", || async {
        !read(&h.root.join("traefik.yml")).contains("nz.example.eu")
            && !h.fake.containers().iter().any(|c| c.name == "ntfy")
    })
    .await;

    let (s, _) = admin(&h, "GET", "/v1/nope", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    h.running.stop().await;
}

/// Issue #30: `state.toml` is written after the health gate, so a recreate is briefly visible as a
/// state/container mismatch. `doctor` must report it as `state.deploying` (`info`), not as drift.
#[tokio::test]
async fn doctor_reports_a_recreate_in_progress_instead_of_state_drift() {
    let h = harness().await;
    // A 2 s gate widens the window in which the instance counts as in flight.
    let health = json!({ "attempts": 1, "window_secs": 2 });
    let mut body = app_body("ntfy", "nz.example.eu");
    body["spec"]["health"] = health.clone();
    let (s, v) = admin(&h, "POST", "/v1/apps", Some(body)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    eventually("first deploy", || async {
        current_digest(&h, "ntfy").await.is_some()
    })
    .await;

    // `env` is part of the spec hash: reconcile recreates the container from the pinned digest.
    let (s, v) = admin(
        &h,
        "PUT",
        "/v1/apps/ntfy",
        Some(json!({
            "spec": {
                "image": IMAGE,
                "domains": ["nz.example.eu"],
                "port": 8085,
                "env": { "CHANGED": "1" },
                "health": health
            }
        })),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");

    let checks = |v: &Value, id: &str| -> Option<Value> {
        v["checks"]
            .as_array()?
            .iter()
            .find(|c| c["id"] == id)
            .cloned()
    };
    let mut saw_deploying = false;
    for _ in 0..200 {
        let (s, v) = admin(&h, "GET", "/v1/doctor", None).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        if let Some(check) = checks(&v, "state.deploying") {
            assert_eq!(check["status"], "info", "{check}");
            let message = check["message"].as_str().unwrap_or_default();
            assert!(message.contains("ntfy"), "{message}");
            assert!(
                message.contains("recreate"),
                "the kind of operation is reported: {message}"
            );
            let drift = checks(&v, "state.drift").expect("state.drift is always reported");
            assert_eq!(
                drift["status"], "ok",
                "no drift warning mid-deploy: {drift}"
            );
            saw_deploying = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(saw_deploying, "doctor never reported state.deploying");

    // Once the deploy is done the transient check disappears and the state is consistent.
    eventually("deploy finished", || async {
        let (_, v) = admin(&h, "GET", "/v1/doctor", None).await;
        checks(&v, "state.deploying").is_none()
            && checks(&v, "state.drift").unwrap()["status"].as_str() == Some("ok")
    })
    .await;
}

#[tokio::test]
async fn provision_only_add_creates_no_container_and_deploy_provisions() {
    let h = harness().await;
    let mut body = app_body("ntfy", "nz.example.eu");
    body["spec"]["start"] = json!(false);
    body["spec"]["volumes"] = json!([{"name": "data", "target": "/data"}]);

    // `start = false`: `add` provisions synchronously and the response already has the pinned digest.
    let (s, v) = admin(&h, "POST", "/v1/apps", Some(body)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["runtime"], "not_started");
    assert_eq!(v["spec"]["start"], json!(false));
    let digest = v["state"]["current"].clone();
    assert!(digest.is_string(), "digest pinned: {v}");
    let digest = digest.as_str().unwrap().to_owned();

    // Nothing runs, but the network and the declared volume are ready.
    assert!(h.fake.containers().iter().all(|c| c.name != "ntfy"));
    assert!(h.fake.networks().contains(&"net-ntfy".to_owned()));
    assert!(h.fake.volumes().iter().any(|v| v.name == "ntfy.data"));

    // Reads agree: `show` and the list report `not_started`.
    let (s, v) = admin(&h, "GET", "/v1/apps/ntfy", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["runtime"], "not_started");
    assert_eq!(v["state"]["current"], json!(digest));
    let (_, v) = admin(&h, "GET", "/v1/apps", None).await;
    assert_eq!(v["apps"][0]["runtime"], "not_started");

    // A manual deploy of a `start = false` app provisions again instead of starting it.
    let (s, v) = admin(&h, "POST", "/v1/apps/ntfy/deploy", Some(json!({}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["outcome"], "provisioned");
    assert_eq!(v["digest"], json!(digest));
    assert!(h.fake.containers().iter().all(|c| c.name != "ntfy"));

    // Wakes from `add`/`deploy` settle without bringing the container back.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(h.fake.containers().iter().all(|c| c.name != "ntfy"));
    h.running.stop().await;
}

#[tokio::test]
async fn webhook_flow() {
    let h = harness().await;
    let addr = h.running.webhook_addr;
    admin(
        &h,
        "POST",
        "/v1/apps",
        Some(app_body("ntfy", "nz.example.eu")),
    )
    .await;
    eventually("first deploy", || async {
        current_digest(&h, "ntfy").await.is_some()
    })
    .await;
    let (s, _) = admin(
        &h,
        "PUT",
        "/v1/apps/ntfy/secrets/webhook-hmac",
        Some(json!({"value": SECRET})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let body = published("latest");
    let good = Some(sign(SECRET.as_bytes(), &body));

    // Bad signature, no signature, wrong secret, unknown app, app without a secret → 401.
    let bad = Some(sign(b"wrong", &body));
    assert_eq!(
        hook(addr, "ntfy", "registry_package", "d0", &body, bad).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        hook(addr, "ntfy", "registry_package", "d0", &body, None).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        hook(addr, "ghost", "registry_package", "d0", &body, good.clone()).await,
        StatusCode::UNAUTHORIZED
    );

    // Irrelevant events (correctly signed) → 204.
    let ping = b"{}".to_vec();
    let ping_sig = Some(sign(SECRET.as_bytes(), &ping));
    assert_eq!(
        hook(addr, "ntfy", "ping", "d1", &ping, ping_sig.clone()).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        hook(addr, "ntfy", "push", "d2", &ping, ping_sig).await,
        StatusCode::NO_CONTENT
    );
    let other = published("sha-abc123");
    assert_eq!(
        hook(
            addr,
            "ntfy",
            "registry_package",
            "d3",
            &other,
            Some(sign(SECRET.as_bytes(), &other))
        )
        .await,
        StatusCode::NO_CONTENT
    );

    // Good signature → 202 right away; the deploy runs in a separate task.
    let before = pulls(&h.fake);
    assert_eq!(
        hook(addr, "ntfy", "registry_package", "d4", &body, good.clone()).await,
        StatusCode::ACCEPTED
    );
    eventually("webhook deploy pulled", || async {
        pulls(&h.fake) > before
    })
    .await;
    let after_first = pulls(&h.fake);

    // Duplicate delivery: 202, but no redeploy (dedup by X-GitHub-Delivery).
    assert_eq!(
        hook(addr, "ntfy", "registry_package", "d4", &body, good.clone()).await,
        StatusCode::ACCEPTED
    );
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(pulls(&h.fake), after_first);

    // Body over the limit → 413.
    let huge = vec![b'x'; 1024 * 1024 + 1];
    assert_eq!(
        hook(
            addr,
            "ntfy",
            "registry_package",
            "d5",
            &huge,
            Some(sign(SECRET.as_bytes(), &huge))
        )
        .await,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    h.running.stop().await;
}

/// Issue #41: handled delivery ids survive a daemon restart. The same `X-GitHub-Delivery` sent to a
/// fresh daemon over the same state directory is a duplicate — 202, no pull, no redeploy.
#[tokio::test]
async fn webhook_dedup_survives_daemon_restart() {
    let h = harness().await;
    let addr = h.running.webhook_addr;
    admin(
        &h,
        "POST",
        "/v1/apps",
        Some(app_body("ntfy", "nz.example.eu")),
    )
    .await;
    eventually("first deploy", || async {
        current_digest(&h, "ntfy").await.is_some()
    })
    .await;
    let (s, _) = admin(
        &h,
        "PUT",
        "/v1/apps/ntfy/secrets/webhook-hmac",
        Some(json!({"value": SECRET})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    let body = published("latest");
    let good = Some(sign(SECRET.as_bytes(), &body));
    let before = pulls(&h.fake);
    assert_eq!(
        hook(
            addr,
            "ntfy",
            "registry_package",
            "restart-1",
            &body,
            good.clone()
        )
        .await,
        StatusCode::ACCEPTED
    );
    eventually("webhook deploy pulled", || async {
        pulls(&h.fake) > before
    })
    .await;

    // Stop and start again on the same state directory (what self-update / a reboot does).
    let Harness {
        _dir,
        root,
        fake,
        running,
        ..
    } = h;
    running.stop().await;
    assert!(
        root.join("state/webhook-deliveries.toml").is_file(),
        "the handled delivery is persisted"
    );
    let running = start(settings(&root, "", ""), fake.clone()).await.unwrap();
    let addr = running.webhook_addr;
    // Let the startup reconcile settle before sampling the pull counter.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let after_restart = pulls(&fake);

    assert_eq!(
        hook(addr, "ntfy", "registry_package", "restart-1", &body, good).await,
        StatusCode::ACCEPTED
    );
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        pulls(&fake),
        after_restart,
        "a redelivery after a restart must not pull"
    );
    running.stop().await;
}

#[tokio::test]
async fn refuses_loose_secrets_permissions() {
    let dir = tempfile::Builder::new()
        .prefix("wg")
        .tempdir_in("/tmp")
        .unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("state")).unwrap();
    std::fs::write(root.join("state/secrets.toml"), "").unwrap();
    std::fs::set_permissions(
        root.join("state/secrets.toml"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let host = HostConfig::from_toml_str(&format!(
        "[ingress]\nmode=\"behind\"\nbind=\"127.0.0.1:18081\"\n[admin]\nsocket=\"{r}/a.sock\"\n[webhook]\nlisten=\"127.0.0.1:0\"\ndomain=\"h.example.eu\"\n[state]\ndir=\"{r}/state\"\n",
        r = root.display()
    ))
    .unwrap();
    let res = start(
        Settings::from_host(host, root.join("weglarka.toml")),
        FakePodman::new(),
    )
    .await;
    assert!(res.is_err());
}

#[tokio::test]
async fn refuses_a_state_schema_from_a_newer_daemon() {
    let (_dir, root) = tempdir("wg");
    std::fs::create_dir_all(root.join("state")).unwrap();

    // `state.toml` written by a newer schema stops the daemon before it binds anything.
    let newer = weglarka_core::state::SCHEMA_VERSION + 1;
    std::fs::write(
        root.join("state/state.toml"),
        format!("schema_version = {newer}\n"),
    )
    .unwrap();
    let err = match start(settings(&root, "", ""), FakePodman::new()).await {
        Ok(_) => panic!("a newer state schema must refuse to start"),
        Err(e) => e,
    };
    let message = err.to_string();
    assert!(
        message.contains("state.toml") && message.contains(&format!("schema version {newer}")),
        "{message}"
    );

    // The same for `apps.toml`, with a valid `state.toml` next to it.
    std::fs::write(root.join("state/state.toml"), "").unwrap();
    std::fs::write(
        root.join("state/apps.toml"),
        format!("schema_version = {newer}\n[apps.a]\nimage = \"x:1\"\n"),
    )
    .unwrap();
    let err = match start(settings(&root, "", ""), FakePodman::new()).await {
        Ok(_) => panic!("a newer apps schema must refuse to start"),
        Err(e) => e,
    };
    assert!(err.to_string().contains("apps.toml"), "{err}");
}

/// An `edge` daemon (issue #95): two public ports, no Traefik, certificates under `<state>/nginx/tls`.
fn edge_settings(root: &Path) -> Settings {
    let host = HostConfig::from_toml_str(&format!(
        r#"
[ingress]
mode = "edge"
bind = "127.0.0.1:18080"
https_bind = "127.0.0.1:18443"

[admin]
socket = "{root}/run/admin.sock"

[webhook]
listen = "127.0.0.1:0"
domain = "hooks.example.eu"

[state]
dir = "{root}/state"
"#,
        root = root.display()
    ))
    .unwrap();
    Settings::from_host(host, root.join("weglarka.toml"))
}

#[tokio::test]
async fn refuses_an_edge_config_without_https_bind() {
    let (_dir, root) = tempdir("wg");
    std::fs::create_dir_all(root.join("state")).unwrap();
    let host = HostConfig::from_toml_str(&format!(
        "[ingress]\nmode=\"edge\"\nbind=\"127.0.0.1:18080\"\n[admin]\nsocket=\"{r}/a.sock\"\n[webhook]\nlisten=\"127.0.0.1:0\"\ndomain=\"h.example.eu\"\n[state]\ndir=\"{r}/state\"\n",
        r = root.display()
    ))
    .unwrap();
    let err = match start(
        Settings::from_host(host, root.join("weglarka.toml")),
        FakePodman::new(),
    )
    .await
    {
        Ok(_) => panic!("edge without https_bind must refuse to start"),
        Err(e) => e,
    };
    assert!(err.to_string().contains("requires https_bind"), "{err}");
}

#[tokio::test]
async fn edge_ingress_owns_two_ports_and_doctor_reports_tls() {
    let dir = tempfile::Builder::new()
        .prefix("wg")
        .tempdir_in("/tmp")
        .unwrap();
    let root = dir.path().to_owned();
    let fake = FakePodman::new();
    let running = start(edge_settings(&root), fake.clone()).await.unwrap();

    eventually("edge ingress applied", || async {
        fake.containers().iter().any(|c| c.name == "weglarka-nginx")
    })
    .await;

    let spec = fake.container_spec("weglarka-nginx").unwrap();
    let publishes: Vec<(u16, u16)> = spec
        .publish
        .iter()
        .map(|p| (p.host_port, p.container_port))
        .collect();
    assert_eq!(publishes, [(18080, 8080), (18443, 8443)]);
    // Traefik has no part in edge: no file is written even though the state dir exists.
    assert!(!root.join("traefik.yml").exists());
    let nginx_dir = root.join("state/nginx");
    let conf = read(&nginx_dir.join("nginx.conf"));
    assert!(conf.contains("listen 8443 ssl default_server;"), "{conf}");
    assert!(conf.contains("ssl_reject_handshake on;"), "{conf}");

    let (status, v) = admin_running(&running, "GET", "/v1/doctor", None).await;
    assert_eq!(status, StatusCode::OK);
    let ids: Vec<&str> = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"ingress.tls"), "{ids:?}");
    assert!(!ids.contains(&"ingress.traefik_file"), "{ids:?}");
    let tls = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "ingress.tls")
        .unwrap();
    assert_eq!(tls["status"], "warn", "{tls}");
    assert!(
        tls["message"]
            .as_str()
            .unwrap()
            .contains("hooks.example.eu"),
        "{tls}"
    );
    running.stop().await;
}
