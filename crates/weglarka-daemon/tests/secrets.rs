//! `secrets remove` and `apps remove --purge-secrets` through the admin API (real unix socket,
//! FakePodman), plus the `state.orphan_secrets` doctor check (issue #80).

use std::path::{Path, PathBuf};
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::net::UnixStream;
use weglarka_core::config::HostConfig;
use weglarka_core::testing::FakePodman;
use weglarka_daemon::{Running, Settings, start};

const IMAGE: &str = "ghcr.io/jpalczewski/ntfy.zig:latest";

struct Harness {
    _dir: tempfile::TempDir,
    root: PathBuf,
    running: Running<FakePodman>,
}

async fn harness() -> Harness {
    // Short path: `sun_path` is limited to ~104 characters.
    let dir = tempfile::Builder::new()
        .prefix("wg")
        .tempdir_in("/tmp")
        .unwrap();
    let root = dir.path().to_owned();
    std::fs::write(root.join("traefik.yml"), "").unwrap();
    let host = HostConfig::from_toml_str(&format!(
        r#"
[ingress]
mode = "behind"
bind = "127.0.0.1:18080"
traefik_dynamic_file = "{root}/traefik.yml"

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
    let fake = FakePodman::new();
    let settings = Settings::from_host(host, root.join("weglarka.toml"));
    let running = start(settings, fake.clone()).await.unwrap();
    Harness {
        _dir: dir,
        root,
        running,
    }
}

async fn send<S>(stream: S, req: Request<Full<Bytes>>) -> (StatusCode, Bytes)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(conn);
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    (status, resp.into_body().collect().await.unwrap().to_bytes())
}

async fn admin(h: &Harness, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
    let stream = UnixStream::connect(&h.running.admin_socket).await.unwrap();
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "weglarka")
        .body(Full::new(Bytes::from(
            body.map(|b| b.to_string()).unwrap_or_default(),
        )))
        .unwrap();
    let (status, bytes) = send(stream, req).await;
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, value)
}

async fn eventually<F: Fn() -> Fut, Fut: Future<Output = bool>>(what: &str, f: F) {
    for _ in 0..100 {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for: {what}");
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

fn spec(domain: &str) -> Value {
    json!({
        "image": IMAGE,
        "domains": [domain],
        "port": 8085,
        "health": { "attempts": 1, "window_secs": 1 }
    })
}

/// A spec that binds `secret` as a mounted file (the app then waits until the value is set).
fn bound_spec(domain: &str, secret: &str) -> Value {
    let mut s = spec(domain);
    s["secrets"] = json!([{ "secret": secret, "kind": "mount", "path": "/config.json" }]);
    s
}

async fn add(h: &Harness, name: &str, spec: Value) {
    let (s, v) = admin(
        h,
        "POST",
        "/v1/apps",
        Some(json!({"name": name, "spec": spec})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

async fn set_secret(h: &Harness, app: &str, secret: &str) {
    let (s, v) = admin(
        h,
        "PUT",
        &format!("/v1/apps/{app}/secrets/{secret}"),
        Some(json!({"value": "{}"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
}

async fn show(h: &Harness, name: &str) -> Value {
    let (s, v) = admin(h, "GET", &format!("/v1/apps/{name}"), None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v
}

async fn deployed(h: &Harness, name: &str) {
    eventually("first deploy", || async {
        show(h, name).await["state"]["current"].is_string()
    })
    .await;
}

async fn doctor(h: &Harness) -> Value {
    let (s, v) = admin(h, "GET", "/v1/doctor", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v
}

fn check<'a>(report: &'a Value, id: &str) -> Option<&'a Value> {
    report["checks"].as_array()?.iter().find(|c| c["id"] == id)
}

fn store(h: &Harness) -> String {
    read(&h.root.join("state/secrets.toml"))
}

#[tokio::test]
async fn remove_secret_is_409_while_bound_204_with_force_and_404_400_otherwise() {
    let h = harness().await;
    add(&h, "ntfy", bound_spec("nz.example.eu", "config")).await;
    set_secret(&h, "ntfy", "config").await;
    deployed(&h, "ntfy").await;

    // (a) The spec still binds it: 409 and nothing is deleted.
    let (s, v) = admin(&h, "DELETE", "/v1/apps/ntfy/secrets/config", None).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::CONFLICT, Some("conflict")),
        "{v}"
    );
    assert!(
        v["message"].as_str().unwrap_or_default().contains("force"),
        "{v}"
    );
    let (_, list) = admin(&h, "GET", "/v1/apps/ntfy/secrets", None).await;
    assert_eq!(list["secrets"][0]["name"], "config", "{list}");

    // (c) An unknown secret is a 404.
    let (s, v) = admin(&h, "DELETE", "/v1/apps/ntfy/secrets/ghost", None).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("not_found")),
        "{v}"
    );

    // (d) A malformed secret name is a 400 before the store is touched.
    let (s, v) = admin(&h, "DELETE", "/v1/apps/ntfy/secrets/bad.name", None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert!(
        v["message"]
            .as_str()
            .unwrap_or_default()
            .contains("secret name must match"),
        "{v}"
    );
    assert!(store(&h).contains("ntfy.config"));

    // (b) `?force=true` removes the bound secret: the list is empty and the app waits for it again.
    // The removal never deploys, so the running container keeps the materialized value (ADR 0022);
    // the wait is recorded in the state and blocks the next recreate.
    let (s, v) = admin(
        &h,
        "DELETE",
        "/v1/apps/ntfy/secrets/config?force=true",
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{v}");
    let (_, list) = admin(&h, "GET", "/v1/apps/ntfy/secrets", None).await;
    assert!(
        list["secrets"].as_array().is_some_and(Vec::is_empty),
        "{list}"
    );
    assert!(!store(&h).contains("ntfy.config"));
    eventually("the app waits for the removed secret", || async {
        show(&h, "ntfy").await["state"]["waiting_for_secrets"] == json!(["config"])
    })
    .await;
    assert_eq!(show(&h, "ntfy").await["runtime"], "running");
    h.running.stop().await;
}

#[tokio::test]
async fn secret_of_a_removed_app_outlives_remove_and_is_cleaned_up_by_the_endpoint() {
    let h = harness().await;
    add(&h, "gone", bound_spec("gone.example.eu", "old")).await;
    set_secret(&h, "gone", "old").await;
    deployed(&h, "gone").await;

    // `apps remove` without `--purge-secrets` keeps the credentials: data survives `add` too.
    let (s, v) = admin(&h, "DELETE", "/v1/apps/gone", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{v}");
    assert!(store(&h).contains("gone.old"), "{}", store(&h));

    // The endpoint works for an app absent from apps.toml — the reason it exists (issue #80).
    let (s, v) = admin(&h, "DELETE", "/v1/apps/gone/secrets/old", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{v}");
    assert!(!store(&h).contains("gone.old"), "{}", store(&h));
    h.running.stop().await;
}

#[tokio::test]
async fn purge_secrets_removes_the_whole_scope_and_keeps_other_apps_alone() {
    let h = harness().await;
    add(&h, "x", bound_spec("x.example.eu", "config")).await;
    add(&h, "other", bound_spec("other.example.eu", "token")).await;
    set_secret(&h, "x", "config").await;
    // An unbound leftover of the same scope: a purge is about `<app>.*`, not about bound names.
    set_secret(&h, "x", "residue").await;
    set_secret(&h, "other", "token").await;
    deployed(&h, "x").await;

    let (s, v) = admin(&h, "DELETE", "/v1/apps/x?purge_secrets=true", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{v}");
    let contents = store(&h);
    assert!(!contents.contains("x.config"), "{contents}");
    assert!(!contents.contains("x.residue"), "{contents}");
    assert!(contents.contains("other.token"), "{contents}");

    // Re-adding the app with the same binding finds no value: it waits until the secret is set.
    add(&h, "x", bound_spec("x.example.eu", "config")).await;
    eventually("the re-added app waits for the purged secret", || async {
        show(&h, "x").await["state"]["waiting_for_secrets"] == json!(["config"])
    })
    .await;
    assert_eq!(show(&h, "x").await["runtime"], "waiting_for_secret");
    set_secret(&h, "x", "config").await;
    deployed(&h, "x").await;
    let v = show(&h, "x").await;
    assert_eq!(v["runtime"], "running", "{v}");
    assert!(v["state"].get("waiting_for_secrets").is_none(), "{v}");
    h.running.stop().await;
}

#[tokio::test]
async fn doctor_warns_about_orphan_secrets_until_the_scope_is_purged() {
    let h = harness().await;
    add(&h, "x", bound_spec("x.example.eu", "config")).await;
    set_secret(&h, "x", "config").await;
    deployed(&h, "x").await;

    // An app that is still in apps.toml is not an orphan.
    assert!(check(&doctor(&h).await, "state.orphan_secrets").is_none());

    // `apps remove` without `--purge-secrets` leaves `<app>.*` behind: doctor warns (not fails).
    let (s, _) = admin(&h, "DELETE", "/v1/apps/x", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let report = doctor(&h).await;
    let warning = check(&report, "state.orphan_secrets").expect("no state.orphan_secrets check");
    assert_eq!(warning["status"], "warn", "{warning}");
    let message = warning["message"].as_str().unwrap_or_default();
    assert!(message.contains("x (config)"), "{message}");
    assert!(!warning["hint"].is_null(), "{warning}");
    let hint = warning["hint"].as_str().unwrap_or_default();
    assert!(hint.contains("secrets remove"), "{hint}");
    assert!(hint.contains("--purge-secrets"), "{hint}");

    // Purging the scope on the next removal (`apps remove --purge-secrets`) clears the warning.
    add(&h, "x", bound_spec("x.example.eu", "config")).await;
    let (s, _) = admin(&h, "DELETE", "/v1/apps/x?purge_secrets=true", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    eventually("no orphan check after the purge", || async {
        check(&doctor(&h).await, "state.orphan_secrets").is_none()
    })
    .await;
    h.running.stop().await;
}
