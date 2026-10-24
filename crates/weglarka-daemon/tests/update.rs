//! `apps update` and "waiting for secret" through the admin API (real unix socket, FakePodman).

use std::path::{Path, PathBuf};
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::net::UnixStream;
use weglarka_core::config::HostConfig;
use weglarka_core::podman::ContainerState;
use weglarka_core::testing::{Call, FakePodman};
use weglarka_daemon::{Running, Settings, start};

const IMAGE: &str = "ghcr.io/jpalczewski/ntfy.zig:latest";

struct Harness {
    _dir: tempfile::TempDir,
    root: PathBuf,
    fake: FakePodman,
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
        fake,
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

fn creates_of(fake: &FakePodman, container: &str) -> usize {
    fake.calls()
        .iter()
        .filter(|c| matches!(c, Call::ContainerCreate(n) if n == container))
        .count()
}

#[tokio::test]
async fn update_validates_like_add_and_404s_for_unknown_apps() {
    let h = harness().await;
    let body = |spec: Value| Some(json!({ "spec": spec }));

    let (s, v) = admin(&h, "PUT", "/v1/apps/ghost", body(spec("a.example.eu"))).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::NOT_FOUND, Some("not_found"))
    );

    add(&h, "ntfy", spec("nz.example.eu")).await;
    add(&h, "other", spec("other.example.eu")).await;
    deployed(&h, "ntfy").await;

    // Domain taken by another app, invalid spec, malformed body, bad name.
    let (s, _) = admin(&h, "PUT", "/v1/apps/ntfy", body(spec("other.example.eu"))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = admin(
        &h,
        "PUT",
        "/v1/apps/ntfy",
        body(json!({"image": "has space"})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = admin(
        &h,
        "PUT",
        "/v1/apps/ntfy",
        body(json!({"image": IMAGE, "bogus": 1})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = admin(&h, "PUT", "/v1/apps/Bad_Name", body(spec("x.example.eu"))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    // Nothing was changed by the rejected requests.
    assert_eq!(
        show(&h, "ntfy").await["spec"]["domains"],
        json!(["nz.example.eu"])
    );
    h.running.stop().await;
}

#[tokio::test]
async fn domain_change_touches_only_ingress_and_env_change_recreates() {
    let h = harness().await;
    add(&h, "ntfy", spec("nz.example.eu")).await;
    deployed(&h, "ntfy").await;
    eventually("ingress for the old domain", || async {
        read(&h.root.join("state/nginx/nginx.conf")).contains("nz.example.eu")
    })
    .await;
    let before = show(&h, "ntfy").await;
    let creates = creates_of(&h.fake, "ntfy");

    // Domain only: the full spec is replaced, ingress follows, the container is not recreated.
    let (s, v) = admin(
        &h,
        "PUT",
        "/v1/apps/ntfy",
        Some(json!({"spec": spec("new.example.eu")})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["app"]["spec"]["domains"], json!(["new.example.eu"]));
    assert!(v["deploy"].is_null(), "{v}");
    eventually("ingress switched to the new domain", || async {
        let conf = read(&h.root.join("state/nginx/nginx.conf"));
        conf.contains("new.example.eu") && !conf.contains("nz.example.eu")
    })
    .await;
    assert!(read(&h.root.join("traefik.yml")).contains("new.example.eu"));
    // Let any reconcile pass triggered by the update finish before looking at the container.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let after = show(&h, "ntfy").await;
    assert_eq!(after["state"]["generation"], before["state"]["generation"]);
    assert_eq!(after["state"]["spec_hash"], before["state"]["spec_hash"]);
    assert_eq!(creates_of(&h.fake, "ntfy"), creates);

    // An env change alters the spec-hash: the container is recreated from the pinned digest.
    let mut with_env = spec("new.example.eu");
    with_env["env"] = json!({"TZ": "Europe/Warsaw"});
    let (s, v) = admin(&h, "PUT", "/v1/apps/ntfy", Some(json!({"spec": with_env}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["deploy"].is_null(), "{v}");
    eventually("recreate", || async {
        show(&h, "ntfy").await["state"]["generation"] == json!(2)
    })
    .await;
    assert_eq!(
        show(&h, "ntfy").await["state"]["current"],
        before["state"]["current"]
    );
    h.running.stop().await;
}

#[tokio::test]
async fn max_body_size_change_touches_only_ingress_and_reloads_nginx() {
    let h = harness().await;
    add(&h, "ntfy", spec("nz.example.eu")).await;
    deployed(&h, "ntfy").await;
    let conf = || read(&h.root.join("state/nginx/nginx.conf"));
    eventually("nginx config for the app", || async {
        conf().contains("nz.example.eu")
    })
    .await;
    let before = show(&h, "ntfy").await;
    let creates = creates_of(&h.fake, "ntfy");
    let reloads = |fake: &FakePodman| {
        fake.calls()
            .iter()
            .filter(|c| matches!(c, Call::ContainerKill { signal, .. } if signal == "HUP"))
            .count()
    };
    let reloads_before = reloads(&h.fake);

    // `ingress.max_body_size` (ADR 0033) is routing-only: nginx is reloaded, nothing else happens.
    let mut big = spec("nz.example.eu");
    big["ingress"] = json!({ "max_body_size": "4g" });
    let (s, v) = admin(&h, "PUT", "/v1/apps/ntfy", Some(json!({ "spec": big }))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["deploy"].is_null(), "{v}");
    assert_eq!(
        v["app"]["spec"]["ingress"],
        json!({ "streaming": false, "max_body_size": "4g" })
    );
    eventually("nginx config with the per-app limit", || async {
        conf().contains("client_max_body_size 4294967296;")
    })
    .await;
    assert!(
        reloads(&h.fake) > reloads_before,
        "nginx was not reloaded: {:?}",
        h.fake.calls()
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    let after = show(&h, "ntfy").await;
    assert_eq!(after["state"]["generation"], before["state"]["generation"]);
    assert_eq!(after["state"]["spec_hash"], before["state"]["spec_hash"]);
    assert_eq!(creates_of(&h.fake, "ntfy"), creates);

    // A malformed size is refused before anything is saved.
    let mut bad = spec("nz.example.eu");
    bad["ingress"] = json!({ "max_body_size": "1.5g" });
    let (s, _) = admin(&h, "PUT", "/v1/apps/ntfy", Some(json!({ "spec": bad }))).await;
    assert!(s.is_client_error(), "{s}");
    h.running.stop().await;
}

#[tokio::test]
async fn streaming_change_touches_only_ingress_and_reloads_nginx() {
    let h = harness().await;
    add(&h, "ntfy", spec("nz.example.eu")).await;
    deployed(&h, "ntfy").await;
    let conf = || read(&h.root.join("state/nginx/nginx.conf"));
    eventually("nginx config for the app", || async {
        conf().contains("nz.example.eu")
    })
    .await;
    let traefik_before = read(&h.root.join("traefik.yml"));
    let before = show(&h, "ntfy").await;
    let creates = creates_of(&h.fake, "ntfy");
    let reloads = |fake: &FakePodman| {
        fake.calls()
            .iter()
            .filter(|c| matches!(c, Call::ContainerKill { signal, .. } if signal == "HUP"))
            .count()
    };
    let reloads_before = reloads(&h.fake);

    // `ingress.streaming` is a routing-only setting: nginx is reloaded, nothing else happens.
    let mut streaming = spec("nz.example.eu");
    streaming["ingress"] = json!({ "streaming": true, "stream_timeout_secs": 300 });
    let (s, v) = admin(
        &h,
        "PUT",
        "/v1/apps/ntfy",
        Some(json!({ "spec": streaming })),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["deploy"].is_null(), "{v}");
    assert_eq!(
        v["app"]["spec"]["ingress"],
        json!({ "streaming": true, "stream_timeout_secs": 300 })
    );
    eventually("nginx config without buffering", || async {
        let c = conf();
        c.contains("proxy_buffering off;") && c.contains("proxy_read_timeout 300s;")
    })
    .await;
    // The config was applied with a reload (SIGHUP), not by recreating anything.
    assert!(
        reloads(&h.fake) > reloads_before,
        "nginx was not reloaded: {:?}",
        h.fake.calls()
    );
    // The Traefik file carries routers only, so streaming does not change it.
    assert_eq!(read(&h.root.join("traefik.yml")), traefik_before);
    // Let any reconcile pass triggered by the update finish before looking at the container.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let after = show(&h, "ntfy").await;
    assert_eq!(after["state"]["generation"], before["state"]["generation"]);
    assert_eq!(after["state"]["spec_hash"], before["state"]["spec_hash"]);
    assert_eq!(creates_of(&h.fake, "ntfy"), creates);

    // Turning it off removes the directives again, still without touching the container.
    let (s, v) = admin(
        &h,
        "PUT",
        "/v1/apps/ntfy",
        Some(json!({ "spec": spec("nz.example.eu") })),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    eventually("nginx config back to the defaults", || async {
        !conf().contains("proxy_buffering")
    })
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        show(&h, "ntfy").await["state"]["generation"],
        before["state"]["generation"]
    );
    assert_eq!(creates_of(&h.fake, "ntfy"), creates);

    // A timeout without `streaming` is a silent no-op, so the API refuses it before saving.
    let mut bad = spec("nz.example.eu");
    bad["ingress"] = json!({ "stream_timeout_secs": 600 });
    let (s, v) = admin(&h, "PUT", "/v1/apps/ntfy", Some(json!({ "spec": bad }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert!(
        v["message"]
            .as_str()
            .unwrap_or_default()
            .contains("ingress.streaming"),
        "{v}"
    );
    // A malformed timeout is refused as well.
    let mut too_long = spec("nz.example.eu");
    too_long["ingress"] = json!({ "streaming": true, "stream_timeout_secs": 7200 });
    let (s, v) = admin(
        &h,
        "PUT",
        "/v1/apps/ntfy",
        Some(json!({ "spec": too_long })),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    // Neither rejection changed the stored spec.
    assert!(show(&h, "ntfy").await["spec"].get("ingress").is_none());
    h.running.stop().await;
}

#[tokio::test]
async fn image_change_deploys_right_away() {
    let h = harness().await;
    add(&h, "ntfy", spec("nz.example.eu")).await;
    deployed(&h, "ntfy").await;

    let mut pinned = spec("nz.example.eu");
    pinned["image"] = json!("ghcr.io/jpalczewski/ntfy.zig:v1.2.3");
    let (s, v) = admin(&h, "PUT", "/v1/apps/ntfy", Some(json!({"spec": pinned}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(
        matches!(
            v["deploy"]["outcome"].as_str(),
            Some("deployed" | "unchanged")
        ),
        "{v}"
    );
    assert!(h.fake.calls().contains(&Call::ImagePull(
        "ghcr.io/jpalczewski/ntfy.zig:v1.2.3".into()
    )));
    h.running.stop().await;
}

#[tokio::test]
async fn stop_provisions_and_start_deploys_synchronously() {
    let h = harness().await;
    add(&h, "ntfy", spec("nz.example.eu")).await;
    deployed(&h, "ntfy").await;
    let digest = show(&h, "ntfy").await["state"]["current"].clone();
    assert_eq!(show(&h, "ntfy").await["runtime"], "running");

    // `apps stop`: PUT with `start = false` — provision (keep the pinned digest) and remove the
    // container right away; the response carries the outcome.
    let mut stopped = spec("nz.example.eu");
    stopped["start"] = json!(false);
    let (s, v) = admin(&h, "PUT", "/v1/apps/ntfy", Some(json!({"spec": stopped}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["deploy"]["outcome"], "provisioned");
    assert_eq!(v["deploy"]["digest"], digest);
    assert_eq!(v["app"]["runtime"], "not_started");
    assert_eq!(v["app"]["state"]["current"], digest);
    assert!(h.fake.containers().iter().all(|c| c.name != "ntfy"));
    assert_eq!(show(&h, "ntfy").await["runtime"], "not_started");

    // A wake from the update must not bring the container back.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(h.fake.containers().iter().all(|c| c.name != "ntfy"));

    // `apps start`: PUT with `start = true` — deploy right away, the container runs.
    let (s, v) = admin(
        &h,
        "PUT",
        "/v1/apps/ntfy",
        Some(json!({"spec": spec("nz.example.eu")})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["deploy"]["outcome"], "deployed");
    assert_eq!(v["app"]["runtime"], "running");
    assert!(
        h.fake
            .containers()
            .iter()
            .any(|c| c.name == "ntfy" && c.state == ContainerState::Running)
    );
    h.running.stop().await;
}

#[tokio::test]
async fn missing_secret_is_a_waiting_state_not_a_failure() {
    let h = harness().await;
    let mut with_secret = spec("nz.example.eu");
    with_secret["secrets"] = json!([{"secret": "config", "kind": "mount", "path": "/config.json"}]);
    add(&h, "ntfy", with_secret).await;

    eventually("waiting recorded", || async {
        show(&h, "ntfy").await["state"]["waiting_for_secrets"] == json!(["config"])
    })
    .await;
    let v = show(&h, "ntfy").await;
    assert_eq!(v["runtime"], "waiting_for_secret");
    assert!(v["state"]["failed"].is_null(), "{v}");
    let (_, list) = admin(&h, "GET", "/v1/apps", None).await;
    assert_eq!(list["apps"][0]["runtime"], "waiting_for_secret");
    assert!(h.fake.containers().iter().all(|c| c.name != "ntfy"));
    assert!(
        !h.fake
            .calls()
            .iter()
            .any(|c| matches!(c, Call::ImagePull(r) if r == IMAGE))
    );

    // Doctor: a warning with the exact command.
    let (_, doctor) = admin(&h, "GET", "/v1/doctor", None).await;
    let check = doctor["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "state.waiting_for_secrets")
        .unwrap();
    assert_eq!(check["status"], "warn");
    assert!(
        check["hint"]
            .as_str()
            .unwrap()
            .contains("weglarka secrets set ntfy config")
    );

    // A manual deploy says what is missing instead of failing mysteriously.
    let (s, v) = admin(&h, "POST", "/v1/apps/ntfy/deploy", Some(json!({}))).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::CONFLICT, Some("conflict"))
    );
    assert!(v["message"].as_str().unwrap().contains("config"));

    // Setting the secret ends the wait and the app comes up by itself.
    let (s, _) = admin(
        &h,
        "PUT",
        "/v1/apps/ntfy/secrets/config",
        Some(json!({"value": "{}"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    deployed(&h, "ntfy").await;
    let v = show(&h, "ntfy").await;
    assert_eq!(v["runtime"], "running");
    assert!(v["state"].get("waiting_for_secrets").is_none(), "{v}");
    h.running.stop().await;
}

#[tokio::test]
async fn paths_share_a_domain_reload_nginx_and_never_touch_containers() {
    let h = harness().await;
    let with_paths = |paths: Value| {
        let mut s = spec("app.example.eu");
        s["paths"] = paths;
        s
    };
    add(&h, "api", with_paths(json!(["/api"]))).await;
    deployed(&h, "api").await;
    let conf = || read(&h.root.join("state/nginx/nginx.conf"));
    eventually("nginx config for the first path", || async {
        conf().contains("location ^~ /api/ {")
    })
    .await;

    // A second instance on the same domain with a disjoint prefix is accepted and routed.
    add(&h, "mcp", with_paths(json!(["/mcp"]))).await;
    deployed(&h, "mcp").await;
    eventually("both paths in one server", || async {
        let c = conf();
        c.contains("location ^~ /mcp/ {") && c.contains("http://api:8085")
    })
    .await;

    // An overlapping prefix is refused with a message naming the conflict, and nothing is saved.
    for clash in [json!(["/api"]), json!(["/api/v2"])] {
        let (s, v) = admin(
            &h,
            "PUT",
            "/v1/apps/mcp",
            Some(json!({ "spec": with_paths(clash) })),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
        assert!(
            v["message"]
                .as_str()
                .unwrap_or_default()
                .contains("overlap"),
            "{v}"
        );
    }
    // The catch-all coexists with prefixes; a second one is the old "domain taken" refusal.
    add(&h, "spa", spec("app.example.eu")).await;
    let (s, _) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(json!({"name": "spa2", "spec": spec("app.example.eu")})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(show(&h, "mcp").await["spec"]["paths"], json!(["/mcp"]));

    // Changing paths re-renders nginx only: same generation, same container.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let before = show(&h, "mcp").await;
    let creates = creates_of(&h.fake, "mcp");
    let (s, v) = admin(
        &h,
        "PUT",
        "/v1/apps/mcp",
        Some(json!({ "spec": with_paths(json!(["/mcp", "/.well-known"])) })),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["deploy"].is_null(), "{v}");
    eventually("the added prefix in nginx", || async {
        conf().contains("location ^~ /.well-known/ {")
    })
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let after = show(&h, "mcp").await;
    assert_eq!(after["state"]["generation"], before["state"]["generation"]);
    assert_eq!(after["state"]["spec_hash"], before["state"]["spec_hash"]);
    assert_eq!(creates_of(&h.fake, "mcp"), creates);
    h.running.stop().await;
}
