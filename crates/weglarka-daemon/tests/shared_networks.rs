//! Shared-network API (issue #128, `docs/decisions/0030-shared-networks.md`) on `FakePodman`, over
//! the real admin socket: declarations (`/v1/networks`), membership through the app spec, the
//! in-use guard on removal and the doctor check.

use std::collections::BTreeMap;
use std::path::PathBuf;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::net::UnixStream;
use weglarka_core::app::{AppsFile, SharedNetworkName};
use weglarka_core::config::HostConfig;
use weglarka_core::labels;
use weglarka_core::podman::{NetworkSpec, PodmanClient};
use weglarka_core::state;
use weglarka_core::testing::FakePodman;
use weglarka_daemon::{Running, Settings, start};

const IMAGE: &str = "ghcr.io/jpalczewski/ntfy.zig:latest";
/// Declared name of the group used by the tests.
const GROUP: &str = "kajet";
/// Its Podman network name ([`labels::shared_network_name`]).
const PODMAN_GROUP: &str = "net-shared-kajet";

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
    let root: PathBuf = dir.path().to_owned();
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

/// Raw admin call: returns the status and the body bytes (tars, error messages).
async fn raw(h: &Harness, method: &str, path: &str, body: Vec<u8>) -> (StatusCode, Bytes) {
    let stream = UnixStream::connect(&h.running.admin_socket).await.unwrap();
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "weglarka")
        .body(Full::new(Bytes::from(body)))
        .unwrap();
    send(stream, req).await
}

fn apps_file(h: &Harness) -> AppsFile {
    state::load_apps(&h.root.join("state/apps.toml")).unwrap()
}

fn member_spec(network: &str, aliases: &[&str]) -> Value {
    json!({
        "image": IMAGE,
        "health": { "attempts": 1, "window_secs": 1 },
        "shared_networks": [{ "name": network, "aliases": aliases }]
    })
}

async fn declare(h: &Harness, name: &str) {
    let (status, _) = admin(h, "PUT", &format!("/v1/networks/{name}"), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "declare {name}");
}

async fn add(h: &Harness, name: &str, spec: Value) -> (StatusCode, Value) {
    admin(
        h,
        "POST",
        "/v1/apps",
        Some(json!({ "name": name, "spec": spec })),
    )
    .await
}

fn doctor_check(report: &Value) -> &Value {
    report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "state.shared_networks")
        .expect("state.shared_networks check exists")
}

#[tokio::test]
async fn declare_is_idempotent_and_listed_without_members() {
    let h = harness().await;
    declare(&h, GROUP).await;
    declare(&h, GROUP).await; // idempotent: no error, no duplicate

    let (status, list) = admin(&h, "GET", "/v1/networks", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        list,
        json!({"networks": [{
            "name": GROUP,
            "podman_name": PODMAN_GROUP,
            "members": [],
            "exists": false,
        }]})
    );
    assert!(
        apps_file(&h)
            .shared_networks
            .contains_key(&SharedNetworkName::new(GROUP).unwrap())
    );

    // The path segment must be a valid shared-network name.
    let (status, _) = raw(&h, "PUT", "/v1/networks/Bad_Name", vec![]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    h.running.stop().await;
}

#[tokio::test]
async fn adding_a_member_creates_the_network_lazily_and_lists_it() {
    let h = harness().await;
    declare(&h, GROUP).await;
    let (status, body) = add(&h, "kajet-api", member_spec(GROUP, &[])).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = add(&h, "kajet-proxy", member_spec(GROUP, &["gateway"])).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    assert!(h.fake.networks().contains(&PODMAN_GROUP.to_owned()));
    let spec = h.fake.network_spec(PODMAN_GROUP).unwrap();
    assert!(spec.internal);
    let proxy = h.fake.container_spec("kajet-proxy").unwrap();
    assert_eq!(
        proxy.network_aliases,
        BTreeMap::from([(PODMAN_GROUP.to_owned(), vec!["gateway".to_owned()])])
    );

    let (_, list) = admin(&h, "GET", "/v1/networks", None).await;
    assert_eq!(
        list["networks"][0]["members"],
        json!(["kajet-api", "kajet-proxy"])
    );
    assert_eq!(list["networks"][0]["exists"], true);
    h.running.stop().await;
}

#[tokio::test]
async fn an_undeclared_network_is_rejected_and_nothing_is_written() {
    let h = harness().await;
    let (status, body) = add(&h, "kajet-api", member_spec("nope", &[])).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("undeclared shared network"),
        "{body}"
    );
    assert!(apps_file(&h).apps.is_empty());

    // An alias that another member already answers to is refused as well.
    declare(&h, GROUP).await;
    let (status, _) = add(&h, "a", member_spec(GROUP, &["web"])).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = add(&h, "b", member_spec(GROUP, &["web"])).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    h.running.stop().await;
}

#[tokio::test]
async fn removal_is_refused_while_members_exist() {
    let h = harness().await;
    declare(&h, GROUP).await;
    let (status, _) = add(&h, "kajet-api", member_spec(GROUP, &[])).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = raw(&h, "DELETE", &format!("/v1/networks/{GROUP}"), vec![]).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(String::from_utf8_lossy(&body).contains("kajet-api"));
    assert!(
        apps_file(&h)
            .shared_networks
            .contains_key(&SharedNetworkName::new(GROUP).unwrap()),
        "nothing was removed"
    );

    // Unknown declarations are a 404.
    let (status, _) = raw(&h, "DELETE", "/v1/networks/ghost", vec![]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Once the member is gone the declaration can be removed.
    let (status, _) = raw(&h, "DELETE", "/v1/apps/kajet-api", vec![]).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = raw(&h, "DELETE", &format!("/v1/networks/{GROUP}"), vec![]).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    h.running.stop().await;
}

#[tokio::test]
async fn doctor_reports_an_undeclared_group_network_and_an_empty_group() {
    let h = harness().await;
    declare(&h, "unused").await;
    // Created after the declaration's reconcile pass: reconcile removes an undeclared, empty group
    // network by itself, so the doctor only ever sees one that is still held by a container.
    h.fake
        .network_create(&NetworkSpec {
            name: "net-shared-ghost".to_owned(),
            internal: true,
            labels: BTreeMap::from([(labels::SHARED_NETWORK.to_owned(), "ghost".to_owned())]),
        })
        .await
        .unwrap();

    let (status, report) = admin(&h, "GET", "/v1/doctor", None).await;
    assert_eq!(status, StatusCode::OK);
    let check = doctor_check(&report);
    assert_eq!(check["status"], "warn");
    let message = check["message"].as_str().unwrap();
    assert!(message.contains("net-shared-ghost"), "{message}");
    assert!(
        message.contains("shared network unused has no members"),
        "{message}"
    );
    h.running.stop().await;
}

#[tokio::test]
async fn doctor_is_quiet_for_a_consistent_group() {
    let h = harness().await;
    declare(&h, GROUP).await;
    let (status, _) = add(&h, "kajet-api", member_spec(GROUP, &[])).await;
    assert_eq!(status, StatusCode::OK);
    let (_, report) = admin(&h, "GET", "/v1/doctor", None).await;
    let check = doctor_check(&report);
    assert_eq!(check["status"], "ok", "{check}");
    h.running.stop().await;
}
