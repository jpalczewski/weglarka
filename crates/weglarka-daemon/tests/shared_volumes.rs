//! Shared-volume API (issue #33, `docs/decisions/0017-shared-volumes.md`) on `FakePodman`, over the
//! real admin socket: declarations (`/v1/volumes`), member mounts, the purge/range-change guards and
//! import/export through the app's volume endpoints.

use std::collections::BTreeMap;
use std::path::PathBuf;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::net::UnixStream;
use weglarka_core::app::{AppsFile, InstanceName, SharedVolumeName};
use weglarka_core::config::HostConfig;
use weglarka_core::labels;
use weglarka_core::podman::{ContainerState, PodmanClient, VolumeSpec};
use weglarka_core::state::{self, StateFile};
use weglarka_core::testing::{Call, FakePodman};
use weglarka_daemon::{Running, Settings, start};

const IMAGE: &str = "ghcr.io/jpalczewski/ntfy.zig:latest";
/// Declared name of the group used by the tests.
const GROUP: &str = "kajet-data";
/// Its Podman volume name ([`labels::shared_volume_name`]).
const PODMAN_GROUP: &str = "wg-shared-kajet-data";

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

fn instance(s: &str) -> InstanceName {
    InstanceName::new(s).unwrap()
}

fn shared(s: &str) -> SharedVolumeName {
    SharedVolumeName::new(s).unwrap()
}

fn state_file(h: &Harness) -> StateFile {
    state::load_state(&h.root.join("state/state.toml")).unwrap()
}

fn apps_file(h: &Harness) -> AppsFile {
    state::load_apps(&h.root.join("state/apps.toml")).unwrap()
}

/// A member of the shared-volume group. `start = false` provisions (range + volume, no container).
fn member_spec(volume: &str, start: bool) -> Value {
    json!({
        "image": IMAGE,
        "start": start,
        "health": { "attempts": 1, "window_secs": 1 },
        "shared_volumes": [{ "name": volume, "target": "/data" }]
    })
}

async fn declare(h: &Harness, name: &str) {
    let (status, _) = admin(h, "PUT", &format!("/v1/volumes/{name}"), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT, "declare {name}");
}

async fn add(h: &Harness, name: &str, spec: Value) {
    let (status, body) = admin(
        h,
        "POST",
        "/v1/apps",
        Some(json!({ "name": name, "spec": spec })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "add {name}: {body}");
}

async fn deploy(h: &Harness, name: &str) {
    let (status, body) = admin(
        h,
        "POST",
        &format!("/v1/apps/{name}/deploy"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "deploy {name}: {body}");
}

fn error_message(body: &Bytes) -> String {
    let value: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    value["message"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| String::from_utf8_lossy(body).into_owned())
}

#[tokio::test]
async fn declare_is_idempotent_and_listed_without_members() {
    let h = harness().await;
    declare(&h, GROUP).await;
    declare(&h, GROUP).await; // idempotent: no error, no duplicate

    let (status, list) = admin(&h, "GET", "/v1/volumes", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        list,
        json!({"volumes": [{
            "name": GROUP,
            "podman_name": PODMAN_GROUP,
            "members": [],
            "exists": false,
        }]}),
        "uid_range is omitted until the first member's deploy"
    );
    assert!(apps_file(&h).shared_volumes.contains_key(&shared(GROUP)));

    // The path segment must be a valid shared-volume name.
    let (status, _) = raw(&h, "PUT", "/v1/volumes/Bad_Name", vec![]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    h.running.stop().await;
}

#[tokio::test]
async fn member_provisioning_allocates_the_group_range_and_creates_the_volume() {
    let h = harness().await;
    declare(&h, GROUP).await;
    add(&h, "kajet-api", member_spec(GROUP, false)).await;

    let (status, list) = admin(&h, "GET", "/v1/volumes", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list["volumes"][0]["members"], json!(["kajet-api"]));
    assert_eq!(list["volumes"][0]["exists"], true);
    assert!(
        list["volumes"][0]["uid_range"].is_object(),
        "provisioning allocates the range: {list}"
    );

    // The app's own volume list resolves the shared volume under its declared name.
    let (status, volumes) = admin(&h, "GET", "/v1/apps/kajet-api/volumes", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        volumes,
        json!({"volumes": [{
            "name": GROUP,
            "target": "/data",
            "podman_name": PODMAN_GROUP,
            "exists": true,
            "shared": true,
        }]})
    );

    // `start = false`: no container, but the range belongs to the volume, not to the instance.
    assert!(
        h.fake.containers().iter().all(|c| c.name != "kajet-api"),
        "provisioned only"
    );
    let st = state_file(&h);
    assert!(st.shared_volumes[&shared(GROUP)].uid_range.is_some());
    assert_eq!(
        st.apps
            .get(&instance("kajet-api"))
            .and_then(|a| a.uid_range),
        None,
        "members do not own a private range"
    );
    h.running.stop().await;
}

#[tokio::test]
async fn removing_a_declaration_a_member_mounts_is_a_conflict_and_touches_nothing() {
    let h = harness().await;
    declare(&h, GROUP).await;
    add(&h, "kajet-api", member_spec(GROUP, false)).await;

    let (status, body) = raw(&h, "DELETE", "/v1/volumes/kajet-data?purge=true", vec![]).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(error_message(&body).contains("kajet-api"), "{body:?}");

    // Nothing was touched: the declaration, the volume and the app are all still there.
    assert!(apps_file(&h).shared_volumes.contains_key(&shared(GROUP)));
    assert!(h.fake.volumes().iter().any(|v| v.name == PODMAN_GROUP));
    let (status, _) = admin(&h, "GET", "/v1/apps/kajet-api", None).await;
    assert_eq!(status, StatusCode::OK);
    h.running.stop().await;
}

#[tokio::test]
async fn purge_of_a_member_with_another_member_is_refused() {
    let h = harness().await;
    declare(&h, GROUP).await;
    add(&h, "kajet-api", member_spec(GROUP, false)).await;
    add(&h, "kajet-mcp", member_spec(GROUP, false)).await;

    let (status, body) = raw(
        &h,
        "DELETE",
        "/v1/apps/kajet-api?purge_volumes=true",
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let message = error_message(&body);
    assert!(message.contains("kajet-mcp"), "{message}");
    assert!(message.contains("still mounted"), "{message}");

    // Nothing was touched: both apps are desired and the group's data is untouched.
    assert_eq!(apps_file(&h).apps.len(), 2);
    assert!(h.fake.volumes().iter().any(|v| v.name == PODMAN_GROUP));
    h.running.stop().await;
}

#[tokio::test]
async fn purge_of_the_last_member_deletes_the_group_volume() {
    let h = harness().await;
    declare(&h, GROUP).await;
    add(&h, "kajet-api", member_spec(GROUP, false)).await;
    add(&h, "kajet-mcp", member_spec(GROUP, false)).await;

    // A plain remove keeps the data and the range (the group still has a member).
    let (status, _) = admin(&h, "DELETE", "/v1/apps/kajet-api", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(h.fake.volumes().iter().any(|v| v.name == PODMAN_GROUP));
    assert!(state_file(&h).shared_volumes.contains_key(&shared(GROUP)));

    // The last member's purge deletes the volume and releases the range; the declaration stays.
    let (status, _) = admin(&h, "DELETE", "/v1/apps/kajet-mcp?purge_volumes=true", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        h.fake.volumes().iter().all(|v| v.name != PODMAN_GROUP),
        "{:?}",
        h.fake.volumes()
    );
    assert!(state_file(&h).shared_volumes.is_empty(), "range released");
    assert!(
        apps_file(&h).shared_volumes.contains_key(&shared(GROUP)),
        "the declaration is desired state and stays"
    );
    h.running.stop().await;
}

#[tokio::test]
async fn remove_shared_volume_needs_purge_while_the_data_exists() {
    let h = harness().await;
    declare(&h, GROUP).await;
    add(&h, "kajet-api", member_spec(GROUP, false)).await;
    let (status, _) = admin(&h, "DELETE", "/v1/apps/kajet-api", None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(
        state_file(&h).shared_volumes.contains_key(&shared(GROUP)),
        "a plain remove keeps the group's data and range"
    );

    // Without `purge` the declaration cannot be dropped while the Podman volume holds data.
    let (status, body) = raw(&h, "DELETE", "/v1/volumes/kajet-data", vec![]).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(
        error_message(&body).contains("still holds data"),
        "{body:?}"
    );

    let (status, _) = raw(&h, "DELETE", "/v1/volumes/kajet-data?purge=true", vec![]).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(h.fake.volumes().iter().all(|v| v.name != PODMAN_GROUP));
    assert!(state_file(&h).shared_volumes.is_empty());
    assert!(!apps_file(&h).shared_volumes.contains_key(&shared(GROUP)));

    // The declaration is gone now.
    let (status, _) = raw(&h, "DELETE", "/v1/volumes/kajet-data?purge=true", vec![]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    h.running.stop().await;
}

#[tokio::test]
async fn update_that_would_change_the_range_with_private_data_is_refused() {
    let h = harness().await;
    // A deployed app with a private volume: it owns a range and the volume holds data.
    add(
        &h,
        "szklana",
        json!({
            "image": IMAGE,
            "health": { "attempts": 1, "window_secs": 1 },
            "volumes": [{ "name": "data", "target": "/data" }]
        }),
    )
    .await;
    deploy(&h, "szklana").await;
    let old_range = state_file(&h)
        .apps
        .get(&instance("szklana"))
        .and_then(|a| a.uid_range)
        .expect("deployed app owns a range");
    let old_label = labels::uid_range_label(old_range);

    // Joining the group would move the container into the group's range.
    declare(&h, GROUP).await;
    let joining = json!({
        "image": IMAGE,
        "health": { "attempts": 1, "window_secs": 1 },
        "volumes": [{ "name": "data", "target": "/data" }],
        "shared_volumes": [{ "name": GROUP, "target": "/group" }]
    });
    let (status, body) = admin(
        &h,
        "PUT",
        "/v1/apps/szklana",
        Some(json!({ "spec": joining })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let message = body["message"].as_str().unwrap_or_default().to_owned();
    assert!(message.contains("uid range"), "{message}");
    assert!(message.contains("export the data"), "{message}");

    // Nothing was persisted and the old container still runs in its range.
    assert!(
        apps_file(&h)
            .apps
            .get(&instance("szklana"))
            .is_some_and(|s| s.shared_volumes.is_empty())
    );
    let container = h
        .fake
        .containers()
        .into_iter()
        .find(|c| c.name == "szklana")
        .expect("old container survives the refused update");
    assert_eq!(container.state, ContainerState::Running);
    assert_eq!(
        container.labels.get(labels::UID_RANGE),
        Some(&old_label),
        "the old container keeps its map"
    );
    assert_eq!(
        state_file(&h)
            .apps
            .get(&instance("szklana"))
            .and_then(|a| a.uid_range),
        Some(old_range)
    );
    h.running.stop().await;
}

#[tokio::test]
async fn joining_a_group_after_stopping_the_app_is_refused() {
    let h = harness().await;
    // A deployed app with a private volume: it owns a range and the volume holds data.
    let spec = json!({
        "image": IMAGE,
        "health": { "attempts": 1, "window_secs": 1 },
        "volumes": [{ "name": "data", "target": "/data" }]
    });
    add(&h, "szklana", spec.clone()).await;
    deploy(&h, "szklana").await;
    let old_range = state_file(&h)
        .apps
        .get(&instance("szklana"))
        .and_then(|a| a.uid_range)
        .expect("deployed app owns a range");

    // `apps stop`: provision only — the container goes away, the private volume and range stay.
    let mut stopped = spec.clone();
    stopped["start"] = json!(false);
    let (status, body) = admin(
        &h,
        "PUT",
        "/v1/apps/szklana",
        Some(json!({ "spec": stopped })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        h.fake.containers().iter().all(|c| c.name != "szklana"),
        "provisioning removes the container"
    );

    // Joining the group would move the app into the group's range; the data owner is in state.
    declare(&h, GROUP).await;
    let mut joining = spec.clone();
    joining["shared_volumes"] = json!([{ "name": GROUP, "target": "/group" }]);
    let (status, body) = admin(
        &h,
        "PUT",
        "/v1/apps/szklana",
        Some(json!({ "spec": joining })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let message = body["message"].as_str().unwrap_or_default().to_owned();
    assert!(message.contains("uid range"), "{message}");

    // Nothing was persisted and nothing started.
    assert!(
        apps_file(&h)
            .apps
            .get(&instance("szklana"))
            .is_some_and(|s| s.shared_volumes.is_empty())
    );
    assert_eq!(
        state_file(&h)
            .apps
            .get(&instance("szklana"))
            .and_then(|a| a.uid_range),
        Some(old_range)
    );
    assert!(h.fake.containers().is_empty(), "nothing was started");
    h.running.stop().await;
}

#[tokio::test]
async fn mounting_an_undeclared_shared_volume_is_a_bad_request() {
    let h = harness().await;
    let (status, body) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(json!({ "name": "kajet-api", "spec": member_spec("ghost", false) })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let message = body["message"].as_str().unwrap_or_default().to_owned();
    assert!(message.contains("undeclared shared volume"), "{message}");
    assert!(message.contains("weglarka volumes add ghost"), "{message}");
    assert!(apps_file(&h).apps.is_empty(), "nothing was persisted");

    // The same rule on update: a declared mount is fine, an undeclared one is rejected.
    declare(&h, GROUP).await;
    add(&h, "kajet-api", member_spec(GROUP, false)).await;
    let (status, body) = admin(
        &h,
        "PUT",
        "/v1/apps/kajet-api",
        Some(json!({ "spec": member_spec("ghost", false) })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("ghost")
    );
    assert!(
        apps_file(&h).apps.get(&instance("kajet-api")).is_some_and(
            |s| s.shared_volumes.len() == 1 && s.shared_volumes[0].name.as_str() == GROUP
        ),
        "the previous spec stays"
    );
    h.running.stop().await;
}

#[tokio::test]
async fn import_into_a_shared_volume_is_refused_while_another_member_runs() {
    let h = harness().await;
    declare(&h, GROUP).await;
    add(&h, "kajet-api", member_spec(GROUP, true)).await;
    add(&h, "kajet-mcp", member_spec(GROUP, true)).await;
    deploy(&h, "kajet-api").await;
    deploy(&h, "kajet-mcp").await;
    assert!(
        h.fake
            .containers()
            .iter()
            .filter(|c| c.name.starts_with("kajet-"))
            .all(|c| c.state == ContainerState::Running)
    );

    let (status, body) = raw(
        &h,
        "PUT",
        "/v1/apps/kajet-api/volumes/kajet-data/import",
        b"own-tar".to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let message = error_message(&body);
    assert!(message.contains("kajet-mcp"), "{message}");
    assert!(message.contains("stop them first"), "{message}");

    // With the other member stopped the shared volume accepts the tar under its Podman name, and
    // the export uses the same shared volume (the path segment stays the declared name).
    h.fake.container_stop("kajet-mcp", 1).await.unwrap();
    let (status, _) = raw(
        &h,
        "PUT",
        "/v1/apps/kajet-api/volumes/kajet-data/import",
        b"shared-tar".to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, tar) = raw(
        &h,
        "GET",
        "/v1/apps/kajet-api/volumes/kajet-data/export",
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(&tar[..], b"shared-tar");
    assert!(
        h.fake
            .calls()
            .contains(&Call::VolumeImport(PODMAN_GROUP.into()))
    );
    h.running.stop().await;
}

#[tokio::test]
async fn doctor_reports_shared_data_without_a_declaration() {
    let h = harness().await;
    // A volume labelled as shared that `apps.toml` does not declare (e.g. left after a rollback).
    h.fake
        .volume_create(&VolumeSpec {
            name: "wg-shared-ghost".to_owned(),
            labels: BTreeMap::from([(labels::SHARED_VOLUME.to_owned(), "ghost".to_owned())]),
        })
        .await
        .unwrap();

    let (status, report) = admin(&h, "GET", "/v1/doctor", None).await;
    assert_eq!(status, StatusCode::OK);
    let check = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "state.shared_volumes")
        .expect("state.shared_volumes check exists");
    assert_eq!(check["status"], "warn");
    let message = check["message"].as_str().unwrap();
    assert!(message.contains("wg-shared-ghost"), "{message}");
    let hint = check["hint"].as_str().unwrap_or_default();
    assert!(
        hint.contains("weglarka volumes remove ghost --purge"),
        "{hint}"
    );
    h.running.stop().await;
}

#[tokio::test]
async fn doctor_notes_a_declared_volume_whose_data_is_missing() {
    let h = harness().await;
    declare(&h, GROUP).await;
    add(&h, "kajet-api", member_spec(GROUP, false)).await;
    // The declaration keeps its range, but the data is gone (e.g. removed by hand).
    h.fake.volume_remove(PODMAN_GROUP, true).await.unwrap();

    let (_, report) = admin(&h, "GET", "/v1/doctor", None).await;
    let check = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "state.shared_volumes")
        .expect("state.shared_volumes check exists");
    assert_eq!(
        check["status"], "info",
        "benign: the next deploy creates it"
    );
    let message = check["message"].as_str().unwrap();
    assert!(message.contains("no Podman volume"), "{message}");
    h.running.stop().await;
}

#[tokio::test]
async fn doctor_hints_that_members_must_share_the_container_user() {
    let h = harness().await;
    declare(&h, GROUP).await;
    add(&h, "kajet-api", member_spec(GROUP, false)).await;
    add(&h, "kajet-mcp", member_spec(GROUP, false)).await;

    let (_, report) = admin(&h, "GET", "/v1/doctor", None).await;
    let check = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "state.shared_volumes")
        .expect("state.shared_volumes check exists");
    assert_eq!(check["status"], "info");
    let message = check["message"].as_str().unwrap();
    assert!(message.contains("same container USER"), "{message}");
    assert!(
        message.contains("kajet-api") && message.contains("kajet-mcp"),
        "{message}"
    );
    let hint = check["hint"].as_str().unwrap_or_default();
    assert!(hint.contains("Config.User"), "{hint}");
    h.running.stop().await;
}
