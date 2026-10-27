//! Shared-network API (issue #128, `docs/decisions/0030-shared-networks.md`) on `FakePodman`, over
//! the real admin socket: declarations (`/v1/networks`), membership through the app spec, the
//! in-use guard on removal and the doctor check.

use crate::common::*;
use std::collections::BTreeMap;

use hyper::StatusCode;
use serde_json::{Value, json};
use weglarka_model::app::{AppsFile, SharedNetworkName};
use weglarka_model::labels;
use weglarka_model::podman::{NetworkSpec, PodmanClient};
use weglarka_model::state;

const IMAGE: &str = "ghcr.io/jpalczewski/ntfy.zig:latest";
/// Declared name of the group used by the tests.
const GROUP: &str = "kajet";
/// Its Podman network name ([`labels::shared_network_name`]).
const PODMAN_GROUP: &str = "net-shared-kajet";

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
    add(&h, "kajet-api", member_spec(GROUP, &[])).await;
    add(&h, "kajet-proxy", member_spec(GROUP, &["gateway"])).await;

    // The adds only write the spec: the group network and the containers appear in a background
    // reconcile pass, so wait for them instead of racing it (issue #147).
    eventually("both members deployed", || async {
        h.fake.container_spec("kajet-api").is_some()
            && h.fake.container_spec("kajet-proxy").is_some()
            && h.fake.networks().contains(&PODMAN_GROUP.to_owned())
    })
    .await;

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
    let (status, body) = post_app(&h, "kajet-api", member_spec("nope", &[])).await;
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
    add(&h, "a", member_spec(GROUP, &["web"])).await;
    let (status, body) = post_app(&h, "b", member_spec(GROUP, &["web"])).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    h.running.stop().await;
}

#[tokio::test]
async fn removal_is_refused_while_members_exist() {
    let h = harness().await;
    declare(&h, GROUP).await;
    add(&h, "kajet-api", member_spec(GROUP, &[])).await;

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
    add(&h, "kajet-api", member_spec(GROUP, &[])).await;
    let (_, report) = admin(&h, "GET", "/v1/doctor", None).await;
    let check = doctor_check(&report);
    assert_eq!(check["status"], "ok", "{check}");
    h.running.stop().await;
}
