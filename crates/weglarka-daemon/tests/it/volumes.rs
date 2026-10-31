//! Volume endpoints and `apps remove --purge-volumes` on `FakePodman`, over the real admin socket.

use crate::common::*;

use hyper::StatusCode;
use serde_json::{Value, json};
use weglarka_engine::testing::Call;

const IMAGE: &str = "ghcr.io/jpalczewski/ntfy.zig:latest";

fn app_with_volume() -> Value {
    json!({
        "name": "szklana",
        "spec": {
            "image": IMAGE,
            "domains": ["pogoda.example.eu"],
            "port": 8085,
            "health": { "attempts": 1, "window_secs": 1 },
            "volumes": [{ "name": "data", "target": "/data" }]
        }
    })
}

async fn deployed_app() -> Harness {
    let h = harness().await;
    let (s, _) = admin(&h, "POST", "/v1/apps", Some(app_with_volume())).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = admin(&h, "POST", "/v1/apps/szklana/deploy", Some(json!({}))).await;
    assert_eq!(s, StatusCode::OK);
    h
}

#[tokio::test]
async fn list_export_and_own_import_use_the_raw_volume_endpoints() {
    let h = deployed_app().await;

    let (s, v) = admin(&h, "GET", "/v1/apps/szklana/volumes", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        v,
        json!({"volumes": [{"name": "data", "target": "/data", "podman_name": "szklana.data", "exists": true}]})
    );

    let (s, _) = raw(
        &h,
        "PUT",
        "/v1/apps/szklana/volumes/data/import",
        b"own-tar".to_vec(),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, tar) = raw(&h, "GET", "/v1/apps/szklana/volumes/data/export", vec![]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(&tar[..], b"own-tar");

    let calls = h.fake.calls();
    assert!(calls.contains(&Call::VolumeImport("szklana.data".into())));
    assert!(
        !calls
            .iter()
            .any(|c| matches!(c, Call::ContainerArchivePut { .. }))
    );
    h.running.stop().await;
}

#[tokio::test]
async fn foreign_import_maps_ids_through_a_helper_container() {
    let h = deployed_app().await;
    let (s, _) = raw(
        &h,
        "PUT",
        "/v1/apps/szklana/volumes/data/import?foreign=true",
        b"coolify-tar".to_vec(),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    let calls = h.fake.calls();
    assert!(calls.contains(&Call::ContainerArchivePut {
        name: "wg-import.szklana".into(),
        path: "/data".into()
    }));
    assert!(!calls.iter().any(|c| matches!(c, Call::VolumeImport(_))));
    assert!(
        h.fake
            .containers()
            .iter()
            .all(|c| c.name != "wg-import.szklana"),
        "helper cleaned up"
    );
    h.running.stop().await;
}

#[tokio::test]
async fn undeclared_or_unknown_targets_are_rejected() {
    let h = deployed_app().await;
    for (method, path) in [
        ("PUT", "/v1/apps/szklana/volumes/other/import"),
        ("GET", "/v1/apps/szklana/volumes/other/export"),
        ("PUT", "/v1/apps/nope/volumes/data/import"),
        ("GET", "/v1/apps/nope/volumes"),
    ] {
        let (s, _) = raw(&h, method, path, vec![]).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{method} {path}");
    }
    h.running.stop().await;
}

#[tokio::test]
async fn import_before_the_first_deploy_is_a_clear_error() {
    let h = harness().await;
    h.fake.fail_pull(IMAGE, "registry down"); // the background reconcile cannot deploy it
    admin(&h, "POST", "/v1/apps", Some(app_with_volume())).await;
    let (s, v) = admin(&h, "GET", "/v1/apps/szklana/volumes", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["volumes"][0]["exists"], false);
    let (s, _) = raw(&h, "PUT", "/v1/apps/szklana/volumes/data/import", vec![]).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, body) = raw(
        &h,
        "PUT",
        "/v1/apps/szklana/volumes/data/import?foreign=true",
        vec![],
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(&body).contains("not deployed"));
    h.running.stop().await;
}

#[tokio::test]
async fn remove_keeps_volumes_unless_purge_is_requested() {
    let h = deployed_app().await;
    let (s, _) = admin(&h, "DELETE", "/v1/apps/szklana", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(h.fake.volumes().len(), 1, "plain remove keeps the data");

    // Add it back, then remove it for good.
    admin(&h, "POST", "/v1/apps", Some(app_with_volume())).await;
    let (s, _) = admin(&h, "DELETE", "/v1/apps/szklana?purge_volumes=true", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(h.fake.volumes().is_empty());
    assert!(h.fake.containers().iter().all(|c| c.name != "szklana"));
    h.running.stop().await;
}

#[tokio::test]
async fn host_wide_listing_names_the_owning_app_on_every_row() {
    let h = deployed_app().await;
    let (s, _) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(json!({
            "name": "bez-danych",
            "spec": {
                "image": IMAGE,
                "domains": ["bez.example.eu"],
                "port": 8085,
                "health": { "attempts": 1, "window_secs": 1 },
                "volumes": [{ "name": "cache", "target": "/cache" }]
            }
        })),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    let (s, v) = admin(&h, "GET", "/v1/app-volumes", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        v,
        json!({"volumes": [
            {"app": "bez-danych", "name": "cache", "target": "/cache", "podman_name": "bez-danych.cache", "exists": true},
            {"app": "szklana", "name": "data", "target": "/data", "podman_name": "szklana.data", "exists": true},
        ]})
    );
    h.running.stop().await;
}
