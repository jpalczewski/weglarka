//! Image retention through the admin API (issue #40): `POST /v1/images/prune` and the `doctor`
//! warning. Real unix socket, `FakePodman`.

mod common;

use common::*;

use futures_util::StreamExt;
use hyper::StatusCode;
use serde_json::{Value, json};
use weglarka_core::app::Digest;
use weglarka_core::podman::PodmanClient;
use weglarka_core::testing::DEFAULT_IMAGE_SIZE_BYTES;

const IMAGE: &str = "ghcr.io/jpalczewski/ntfy.zig:latest";

fn digest(c: char) -> Digest {
    Digest::new(format!("sha256:{}", c.to_string().repeat(64))).unwrap()
}

/// The `runtime.images` check of a `GET /v1/doctor`.
async fn image_check(h: &Harness) -> Value {
    let (status, report) = admin(h, "GET", "/v1/doctor", None).await;
    assert_eq!(status, StatusCode::OK, "{report}");
    report["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .find(|c| c["id"] == "runtime.images")
        .cloned()
        .expect("every report carries the image check")
}

#[tokio::test]
async fn prune_dry_run_then_removes_and_doctor_reports_it() {
    let h = harness().await;
    h.fake.set_pull_digest(IMAGE, digest('a'));
    let (status, value) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(json!({
            "name": "ntfy",
            "spec": {
                "image": IMAGE,
                "domains": ["nz.example.eu"],
                "port": 8085,
                "health": { "attempts": 1, "window_secs": 1 }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    eventually("first deploy", || async {
        let (_, app) = admin(&h, "GET", "/v1/apps/ntfy", None).await;
        app["state"]["current"].is_string()
    })
    .await;

    // What an earlier deploy left behind: an image of the app's repository that `state.toml` does
    // not know (the daemon used to keep every pulled image).
    // The ingress nginx image sits in the same store, so counts are relative to it.
    let seeded = h.fake.images().len() + 1;
    let stale = format!("ghcr.io/jpalczewski/ntfy.zig@{}", digest('e'));
    h.fake.set_pull_digest(&stale, digest('e'));
    h.fake.image_pull(&stale).collect::<Vec<_>>().await;
    assert_eq!(h.fake.images().len(), seeded);

    let check = image_check(&h).await;
    assert_eq!(check["status"], "warn", "{check}");
    assert!(
        check["message"]
            .as_str()
            .unwrap()
            .contains("1 unused image(s)"),
        "{check}"
    );
    assert!(
        check["hint"]
            .as_str()
            .unwrap()
            .contains("weglarka images prune"),
        "{check}"
    );

    let (status, value) = admin(
        &h,
        "POST",
        "/v1/images/prune",
        Some(json!({ "dry_run": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(value["dry_run"], true);
    assert_eq!(value["removed"].as_array().unwrap().len(), 1, "{value}");
    assert_eq!(value["reclaimed_bytes"], json!(DEFAULT_IMAGE_SIZE_BYTES));
    assert_eq!(h.fake.images().len(), seeded, "a dry run removes nothing");

    // No body = an actual prune.
    let (status, value) = admin(&h, "POST", "/v1/images/prune", None).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(value["dry_run"], false);
    assert_eq!(value["removed"][0]["digests"], json!([stale]));
    assert_eq!(value["reclaimed_bytes"], json!(DEFAULT_IMAGE_SIZE_BYTES));
    assert!(value.get("failed").is_none(), "nothing failed: {value}");
    assert_eq!(h.fake.images().len(), seeded - 1, "the leftover is gone");

    let check = image_check(&h).await;
    assert_eq!(check["status"], "ok", "{check}");
}

/// An image a container still uses is never removed, not even when nothing in `state.toml` protects
/// it: the planner only removes what is provably dead weight, and Podman is the backstop.
#[tokio::test]
async fn an_image_used_by_a_container_survives_a_prune() {
    let h = harness().await;
    h.fake.set_pull_digest(IMAGE, digest('a'));
    let (status, value) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(json!({
            "name": "ntfy",
            "spec": {
                "image": IMAGE,
                "domains": ["nz.example.eu"],
                "port": 8085,
                "health": { "attempts": 1, "window_secs": 1 }
            }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{value}");
    eventually("first deploy", || async {
        let (_, app) = admin(&h, "GET", "/v1/apps/ntfy", None).await;
        app["state"]["current"].is_string()
    })
    .await;

    // The ingress nginx image lives in the same store; only the app image is interesting here.
    let before = h.fake.images().len();
    let (status, value) = admin(&h, "POST", "/v1/images/prune", None).await;
    assert_eq!(status, StatusCode::OK, "{value}");
    assert_eq!(value["removed"], json!([]), "{value}");
    assert_eq!(h.fake.images().len(), before);

    // Nothing was removed, so the doctor reports no leftovers either.
    let check = image_check(&h).await;
    assert_eq!(check["status"], "ok", "{check}");
}
