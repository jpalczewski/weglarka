//! `weglarka push` (issue #109): `PUT /v1/apps/{name}/image` and `POST /v1/apps/{name}/deploy` with an
//! `image_ref`, over the real admin socket on `FakePodman`.

use crate::common::*;
use hyper::StatusCode;
use hyper::body::Bytes;
use serde_json::{Value, json};
use weglarka_core::testing::Call;

const REPO: &str = "ghcr.io/jpalczewski/ntfy.zig";

fn message(body: &Bytes) -> String {
    let value: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    value["message"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| String::from_utf8_lossy(body).into_owned())
}

async fn deployed_app() -> Harness {
    let h = harness().await;
    add(&h, "ntfy", spec("ntfy.example.eu")).await;
    deployed(&h, "ntfy").await;
    h
}

#[tokio::test]
async fn a_pushed_archive_is_deployed_and_pinned_in_the_state() {
    let h = deployed_app().await;
    let before = show(&h, "ntfy").await["state"]["current"].clone();

    let (status, body) = raw(&h, "PUT", "/v1/apps/ntfy/image", b"image-1".to_vec()).await;
    assert_eq!(status, StatusCode::OK, "{}", message(&body));
    let resp: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp["outcome"], "deployed");
    let pushed = resp["digest"].clone();
    assert_ne!(pushed, before);

    let state = show(&h, "ntfy").await["state"].clone();
    assert_eq!(state["current"], pushed);
    assert_eq!(state["previous"], before);
    // The spec keeps its tag: only the state moved.
    assert_eq!(show(&h, "ntfy").await["spec"]["image"], IMAGE);

    let calls = h.fake.calls();
    assert!(calls.contains(&Call::ImageLoad { bytes: 7 }), "{calls:?}");
    assert!(
        calls
            .iter()
            .any(|c| matches!(c, Call::ImageTag { repo, .. } if repo == REPO)),
        "{calls:?}"
    );

    // The same archive again changes nothing.
    let (status, body) = raw(&h, "PUT", "/v1/apps/ntfy/image", b"image-1".to_vec()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["outcome"],
        "unchanged"
    );
    h.running.stop().await;
}

#[tokio::test]
async fn a_broken_archive_is_a_400_and_an_unknown_app_a_404() {
    let h = deployed_app().await;
    h.fake.script_next_load_failure("unrecognized image format");
    let (status, body) = raw(&h, "PUT", "/v1/apps/ntfy/image", b"junk".to_vec()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        message(&body).contains("cannot load the image archive"),
        "{}",
        message(&body)
    );
    assert!(message(&body).contains("unrecognized image format"));

    let (status, _) = raw(&h, "PUT", "/v1/apps/nope/image", b"image-1".to_vec()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // Nothing was loaded for the unknown app, and the state of the real one is untouched.
    assert_eq!(
        h.fake
            .calls()
            .iter()
            .filter(|c| matches!(c, Call::ImageLoad { .. }))
            .count(),
        1,
        "only the broken archive reached Podman"
    );
    h.running.stop().await;
}

#[tokio::test]
async fn deploy_with_an_image_ref_pins_that_reference_and_keeps_the_spec() {
    let h = deployed_app().await;
    let reference = format!("{REPO}:sha-1");
    let (status, resp) = admin(
        &h,
        "POST",
        "/v1/apps/ntfy/deploy",
        Some(json!({ "image_ref": reference })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{resp}");
    assert_eq!(resp["outcome"], "deployed");
    assert!(h.fake.calls().contains(&Call::ImagePull(reference)));
    assert_eq!(show(&h, "ntfy").await["spec"]["image"], IMAGE);

    // Another repository is refused before anything is pulled.
    let (status, resp) = admin(
        &h,
        "POST",
        "/v1/apps/ntfy/deploy",
        Some(json!({ "image_ref": "docker.io/x/other:latest" })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{resp}");
    assert!(
        resp["message"]
            .as_str()
            .unwrap()
            .contains("not in the repository")
    );
    h.running.stop().await;
}
