//! Spike for docs/decisions/0042-push-local-images.md: what libpod does when an image is loaded from an
//! archive instead of pulled. Requires `WEGLARKA_PODMAN_SOCKET`; skipped without it
//! (docs/decisions/0002-podman-in-ci.md).
//!
//! The test records what it observes (`--nocapture` shows it) and asserts only what the push design
//! depends on: the loaded image keeps the manifest digest of the archive's image, and that digest is
//! resolvable through `image_inspect`.

use std::fs;
use std::process::Command;

use weglarka_core::podman::{PodmanClient, PodmanError, PullEvent};
use weglarka_podman::LibpodClient;

use futures_util::StreamExt;

const ALPINE: &str = "docker.io/library/alpine:3.20";

fn socket() -> Option<String> {
    let socket = std::env::var("WEGLARKA_PODMAN_SOCKET")
        .ok()
        .filter(|s| !s.is_empty());
    if socket.is_none() {
        eprintln!("WEGLARKA_PODMAN_SOCKET not set — skipping integration test");
    }
    socket
}

/// Raw libpod call with the response body written to `out` (`GET`) or `data` sent as the body (`POST`).
fn curl(socket: &str, method: &str, path: &str, data: Option<&str>, out: Option<&str>) -> String {
    let mut cmd = Command::new("curl");
    cmd.args([
        "-sS",
        "--fail-with-body",
        "--unix-socket",
        socket,
        "-X",
        method,
    ]);
    if let Some(data) = data {
        cmd.args(["-H", "content-type: application/x-tar", "--data-binary"]);
        cmd.arg(format!("@{data}"));
    }
    if let Some(out) = out {
        cmd.args(["-o", out]);
    }
    cmd.arg(format!("http://d/v6.0.0/libpod{path}"));
    let result = cmd
        .output()
        .expect("curl is required for integration tests");
    let text = String::from_utf8_lossy(&result.stdout).into_owned();
    assert!(
        result.status.success(),
        "{method} {path} failed: {text}{}",
        String::from_utf8_lossy(&result.stderr)
    );
    text
}

async fn pull(client: &LibpodClient, reference: &str) {
    let mut stream = std::pin::pin!(client.image_pull(reference));
    while let Some(event) = stream.next().await {
        if let PullEvent::Complete { .. } = event.expect("pull") {}
    }
}

/// Saves `ALPINE` in `format`, removes it, loads the archive back and reports what libpod made of it.
async fn round_trip(socket: &str, client: &LibpodClient, format: &str) {
    pull(client, ALPINE).await;
    let before = client.image_inspect(ALPINE).await.expect("inspect");
    let digest = before.digest.clone().expect("a pulled image has a digest");

    let dir = std::env::temp_dir().join(format!("wg-image-load-{format}-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let archive = dir.join("image.tar");
    let archive = archive.to_str().unwrap();
    curl(
        socket,
        "GET",
        &format!("/images/{ALPINE}/get?format={format}"),
        None,
        Some(archive),
    );

    client.image_remove(ALPINE).await.expect("remove");
    assert!(matches!(
        client.image_inspect(ALPINE).await,
        Err(PodmanError::NotFound(_))
    ));

    let response = curl(socket, "POST", "/images/load", Some(archive), None);
    println!("[{format}] load response: {response}");

    // 1. By the original name (the archive carries it).
    let by_name = client.image_inspect(ALPINE).await;
    println!("[{format}] inspect {ALPINE}: {by_name:?}");

    // 2. By `repo@digest` — what `ensure_image` looks up after a deploy pinned the digest.
    let pinned = format!("docker.io/library/alpine@{digest}");
    let by_digest = client.image_inspect(&pinned).await;
    println!("[{format}] inspect {pinned}: {by_digest:?}");

    // 3. By image id — the `local_id` fallback.
    let by_id = match &by_name {
        Ok(info) => Some(client.image_inspect(&info.id).await),
        Err(_) => None,
    };
    println!("[{format}] inspect by id: {by_id:?}");

    let loaded = by_name.expect("the loaded image is known by the name stored in the archive");
    println!(
        "[{format}] digest before {digest}, after {:?}; repo_digests {:?}",
        loaded.digest, loaded.repo_digests
    );
    assert_eq!(
        loaded.digest.as_ref(),
        Some(&digest),
        "{format}: loading must keep the manifest digest, or the pin cannot be reproduced"
    );
    let found = by_digest.as_ref().map(|i| i.id.clone());
    assert_eq!(
        found.as_deref().ok(),
        Some(loaded.id.as_str()),
        "{format}: `repo@digest` must resolve to the loaded image, got {by_digest:?}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn loaded_oci_archive_keeps_its_digest() {
    let Some(socket) = socket() else { return };
    let client = LibpodClient::new(&socket);
    round_trip(&socket, &client, "oci-archive").await;
}

#[tokio::test]
async fn loaded_docker_archive_keeps_its_digest() {
    let Some(socket) = socket() else { return };
    let client = LibpodClient::new(&socket);
    round_trip(&socket, &client, "docker-archive").await;
}
