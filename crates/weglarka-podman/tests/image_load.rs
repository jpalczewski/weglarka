//! Spike for docs/decisions/0042-push-local-images.md: what libpod does when an image is loaded from an
//! archive instead of pulled. Requires `WEGLARKA_PODMAN_SOCKET`; skipped without it
//! (docs/decisions/0002-podman-in-ci.md).
//!
//! `weglarka push` pins the digest of the image *after* the load (a docker archive carries no manifest,
//! so libpod computes one and it differs from the registry's), so the properties the design depends on are:
//! the loaded image reports a digest, `repo@digest` resolves to it (after tagging it with the app's
//! repository when the archive has no name), and loading the same archive again gives the same digest.
//! Whether the digest equals the original one is only recorded (`--nocapture`), not asserted.
//!
//! One test runs every scenario in turn: they share one image in the store and remove it in between, so
//! parallel tests would pull it out from under each other.

use std::fs;
use std::process::Command;

use futures_util::StreamExt;
use serde_json::Value;
use weglarka_core::podman::{ImageInfo, PodmanClient, PodmanError};
use weglarka_podman::LibpodClient;

const ALPINE: &str = "docker.io/library/alpine:3.20";
const ALPINE_REPO: &str = "docker.io/library/alpine";
/// Repository an archive without a name is tagged with, as the daemon will tag it with the app's.
const APP_REPO: &str = "localhost/wg-spike/app";

fn socket() -> Option<String> {
    let socket = std::env::var("WEGLARKA_PODMAN_SOCKET")
        .ok()
        .filter(|s| !s.is_empty());
    if socket.is_none() {
        eprintln!("WEGLARKA_PODMAN_SOCKET not set — skipping integration test");
    }
    socket
}

/// Raw libpod call: `data` is a file sent as the body, `out` a file the response is written to.
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
        event.expect("pull");
    }
}

/// Loads `archive` and returns the names libpod reports for it.
fn load(socket: &str, archive: &str, label: &str) -> Vec<String> {
    let response = curl(socket, "POST", "/images/load", Some(archive), None);
    println!("[{label}] load response: {response}");
    let parsed: Value = serde_json::from_str(&response).expect("load answers JSON");
    parsed["Names"]
        .as_array()
        .map(|names| {
            names
                .iter()
                .filter_map(|n| n.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// One scenario: save the pulled image as `format` (under its name, or by id when `nameless`), remove it,
/// load it, tag it when it came without a name, and check the pin. Returns the loaded digest and what
/// went wrong.
async fn scenario(
    socket: &str,
    client: &LibpodClient,
    format: &str,
    nameless: bool,
) -> Result<String, Vec<String>> {
    let label = format!("{format}{}", if nameless { ", nameless" } else { "" });
    let mut problems = Vec::new();

    pull(client, ALPINE).await;
    let original = client.image_inspect(ALPINE).await.expect("inspect");
    let original_digest = original
        .digest
        .clone()
        .expect("a pulled image has a digest");

    let dir = std::env::temp_dir().join(format!(
        "wg-image-load-{format}-{nameless}-{}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    let archive = dir.join("image.tar");
    let archive = archive.to_str().unwrap();
    let saved = if nameless { &original.id } else { ALPINE };
    curl(
        socket,
        "GET",
        &format!("/images/{saved}/get?format={format}"),
        None,
        Some(archive),
    );

    // The repository the pin is built from, and the way the loaded image is reached afterwards.
    let (repo, tag) = if nameless {
        (APP_REPO, "pushed")
    } else {
        (ALPINE_REPO, "3.20")
    };
    let name = format!("{repo}:{tag}");

    let mut digests = Vec::new();
    for round in ["first load", "second load"] {
        client.image_remove(&name).await.ok();
        client.image_remove(ALPINE).await.ok();
        assert!(
            matches!(
                client.image_inspect(&original.id).await,
                Err(PodmanError::NotFound(_))
            ),
            "[{label}] the image must be gone before {round}"
        );

        let names = load(socket, archive, &format!("{label}, {round}"));
        if nameless {
            client
                .image_tag(&original.id, repo, tag)
                .await
                .expect("tag the loaded image with the app repository");
        }
        let info: ImageInfo = match client.image_inspect(&original.id).await {
            Ok(info) => info,
            Err(e) => {
                problems.push(format!("{round}: loaded image not found by id: {e:?}"));
                break;
            }
        };
        println!("[{label}, {round}] names {names:?}, inspect: {info:?}");
        let Some(digest) = info.digest.clone() else {
            problems.push(format!("{round}: the loaded image has no digest"));
            break;
        };
        println!(
            "[{label}, {round}] digest {digest} (registry digest {original_digest}, equal: {})",
            digest == original_digest
        );

        let pinned = format!("{repo}@{digest}");
        match client.image_inspect(&pinned).await {
            Ok(by_pin) if by_pin.id == info.id => {}
            Ok(other) => problems.push(format!("{round}: {pinned} resolved to {}", other.id)),
            Err(e) => problems.push(format!("{round}: {pinned} does not resolve: {e:?}")),
        }
        digests.push(digest);
    }
    if let [first, second] = digests.as_slice()
        && first != second
    {
        problems.push(format!(
            "the same archive gave two digests: {first} then {second}"
        ));
    }

    client.image_remove(&name).await.ok();
    client.image_remove(ALPINE).await.ok();
    let _ = fs::remove_dir_all(&dir);

    match (problems.is_empty(), digests.first()) {
        (true, Some(digest)) => Ok(digest.to_string()),
        _ => Err(problems),
    }
}

#[tokio::test]
async fn loaded_archives_can_be_pinned_by_digest() {
    let Some(socket) = socket() else { return };
    let client = LibpodClient::new(&socket);
    let mut failures = Vec::new();
    for (format, nameless) in [
        ("oci-archive", false),
        ("oci-archive", true),
        ("docker-archive", false),
        ("docker-archive", true),
    ] {
        match scenario(&socket, &client, format, nameless).await {
            Ok(digest) => println!("OK {format} nameless={nameless}: pinned {digest}"),
            Err(problems) => failures.push(format!("{format} nameless={nameless}: {problems:?}")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
