//! `PodmanClient::image_save` against a real Podman 6 for the image a static site ships as
//! (docs/decisions/0049-static-sites.md): built `FROM scratch` with `COPY dist/ /`, exported as an
//! `oci-archive`, and unpacked by the site extractor. Requires `WEGLARKA_PODMAN_SOCKET`; skipped without
//! it (docs/decisions/0002-podman-in-ci.md).
//!
//! This is the measurement the ADR left open: what libpod's export of a one-layer scratch image looks like
//! and that `weglarka_core::sites::extract_release` reads it. The export is also taken by `repo@digest`,
//! the reference the deploy uses after a pull, from an image that went through `image_load` (the way an
//! image reaches the store without a registry).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use bytes::Bytes;
use futures_util::{StreamExt, stream};
use weglarka_core::podman::{PodmanClient, TarStream};
use weglarka_core::sites::{ExtractLimits, extract_release};
use weglarka_podman::LibpodClient;

const REPO: &str = "localhost/wg-static/site";
const TAG: &str = "1";

fn socket() -> Option<String> {
    let socket = std::env::var("WEGLARKA_PODMAN_SOCKET")
        .ok()
        .filter(|s| !s.is_empty());
    if socket.is_none() {
        eprintln!("WEGLARKA_PODMAN_SOCKET not set — skipping integration test");
    }
    socket
}

/// Raw libpod call for what the client has no method for (`build`): `data` is a tar file sent as the body.
fn curl_post(socket: &str, path: &str, data: &Path) {
    let result = Command::new("curl")
        .args([
            "-sS",
            "--fail-with-body",
            "--unix-socket",
            socket,
            "-X",
            "POST",
            "-H",
            "content-type: application/x-tar",
            "--data-binary",
        ])
        .arg(format!("@{}", data.display()))
        .arg(format!("http://d/v6.0.0/libpod{path}"))
        .output()
        .expect("curl is required for integration tests");
    assert!(
        result.status.success(),
        "POST {path} failed: {}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

/// Builds `FROM scratch` + `COPY dist/ /` over a small site and returns the scratch directory.
fn build_site(socket: &str, name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("wg-image-save-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let context = dir.join("context");
    fs::create_dir_all(context.join("dist/assets")).unwrap();
    fs::write(
        context.join("Containerfile"),
        "FROM scratch\nCOPY dist/ /\n",
    )
    .unwrap();
    fs::write(context.join("dist/index.html"), "<h1>hello</h1>").unwrap();
    fs::write(context.join("dist/assets/app.css"), "body{margin:0}").unwrap();
    let context_tar = dir.join("context.tar");
    let status = Command::new("tar")
        .arg("-cf")
        .arg(&context_tar)
        .arg("-C")
        .arg(&context)
        .arg(".")
        .status()
        .expect("tar is required for integration tests");
    assert!(status.success(), "tar failed");
    curl_post(
        socket,
        &format!("/build?t={name}&dockerfile=Containerfile"),
        &context_tar,
    );
    dir
}

/// Reads a whole export stream into `file`.
async fn save_to(client: &LibpodClient, reference: &str, file: &Path) {
    let mut stream = client
        .image_save(reference)
        .await
        .unwrap_or_else(|e| panic!("image_save({reference}): {e:?}"));
    let mut out = Vec::new();
    while let Some(chunk) = stream.next().await {
        out.extend_from_slice(&chunk.expect("export stream"));
    }
    assert!(!out.is_empty(), "{reference}: the export is empty");
    fs::write(file, out).unwrap();
}

/// The unpacked tree: `(relative path, content)` of every regular file, sorted.
fn tree(root: &Path) -> Vec<(String, String)> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(base, &path, out);
            } else {
                let rel = path.strip_prefix(base).unwrap().display().to_string();
                out.push((rel, fs::read_to_string(&path).unwrap()));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

fn expected() -> Vec<(String, String)> {
    vec![
        ("assets/app.css".to_owned(), "body{margin:0}".to_owned()),
        ("index.html".to_owned(), "<h1>hello</h1>".to_owned()),
    ]
}

#[tokio::test]
async fn a_scratch_site_image_exports_and_unpacks() {
    let Some(socket) = socket() else { return };
    let client = LibpodClient::new(&socket);
    let name = format!("{REPO}:{TAG}");
    let _ = client.image_remove(&name).await;
    let dir = build_site(&socket, &name);

    // 1. Export by tag and unpack.
    let first = dir.join("first.tar");
    save_to(&client, &name, &first).await;
    let released = dir.join("release-by-tag");
    let report = extract_release(&first, &released, &ExtractLimits::default())
        .expect("the exported scratch image unpacks");
    println!("export by tag: {report:?}");
    assert_eq!(tree(&released), expected());

    // 2. The deploy refers to `repo@digest`: reload the exported image and export it by its pin.
    let digest = client
        .image_inspect(&name)
        .await
        .expect("inspect the built image")
        .digest;
    client.image_remove(&name).await.expect("remove the image");
    let bytes = Bytes::from(fs::read(&first).unwrap());
    let tar: TarStream = stream::iter([Ok(bytes)]).boxed();
    let loaded = client.image_load(tar).await.expect("image_load");
    println!("loaded: {loaded:?}");
    let digest = loaded
        .digest
        .or(digest)
        .expect("the loaded image has a digest");
    let second = dir.join("second.tar");
    save_to(&client, &format!("{REPO}@{digest}"), &second).await;
    let released = dir.join("release-by-pin");
    extract_release(&second, &released, &ExtractLimits::default())
        .expect("the export by digest unpacks");
    assert_eq!(tree(&released), expected());

    // 3. A missing image is `NotFound`, not an empty archive.
    let missing = format!("{REPO}@sha256:{}", "0".repeat(64));
    assert!(
        matches!(
            client.image_save(&missing).await,
            Err(weglarka_core::podman::PodmanError::NotFound(_))
        ),
        "an unknown digest must not export"
    );

    let _ = client.image_remove(&name).await;
    let _ = fs::remove_dir_all(&dir);
}
