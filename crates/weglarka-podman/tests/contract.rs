//! `LibpodClient` against the `PodmanClient` contract suite that `FakePodman` also passes
//! (`weglarka_model::podman_contract`). The reachable cases need `WEGLARKA_PODMAN_SOCKET` and are
//! skipped without it (docs/decisions/0002-podman-in-ci.md); the unreachable case needs no Podman.

use weglarka_model::podman_contract;
use weglarka_podman::LibpodClient;

#[tokio::test]
async fn libpod_client_passes_the_podman_contract() {
    let Some(socket) = std::env::var("WEGLARKA_PODMAN_SOCKET")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        eprintln!("WEGLARKA_PODMAN_SOCKET not set — skipping integration test");
        return;
    };
    podman_contract::run_reachable(&LibpodClient::new(socket)).await;
}

/// A socket path that does not exist: every call is `Unreachable`, never "not found".
#[tokio::test]
async fn missing_socket_is_an_error_not_absent() {
    let dir = tempfile::tempdir().unwrap();
    let client = LibpodClient::new(dir.path().join("no-such-podman.sock"));
    podman_contract::unreachable_is_an_error_not_absent(&client).await;
}
