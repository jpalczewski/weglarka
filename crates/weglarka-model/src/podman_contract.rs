//! Contract suite for [`PodmanClient`] implementations (feature `testing`).
//!
//! One function per behaviour, each taking `&impl PodmanClient`, so the in-memory `FakePodman`
//! (engine unit tests) and the real `LibpodClient` (`weglarka-podman` integration tests against a
//! live socket) are held to the same answers. Every function panics on a violation. When the two
//! implementations disagree, the fake is changed to match Podman, never the other way round.
//!
//! The cases here use only names that cannot exist on a real host, so they are safe to run against
//! a Podman that also serves other workloads.

use crate::podman::{ContainerFilter, PodmanClient, PodmanError};

/// A name no container, image or network on a real host will have.
pub const MISSING: &str = "weglarka-contract-missing";
/// A well-formed image reference nothing has pulled.
pub const MISSING_IMAGE: &str = "localhost/weglarka-contract-missing:none";

/// Runs the cases that need a reachable, empty-enough Podman.
pub async fn run_reachable(client: &impl PodmanClient) {
    missing_container_is_not_found(client).await;
    missing_image_is_not_found(client).await;
    missing_network_is_not_found(client).await;
    unmatched_label_filter_lists_nothing(client).await;
}

/// Inspecting or removing a container that does not exist answers `NotFound` — the answer the
/// engine treats as "absent" (reconcile, cleanup).
pub async fn missing_container_is_not_found(client: &impl PodmanClient) {
    let inspected = client.container_inspect(MISSING).await;
    assert!(
        matches!(inspected, Err(PodmanError::NotFound(_))),
        "container_inspect of a missing container: {inspected:?}"
    );
    let removed = client.container_remove(MISSING, false).await;
    assert!(
        matches!(removed, Err(PodmanError::NotFound(_))),
        "container_remove of a missing container: {removed:?}"
    );
}

/// `image_inspect` of an image that was never pulled answers `NotFound` (the "pull it first" branch).
pub async fn missing_image_is_not_found(client: &impl PodmanClient) {
    let inspected = client.image_inspect(MISSING_IMAGE).await;
    assert!(
        matches!(inspected, Err(PodmanError::NotFound(_))),
        "image_inspect of a missing image: {inspected:?}"
    );
}

/// `network_inspect` of a network that does not exist answers `NotFound`.
pub async fn missing_network_is_not_found(client: &impl PodmanClient) {
    let inspected = client.network_inspect(MISSING).await;
    assert!(
        matches!(inspected, Err(PodmanError::NotFound(_))),
        "network_inspect of a missing network: {inspected:?}"
    );
}

/// A label filter nothing matches is an empty list, not an error.
pub async fn unmatched_label_filter_lists_nothing(client: &impl PodmanClient) {
    let filter = ContainerFilter {
        labels: [("weglarka.contract".to_owned(), MISSING.to_owned())].into(),
    };
    let listed = client.container_list(&filter).await;
    assert!(
        matches!(&listed, Ok(containers) if containers.is_empty()),
        "container_list with an unmatched label: {listed:?}"
    );
}

/// For a client whose socket cannot be reached: every call fails with `PodmanError::Unreachable`.
/// In particular a lookup must never read as "absent" (`NotFound`) — that would make reconcile
/// recreate, or cleanup forget, things it merely cannot see.
pub async fn unreachable_is_an_error_not_absent(client: &impl PodmanClient) {
    let version = client.version().await;
    assert!(
        matches!(version, Err(PodmanError::Unreachable(_))),
        "version: {version:?}"
    );
    let inspected = client.container_inspect(MISSING).await;
    assert!(
        matches!(inspected, Err(PodmanError::Unreachable(_))),
        "container_inspect: {inspected:?}"
    );
    let removed = client.container_remove(MISSING, false).await;
    assert!(
        matches!(removed, Err(PodmanError::Unreachable(_))),
        "container_remove: {removed:?}"
    );
    let listed = client.container_list(&ContainerFilter::default()).await;
    assert!(
        matches!(listed, Err(PodmanError::Unreachable(_))),
        "container_list: {listed:?}"
    );
    let image = client.image_inspect(MISSING_IMAGE).await;
    assert!(
        matches!(image, Err(PodmanError::Unreachable(_))),
        "image_inspect: {image:?}"
    );
    let network = client.network_inspect(MISSING).await;
    assert!(
        matches!(network, Err(PodmanError::Unreachable(_))),
        "network_inspect: {network:?}"
    );
}
