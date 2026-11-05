//! Contract suites shared by every registry adapter.
//!
//! One suite function per trait, taking `&impl Trait`: the in-memory fakes run it in unit tests and
//! [`crate::HttpRegistry`] runs it against a real registry (`tests/contract.rs`, `WEGLARKA_REGISTRY_URL`).
//! A case that passes on a fake but fails on the real registry means the fake is wrong.
//!
//! Every case works in a repository of its own, named from a per-process nonce, so a registry that
//! outlives the run (a long-lived local one) never sees a stale tag from an earlier run. `host` is
//! the registry authority (`127.0.0.1:5000`); a fake accepts any syntactically valid one. The
//! suites panic on a violated expectation, like a test.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest as _, Sha256};
use weglarka_model::app::Digest;
use weglarka_model::release_set::{Repository, StrictDigest};

use crate::image_ref::ImageRef;
use crate::registry::{Registry, RegistryError, ReleaseRegistry, hex_lower, push_signature};
use crate::testing::TestSigningKey;

/// Upper bound passed as `max_body` to reads; far above anything the suites store.
const MAX_BODY: usize = 64 * 1024;
/// The `{}` config blob every OCI image manifest below points at.
const EMPTY_CONFIG: &[u8] = b"{}";

/// A repository no earlier run can have touched.
fn unique_repository(host: &str, case: &str) -> Repository {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    let name = format!(
        "{host}/weglarka-contract/{case}-{nanos:x}-{:x}-{count}",
        std::process::id()
    );
    Repository::new(name).expect("a contract repository name is a valid repository")
}

fn sha256_of(bytes: &[u8]) -> StrictDigest {
    StrictDigest::new(format!("sha256:{}", hex_lower(&Sha256::digest(bytes))))
        .expect("a computed sha256 is a strict digest")
}

/// An OCI image manifest with the `{}` config and no layers; `marker` makes the bytes unique.
fn image_manifest(marker: &str) -> Vec<u8> {
    let document = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.empty.v1+json",
            "digest": sha256_of(EMPTY_CONFIG).as_str(),
            "size": EMPTY_CONFIG.len(),
        },
        "layers": [],
        "annotations": { "org.example.contract": marker },
    });
    serde_json::to_vec(&document).expect("a JSON value serializes")
}

fn assert_not_found<T: std::fmt::Debug>(result: Result<T, RegistryError>, what: &str) {
    match result {
        Ok(value) => panic!("{what}: expected a not-found error, got {value:?}"),
        Err(error) => assert!(
            error.is_not_found(),
            "{what}: expected a not-found error, got {error:?}"
        ),
    }
}

fn image_in(repository: &Repository, tag: &str) -> ImageRef {
    ImageRef::parse(&format!("{repository}:{tag}")).expect("a contract image reference parses")
}

fn digest_in(digest: &StrictDigest) -> Digest {
    digest.as_digest().clone()
}

/// What every [`Registry`] must do, using nothing but the trait: a `.sig` that was never stored is a
/// not-found error (not an empty list, not another error), for a repository that does not exist.
pub async fn registry_suite(registry: &impl Registry, host: &str) {
    let repository = unique_repository(host, "registry");
    let digest = sha256_of(b"an image nobody signed");
    let image = image_in(&repository, "latest");
    assert_not_found(
        registry
            .cosign_signatures(&image, &digest_in(&digest))
            .await,
        "a signature of an unknown repository",
    );
}

/// What every [`ReleaseRegistry`] must do, on top of [`registry_suite`]: missing objects are
/// not-found errors, and pushed objects read back byte for byte.
pub async fn release_registry_suite(registry: &impl ReleaseRegistry, host: &str) {
    registry_suite(registry, host).await;
    missing_objects_are_not_found(registry, host).await;
    pushed_objects_round_trip(registry, host).await;
    pushed_signature_round_trips(registry, host).await;
}

/// A missing tag, blob and `.sig` tag are all `RegistryError::is_not_found()`, both in a repository
/// that has content and in one that has none.
async fn missing_objects_are_not_found(registry: &impl ReleaseRegistry, host: &str) {
    let missing_blob = sha256_of(b"a blob nobody uploaded");
    let missing_manifest = sha256_of(b"a manifest nobody uploaded");

    // An empty (unknown) repository.
    let empty = unique_repository(host, "empty");
    assert_not_found(
        registry.manifest(&empty, "absent", MAX_BODY).await,
        "a tag of an unknown repository",
    );
    assert_not_found(
        registry.blob(&empty, &missing_blob, MAX_BODY).await,
        "a blob of an unknown repository",
    );
    // The first release set of a channel lists the tags of a repository nobody pushed to yet.
    assert_not_found(
        registry.tags(&empty).await,
        "the tag list of an unknown repository",
    );

    // A repository that exists but lacks the object.
    let repository = unique_repository(host, "populated");
    registry
        .put_blob(&repository, EMPTY_CONFIG)
        .await
        .expect("the config blob uploads");
    registry
        .put_manifest(&repository, "present", &image_manifest("populated"))
        .await
        .expect("the manifest uploads");
    assert_not_found(
        registry.manifest(&repository, "absent", MAX_BODY).await,
        "a missing tag",
    );
    assert_not_found(
        registry
            .manifest(&repository, missing_manifest.as_str(), MAX_BODY)
            .await,
        "a missing manifest digest",
    );
    assert_not_found(
        registry.blob(&repository, &missing_blob, MAX_BODY).await,
        "a missing blob",
    );
    assert_not_found(
        registry
            .cosign_signatures(
                &image_in(&repository, "present"),
                &digest_in(&missing_manifest),
            )
            .await,
        "a missing signature tag",
    );
}

/// Blobs and manifests read back exactly as stored, by tag and by digest, and the tag is listed.
async fn pushed_objects_round_trip(registry: &impl ReleaseRegistry, host: &str) {
    let repository = unique_repository(host, "round-trip");

    let payload = b"contract blob".to_vec();
    let blob_digest = registry
        .put_blob(&repository, &payload)
        .await
        .expect("the blob uploads");
    assert_eq!(blob_digest, sha256_of(&payload));
    // Uploading the same bytes again is fine and yields the same identity.
    assert_eq!(
        registry
            .put_blob(&repository, &payload)
            .await
            .expect("an identical blob uploads again"),
        blob_digest
    );
    assert_eq!(
        registry
            .blob(&repository, &blob_digest, MAX_BODY)
            .await
            .expect("the blob reads back"),
        payload
    );

    registry
        .put_blob(&repository, EMPTY_CONFIG)
        .await
        .expect("the config blob uploads");
    let manifest = image_manifest("round-trip");
    let manifest_digest = registry
        .put_manifest(&repository, "v1", &manifest)
        .await
        .expect("the manifest uploads");
    assert_eq!(manifest_digest, sha256_of(&manifest));

    let by_tag = registry
        .manifest(&repository, "v1", MAX_BODY)
        .await
        .expect("the manifest reads back by tag");
    assert_eq!(by_tag.bytes, manifest);
    assert_eq!(by_tag.digest, manifest_digest);
    let by_digest = registry
        .manifest(&repository, manifest_digest.as_str(), MAX_BODY)
        .await
        .expect("the manifest reads back by digest");
    assert_eq!(by_digest.bytes, manifest);
    assert_eq!(by_digest.digest, manifest_digest);

    let tags = registry.tags(&repository).await.expect("the tags list");
    assert!(tags.iter().any(|tag| tag == "v1"), "{tags:?}");
}

/// `push_signature` stores a `.sig` that `cosign_signatures` reads back and `verify` accepts.
async fn pushed_signature_round_trips(registry: &impl ReleaseRegistry, host: &str) {
    let repository = unique_repository(host, "signature");
    // The signed object and the empty config the signature manifest points at.
    registry
        .put_blob(&repository, EMPTY_CONFIG)
        .await
        .expect("the config blob uploads");
    let image_digest = registry
        .put_manifest(&repository, "v1", &image_manifest("signature"))
        .await
        .expect("the signed manifest uploads");
    let image = image_in(&repository, "v1");

    let key = TestSigningKey::generate().expect("a test key generates");
    push_signature(
        registry,
        &repository,
        &image,
        &image_digest,
        key.signing_key(),
    )
    .await
    .expect("the signature uploads");

    let signatures = registry
        .cosign_signatures(&image, image_digest.as_digest())
        .await
        .expect("the signature reads back");
    assert_eq!(signatures.len(), 1, "{signatures:?}");
    crate::verify(
        &signatures[0],
        key.public_key(),
        &image,
        image_digest.as_digest(),
    )
    .expect("the stored signature verifies");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{FakeRegistry, FakeReleaseRegistry};

    const FAKE_HOST: &str = "registry.example.com";

    #[tokio::test]
    async fn the_unsigned_scripted_fake_passes_the_registry_suite() {
        registry_suite(&FakeRegistry::without_signature_tag(), FAKE_HOST).await;
    }

    #[tokio::test]
    async fn the_release_fake_passes_the_release_registry_suite() {
        release_registry_suite(&FakeReleaseRegistry::new(), FAKE_HOST).await;
    }
}
