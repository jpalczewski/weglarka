//! Publish, verify and reconcile release sets through the shared registry transport.
//!
//! The publisher and the runtime verifier are one implementation: every document is parsed with
//! [`weglarka_model::release_set`], every blob is fetched by digest with a size cap, and every
//! signature is checked with [`weglarka_registry::verify`] against the pinned key. No shell/JQ
//! pipeline builds or validates release bytes.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use weglarka_model::release_set::{
    Channel, Component, Descriptor, DescriptorContext, INDEX_MEDIA_TYPE, MAX_DESCRIPTOR_BYTES,
    MAX_MANIFEST_BYTES, Repository, StrictDigest, parse_descriptor, parse_manifest,
};
use weglarka_registry::{
    ImageRef, PublicKey, RegistryError, ReleaseRegistry, SigningKey, push_signature, verify,
};

use crate::assemble::{manifest_for, next_sequence, parse_set_tag, set_tag};

/// Label that names the component crate version inside an image.
pub const VERSION_LABEL: &str = "org.opencontainers.image.version";
/// A component image manifest is small; bound it explicitly.
const MAX_IMAGE_MANIFEST_BYTES: usize = 1024 * 1024;
/// An image config is a few KiB; bound it before parsing.
const MAX_IMAGE_CONFIG_BYTES: usize = 1024 * 1024;
/// The release-artifact config is exactly `{}`; never read more than a handful of bytes.
const MAX_ARTIFACT_CONFIG_BYTES: usize = 64;

/// A release-set repository turned into the `registry/repository` shape the signature identity
/// check uses. The tag is a placeholder: `verify` compares the repository only.
pub fn image_ref(repository: &Repository) -> Result<ImageRef> {
    let (registry, path) = repository
        .as_str()
        .split_once('/')
        .with_context(|| format!("repository {repository} has no host"))?;
    Ok(ImageRef {
        registry: registry.to_owned(),
        repository: path.to_owned(),
        tag: "release".to_owned(),
    })
}

/// A fully parsed release set plus the identities the caller needs.
#[derive(Debug, Clone)]
pub struct LoadedSet {
    pub descriptor: Descriptor,
    pub manifest_bytes: Vec<u8>,
    pub manifest_digest: StrictDigest,
    pub layer_digest: StrictDigest,
}

/// The accepted per-channel pointer, read from the channel tag.
#[derive(Debug, Clone)]
pub struct Pointer {
    pub sequence: u64,
    pub descriptor: Descriptor,
}

/// Outcome of publishing one immutable set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishOutcome {
    pub sequence: u64,
    pub release_set_digest: StrictDigest,
    /// `set-<channel>-<sequence>`: the immutable tag the signature is attached to.
    pub tag: String,
}

/// Outcome of moving the channel pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromoteOutcome {
    pub sequence: u64,
    pub release_set_digest: StrictDigest,
    pub revision: String,
    pub pointer_moved: bool,
    /// Set when the channel pointer already named an equal or higher sequence; the caller then
    /// runs reconciliation instead of forcing the pointer backwards.
    pub superseded_by: Option<u64>,
}

/// Outcome of reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileOutcome {
    pub moved_to: Option<u64>,
    /// Immutable tags skipped because they carry no signature (orphans of a crashed run).
    pub skipped: Vec<String>,
}

/// Fetches the signatures for `digest` and requires one to verify against `key`.
async fn require_signature<R: ReleaseRegistry + ?Sized>(
    registry: &R,
    repository: &Repository,
    digest: &StrictDigest,
    key: &PublicKey,
) -> Result<()> {
    let image = image_ref(repository)?;
    let signatures = match registry.cosign_signatures(&image, digest.as_digest()).await {
        Ok(signatures) => signatures,
        // No `.sig` tag at all is the same failure as an empty list: the image is unsigned.
        Err(error) if error.is_not_found() => Vec::new(),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("cannot fetch the cosign signature for {digest}"));
        }
    };
    if signatures.is_empty() {
        bail!(
            "{repository}@{digest} has no key-based cosign signature; \
             a release set must be signed with the static release key"
        );
    }
    let mut last = None;
    for signature in &signatures {
        match verify(signature, key, &image, digest.as_digest()) {
            Ok(()) => return Ok(()),
            Err(error) => last = Some(error.to_string()),
        }
    }
    bail!(
        "no cosign signature for {repository}@{digest} verifies against the pinned key: {}",
        last.unwrap_or_else(|| "no usable signature".to_owned())
    )
}

async fn has_signature<R: ReleaseRegistry + ?Sized>(
    registry: &R,
    repository: &Repository,
    digest: &StrictDigest,
) -> Result<bool> {
    let image = image_ref(repository)?;
    match registry.cosign_signatures(&image, digest.as_digest()).await {
        Ok(signatures) => Ok(!signatures.is_empty()),
        // No `.sig` tag at all: the image is unsigned, not a failed lookup.
        Err(error) if error.is_not_found() => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("cannot fetch the cosign signature for {digest}"))
        }
    }
}

/// Parses a fetched manifest and its two blobs, then the descriptor. Signature and component
/// checks are separate so a pointer read can stay cheap.
async fn decode_set<R: ReleaseRegistry + ?Sized>(
    registry: &R,
    repository: &Repository,
    bytes: Vec<u8>,
    digest: StrictDigest,
    context: &DescriptorContext,
) -> Result<LoadedSet> {
    let manifest = parse_manifest(&bytes)
        .map_err(|error| anyhow::anyhow!("invalid release-set manifest: {error}"))?;
    let config = registry
        .blob(
            repository,
            &manifest.config.digest,
            MAX_ARTIFACT_CONFIG_BYTES,
        )
        .await
        .with_context(|| {
            format!(
                "cannot fetch the artifact config {}",
                manifest.config.digest
            )
        })?;
    let layer_descriptor = manifest
        .descriptor_layer()
        .cloned()
        .context("the manifest carries no descriptor layer")?;
    let layer = registry
        .blob(repository, &layer_descriptor.digest, MAX_DESCRIPTOR_BYTES)
        .await
        .with_context(|| {
            format!(
                "cannot fetch the descriptor layer {}",
                layer_descriptor.digest
            )
        })?;
    manifest
        .verify_blobs(&layer, &config)
        .map_err(|error| anyhow::anyhow!("release-set blobs do not match the manifest: {error}"))?;
    let descriptor = parse_descriptor(&layer, context)
        .map_err(|error| anyhow::anyhow!("invalid release-set descriptor: {error}"))?;
    Ok(LoadedSet {
        descriptor,
        manifest_bytes: bytes,
        manifest_digest: digest,
        layer_digest: layer_descriptor.digest,
    })
}

/// Lenient view of an OCI image manifest; only the config pointer is used.
#[derive(Debug, Deserialize)]
struct ImageManifest {
    #[serde(rename = "mediaType", default)]
    media_type: String,
    #[serde(default)]
    config: Option<BlobRef>,
    #[serde(default)]
    manifests: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct BlobRef {
    #[serde(default)]
    digest: String,
    #[serde(default)]
    size: u64,
}

#[derive(Debug, Deserialize)]
struct ImageConfig {
    #[serde(default)]
    config: Option<ImageConfigInner>,
}

#[derive(Debug, Deserialize)]
struct ImageConfigInner {
    #[serde(rename = "Labels", default)]
    labels: std::collections::BTreeMap<String, String>,
}

/// Verifies one component image: exact manifest bytes for its digest, the version label, and its
/// own cosign signature in its own repository. An image index is rejected: v1 selects a single
/// linux/amd64/musl manifest, never an inherited multi-arch default.
async fn verify_component<R: ReleaseRegistry + ?Sized>(
    registry: &R,
    component: &Component,
    key: &PublicKey,
) -> Result<()> {
    let fetched = registry
        .manifest(
            &component.repository,
            component.digest.as_str(),
            MAX_IMAGE_MANIFEST_BYTES,
        )
        .await
        .with_context(|| {
            format!(
                "cannot fetch component image {}@{}",
                component.repository, component.digest
            )
        })?;
    if fetched.digest != component.digest {
        bail!(
            "component image {} resolved to {} instead of {}",
            component.repository,
            fetched.digest,
            component.digest
        );
    }
    let manifest: ImageManifest = serde_json::from_slice(&fetched.bytes).with_context(|| {
        format!(
            "component image {}@{} is not valid JSON",
            component.repository, component.digest
        )
    })?;
    if manifest.manifests.is_some() || manifest.media_type == INDEX_MEDIA_TYPE {
        bail!(
            "component image {}@{} is an image index, not a single image manifest",
            component.repository,
            component.digest
        );
    }
    let config_ref = manifest.config.with_context(|| {
        format!(
            "component image {}@{} has no config descriptor",
            component.repository, component.digest
        )
    })?;
    if config_ref.size > MAX_IMAGE_CONFIG_BYTES as u64 {
        bail!(
            "component config {} is {} bytes, the limit is {MAX_IMAGE_CONFIG_BYTES}",
            config_ref.digest,
            config_ref.size
        );
    }
    let config_digest = StrictDigest::new(config_ref.digest).with_context(|| {
        format!(
            "component {} has an invalid config digest",
            component.repository
        )
    })?;
    let config = registry
        .blob(
            &component.repository,
            &config_digest,
            MAX_IMAGE_CONFIG_BYTES,
        )
        .await
        .with_context(|| {
            format!(
                "cannot fetch the config of {}@{}",
                component.repository, component.digest
            )
        })?;
    let config: ImageConfig = serde_json::from_slice(&config).with_context(|| {
        format!(
            "the config of {}@{} is not valid JSON",
            component.repository, component.digest
        )
    })?;
    let labels = config.config.map(|inner| inner.labels).unwrap_or_default();
    let version = labels.get(VERSION_LABEL).with_context(|| {
        format!(
            "{}@{} has no {VERSION_LABEL} label",
            component.repository, component.digest
        )
    })?;
    if version != &component.version {
        bail!(
            "{}@{} declares {VERSION_LABEL}={version:?}, the descriptor says {:?}",
            component.repository,
            component.digest,
            component.version
        );
    }
    require_signature(registry, &component.repository, &component.digest, key).await?;
    Ok(())
}

/// The registry has no manifest under the channel tag itself (`main`/`stable`): the channel has
/// never been released. Any other "not found" (a set tag, a blob, a signature) is an ordinary
/// failure, so callers can tell a first release from a broken registry state.
#[derive(Debug, thiserror::Error)]
#[error("the {channel} channel tag {repository}:{channel} does not exist")]
pub struct ChannelTagMissing {
    pub channel: Channel,
    pub repository: Repository,
    #[source]
    pub source: RegistryError,
}

/// Full verification of a published set: signature over the manifest digest, exact manifest
/// bytes, the descriptor layer, and both component images with their version labels and
/// signatures.
///
/// `context.channel` binds the descriptor's own channel to the one the caller resolved.
///
/// A missing manifest under the channel tag itself fails with [`ChannelTagMissing`] (reachable
/// with `downcast_ref` through the added context); every other failure is an ordinary error.
pub async fn verify_reference<R: ReleaseRegistry + ?Sized>(
    registry: &R,
    repository: &Repository,
    reference: &str,
    context: DescriptorContext,
    key: &PublicKey,
) -> Result<LoadedSet> {
    let fetched = match registry
        .manifest(repository, reference, MAX_MANIFEST_BYTES)
        .await
    {
        Ok(fetched) => fetched,
        Err(source) if source.is_not_found() => {
            let error = match Channel::parse(reference) {
                Some(channel) => anyhow::Error::new(ChannelTagMissing {
                    channel,
                    repository: repository.clone(),
                    source,
                }),
                None => anyhow::Error::new(source),
            };
            return Err(error.context(format!("cannot resolve {repository}:{reference}")));
        }
        Err(source) => {
            return Err(anyhow::Error::new(source)
                .context(format!("cannot resolve {repository}:{reference}")));
        }
    };
    // Verify the signature over the digest before the layer is even fetched.
    require_signature(registry, repository, &fetched.digest, key).await?;
    let set = decode_set(
        registry,
        repository,
        fetched.bytes,
        fetched.digest,
        &context,
    )
    .await?;
    // An immutable tag must name the set it carries; a stale or hand-written tag is not a set.
    if let Some(sequence) = context
        .channel
        .and_then(|channel| parse_set_tag(channel, reference))
        && set.descriptor.sequence != sequence
    {
        bail!(
            "tag {reference} names sequence {sequence}, but its descriptor says {}",
            set.descriptor.sequence
        );
    }
    verify_component(registry, &set.descriptor.daemon, key).await?;
    verify_component(registry, &set.descriptor.panel, key).await?;
    Ok(set)
}

/// Reads the channel pointer. The pointer's own signature is required, but component images are
/// not re-verified here: allocation needs the authentic sequence, and full acceptance happens on
/// promotion.
pub async fn read_pointer<R: ReleaseRegistry + ?Sized>(
    registry: &R,
    repository: &Repository,
    channel: Channel,
    key: &PublicKey,
) -> Result<Option<Pointer>> {
    let fetched = match registry
        .manifest(repository, channel.as_str(), MAX_MANIFEST_BYTES)
        .await
    {
        Ok(fetched) => fetched,
        Err(error) if error.is_not_found() => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("cannot read the {channel} pointer"));
        }
    };
    require_signature(registry, repository, &fetched.digest, key).await?;
    let set = decode_set(
        registry,
        repository,
        fetched.bytes,
        fetched.digest,
        &DescriptorContext {
            channel: Some(channel),
        },
    )
    .await?;
    Ok(Some(Pointer {
        sequence: set.descriptor.sequence,
        descriptor: set.descriptor,
    }))
}

/// Publishes one immutable set: allocate the sequence and push the immutable tag (blobs first,
/// then the manifest). A signature is **not** written here: CI signs the manifest digest with the
/// existing static cosign key, exactly as it signs images, and only then calls [`promote`].
///
/// The promotion critical section is the workflow's per-channel concurrency group. This function
/// never moves the pointer and never overwrites an existing immutable tag.
pub async fn publish<R: ReleaseRegistry + ?Sized>(
    registry: &R,
    repository: &Repository,
    spec: &crate::assemble::ReleaseSpec,
    requested_sequence: Option<u64>,
) -> Result<PublishOutcome> {
    let pointer = read_pointer_structure(registry, repository, spec.channel).await?;
    let tags = registry
        .tags(repository)
        .await
        .context("cannot list the release-set tags")?;
    let next = next_sequence(
        spec.channel,
        pointer.as_ref().map(|pointer| pointer.descriptor.sequence),
        &tags,
    );
    let sequence = match requested_sequence {
        Some(sequence) if sequence >= next => sequence,
        Some(sequence) => {
            bail!("requested sequence {sequence} is already used; the next free sequence is {next}")
        }
        None => next,
    };
    let tag = set_tag(spec.channel, sequence);
    let layer = spec.descriptor_bytes(sequence)?;
    let (_manifest, manifest_bytes) = manifest_for(&layer)?;

    // An immutable tag is never overwritten. Identical bytes mean a retried run (crash after the
    // push, before the pointer move) and are reused; different bytes are a sequence collision.
    let release_set_digest = match registry
        .manifest(repository, &tag, MAX_MANIFEST_BYTES)
        .await
    {
        Ok(existing) if existing.bytes == manifest_bytes => existing.digest,
        Ok(existing) => bail!(
            "immutable tag {tag} already exists with manifest {}, refusing to overwrite it with {}",
            existing.digest,
            crate::assemble::sha256(&manifest_bytes)
        ),
        Err(error) if error.is_not_found() => {
            // Blobs first: the manifest is only stored once everything it references exists.
            registry
                .put_blob(repository, b"{}")
                .await
                .context("cannot upload the artifact config")?;
            registry
                .put_blob(repository, &layer)
                .await
                .context("cannot upload the descriptor layer")?;
            let digest = registry
                .put_manifest(repository, &tag, &manifest_bytes)
                .await
                .with_context(|| format!("cannot publish {tag}"))?;
            if digest != crate::assemble::sha256(&manifest_bytes) {
                bail!("the registry assigned an unexpected digest to {tag}");
            }
            digest
        }
        Err(error) => {
            return Err(error).with_context(|| format!("cannot check whether {tag} exists"));
        }
    };
    Ok(PublishOutcome {
        sequence,
        release_set_digest,
        tag,
    })
}

/// Reads only the descriptor structure of the channel pointer (no signature, no components).
///
/// Sequence allocation needs the authentic *sequence*, but it must also work before the first set
/// is signed. A missing tag is an empty channel; a present but malformed pointer is an error, never
/// silently treated as sequence zero.
async fn read_pointer_structure<R: ReleaseRegistry + ?Sized>(
    registry: &R,
    repository: &Repository,
    channel: Channel,
) -> Result<Option<LoadedSet>> {
    let fetched = match registry
        .manifest(repository, channel.as_str(), MAX_MANIFEST_BYTES)
        .await
    {
        Ok(fetched) => fetched,
        Err(error) if error.is_not_found() => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("cannot read the {channel} pointer"));
        }
    };
    let set = decode_set(
        registry,
        repository,
        fetched.bytes,
        fetched.digest,
        &DescriptorContext {
            channel: Some(channel),
        },
    )
    .await?;
    // A channel tag is a pointer, not a set: its sequence must be the one the registry can move,
    // so allocating above it is always safe. The signature is checked on `promote`.
    Ok(Some(set))
}

/// Attaches the legacy cosign signature to an already-published immutable set. Used by local and
/// test flows that hold the key; CI runs `cosign sign` with the existing secret instead.
pub async fn sign<R: ReleaseRegistry + ?Sized>(
    registry: &R,
    repository: &Repository,
    digest: &StrictDigest,
    key: &SigningKey,
) -> Result<()> {
    push_signature(registry, repository, &image_ref(repository)?, digest, key)
        .await
        .with_context(|| format!("cannot sign {repository}@{digest}"))
}

/// Verifies a published immutable set with the runtime verifier and only then moves the channel
/// pointer forward.
///
/// The pointer is re-read after verification: a newer promotion that won the race is never
/// overwritten, and an older sequence never moves the channel backwards.
pub async fn promote<R: ReleaseRegistry + ?Sized>(
    registry: &R,
    repository: &Repository,
    channel: Channel,
    tag: &str,
    key: &PublicKey,
) -> Result<PromoteOutcome> {
    let sequence = parse_set_tag(channel, tag).with_context(|| {
        format!(
            "{tag} is not set-{}-<sequence>; only immutable sets are promoted",
            channel
        )
    })?;
    let set = verify_reference(
        registry,
        repository,
        tag,
        DescriptorContext {
            channel: Some(channel),
        },
        key,
    )
    .await
    .with_context(|| format!("the published set {tag} does not verify"))?;
    if set.descriptor.sequence != sequence {
        bail!(
            "tag {tag} names sequence {sequence}, but its descriptor says {}",
            set.descriptor.sequence
        );
    }
    let current = read_pointer(registry, repository, channel, key).await?;
    let mut pointer_moved = false;
    let mut superseded_by = None;
    match current {
        Some(pointer) if pointer.sequence >= sequence => {
            superseded_by = Some(pointer.sequence);
        }
        _ => {
            registry
                .put_manifest(repository, channel.as_str(), &set.manifest_bytes)
                .await
                .with_context(|| format!("cannot move the {channel} pointer"))?;
            pointer_moved = true;
        }
    }
    Ok(PromoteOutcome {
        sequence,
        release_set_digest: set.manifest_digest,
        revision: set.descriptor.revision,
        pointer_moved,
        superseded_by,
    })
}

/// Moves the channel pointer to the highest *complete* set above the current pointer.
///
/// An unsigned immutable tag is an orphan of a crashed run and is skipped (the next publish
/// allocates above it). A tag that carries a signature but does not verify aborts: that is either
/// tampering or a broken publication, not an orphan.
pub async fn reconcile<R: ReleaseRegistry + ?Sized>(
    registry: &R,
    repository: &Repository,
    channel: Channel,
    key: &PublicKey,
) -> Result<ReconcileOutcome> {
    let pointer = read_pointer(registry, repository, channel, key).await?;
    let current = pointer
        .as_ref()
        .map(|pointer| pointer.sequence)
        .unwrap_or(0);
    let tags = registry
        .tags(repository)
        .await
        .context("cannot list the release-set tags")?;
    let mut candidates: Vec<(u64, String)> = tags
        .iter()
        .filter_map(|tag| parse_set_tag(channel, tag).map(|sequence| (sequence, tag.clone())))
        .filter(|(sequence, _)| *sequence > current)
        .collect();
    candidates.sort_by_key(|(sequence, _)| std::cmp::Reverse(*sequence));
    let mut skipped = Vec::new();
    for (_sequence, tag) in candidates {
        // The pointer read above already proved the current set's signature. For a candidate, a
        // missing signature is the expected crash orphan; a present-but-invalid one is fatal.
        let fetched = match registry
            .manifest(repository, &tag, MAX_MANIFEST_BYTES)
            .await
        {
            Ok(fetched) => fetched,
            Err(error) if error.is_not_found() => {
                skipped.push(tag);
                continue;
            }
            Err(error) => return Err(error).with_context(|| format!("cannot read {tag}")),
        };
        if !has_signature(registry, repository, &fetched.digest).await? {
            skipped.push(tag);
            continue;
        }
        let outcome = promote(registry, repository, channel, &tag, key)
            .await
            .with_context(|| {
                format!(
                    "newer signed release set {tag} does not verify; refusing to reconcile past it"
                )
            })?;
        if outcome.pointer_moved {
            return Ok(ReconcileOutcome {
                moved_to: Some(outcome.sequence),
                skipped,
            });
        }
        // The pointer moved past it between the listing and the verification; nothing to do.
        return Ok(ReconcileOutcome {
            moved_to: None,
            skipped,
        });
    }
    Ok(ReconcileOutcome {
        moved_to: None,
        skipped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use weglarka_model::release_set::{DescriptorContext, HostFile, Repository};
    use weglarka_registry::Registry as _;
    use weglarka_registry::testing::{FakeReleaseRegistry, TestSigningKey};

    use crate::assemble::{ReleaseSpec, compatibility, component, manifest_for, set_tag, sha256};

    const DAEMON_REPO: &str = "ghcr.io/example/weglarka";
    const PANEL_REPO: &str = "ghcr.io/example/weglarka-panel";
    const RELEASE_REPO: &str = "ghcr.io/example/releases";
    const REVISION: &str = "0123456789abcdef0123456789abcdef01234567";

    async fn image(
        registry: &FakeReleaseRegistry,
        repository: &str,
        version: &str,
        key: &SigningKey,
    ) -> StrictDigest {
        let repository = Repository::new(repository).unwrap();
        let config = serde_json::to_vec(&json!({
            "architecture": "amd64",
            "os": "linux",
            "config": { "Labels": {
                "org.opencontainers.image.version": version,
                "org.opencontainers.image.revision": "feedface",
            } },
        }))
        .unwrap();
        let config_digest = registry.put_blob(&repository, &config).await.unwrap();
        let manifest = serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest.as_str(),
                "size": config.len(),
            },
            "layers": [],
        }))
        .unwrap();
        let digest = registry
            .put_manifest(&repository, &format!("image-{version}"), &manifest)
            .await
            .unwrap();
        push_signature(
            registry,
            &repository,
            &image_ref(&repository).unwrap(),
            &digest,
            key,
        )
        .await
        .unwrap();
        digest
    }

    async fn image_index(registry: &FakeReleaseRegistry, repository: &str) -> StrictDigest {
        let repository = Repository::new(repository).unwrap();
        let bytes = serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "mediaType": INDEX_MEDIA_TYPE,
            "manifests": [],
        }))
        .unwrap();
        registry
            .put_manifest(&repository, "index", &bytes)
            .await
            .unwrap()
    }

    fn host_files() -> Vec<HostFile> {
        vec![
            HostFile {
                name: "weglarka-daemon".into(),
                path: "/usr/local/bin/weglarka-daemon".into(),
                version: "0.9.0".into(),
                size: 4_000_000,
                digest: sha256(b"daemon binary"),
            },
            HostFile {
                name: "weglarka".into(),
                path: "/usr/local/bin/weglarka".into(),
                version: "0.8.0".into(),
                size: 3_000_000,
                digest: sha256(b"cli binary"),
            },
        ]
    }

    fn spec(
        daemon: StrictDigest,
        panel: StrictDigest,
        panel_version: &str,
        tested: Vec<StrictDigest>,
    ) -> ReleaseSpec {
        ReleaseSpec {
            channel: Channel::Stable,
            revision: REVISION.to_owned(),
            daemon: component(DAEMON_REPO, daemon.as_str(), "0.9.0").unwrap(),
            panel: component(PANEL_REPO, panel.as_str(), panel_version).unwrap(),
            host_files: host_files(),
            compatibility: compatibility(vec![17], 17, tested.clone(), &panel).unwrap(),
        }
    }

    fn stable() -> DescriptorContext {
        DescriptorContext {
            channel: Some(Channel::Stable),
        }
    }

    fn repo() -> Repository {
        Repository::new(RELEASE_REPO).unwrap()
    }

    /// The CI sequence: publish the immutable set, sign it, then verify and promote.
    async fn publish_signed(
        registry: &FakeReleaseRegistry,
        spec: &ReleaseSpec,
        key: &TestSigningKey,
    ) -> Result<(PublishOutcome, PromoteOutcome)> {
        let published = publish(registry, &repo(), spec, None).await?;
        sign(
            registry,
            &repo(),
            &published.release_set_digest,
            key.signing_key(),
        )
        .await?;
        let promoted = promote(
            registry,
            &repo(),
            Channel::Stable,
            &published.tag,
            key.public_key(),
        )
        .await?;
        Ok((published, promoted))
    }

    async fn verify_stable(
        registry: &FakeReleaseRegistry,
        key: &TestSigningKey,
    ) -> Result<LoadedSet> {
        verify_reference(registry, &repo(), "stable", stable(), key.public_key()).await
    }

    #[tokio::test]
    async fn panel_only_release_keeps_the_daemon_artifact_and_truthful_versions() {
        let key = TestSigningKey::generate().unwrap();
        let registry = FakeReleaseRegistry::new();
        let daemon = image(&registry, DAEMON_REPO, "0.9.0", key.signing_key()).await;
        let panel = image(&registry, PANEL_REPO, "0.3.0", key.signing_key()).await;
        let (first, promoted) = publish_signed(
            &registry,
            &spec(daemon.clone(), panel.clone(), "0.3.0", vec![panel.clone()]),
            &key,
        )
        .await
        .unwrap();
        assert_eq!(first.sequence, 1);
        assert!(promoted.pointer_moved);
        assert_eq!(promoted.revision, REVISION);
        let loaded = verify_stable(&registry, &key).await.unwrap();
        assert_eq!(loaded.descriptor.sequence, 1);

        // A panel-only release: same daemon image (and host files), new panel version.
        let new_panel = image(&registry, PANEL_REPO, "0.4.0", key.signing_key()).await;
        let mut next = spec(
            daemon.clone(),
            new_panel.clone(),
            "0.4.0",
            vec![new_panel.clone(), panel.clone()],
        );
        next.reuse_daemon(&loaded.descriptor);
        let (second, _) = publish_signed(&registry, &next, &key).await.unwrap();
        assert_eq!(second.sequence, 2);

        let promoted = verify_stable(&registry, &key).await.unwrap();
        assert_eq!(promoted.descriptor.daemon.digest, daemon);
        assert_eq!(promoted.descriptor.daemon.version, "0.9.0");
        assert_eq!(promoted.descriptor.panel.digest, new_panel);
        assert_eq!(promoted.descriptor.panel.version, "0.4.0");
        assert_eq!(
            promoted.descriptor.host_tools.files,
            loaded.descriptor.host_tools.files
        );
        assert_eq!(promoted.descriptor.sequence, 2);
        // The old immutable tag was not overwritten.
        assert!(registry.manifest_bytes(&repo(), "set-stable-1").is_some());
    }

    #[tokio::test]
    async fn a_missing_component_artifact_prevents_promotion() {
        let key = TestSigningKey::generate().unwrap();
        let registry = FakeReleaseRegistry::new();
        let daemon = image(&registry, DAEMON_REPO, "0.9.0", key.signing_key()).await;
        let missing = sha256(b"an image that was never pushed");
        let error = publish_signed(
            &registry,
            &spec(daemon, missing.clone(), "0.4.0", vec![missing]),
            &key,
        )
        .await
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("cannot fetch component image"),
            "{error:#}"
        );
        // The channel pointer is only moved after the whole set verifies.
        assert!(
            read_pointer(&registry, &repo(), Channel::Stable, key.public_key())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn an_image_index_is_not_a_component() {
        let key = TestSigningKey::generate().unwrap();
        let registry = FakeReleaseRegistry::new();
        let daemon = image(&registry, DAEMON_REPO, "0.9.0", key.signing_key()).await;
        let index = image_index(&registry, PANEL_REPO).await;
        let error = publish_signed(
            &registry,
            &spec(daemon, index.clone(), "0.4.0", vec![index]),
            &key,
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("image index"), "{error:#}");
    }

    #[tokio::test]
    async fn a_version_label_mismatch_is_rejected() {
        let key = TestSigningKey::generate().unwrap();
        let registry = FakeReleaseRegistry::new();
        let daemon = image(&registry, DAEMON_REPO, "0.9.0", key.signing_key()).await;
        // The image inside says 0.3.9, the descriptor claims 0.4.0.
        let panel = image(&registry, PANEL_REPO, "0.3.9", key.signing_key()).await;
        let error = publish_signed(
            &registry,
            &spec(daemon, panel.clone(), "0.4.0", vec![panel]),
            &key,
        )
        .await
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("org.opencontainers.image.version"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn only_a_missing_channel_tag_is_reported_as_a_missing_channel() {
        let key = TestSigningKey::generate().unwrap();
        let registry = FakeReleaseRegistry::new();

        // Nothing published: the channel tag itself is absent.
        let error = verify_stable(&registry, &key).await.unwrap_err();
        let missing = error
            .downcast_ref::<ChannelTagMissing>()
            .unwrap_or_else(|| panic!("not a missing channel tag: {error:#}"));
        assert_eq!(missing.channel, Channel::Stable);
        assert!(missing.source.is_not_found());

        // A missing immutable set tag is a 404 too, but not the channel pointer.
        let error = verify_reference(
            &registry,
            &repo(),
            "set-stable-1",
            stable(),
            key.public_key(),
        )
        .await
        .unwrap_err();
        assert!(error.downcast_ref::<ChannelTagMissing>().is_none());
        assert!(
            error
                .downcast_ref::<RegistryError>()
                .is_some_and(RegistryError::is_not_found),
            "{error:#}"
        );

        // A channel manifest without a signature: a failure, not a missing channel.
        let layer = br#"{}"#;
        let (_, manifest) = manifest_for(layer).unwrap();
        registry
            .put_manifest(&repo(), "stable", &manifest)
            .await
            .unwrap();
        let error = verify_stable(&registry, &key).await.unwrap_err();
        assert!(error.downcast_ref::<ChannelTagMissing>().is_none());
        assert!(
            format!("{error:#}").contains("no key-based cosign signature"),
            "{error:#}"
        );

        // A signed channel manifest whose descriptor blob was never pushed: also a 404, also not
        // a missing channel.
        let digest = sha256(&manifest);
        push_signature(
            &registry,
            &repo(),
            &image_ref(&repo()).unwrap(),
            &digest,
            key.signing_key(),
        )
        .await
        .unwrap();
        let error = verify_stable(&registry, &key).await.unwrap_err();
        assert!(error.downcast_ref::<ChannelTagMissing>().is_none());
        assert!(
            error
                .chain()
                .filter_map(|cause| cause.downcast_ref::<RegistryError>())
                .any(RegistryError::is_not_found),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn a_missing_signature_tag_is_unsigned_not_a_failed_lookup() {
        let key = TestSigningKey::generate().unwrap();
        let registry = FakeReleaseRegistry::new();
        let repository = Repository::new(DAEMON_REPO).unwrap();
        let digest = image_index(&registry, DAEMON_REPO).await;

        // The fake answers a missing `.sig` tag with the 404 the HTTP client returns.
        let image = image_ref(&repository).unwrap();
        let error = registry
            .cosign_signatures(&image, digest.as_digest())
            .await
            .unwrap_err();
        assert!(error.is_not_found(), "{error}");

        assert!(
            !has_signature(&registry, &repository, &digest)
                .await
                .unwrap()
        );

        // Verification still fails closed, with the unsigned-image message.
        let error = require_signature(&registry, &repository, &digest, key.public_key())
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("no key-based cosign signature"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn an_unreadable_signature_manifest_is_still_a_failed_lookup() {
        let key = TestSigningKey::generate().unwrap();
        let registry = FakeReleaseRegistry::new();
        let repository = Repository::new(DAEMON_REPO).unwrap();
        let digest = image_index(&registry, DAEMON_REPO).await;
        let tag = format!("{}.sig", digest.as_str().replace(':', "-"));
        registry
            .put_manifest(&repository, &tag, b"not json")
            .await
            .unwrap();

        let error = has_signature(&registry, &repository, &digest)
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("cannot fetch the cosign signature"),
            "{error:#}"
        );
        let error = require_signature(&registry, &repository, &digest, key.public_key())
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("cannot fetch the cosign signature"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn byte_tampering_or_a_wrong_repository_invalidates_the_set() {
        let key = TestSigningKey::generate().unwrap();
        let registry = FakeReleaseRegistry::new();
        let daemon = image(&registry, DAEMON_REPO, "0.9.0", key.signing_key()).await;
        let panel = image(&registry, PANEL_REPO, "0.3.0", key.signing_key()).await;
        publish_signed(
            &registry,
            &spec(daemon, panel.clone(), "0.3.0", vec![panel]),
            &key,
        )
        .await
        .unwrap();

        // A different key does not verify the published set.
        let other = TestSigningKey::generate().unwrap();
        assert!(verify_stable(&registry, &other).await.is_err());

        // Tampering with the channel manifest changes its digest, so the existing `.sig` no longer
        // hangs off it.
        let bytes = registry.manifest_bytes(&repo(), "stable").unwrap();
        let mut tampered = bytes.clone();
        tampered.push(b' ');
        registry
            .put_manifest(&repo(), "stable", &tampered)
            .await
            .unwrap();
        let error = verify_stable(&registry, &key).await.unwrap_err();
        assert!(
            format!("{error:#}").contains("no key-based cosign signature"),
            "{error:#}"
        );

        // A signature made for another repository is rejected even for the right digest.
        registry
            .put_manifest(&repo(), "stable", &bytes)
            .await
            .unwrap();
        let digest = sha256(&bytes);
        let elsewhere = Repository::new("ghcr.io/example/other").unwrap();
        push_signature(
            &registry,
            &repo(),
            &image_ref(&elsewhere).unwrap(),
            &digest,
            key.signing_key(),
        )
        .await
        .unwrap();
        let error = verify_stable(&registry, &key).await.unwrap_err();
        assert!(
            format!("{error:#}").contains("not for the repository"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn a_crash_between_tag_push_and_pointer_move_allocates_the_next_sequence() {
        let key = TestSigningKey::generate().unwrap();
        let registry = FakeReleaseRegistry::new();
        let daemon = image(&registry, DAEMON_REPO, "0.9.0", key.signing_key()).await;
        let panel = image(&registry, PANEL_REPO, "0.3.0", key.signing_key()).await;
        let spec = spec(daemon, panel.clone(), "0.3.0", vec![panel]);
        let (first, _) = publish_signed(&registry, &spec, &key).await.unwrap();
        assert_eq!(first.sequence, 1);

        // Simulate a crash: the immutable tag for sequence 2 exists, the pointer still says 1.
        let layer = spec.descriptor_bytes(2).unwrap();
        let (_, manifest) = manifest_for(&layer).unwrap();
        registry.put_blob(&repo(), b"{}").await.unwrap();
        registry.put_blob(&repo(), &layer).await.unwrap();
        registry
            .put_manifest(&repo(), &set_tag(Channel::Stable, 2), &manifest)
            .await
            .unwrap();

        let (next, _) = publish_signed(&registry, &spec, &key).await.unwrap();
        assert_eq!(next.sequence, 3);
        let loaded = verify_stable(&registry, &key).await.unwrap();
        assert_eq!(loaded.descriptor.sequence, 3);
    }

    #[tokio::test]
    async fn an_existing_sequence_with_different_bytes_is_never_overwritten() {
        let key = TestSigningKey::generate().unwrap();
        let registry = FakeReleaseRegistry::new();
        let daemon = image(&registry, DAEMON_REPO, "0.9.0", key.signing_key()).await;
        let panel = image(&registry, PANEL_REPO, "0.3.0", key.signing_key()).await;
        let first = spec(daemon.clone(), panel.clone(), "0.3.0", vec![panel.clone()]);
        publish_signed(&registry, &first, &key).await.unwrap();

        // A distinct set claimed sequence 2, but this run's allocation did not see the tag (a
        // concurrent push or a stale listing). The immutable bytes must win.
        let other_panel = image(&registry, PANEL_REPO, "0.5.0", key.signing_key()).await;
        let other = spec(
            daemon,
            other_panel.clone(),
            "0.5.0",
            vec![other_panel.clone(), panel],
        );
        // The tag holds the *older* spec's bytes for sequence 2.
        let layer = first.descriptor_bytes(2).unwrap();
        let (_, manifest) = manifest_for(&layer).unwrap();
        registry.put_blob(&repo(), b"{}").await.unwrap();
        registry.put_blob(&repo(), &layer).await.unwrap();
        registry
            .put_manifest(&repo(), &set_tag(Channel::Stable, 2), &manifest)
            .await
            .unwrap();
        registry.hide_tag(&repo(), &set_tag(Channel::Stable, 2));

        let error = publish(&registry, &repo(), &other, Some(2))
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("refusing to overwrite"),
            "{error:#}"
        );
        // The original immutable bytes are still in place.
        assert_eq!(
            registry
                .manifest_bytes(&repo(), &set_tag(Channel::Stable, 2))
                .unwrap(),
            manifest
        );
    }

    #[tokio::test]
    async fn an_older_workflow_cannot_move_the_channel_backward() {
        let key = TestSigningKey::generate().unwrap();
        let registry = FakeReleaseRegistry::new();
        let daemon = image(&registry, DAEMON_REPO, "0.9.0", key.signing_key()).await;
        let panel = image(&registry, PANEL_REPO, "0.3.0", key.signing_key()).await;
        let spec = spec(daemon, panel.clone(), "0.3.0", vec![panel]);
        publish_signed(&registry, &spec, &key).await.unwrap();
        publish_signed(&registry, &spec, &key).await.unwrap();

        // Replaying an old sequence is refused, not rewritten under the same immutable tag.
        let error = publish(&registry, &repo(), &spec, Some(1))
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("already used"), "{error:#}");
        let loaded = verify_stable(&registry, &key).await.unwrap();
        assert_eq!(loaded.descriptor.sequence, 2);

        // Promoting an older tag never moves a newer pointer backwards.
        let outcome = promote(
            &registry,
            &repo(),
            Channel::Stable,
            "set-stable-1",
            key.public_key(),
        )
        .await
        .unwrap();
        assert!(!outcome.pointer_moved);
        assert_eq!(outcome.superseded_by, Some(2));
        assert_eq!(
            verify_stable(&registry, &key)
                .await
                .unwrap()
                .descriptor
                .sequence,
            2
        );
    }

    #[tokio::test]
    async fn reconcile_moves_a_superseded_pointer_to_the_newest_complete_set() {
        let key = TestSigningKey::generate().unwrap();
        let registry = FakeReleaseRegistry::new();
        let daemon = image(&registry, DAEMON_REPO, "0.9.0", key.signing_key()).await;
        let panel = image(&registry, PANEL_REPO, "0.3.0", key.signing_key()).await;
        let spec = spec(daemon, panel.clone(), "0.3.0", vec![panel]);
        publish_signed(&registry, &spec, &key).await.unwrap();

        // Another run published a complete set 2 but its pointer move was lost.
        let layer = spec.descriptor_bytes(2).unwrap();
        let (_, manifest) = manifest_for(&layer).unwrap();
        registry.put_blob(&repo(), b"{}").await.unwrap();
        registry.put_blob(&repo(), &layer).await.unwrap();
        let digest = registry
            .put_manifest(&repo(), &set_tag(Channel::Stable, 2), &manifest)
            .await
            .unwrap();
        push_signature(
            &registry,
            &repo(),
            &image_ref(&repo()).unwrap(),
            &digest,
            key.signing_key(),
        )
        .await
        .unwrap();

        let outcome = reconcile(&registry, &repo(), Channel::Stable, key.public_key())
            .await
            .unwrap();
        assert_eq!(outcome.moved_to, Some(2));
        let loaded = verify_stable(&registry, &key).await.unwrap();
        assert_eq!(loaded.descriptor.sequence, 2);
    }

    #[tokio::test]
    async fn reconcile_skips_an_unsigned_orphan_and_refuses_a_signed_invalid_set() {
        let key = TestSigningKey::generate().unwrap();
        let registry = FakeReleaseRegistry::new();
        let daemon = image(&registry, DAEMON_REPO, "0.9.0", key.signing_key()).await;
        let panel = image(&registry, PANEL_REPO, "0.3.0", key.signing_key()).await;
        let spec = spec(daemon, panel.clone(), "0.3.0", vec![panel]);
        publish_signed(&registry, &spec, &key).await.unwrap();

        // Sequence 2 is complete and signed.
        let layer = spec.descriptor_bytes(2).unwrap();
        let (_, manifest) = manifest_for(&layer).unwrap();
        registry.put_blob(&repo(), b"{}").await.unwrap();
        registry.put_blob(&repo(), &layer).await.unwrap();
        let digest = registry
            .put_manifest(&repo(), &set_tag(Channel::Stable, 2), &manifest)
            .await
            .unwrap();
        push_signature(
            &registry,
            &repo(),
            &image_ref(&repo()).unwrap(),
            &digest,
            key.signing_key(),
        )
        .await
        .unwrap();

        // Sequence 3 is the crash orphan: the tag exists, no signature yet.
        let layer = spec.descriptor_bytes(3).unwrap();
        let (_, manifest) = manifest_for(&layer).unwrap();
        registry.put_blob(&repo(), &layer).await.unwrap();
        registry
            .put_manifest(&repo(), &set_tag(Channel::Stable, 3), &manifest)
            .await
            .unwrap();

        let outcome = reconcile(&registry, &repo(), Channel::Stable, key.public_key())
            .await
            .unwrap();
        assert_eq!(outcome.moved_to, Some(2));
        assert_eq!(outcome.skipped, vec!["set-stable-3".to_owned()]);

        // A signed set 4 that does not verify is not silently skipped.
        let mut broken = spec.clone();
        broken.panel.version = "9.9.9".to_owned();
        let layer = broken.descriptor_bytes(4).unwrap();
        let (_, manifest) = manifest_for(&layer).unwrap();
        registry.put_blob(&repo(), &layer).await.unwrap();
        let digest = registry
            .put_manifest(&repo(), &set_tag(Channel::Stable, 4), &manifest)
            .await
            .unwrap();
        push_signature(
            &registry,
            &repo(),
            &image_ref(&repo()).unwrap(),
            &digest,
            key.signing_key(),
        )
        .await
        .unwrap();
        let error = reconcile(&registry, &repo(), Channel::Stable, key.public_key())
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("refusing to reconcile"),
            "{error:#}"
        );
    }
}
