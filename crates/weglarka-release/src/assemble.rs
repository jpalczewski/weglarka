//! Descriptor assembly: crate versions, host-file hashes, the OCI manifest and the per-channel
//! sequence.
//!
//! Everything here is offline and pure: the registry is not contacted. `publish` combines these
//! pieces with the transport in `weglarka-registry`; both use [`parse_descriptor`] and
//! [`parse_manifest`] to validate what was built, so assembly cannot produce a document the host
//! would reject.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use semver::Version;
use sha2::{Digest as _, Sha256};
use weglarka_model::release_set::{
    Channel, Compatibility, Component, DESCRIPTOR_MEDIA_TYPE, Descriptor, EMPTY_CONFIG_DIGEST,
    EMPTY_CONFIG_MEDIA_TYPE, HOST_FILES, HostFile, HostTools, MANIFEST_MEDIA_TYPE,
    MAX_DESCRIPTOR_BYTES, MAX_HOST_FILE_BYTES, Manifest, ManifestDescriptor, Repository,
    StrictDigest, Target, parse_descriptor, parse_manifest,
};

/// The release-set artifact repository. The contract fixes this repository; the publisher takes it
/// as a parameter so tests use a fake, but the workflow passes this constant.
pub const RELEASE_REPOSITORY: &str = "ghcr.io/jpalczewski/weglarka-releases";

/// Default crate directories relative to the repository root.
pub const DAEMON_CRATE: &str = "crates/weglarka-daemon";
pub const PANEL_CRATE: &str = "crates/weglarka-panel";
pub const CLI_CRATE: &str = "crates/weglarka-cli";

/// A digest of `bytes` as the strict canonical form the contract requires.
pub fn sha256(bytes: &[u8]) -> StrictDigest {
    StrictDigest::new(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
        .expect("a computed SHA-256 is always canonical")
}

/// Reads `[package].version` from a crate directory and checks it is semver. This is the only
/// source of component versions in the release path: the workflow passes the crate directories,
/// never a tag or a metadata-action output.
pub fn crate_version(directory: &Path) -> Result<String> {
    let manifest = directory.join("Cargo.toml");
    let text = fs::read_to_string(&manifest)
        .with_context(|| format!("cannot read {}", manifest.display()))?;
    let document: toml::Value = toml::from_str(&text)
        .with_context(|| format!("{} is not valid TOML", manifest.display()))?;
    let version = document
        .get("package")
        .and_then(|package| package.get("version"))
        .and_then(toml::Value::as_str)
        .with_context(|| format!("{} has no [package] version", manifest.display()))?;
    Version::parse(version)
        .with_context(|| format!("{} version {version:?} is not semver", manifest.display()))?;
    Ok(version.to_owned())
}

/// One host-tool binary read from disk and hashed for the descriptor.
///
/// `name` must be one of the two contract constants; the in-image path is derived from it, not
/// supplied by the caller.
pub fn host_file(name: &str, binary: &Path, version: &str) -> Result<HostFile> {
    let path = HOST_FILES
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, path)| (*path).to_owned())
        .with_context(|| {
            format!("unknown host file {name:?}; expected one of the contract names")
        })?;
    let metadata =
        fs::metadata(binary).with_context(|| format!("cannot stat {}", binary.display()))?;
    if !metadata.is_file() {
        bail!("{} is not a regular file", binary.display());
    }
    if metadata.len() == 0 || metadata.len() > MAX_HOST_FILE_BYTES {
        bail!(
            "{} is {} bytes, the contract allows 1..={MAX_HOST_FILE_BYTES}",
            binary.display(),
            metadata.len()
        );
    }
    let bytes = fs::read(binary).with_context(|| format!("cannot read {}", binary.display()))?;
    Ok(HostFile {
        name: name.to_owned(),
        path,
        version: version.to_owned(),
        size: bytes.len() as u64,
        digest: sha256(&bytes),
    })
}

/// Everything one release set declares apart from its sequence.
#[derive(Debug, Clone)]
pub struct ReleaseSpec {
    pub channel: Channel,
    pub revision: String,
    pub daemon: Component,
    pub panel: Component,
    pub host_files: Vec<HostFile>,
    pub compatibility: Compatibility,
}

/// Which component a partial release reuses from the previous promoted set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReuseComponent {
    Daemon,
    Panel,
}

impl ReleaseSpec {
    /// The descriptor for `sequence`, with the host-tools image pinned to the daemon image (the
    /// contract's v1 rule: the tools come from the selected daemon image).
    pub fn descriptor(&self, sequence: u64) -> Descriptor {
        Descriptor {
            format_version: weglarka_model::release_set::FORMAT_VERSION,
            channel: self.channel,
            sequence,
            revision: self.revision.clone(),
            target: Target {
                os: "linux".to_owned(),
                architecture: "amd64".to_owned(),
                abi: "musl".to_owned(),
            },
            daemon: self.daemon.clone(),
            panel: self.panel.clone(),
            host_tools: HostTools {
                repository: self.daemon.repository.clone(),
                digest: self.daemon.digest.clone(),
                files: self.host_files.clone(),
            },
            compatibility: self.compatibility.clone(),
        }
    }

    /// Serializes the descriptor and re-parses it through the shared parser. The returned bytes are
    /// the ones the OCI layer carries (never re-serialized by the caller).
    pub fn descriptor_bytes(&self, sequence: u64) -> Result<Vec<u8>> {
        let descriptor = self.descriptor(sequence);
        let bytes = serde_json::to_vec(&descriptor).context("cannot serialize the descriptor")?;
        parse_descriptor(
            &bytes,
            &weglarka_model::release_set::DescriptorContext {
                channel: Some(self.channel),
            },
        )
        .map_err(|error| {
            anyhow::anyhow!("assembled descriptor is rejected by the parser: {error}")
        })?;
        Ok(bytes)
    }

    /// Copies one component's whole descriptor from `previous`: its repository, digest and
    /// version, and — for the daemon — the host files it ships and the state schemas it reads and
    /// writes. Used for a partial release: the unchanged component image must not be re-derived
    /// (and must not be relabeled under a new tag).
    pub fn reuse(&mut self, component: ReuseComponent, previous: &Descriptor) {
        match component {
            ReuseComponent::Daemon => {
                self.daemon = previous.daemon.clone();
                self.host_files = previous.host_tools.files.clone();
                self.compatibility.state_read = previous.compatibility.state_read.clone();
                self.compatibility.state_write = previous.compatibility.state_write;
            }
            ReuseComponent::Panel => {
                self.panel = previous.panel.clone();
            }
        }
    }

    /// Reuses the daemon's whole descriptor (see [`Self::reuse`]); `publish`'s tests call it by name.
    #[cfg(test)]
    pub fn reuse_daemon(&mut self, previous: &Descriptor) {
        self.reuse(ReuseComponent::Daemon, previous);
    }
}

/// Builds the OCI manifest around exact descriptor bytes and validates the envelope.
pub fn manifest_for(layer: &[u8]) -> Result<(Manifest, Vec<u8>)> {
    if layer.len() > MAX_DESCRIPTOR_BYTES {
        bail!(
            "descriptor is {} bytes, the contract limit is {MAX_DESCRIPTOR_BYTES}",
            layer.len()
        );
    }
    let manifest = Manifest {
        schema_version: 2,
        media_type: MANIFEST_MEDIA_TYPE.to_owned(),
        artifact_type: DESCRIPTOR_MEDIA_TYPE.to_owned(),
        config: ManifestDescriptor {
            media_type: EMPTY_CONFIG_MEDIA_TYPE.to_owned(),
            digest: StrictDigest::new(EMPTY_CONFIG_DIGEST)
                .expect("the empty-config digest is canonical"),
            size: 2,
            urls: None,
        },
        layers: vec![ManifestDescriptor {
            media_type: DESCRIPTOR_MEDIA_TYPE.to_owned(),
            digest: sha256(layer),
            size: layer.len() as u64,
            urls: None,
        }],
    };
    let bytes = serde_json::to_vec(&manifest).context("cannot serialize the OCI manifest")?;
    parse_manifest(&bytes).map_err(|error| {
        anyhow::anyhow!("assembled manifest is rejected by the parser: {error}")
    })?;
    Ok((manifest, bytes))
}

/// `set-<channel>-<sequence>`: the immutable tag of one release set.
pub fn set_tag(channel: Channel, sequence: u64) -> String {
    format!("set-{}-{sequence}", channel.as_str())
}

/// Parses `set-<channel>-<N>` for exactly `channel`. Leading zeros, `0` and extra suffixes are not
/// sequences: an ambiguous tag must never raise the allocation floor.
pub fn parse_set_tag(channel: Channel, tag: &str) -> Option<u64> {
    let rest = tag.strip_prefix("set-")?;
    let rest = rest.strip_prefix(channel.as_str())?;
    let number = rest.strip_prefix('-')?;
    if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if number.len() > 1 && number.starts_with('0') {
        return None;
    }
    number.parse::<u64>().ok().filter(|value| *value > 0)
}

/// The next sequence: `max(current channel pointer, highest existing set tag) + 1`.
///
/// A crash after pushing `set-<channel>-N` but before moving the pointer leaves `N` in the tag
/// list, so the next run allocates `N+1` — never `N` from the stale pointer.
pub fn next_sequence(channel: Channel, pointer: Option<u64>, tags: &[String]) -> u64 {
    let highest = tags
        .iter()
        .filter_map(|tag| parse_set_tag(channel, tag))
        .max()
        .unwrap_or(0);
    // Saturating, not `+ 1`: a planted `set-<channel>-18446744073709551615` tag must not wrap the
    // allocation to 0 in a release build. The saturated value collides with that immutable tag, and
    // `publish` refuses to overwrite it.
    pointer.unwrap_or(0).max(highest).saturating_add(1)
}

/// Validates the compatibility list the compatibility job produced: every entry is unique, the
/// selected panel is present, and nothing is inherited silently. The parser re-checks the shape;
/// this function states the *publication* rule in one place.
pub fn compatibility(
    state_read: Vec<u32>,
    state_write: u32,
    panel_tested: Vec<StrictDigest>,
    selected_panel: &StrictDigest,
) -> Result<Compatibility> {
    let mut unique = BTreeSet::new();
    for schema in &state_read {
        if !unique.insert(*schema) {
            bail!("compatibility state_read contains duplicate schema {schema}");
        }
    }
    if !unique.contains(&state_write) {
        bail!("compatibility state_write {state_write} must appear in state_read");
    }
    let mut tested = BTreeSet::new();
    for digest in &panel_tested {
        if !tested.insert(digest) {
            bail!("compatibility panel_digests contains duplicate {digest}");
        }
    }
    if !tested.contains(selected_panel) {
        bail!(
            "the selected panel {selected_panel} is not in the tested list; \
             the compatibility job must test the new panel and the previous promoted panel"
        );
    }
    Ok(Compatibility {
        host_protocol: 1,
        state_read,
        state_write,
        panel_digests: panel_tested,
    })
}

/// Parses the two repository/digest/version inputs of the CLI into a component.
pub fn component(repository: &str, digest: &str, version: &str) -> Result<Component> {
    Ok(Component {
        repository: Repository::new(repository)
            .map_err(|error| anyhow::anyhow!("invalid component repository: {error}"))?,
        digest: StrictDigest::new(digest)
            .map_err(|error| anyhow::anyhow!("invalid component digest: {error}"))?,
        version: version.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_sequence_never_wraps_around() {
        let tags = vec![format!("set-main-{}", u64::MAX)];
        assert_eq!(next_sequence(Channel::Main, None, &tags), u64::MAX);
        assert_eq!(next_sequence(Channel::Main, Some(u64::MAX), &[]), u64::MAX);
    }
    use weglarka_model::release_set::parse_descriptor;

    const DAEMON: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PANEL: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn digest(value: &str) -> StrictDigest {
        StrictDigest::new(value).unwrap()
    }

    fn spec() -> ReleaseSpec {
        ReleaseSpec {
            channel: Channel::Stable,
            revision: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            daemon: component("ghcr.io/example/weglarka", DAEMON, "0.9.0").unwrap(),
            panel: component("ghcr.io/example/weglarka-panel", PANEL, "0.3.1").unwrap(),
            host_files: vec![
                HostFile {
                    name: "weglarka-daemon".into(),
                    path: "/usr/local/bin/weglarka-daemon".into(),
                    version: "0.9.0".into(),
                    size: 4_000_000,
                    digest: digest(
                        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                    ),
                },
                HostFile {
                    name: "weglarka".into(),
                    path: "/usr/local/bin/weglarka".into(),
                    version: "0.8.0".into(),
                    size: 3_000_000,
                    digest: digest(
                        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                    ),
                },
            ],
            compatibility: compatibility(vec![17], 17, vec![digest(PANEL)], &digest(PANEL))
                .unwrap(),
        }
    }

    #[test]
    fn sequence_is_one_more_than_the_highest_floor() {
        assert_eq!(next_sequence(Channel::Stable, None, &[]), 1);
        assert_eq!(next_sequence(Channel::Stable, Some(7), &[]), 8);
        assert_eq!(
            next_sequence(Channel::Stable, Some(7), &["set-stable-9".into()]),
            10
        );
        // A pointer ahead of every tag still wins.
        assert_eq!(
            next_sequence(Channel::Stable, Some(12), &["set-stable-9".into()]),
            13
        );
        // The other channel's tags do not raise this floor.
        assert_eq!(
            next_sequence(Channel::Stable, None, &["set-main-42".into()]),
            1
        );
        // Nor do malformed or zero tags.
        assert_eq!(
            next_sequence(
                Channel::Stable,
                None,
                &[
                    "set-stable-0".into(),
                    "set-stable-007".into(),
                    "set-stable--1".into()
                ]
            ),
            1
        );
    }

    #[test]
    fn set_tags_round_trip_and_reject_ambiguity() {
        assert_eq!(
            parse_set_tag(Channel::Main, &set_tag(Channel::Main, 5)),
            Some(5)
        );
        for tag in [
            "set-stable-",
            "set-stable-01",
            "set-stable-0",
            "set-stable-1x",
            "set-main-1",
            "stable",
        ] {
            assert_eq!(parse_set_tag(Channel::Stable, tag), None, "{tag}");
        }
    }

    #[test]
    fn a_descriptor_serializes_and_parses_with_the_shared_parser() {
        let bytes = spec().descriptor_bytes(3).unwrap();
        let descriptor = parse_descriptor(
            &bytes,
            &weglarka_model::release_set::DescriptorContext {
                channel: Some(Channel::Stable),
            },
        )
        .unwrap();
        assert_eq!(descriptor.sequence, 3);
        assert_eq!(descriptor.host_tools.digest, descriptor.daemon.digest);
    }

    #[test]
    fn the_manifest_matches_the_descriptor_bytes() {
        let layer = spec().descriptor_bytes(1).unwrap();
        let (manifest, bytes) = manifest_for(&layer).unwrap();
        let parsed = parse_manifest(&bytes).unwrap();
        assert_eq!(parsed, manifest);
        assert_eq!(parsed.layers[0].size, layer.len() as u64);
        assert_eq!(parsed.layers[0].digest, sha256(&layer));
        parsed.verify_blobs(&layer, b"{}").unwrap();
    }

    #[test]
    fn the_selected_panel_must_be_tested() {
        let other =
            digest("sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
        assert!(
            compatibility(vec![17], 17, vec![other], &digest(PANEL))
                .unwrap_err()
                .to_string()
                .contains("not in the tested list")
        );
        assert!(compatibility(vec![17], 18, vec![digest(PANEL)], &digest(PANEL)).is_err());
        assert!(compatibility(vec![17, 17], 17, vec![digest(PANEL)], &digest(PANEL)).is_err());
    }

    #[test]
    fn a_panel_only_reuse_keeps_the_daemon_and_host_files() {
        let mut next = spec();
        let previous = spec().descriptor(9);
        next.panel = component(
            "ghcr.io/example/weglarka-panel",
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "0.4.0",
        )
        .unwrap();
        next.reuse(ReuseComponent::Daemon, &previous);
        assert_eq!(next.daemon, previous.daemon);
        assert_eq!(next.host_files, previous.host_tools.files);
        assert_ne!(next.panel, previous.panel);
    }

    #[test]
    fn a_panel_only_reuse_after_a_schema_bump_keeps_the_daemon_state_versions() {
        let mut next = spec();
        let previous = spec().descriptor(9);
        // The schema advanced since the previous set; the reused daemon still reads and writes the
        // old schema, so its state versions must come from the previous set, not the flags.
        next.compatibility =
            compatibility(vec![18], 18, vec![digest(PANEL)], &digest(PANEL)).unwrap();
        next.reuse(ReuseComponent::Daemon, &previous);
        assert_eq!(next.compatibility.state_read, vec![17]);
        assert_eq!(next.compatibility.state_write, 17);
    }

    #[test]
    fn a_cli_only_reuse_keeps_the_panel_digest_and_version() {
        let mut next = spec();
        let previous = spec().descriptor(9);
        next.daemon = component(
            "ghcr.io/example/weglarka",
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "0.10.0",
        )
        .unwrap();
        // A panel version bump must not be paired with the reused digest: reuse copies the whole
        // panel record — the digest and the version that digest was built from.
        next.panel = component(
            "ghcr.io/example/weglarka-panel",
            "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "0.4.0",
        )
        .unwrap();
        next.reuse(ReuseComponent::Panel, &previous);
        assert_eq!(next.panel, previous.panel);
        assert_eq!(next.panel.version, previous.panel.version);
        assert_eq!(next.panel.digest, previous.panel.digest);
        assert_ne!(next.daemon, previous.daemon);
    }

    #[test]
    fn crate_versions_come_from_the_package_table() {
        let version = crate_version(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
        assert!(Version::parse(&version).is_ok());
    }
}
