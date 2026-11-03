//! Platform update release set v1: the signed descriptor and its OCI manifest envelope.
//!
//! This module is the wire contract from
//! [`docs/contracts/platform-update-v1`](../../../docs/contracts/platform-update-v1/README.md). It
//! parses and validates **bytes**; it does not fetch, verify a signature or hash a registry blob
//! (except [`Manifest::verify_blobs`], which checks bytes the caller already obtained). The parser is
//! deliberately strict:
//!
//! - duplicate JSON keys are rejected at every nesting level, before serde sees the document;
//! - unknown fields are rejected at every level ([`Descriptor`] and its nested objects);
//! - digests must be canonical lower-case `sha256:<64 hex>` — [`Digest::new`](crate::app::Digest::new)
//!   alone accepts upper-case hex, which the contract forbids (see [`StrictDigest`]);
//! - component versions are real semver values;
//! - repositories are tag-free, digest-free, credential-free and contain no query or fragment.
//!
//! Identity: `release_set_digest` everywhere in the platform protocol means the **resolved OCI
//! manifest digest**, never the descriptor layer digest (see [`Manifest::digest`] and
//! [`Descriptor::digest`]). This module only models the layer; the caller resolves the digest.
//!
//! Rejection names come from the contract's result vocabulary. Where the contract requires a rule
//! (unknown fields, duplicate host-file names, a zero sequence, a non-semver version) but its list
//! has no dedicated name, the parser reports the closest structural name (`MissingField` or
//! `InvalidDigest`) and puts the exact reason in [`ReleaseError::detail`]. The behavior — rejection —
//! is unchanged; the vocabulary is not extended.

use std::collections::BTreeSet;
use std::fmt;

use semver::Version;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest as _, Sha256};

use crate::app::{Digest, InvalidDigest};
use crate::image_ref::ImageRef;

/// Descriptor format understood by this parser.
pub const FORMAT_VERSION: u32 = 1;
/// Media type of the release-set descriptor layer and of the manifest's `artifactType`.
pub const DESCRIPTOR_MEDIA_TYPE: &str = "application/vnd.weglarka.release.v1+json";
/// Media type of the OCI image manifest carrying the descriptor.
pub const MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
/// Media type of an OCI image index, which is never a release set.
pub const INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";
/// Media type of the empty JSON config (`{}`).
pub const EMPTY_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.empty.v1+json";
/// SHA-256 of the two bytes `{}`: the only config content v1 accepts.
pub const EMPTY_CONFIG_DIGEST: &str =
    "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";
/// Largest accepted descriptor, enforced before parsing.
pub const MAX_DESCRIPTOR_BYTES: usize = 64 * 1024;
/// Largest accepted OCI manifest, enforced before parsing.
pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
/// Readable state schemas a descriptor may declare.
pub const MAX_STATE_SCHEMAS: usize = 64;
/// Tested panel digests a descriptor may declare.
pub const MAX_PANEL_DIGESTS: usize = 32;
/// Largest host tool file accepted from the source image.
pub const MAX_HOST_FILE_BYTES: u64 = 64 * 1024 * 1024;
/// Exactly two host tool files: the daemon and the CLI.
pub const HOST_FILE_COUNT: usize = 2;

/// The only two host-tool records v1 accepts: `(name, path inside the source image)`.
pub const HOST_FILES: [(&str, &str); HOST_FILE_COUNT] = [
    ("weglarka-daemon", "/usr/local/bin/weglarka-daemon"),
    ("weglarka", "/usr/local/bin/weglarka"),
];

/// A named rejection from the contract's result vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Rejection {
    UnsupportedFormat,
    MissingField,
    DuplicateField,
    InvalidDigest,
    UnsupportedTarget,
    ChannelMismatch,
    IncompatibleSelectedPanel,
    UnexpectedImagePath,
    HostImageMismatch,
    UnsupportedArtifactType,
    ExtraLayer,
    ForeignUrl,
    NotAnImageManifest,
    ConfigMediaTypeMismatch,
    NonEmptyConfig,
    LayerMediaTypeMismatch,
    SizeMismatch,
}

impl Rejection {
    /// Every name, in contract order. Tests and the fixture harness use it to prove the enum and
    /// the published vocabulary cannot drift apart.
    pub const ALL: [Rejection; 17] = [
        Rejection::UnsupportedFormat,
        Rejection::MissingField,
        Rejection::DuplicateField,
        Rejection::InvalidDigest,
        Rejection::UnsupportedTarget,
        Rejection::ChannelMismatch,
        Rejection::IncompatibleSelectedPanel,
        Rejection::UnexpectedImagePath,
        Rejection::HostImageMismatch,
        Rejection::UnsupportedArtifactType,
        Rejection::ExtraLayer,
        Rejection::ForeignUrl,
        Rejection::NotAnImageManifest,
        Rejection::ConfigMediaTypeMismatch,
        Rejection::NonEmptyConfig,
        Rejection::LayerMediaTypeMismatch,
        Rejection::SizeMismatch,
    ];

    /// The exact contract spelling (`valid_descriptor`/`valid_envelope`/`valid_blobs` are results,
    /// not rejections).
    pub const fn as_str(self) -> &'static str {
        match self {
            Rejection::UnsupportedFormat => "UnsupportedFormat",
            Rejection::MissingField => "MissingField",
            Rejection::DuplicateField => "DuplicateField",
            Rejection::InvalidDigest => "InvalidDigest",
            Rejection::UnsupportedTarget => "UnsupportedTarget",
            Rejection::ChannelMismatch => "ChannelMismatch",
            Rejection::IncompatibleSelectedPanel => "IncompatibleSelectedPanel",
            Rejection::UnexpectedImagePath => "UnexpectedImagePath",
            Rejection::HostImageMismatch => "HostImageMismatch",
            Rejection::UnsupportedArtifactType => "UnsupportedArtifactType",
            Rejection::ExtraLayer => "ExtraLayer",
            Rejection::ForeignUrl => "ForeignUrl",
            Rejection::NotAnImageManifest => "NotAnImageManifest",
            Rejection::ConfigMediaTypeMismatch => "ConfigMediaTypeMismatch",
            Rejection::NonEmptyConfig => "NonEmptyConfig",
            Rejection::LayerMediaTypeMismatch => "LayerMediaTypeMismatch",
            Rejection::SizeMismatch => "SizeMismatch",
        }
    }

    /// Parses a contract result name. `None` for `valid_*` and unknown names.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == name)
    }
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A rejected document: the contract name plus a human-readable reason for logs and `doctor`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{rejection}: {detail}")]
pub struct ReleaseError {
    pub rejection: Rejection,
    pub detail: String,
}

impl ReleaseError {
    pub fn new(rejection: Rejection, detail: impl Into<String>) -> Self {
        Self {
            rejection,
            detail: detail.into(),
        }
    }
}

/// A canonical lower-case `sha256:<64 hex>` digest.
///
/// [`Digest`] itself is deliberately lenient (it accepts upper-case hex) because existing
/// `apps.toml`/`state.toml` values must keep parsing. Platform update files use this wrapper instead:
/// the contract requires the wire bytes to be byte-identical to their lower-case form.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct StrictDigest(Digest);

impl StrictDigest {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidDigest> {
        let value = value.into();
        let digest = Digest::new(value.clone())?;
        let hex = digest.as_str().strip_prefix("sha256:").unwrap_or_default();
        if hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            Ok(Self(digest))
        } else {
            Err(InvalidDigest(value))
        }
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn as_digest(&self) -> &Digest {
        &self.0
    }
}

impl TryFrom<String> for StrictDigest {
    type Error = InvalidDigest;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<StrictDigest> for String {
    fn from(value: StrictDigest) -> Self {
        value.0.into()
    }
}

impl fmt::Display for StrictDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for StrictDigest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(|_| {
            de::Error::custom(
                "InvalidDigest: expected a canonical lower-case sha256:<64 hex> digest",
            )
        })
    }
}

/// A tag-free, digest-free OCI repository (`ghcr.io/owner/name`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Repository(String);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "invalid repository {0:?}: expected host[:port]/lowercase/path, no tag, digest, credentials, query or fragment"
)]
pub struct InvalidRepository(pub String);

impl Repository {
    /// Validated by the same parser as every other image reference (`image_ref`), so a name without a
    /// registry host (`example/weglarka`) is rejected instead of being resolved through Podman's
    /// unqualified-search registries.
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidRepository> {
        let value = value.into();
        // Lower case only: the registry parser allows an upper-case host, but `GHCR.io/a` and `ghcr.io/a`
        // would then be two different keys for the same repository.
        if value.len() > 255
            || value.bytes().any(|b| b.is_ascii_uppercase())
            || ImageRef::parse_repository(&value).is_err()
        {
            return Err(InvalidRepository(value));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Repository {
    type Error = InvalidRepository;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Repository> for String {
    fn from(value: Repository) -> Self {
        value.0
    }
}

impl fmt::Display for Repository {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Release channel. The channel in the descriptor is compared with the resolved channel by the host
/// ([`DescriptorContext::channel`]); the signature does not bind the two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    Stable,
    Main,
}

impl Channel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Main => "main",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "stable" => Some(Self::Stable),
            "main" => Some(Self::Main),
            _ => None,
        }
    }
}

impl fmt::Display for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Host context a descriptor is validated against. The fixture harness passes the case's channel;
/// the host passes its configured channel.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DescriptorContext {
    /// Channel that was actually resolved. `Some` rejects a descriptor whose own channel differs.
    pub channel: Option<Channel>,
}

/// The v1 descriptor (`fixtures/release-valid.json` is the complete field shape).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub format_version: u32,
    pub channel: Channel,
    pub sequence: u64,
    pub revision: String,
    pub target: Target,
    pub daemon: Component,
    pub panel: Component,
    pub host_tools: HostTools,
    pub compatibility: Compatibility,
}

/// Exact target in v1: `linux` / `amd64` / `musl`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub os: String,
    pub architecture: String,
    pub abi: String,
}

/// One component image: repository, manifest digest and the crate version baked into the image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Component {
    pub repository: Repository,
    pub digest: StrictDigest,
    pub version: String,
}

/// Host tools source image and the exactly two files extracted from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostTools {
    pub repository: Repository,
    pub digest: StrictDigest,
    pub files: Vec<HostFile>,
}

/// One file inside the host tools source image. `path` is an in-image path, never a host
/// destination; the host installs it as `<host-only generation dir>/<name>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostFile {
    pub name: String,
    pub path: String,
    pub version: String,
    pub size: u64,
    pub digest: StrictDigest,
}

/// State-schema and panel compatibility the target daemon declares.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Compatibility {
    pub host_protocol: u32,
    pub state_read: Vec<u32>,
    pub state_write: u32,
    pub panel_digests: Vec<StrictDigest>,
}

impl Descriptor {
    fn validate(&self, context: &DescriptorContext) -> Result<(), ReleaseError> {
        if self.format_version != FORMAT_VERSION {
            return Err(ReleaseError::new(
                Rejection::UnsupportedFormat,
                format!(
                    "descriptor format_version {} is not {FORMAT_VERSION}",
                    self.format_version
                ),
            ));
        }
        if let Some(channel) = context.channel
            && self.channel != channel
        {
            return Err(ReleaseError::new(
                Rejection::ChannelMismatch,
                format!(
                    "descriptor channel {} does not match resolved channel {channel}",
                    self.channel
                ),
            ));
        }
        if self.sequence == 0 {
            return Err(ReleaseError::new(
                Rejection::MissingField,
                "sequence must be a positive integer",
            ));
        }
        if !is_lower_hex(&self.revision, 40) {
            return Err(ReleaseError::new(
                Rejection::InvalidDigest,
                format!(
                    "revision {:?} is not a 40-character lower-case hex commit id",
                    self.revision
                ),
            ));
        }
        if self.target.os != "linux"
            || self.target.architecture != "amd64"
            || self.target.abi != "musl"
        {
            return Err(ReleaseError::new(
                Rejection::UnsupportedTarget,
                format!(
                    "target {}/{}/{} is not linux/amd64/musl",
                    self.target.os, self.target.architecture, self.target.abi
                ),
            ));
        }
        validate_component("daemon", &self.daemon)?;
        validate_component("panel", &self.panel)?;
        self.host_tools.validate(&self.daemon)?;
        self.compatibility.validate(&self.panel.digest)?;
        Ok(())
    }
}

fn validate_component(name: &str, component: &Component) -> Result<(), ReleaseError> {
    Version::parse(&component.version).map_err(|error| {
        ReleaseError::new(
            Rejection::MissingField,
            format!(
                "{name} version {:?} is not semver: {error}",
                component.version
            ),
        )
    })?;
    Ok(())
}

impl HostTools {
    fn validate(&self, daemon: &Component) -> Result<(), ReleaseError> {
        if self.digest != daemon.digest || self.repository != daemon.repository {
            return Err(ReleaseError::new(
                Rejection::HostImageMismatch,
                "host_tools image must be exactly the selected daemon image (same repository and digest)",
            ));
        }
        if self.files.len() != HOST_FILE_COUNT {
            return Err(ReleaseError::new(
                Rejection::MissingField,
                format!(
                    "host_tools.files must contain exactly {HOST_FILE_COUNT} records, got {}",
                    self.files.len()
                ),
            ));
        }
        let mut names = BTreeSet::new();
        for file in &self.files {
            let expected = HOST_FILES
                .iter()
                .find(|(name, _)| *name == file.name)
                .map(|(_, path)| *path);
            if expected != Some(file.path.as_str()) {
                return Err(ReleaseError::new(
                    Rejection::UnexpectedImagePath,
                    format!(
                        "host_tools file {:?} has path {:?}; v1 allows only the fixed names and in-image paths",
                        file.name, file.path
                    ),
                ));
            }
            if !names.insert(file.name.as_str()) {
                return Err(ReleaseError::new(
                    Rejection::MissingField,
                    format!("duplicate host_tools file name {:?}", file.name),
                ));
            }
            if file.size == 0 || file.size > MAX_HOST_FILE_BYTES {
                return Err(ReleaseError::new(
                    Rejection::SizeMismatch,
                    format!(
                        "host_tools file {:?} size {} is outside 1..={MAX_HOST_FILE_BYTES}",
                        file.name, file.size
                    ),
                ));
            }
            Version::parse(&file.version).map_err(|error| {
                ReleaseError::new(
                    Rejection::MissingField,
                    format!(
                        "host_tools file {:?} version {:?} is not semver: {error}",
                        file.name, file.version
                    ),
                )
            })?;
        }
        Ok(())
    }
}

impl Compatibility {
    fn validate(&self, panel_digest: &StrictDigest) -> Result<(), ReleaseError> {
        if self.host_protocol != 1 {
            return Err(ReleaseError::new(
                Rejection::MissingField,
                format!("host protocol {} is not 1", self.host_protocol),
            ));
        }
        if self.state_read.len() > MAX_STATE_SCHEMAS {
            return Err(ReleaseError::new(
                Rejection::MissingField,
                format!(
                    "compatibility.state_read has {} entries, at most {MAX_STATE_SCHEMAS} allowed",
                    self.state_read.len()
                ),
            ));
        }
        if !all_unique(&self.state_read) {
            return Err(ReleaseError::new(
                Rejection::MissingField,
                "compatibility.state_read contains duplicate schema numbers",
            ));
        }
        if !self.state_read.contains(&self.state_write) {
            return Err(ReleaseError::new(
                Rejection::MissingField,
                "compatibility.state_write must appear in state_read",
            ));
        }
        if self.panel_digests.len() > MAX_PANEL_DIGESTS {
            return Err(ReleaseError::new(
                Rejection::IncompatibleSelectedPanel,
                format!(
                    "compatibility.panel_digests has {} entries, at most {MAX_PANEL_DIGESTS} allowed",
                    self.panel_digests.len()
                ),
            ));
        }
        if !all_unique(&self.panel_digests) {
            return Err(ReleaseError::new(
                Rejection::IncompatibleSelectedPanel,
                "compatibility.panel_digests contains duplicate digests",
            ));
        }
        if !self.panel_digests.contains(panel_digest) {
            return Err(ReleaseError::new(
                Rejection::IncompatibleSelectedPanel,
                format!("selected panel {panel_digest} is not listed as tested"),
            ));
        }
        Ok(())
    }
}

fn all_unique<T: Ord>(values: &[T]) -> bool {
    let set: BTreeSet<&T> = values.iter().collect();
    set.len() == values.len()
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Parses and validates a descriptor. Host rules that need the durable journal (sequence must not
/// move backwards) are applied by the coordinator against its accepted pointer; the shape and
/// channel binding are checked here.
pub fn parse_descriptor(
    bytes: &[u8],
    context: &DescriptorContext,
) -> Result<Descriptor, ReleaseError> {
    if bytes.len() > MAX_DESCRIPTOR_BYTES {
        return Err(ReleaseError::new(
            Rejection::SizeMismatch,
            format!(
                "descriptor is {} bytes, the limit is {MAX_DESCRIPTOR_BYTES}",
                bytes.len()
            ),
        ));
    }
    reject_duplicate_keys(bytes)?;
    #[derive(Deserialize)]
    struct Probe {
        #[serde(default)]
        format_version: Option<u32>,
    }
    let probe: Probe = serde_json::from_slice(bytes).map_err(serde_error)?;
    let version = probe
        .format_version
        .ok_or_else(|| missing("format_version"))?;
    if version != FORMAT_VERSION {
        return Err(ReleaseError::new(
            Rejection::UnsupportedFormat,
            format!("descriptor format_version {version} is not {FORMAT_VERSION}"),
        ));
    }
    let descriptor: Descriptor = serde_json::from_slice(bytes).map_err(serde_error)?;
    descriptor.validate(context)?;
    Ok(descriptor)
}

/// An OCI image manifest that carries a release-set descriptor layer.
///
/// An external format, so unknown fields are ignored: common tools add `annotations` (and the
/// OCI spec allows more), and rejecting them would reject a release set nothing is wrong with. What
/// matters is checked explicitly instead (artifact and media types, blob digests and sizes, no
/// `urls`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    #[serde(rename = "mediaType")]
    pub media_type: String,
    #[serde(rename = "artifactType")]
    pub artifact_type: String,
    pub config: ManifestDescriptor,
    pub layers: Vec<ManifestDescriptor>,
}

/// One descriptor in a manifest (`config` or a layer). Unknown fields (`annotations`, ...) are ignored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestDescriptor {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub digest: StrictDigest,
    pub size: u64,
    /// Descriptor `urls` are never accepted: the host fetches from the resolved repository only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub urls: Option<Vec<String>>,
}

impl Manifest {
    /// The descriptor layer. `parse_manifest` guarantees exactly one; a manually built value that
    /// has none yields `None` instead of panicking.
    pub fn descriptor_layer(&self) -> Option<&ManifestDescriptor> {
        self.layers.first()
    }

    /// Checks the exact bytes the caller fetched against the advertised sizes and SHA-256 digests.
    ///
    /// The config must be exactly `{}`; the layer is the descriptor document. Both checks report
    /// [`Rejection::SizeMismatch`] for a size or digest disagreement because the contract's result
    /// vocabulary has no separate digest-mismatch name.
    pub fn verify_blobs(&self, layer: &[u8], config: &[u8]) -> Result<(), ReleaseError> {
        if config != b"{}" {
            return Err(ReleaseError::new(
                Rejection::NonEmptyConfig,
                "config bytes are not the empty JSON object `{}`",
            ));
        }
        check_blob(&self.config, config, "config")?;
        let descriptor = self.descriptor_layer().ok_or_else(|| {
            ReleaseError::new(
                Rejection::ExtraLayer,
                "manifest carries no descriptor layer",
            )
        })?;
        check_blob(descriptor, layer, "descriptor layer")?;
        Ok(())
    }

    fn validate(&self) -> Result<(), ReleaseError> {
        if self.schema_version != 2 || self.media_type != MANIFEST_MEDIA_TYPE {
            return Err(ReleaseError::new(
                Rejection::NotAnImageManifest,
                format!(
                    "expected an OCI image manifest v2, got schemaVersion {} mediaType {:?}",
                    self.schema_version, self.media_type
                ),
            ));
        }
        if self.artifact_type != DESCRIPTOR_MEDIA_TYPE {
            return Err(ReleaseError::new(
                Rejection::UnsupportedArtifactType,
                format!(
                    "artifactType {:?} is not {DESCRIPTOR_MEDIA_TYPE}",
                    self.artifact_type
                ),
            ));
        }
        if self.config.media_type != EMPTY_CONFIG_MEDIA_TYPE {
            return Err(ReleaseError::new(
                Rejection::ConfigMediaTypeMismatch,
                format!(
                    "config mediaType {:?} is not {EMPTY_CONFIG_MEDIA_TYPE}",
                    self.config.media_type
                ),
            ));
        }
        if self.config.urls.is_some() {
            return Err(ReleaseError::new(
                Rejection::ForeignUrl,
                "config descriptor carries urls",
            ));
        }
        if self.config.size != 2 {
            return Err(ReleaseError::new(
                Rejection::NonEmptyConfig,
                format!("config size {} is not 2 bytes (`{{}}`)", self.config.size),
            ));
        }
        if self.layers.len() != 1 {
            return Err(ReleaseError::new(
                Rejection::ExtraLayer,
                format!(
                    "manifest must carry exactly one descriptor layer, got {}",
                    self.layers.len()
                ),
            ));
        }
        let Some(layer) = self.descriptor_layer() else {
            return Err(ReleaseError::new(
                Rejection::ExtraLayer,
                "manifest carries no descriptor layer",
            ));
        };
        if layer.urls.is_some() {
            return Err(ReleaseError::new(
                Rejection::ForeignUrl,
                "descriptor layer carries urls",
            ));
        }
        if layer.media_type != DESCRIPTOR_MEDIA_TYPE {
            return Err(ReleaseError::new(
                Rejection::LayerMediaTypeMismatch,
                format!(
                    "layer mediaType {:?} is not {DESCRIPTOR_MEDIA_TYPE}",
                    layer.media_type
                ),
            ));
        }
        Ok(())
    }
}

fn check_blob(
    descriptor: &ManifestDescriptor,
    bytes: &[u8],
    what: &str,
) -> Result<(), ReleaseError> {
    if descriptor.size != bytes.len() as u64 {
        return Err(ReleaseError::new(
            Rejection::SizeMismatch,
            format!(
                "{what} is {} bytes but the manifest advertises {}",
                bytes.len(),
                descriptor.size
            ),
        ));
    }
    let actual = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
    if descriptor.digest.as_str() != actual {
        return Err(ReleaseError::new(
            Rejection::SizeMismatch,
            format!(
                "{what} digest is {actual} but the manifest advertises {}",
                descriptor.digest
            ),
        ));
    }
    Ok(())
}

/// Parses and validates the OCI manifest envelope. Blob contents are not hashed; use
/// [`Manifest::verify_blobs`] once the referenced bytes are fetched.
pub fn parse_manifest(bytes: &[u8]) -> Result<Manifest, ReleaseError> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(ReleaseError::new(
            Rejection::SizeMismatch,
            format!(
                "manifest is {} bytes, the limit is {MAX_MANIFEST_BYTES}",
                bytes.len()
            ),
        ));
    }
    reject_duplicate_keys(bytes)?;
    #[derive(Deserialize)]
    struct Probe {
        #[serde(default, rename = "mediaType")]
        media_type: Option<String>,
        #[serde(default)]
        manifests: Option<serde_json::Value>,
    }
    let probe: Probe = serde_json::from_slice(bytes).map_err(serde_error)?;
    if probe.manifests.is_some() {
        return Err(ReleaseError::new(
            Rejection::NotAnImageManifest,
            "document carries a `manifests` array: an image index is not a release set",
        ));
    }
    let media_type = probe.media_type.ok_or_else(|| missing("mediaType"))?;
    if media_type != MANIFEST_MEDIA_TYPE {
        return Err(ReleaseError::new(
            Rejection::NotAnImageManifest,
            format!("mediaType {media_type:?} is not {MANIFEST_MEDIA_TYPE}"),
        ));
    }
    let manifest: Manifest = serde_json::from_slice(bytes).map_err(serde_error)?;
    manifest.validate()?;
    Ok(manifest)
}

fn missing(field: &str) -> ReleaseError {
    ReleaseError::new(Rejection::MissingField, format!("missing field {field:?}"))
}

fn serde_error(error: serde_json::Error) -> ReleaseError {
    let message = error.to_string();
    let rejection = if message.contains("InvalidDigest") {
        Rejection::InvalidDigest
    } else {
        Rejection::MissingField
    };
    ReleaseError::new(rejection, message)
}

/// Rejects a duplicate JSON key at any nesting level. `serde_json::Value` would silently keep the
/// last one, so this runs over the raw document before deserialization.
fn reject_duplicate_keys(bytes: &[u8]) -> Result<(), ReleaseError> {
    match serde_json::from_slice::<NoDuplicates>(bytes) {
        Ok(NoDuplicates) => Ok(()),
        Err(error) if error.to_string().contains("DuplicateField") => Err(ReleaseError::new(
            Rejection::DuplicateField,
            error.to_string(),
        )),
        Err(error) => Err(ReleaseError::new(
            Rejection::MissingField,
            format!("invalid JSON: {error}"),
        )),
    }
}

struct NoDuplicates;

impl<'de> Deserialize<'de> for NoDuplicates {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(NoDuplicatesVisitor)
    }
}

struct NoDuplicatesVisitor;

impl<'de> Visitor<'de> for NoDuplicatesVisitor {
    type Value = NoDuplicates;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut seen = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom(format!(
                    "DuplicateField: duplicate key {key:?}"
                )));
            }
            map.next_value::<NoDuplicates>()?;
        }
        Ok(NoDuplicates)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        while seq.next_element::<NoDuplicates>()?.is_some() {}
        Ok(NoDuplicates)
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(NoDuplicates)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(NoDuplicates)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(NoDuplicates)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(NoDuplicates)
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(NoDuplicates)
    }

    fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
        Ok(NoDuplicates)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicates)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicates)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(NoDuplicatesVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str =
        include_str!("../../../docs/contracts/platform-update-v1/fixtures/release-valid.json");
    const MANIFEST: &str =
        include_str!("../../../docs/contracts/platform-update-v1/fixtures/oci-manifest-valid.json");

    fn parse(src: &str) -> Result<Descriptor, ReleaseError> {
        parse_descriptor(src.as_bytes(), &DescriptorContext::default())
    }

    fn rejection(src: &str) -> Rejection {
        parse(src).expect_err("must reject").rejection
    }

    #[test]
    fn valid_descriptor_round_trips_byte_for_byte() {
        let descriptor = parse(VALID).unwrap();
        assert_eq!(descriptor.channel, Channel::Stable);
        assert_eq!(descriptor.sequence, 42);
        assert_eq!(descriptor.host_tools.files.len(), 2);
        let serialized = serde_json::to_string(&descriptor).unwrap();
        assert_eq!(parse(&serialized).unwrap(), descriptor);
    }

    #[test]
    fn unknown_fields_and_duplicates_are_rejected_at_every_level() {
        let unknown = VALID.replacen("\"sequence\": 42,", "\"sequence\": 42,\n  \"bogus\": 1,", 1);
        assert_eq!(rejection(&unknown), Rejection::MissingField);
        let duplicate = VALID.replacen(
            "\"sequence\": 42,",
            "\"sequence\": 42,\n  \"sequence\": 43,",
            1,
        );
        assert_eq!(rejection(&duplicate), Rejection::DuplicateField);
        let nested = r#"{
          "format_version": 1,
          "channel": "stable",
          "sequence": 1,
          "revision": "0123456789abcdef0123456789abcdef01234567",
          "target": {"os": "linux", "architecture": "amd64", "abi": "musl", "abi": "musl"},
          "daemon": {"repository": "ghcr.io/example/weglarka", "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "version": "0.9.0"},
          "panel": {"repository": "ghcr.io/example/weglarka-panel", "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "version": "0.3.1"},
          "host_tools": {"repository": "ghcr.io/example/weglarka", "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "files": [
            {"name": "weglarka-daemon", "path": "/usr/local/bin/weglarka-daemon", "version": "0.9.0", "size": 4000000, "digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"},
            {"name": "weglarka", "path": "/usr/local/bin/weglarka", "version": "0.8.0", "size": 3000000, "digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}
          ]},
          "compatibility": {"host_protocol": 1, "state_read": [17], "state_write": 17, "panel_digests": ["sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]}
        }"#;
        assert_eq!(rejection(nested), Rejection::DuplicateField);
    }

    #[test]
    fn canonical_digests_are_required() {
        let upper = VALID.replacen("sha256:cccc", "sha256:Cccc", 1);
        assert_eq!(rejection(&upper), Rejection::InvalidDigest);
        let short = VALID.replacen(
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "sha256:123",
            1,
        );
        assert_eq!(rejection(&short), Rejection::InvalidDigest);
    }

    #[test]
    fn repositories_reject_tags_digests_credentials_and_queries() {
        for bad in [
            "ghcr.io/example/weglarka:latest",
            "ghcr.io/example/weglarka@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "user:pass@ghcr.io/example/weglarka",
            "ghcr.io/example/weglarka?x=1",
            "ghcr.io/example/weglarka#frag",
            "https://ghcr.io/example/weglarka",
            "ghcr.io/Example/weglarka",
            "GHCR.io/example/weglarka",
            // No registry host: Podman would resolve it through its unqualified-search registries.
            "example/weglarka",
        ] {
            assert!(Repository::new(bad).is_err(), "{bad:?}");
        }
        assert!(Repository::new("ghcr.io/example/weglarka").is_ok());
        assert!(Repository::new("localhost:5000/example/weglarka").is_ok());
    }

    #[test]
    fn manifest_with_standard_annotations_parses() {
        let mut value: serde_json::Value = serde_json::from_str(MANIFEST).unwrap();
        value["annotations"] =
            serde_json::json!({"org.opencontainers.image.created": "2026-01-01T00:00:00Z"});
        value["config"]["annotations"] = serde_json::json!({"a": "b"});
        value["layers"][0]["annotations"] =
            serde_json::json!({"org.opencontainers.image.title": "release.json"});
        let manifest = parse_manifest(value.to_string().as_bytes()).unwrap();
        assert_eq!(manifest, parse_manifest(MANIFEST.as_bytes()).unwrap());
    }

    #[test]
    fn envelope_round_trips_and_verifies_the_fixture_blobs() {
        let manifest = parse_manifest(MANIFEST.as_bytes()).unwrap();
        assert_eq!(manifest.layers.len(), 1);
        let serialized = serde_json::to_string(&manifest).unwrap();
        assert_eq!(parse_manifest(serialized.as_bytes()).unwrap(), manifest);
        let layer = VALID.as_bytes();
        let config = b"{}";
        manifest.verify_blobs(layer, config).unwrap();
        assert_eq!(layer.len(), 1526);
        assert_eq!(
            StrictDigest::new(format!("sha256:{}", hex::encode(Sha256::digest(config)))).unwrap(),
            StrictDigest::new(EMPTY_CONFIG_DIGEST).unwrap()
        );
    }

    #[test]
    fn envelope_rejects_index_extra_layers_and_urls() {
        let index = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}"#;
        assert_eq!(
            parse_manifest(index.as_bytes()).unwrap_err().rejection,
            Rejection::NotAnImageManifest
        );
        let mut manifest = parse_manifest(MANIFEST.as_bytes()).unwrap();
        manifest.layers.push(manifest.layers[0].clone());
        assert_eq!(
            manifest.validate().unwrap_err().rejection,
            Rejection::ExtraLayer
        );
        let mut manifest = parse_manifest(MANIFEST.as_bytes()).unwrap();
        manifest.layers[0].urls = Some(vec!["https://evil.example/x".into()]);
        assert_eq!(
            manifest.validate().unwrap_err().rejection,
            Rejection::ForeignUrl
        );
    }

    #[test]
    fn vocabulary_matches_the_contract_order() {
        assert_eq!(Rejection::ALL.len(), 17);
        for rejection in Rejection::ALL {
            assert_eq!(Rejection::from_name(rejection.as_str()), Some(rejection));
        }
        assert_eq!(Rejection::from_name("valid_descriptor"), None);
    }
}
