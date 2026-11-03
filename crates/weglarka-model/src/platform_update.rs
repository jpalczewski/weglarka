//! Platform update journal and host capability record.
//!
//! Two shared files from
//! [`docs/contracts/platform-update-v1`](../../../docs/contracts/platform-update-v1/README.md):
//!
//! - `platform-update.toml` carries the durable per-channel accepted pointer (never cleared) and the
//!   current transaction journal. The accepted pointer survives journal cleanup and is the rollback
//!   high-water mark.
//! - `host-capabilities.toml` is written by the installed host tools during bootstrap and after each
//!   successful generation switch. **Retention must not delete platform images until this record
//!   proves host protocol 1 and every required coordination feature.** Absence, an older protocol or
//!   a missing feature means "platform image deletion disabled", with a diagnostic — never a guess
//!   from a lock file's presence. [`platform_prune_allowed`] is the single entry point for that
//!   gate.
//!
//! Both files are strict (`deny_unknown_fields`) and versioned. A file with another
//! `format_version` fails to parse, so the caller cannot mutate a format it does not understand.
//! Serialization is deterministic (sorted maps); timestamps are Unix seconds, like the rest of the
//! daemon's bookkeeping.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::image_inventory::OperationId;
use crate::release_set::{Channel, Repository, StrictDigest};

/// File in the shared state directory.
pub const FILE_NAME: &str = "platform-update.toml";
/// Version of the journal format.
pub const FORMAT_VERSION: u32 = 1;
/// Largest accepted journal file.
pub const MAX_BYTES: usize = 1024 * 1024;

/// Capability record written by the installed host tools.
pub const CAPABILITIES_FILE_NAME: &str = "host-capabilities.toml";
/// Largest accepted capability record.
pub const CAPABILITIES_MAX_BYTES: usize = 64 * 1024;
/// Host protocol implemented by this contract.
pub const HOST_PROTOCOL_VERSION: u32 = 1;

/// A stable transaction identifier (`platform-update.toml`, the transition journal and the unix-only
/// panel transition API share it).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TransactionId(String);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid transaction id {0:?}: expected 1-128 characters of [A-Za-z0-9._:-]")]
pub struct InvalidTransactionId(pub String);

impl TransactionId {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidTransactionId> {
        let value = value.into();
        let ok = (1..=128).contains(&value.len())
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'));
        if ok {
            Ok(Self(value))
        } else {
            Err(InvalidTransactionId(value))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for TransactionId {
    type Error = InvalidTransactionId;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<TransactionId> for String {
    fn from(value: TransactionId) -> Self {
        value.0
    }
}

impl fmt::Display for TransactionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The durable per-channel pointer: the release set accepted for a channel. It is never cleared, so
/// a transaction crash cannot move the channel backwards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedPointer {
    pub sequence: u64,
    pub release_set_digest: StrictDigest,
    /// Source commit that assembled the set (full 40-character lower-case hex).
    pub revision: String,
}

/// Where a transaction is. The first five are terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Preparing,
    Prepared,
    Handoff,
    Ack,
    SwitchingDaemon,
    DaemonHealthy,
    PanelTransition,
    CommitPersisted,
    Committed,
    Degraded,
    BlockedRecovery,
    RolledBack,
    HandoffFailed,
}

impl Stage {
    /// Terminal stages need no worker; their journal entry is kept for idempotent recovery.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Stage::Committed
                | Stage::Degraded
                | Stage::BlockedRecovery
                | Stage::RolledBack
                | Stage::HandoffFailed
        )
    }
}

/// Identity of the process that owns the transaction. Persisted so a stale worker can be detected
/// across restarts and a candidate that never acknowledges cannot own the failure path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerIdentity {
    pub pid: u32,
    pub boot_id: String,
    /// Unix seconds when the owner started.
    pub started_at: u64,
    /// Unix seconds by which a candidate must persist `Ack`; set when `CandidateSelected` is
    /// recorded. Always bounded when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handoff_deadline: Option<u64>,
}

/// Identities and schemas of one side of a switch: the running old side or the prepared target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalEndpoint {
    pub daemon_repository: Repository,
    pub daemon_digest: StrictDigest,
    /// Verified host tools generation (the source image digest).
    pub tools_digest: StrictDigest,
    pub state_read: Vec<u32>,
    pub state_write: u32,
    pub host_protocol: u32,
}

/// The candidate generation persisted inside a `Handoff` record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateSelection {
    pub generation: StrictDigest,
    pub selector_epoch: u64,
}

/// The candidate's acknowledgment of a handoff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckRecord {
    pub selector_epoch: u64,
    /// Unix seconds when the candidate acknowledged.
    pub acknowledged_at: u64,
}

/// One resumable platform update. At `Prepared` it carries everything offline recovery needs
/// (old/target images, state schemas, host protocols, release-set digest and reservations); the
/// descriptor and registry are not consulted again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionJournal {
    pub transaction_id: TransactionId,
    pub stage: Stage,
    pub owner: OwnerIdentity,
    pub old: JournalEndpoint,
    pub target: JournalEndpoint,
    /// Resolved OCI manifest digest, never the descriptor layer digest.
    pub release_set_digest: StrictDigest,
    /// Image operations protected by this transaction.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reservations: Vec<OperationId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate: Option<CandidateSelection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack: Option<AckRecord>,
    /// Host tools generation selected after commit, matching the schema support of the daemon that
    /// actually runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_generation: Option<StrictDigest>,
    /// Terminal explanation (`Degraded`, `BlockedRecovery`, `RolledBack`, `HandoffFailed`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Unix seconds of the last durable write.
    pub updated_at: u64,
}

impl TransactionJournal {
    /// `stage` is terminal; the journal entry may be cleaned up.
    pub fn is_terminal(&self) -> bool {
        self.stage.is_terminal()
    }
}

/// `platform-update.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformUpdate {
    pub format_version: u32,
    /// `accepted[channel]`; keys are `stable`/`main`, validated on load. A `BTreeMap` with string
    /// keys keeps TOML serialization deterministic and portable.
    #[serde(default)]
    pub accepted: BTreeMap<String, AcceptedPointer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction: Option<TransactionJournal>,
}

impl Default for PlatformUpdate {
    fn default() -> Self {
        Self {
            format_version: FORMAT_VERSION,
            accepted: BTreeMap::new(),
            transaction: None,
        }
    }
}

impl PlatformUpdate {
    /// The accepted pointer of a channel, if the channel has ever been promoted.
    pub fn accepted(&self, channel: Channel) -> Option<&AcceptedPointer> {
        self.accepted.get(channel.as_str())
    }

    /// Records an accepted pointer. The caller must durably persist the document atomically.
    ///
    /// The pointer only moves forward: a lower `sequence`, or the same `sequence` naming another
    /// release set or revision, is rejected and leaves the document unchanged (a correctly signed
    /// older set must not be stored, or a replay or downgrade would stop being rejected). Accepting
    /// exactly the stored pointer again is a no-op.
    pub fn accept(
        &mut self,
        channel: Channel,
        pointer: AcceptedPointer,
    ) -> Result<(), PlatformUpdateError> {
        if let Some(stored) = self.accepted.get(channel.as_str()) {
            if pointer.sequence < stored.sequence {
                return Err(PlatformUpdateError::Invalid(format!(
                    "channel {} is at sequence {}; refusing to move back to {}",
                    channel.as_str(),
                    stored.sequence,
                    pointer.sequence
                )));
            }
            if pointer.sequence == stored.sequence && &pointer != stored {
                return Err(PlatformUpdateError::Invalid(format!(
                    "channel {} already accepted sequence {} with another release set or revision",
                    channel.as_str(),
                    stored.sequence
                )));
            }
        }
        self.accepted.insert(channel.as_str().to_owned(), pointer);
        Ok(())
    }

    pub fn parse(src: &str) -> Result<Self, PlatformUpdateError> {
        check_size(src.len(), MAX_BYTES)?;
        let probe: FormatProbe = toml::from_str(src)?;
        check_format(probe.format_version)?;
        let document: Self = toml::from_str(src)?;
        document.validate()?;
        Ok(document)
    }

    pub fn to_toml(&self) -> Result<String, PlatformUpdateError> {
        self.validate()?;
        Ok(toml::to_string(self)?)
    }

    fn validate(&self) -> Result<(), PlatformUpdateError> {
        check_format(Some(self.format_version))?;
        for channel in self.accepted.keys() {
            if Channel::parse(channel).is_none() {
                return Err(PlatformUpdateError::Invalid(format!(
                    "unknown channel {channel:?}"
                )));
            }
        }
        if let Some(pointer) = self
            .accepted
            .values()
            .find(|p| !is_lower_hex(&p.revision, 40))
        {
            return Err(PlatformUpdateError::Invalid(format!(
                "accepted revision {:?} is not a 40-character lower-case hex commit id",
                pointer.revision
            )));
        }
        if let Some(transaction) = &self.transaction {
            if transaction.owner.boot_id.is_empty() || transaction.owner.boot_id.len() > 128 {
                return Err(PlatformUpdateError::Invalid(
                    "owner boot_id must be 1-128 characters".into(),
                ));
            }
            if !all_unique(&transaction.reservations) {
                return Err(PlatformUpdateError::Invalid(
                    "transaction reservations contain duplicate operation ids".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlatformUpdateError {
    #[error("{what} is {size} bytes, the limit is {limit}")]
    TooLarge {
        what: &'static str,
        size: usize,
        limit: usize,
    },
    #[error("unsupported format_version {0}")]
    UnsupportedFormat(u32),
    #[error("invalid platform update state: {0}")]
    Invalid(String),
    #[error("invalid TOML: {0}")]
    TomlDe(String),
    #[error("cannot serialize TOML: {0}")]
    TomlSer(String),
}

impl From<toml::de::Error> for PlatformUpdateError {
    fn from(error: toml::de::Error) -> Self {
        Self::TomlDe(error.to_string())
    }
}

impl From<toml::ser::Error> for PlatformUpdateError {
    fn from(error: toml::ser::Error) -> Self {
        Self::TomlSer(error.to_string())
    }
}

#[derive(Deserialize)]
struct FormatProbe {
    #[serde(default)]
    format_version: Option<u32>,
}

fn check_format(value: Option<u32>) -> Result<(), PlatformUpdateError> {
    match value {
        Some(FORMAT_VERSION) => Ok(()),
        Some(other) => Err(PlatformUpdateError::UnsupportedFormat(other)),
        None => Err(PlatformUpdateError::Invalid(
            "missing format_version".into(),
        )),
    }
}

fn check_size(size: usize, limit: usize) -> Result<(), PlatformUpdateError> {
    if size > limit {
        Err(PlatformUpdateError::TooLarge {
            what: FILE_NAME,
            size,
            limit,
        })
    } else {
        Ok(())
    }
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn all_unique<T: Ord>(values: &[T]) -> bool {
    let set: BTreeSet<&T> = values.iter().collect();
    set.len() == values.len()
}

/// Coordination capability the installed host tools actually implement. Lock-file presence is not
/// a signal: only this record proves it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoordinationFeature {
    /// Acquisitions and pruning honor the shared image lock.
    ImageLockHonoured,
    /// The host runner honors the platform update lock.
    PlatformUpdateLock,
    /// Service activation writes and observes an activation epoch.
    ServiceActivation,
    /// Durable reservation phases are implemented.
    ReservationPhases,
}

impl CoordinationFeature {
    pub const fn as_str(self) -> &'static str {
        match self {
            CoordinationFeature::ImageLockHonoured => "image_lock_honoured",
            CoordinationFeature::PlatformUpdateLock => "platform_update_lock",
            CoordinationFeature::ServiceActivation => "service_activation",
            CoordinationFeature::ReservationPhases => "reservation_phases",
        }
    }
}

impl fmt::Display for CoordinationFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Features retention needs before it may delete a platform image at all.
pub const REQUIRED_FOR_PLATFORM_PRUNE: [CoordinationFeature; 4] = [
    CoordinationFeature::ImageLockHonoured,
    CoordinationFeature::PlatformUpdateLock,
    CoordinationFeature::ServiceActivation,
    CoordinationFeature::ReservationPhases,
];

/// `host-capabilities.toml`, written by the installed host tools.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRecord {
    pub format_version: u32,
    pub host_protocol: u32,
    #[serde(default)]
    pub features: BTreeSet<CoordinationFeature>,
    /// Digest of the active host tools generation.
    pub active_generation: StrictDigest,
    /// Boot identity of the writer, so a stale record can be recognized.
    pub writer_boot_id: String,
}

impl CapabilityRecord {
    pub fn parse(src: &str) -> Result<Self, CapabilityError> {
        if src.len() > CAPABILITIES_MAX_BYTES {
            return Err(CapabilityError::Invalid(format!(
                "{CAPABILITIES_FILE_NAME} is {} bytes, the limit is {CAPABILITIES_MAX_BYTES}",
                src.len()
            )));
        }
        let probe: FormatProbe =
            toml::from_str(src).map_err(|e| CapabilityError::Invalid(e.to_string()))?;
        if probe.format_version != Some(FORMAT_VERSION) {
            return Err(CapabilityError::Invalid(format!(
                "{CAPABILITIES_FILE_NAME} has unsupported format_version {:?}",
                probe.format_version
            )));
        }
        let record: Self =
            toml::from_str(src).map_err(|e| CapabilityError::Invalid(e.to_string()))?;
        record.validate()?;
        Ok(record)
    }

    pub fn to_toml(&self) -> Result<String, CapabilityError> {
        self.validate()?;
        toml::to_string(self).map_err(|e| CapabilityError::Invalid(e.to_string()))
    }

    fn validate(&self) -> Result<(), CapabilityError> {
        if self.format_version != FORMAT_VERSION {
            return Err(CapabilityError::Invalid(format!(
                "unsupported format_version {}",
                self.format_version
            )));
        }
        if self.writer_boot_id.is_empty() || self.writer_boot_id.len() > 128 {
            return Err(CapabilityError::Invalid(
                "writer_boot_id must be 1-128 characters".into(),
            ));
        }
        Ok(())
    }

    /// Fails unless this host may participate in platform image deletion.
    pub fn check_platform_prune(&self) -> Result<(), CapabilityError> {
        if self.host_protocol != HOST_PROTOCOL_VERSION {
            return Err(CapabilityError::UnsupportedProtocol(self.host_protocol));
        }
        for feature in REQUIRED_FOR_PLATFORM_PRUNE {
            if !self.features.contains(&feature) {
                return Err(CapabilityError::MissingFeature(feature));
            }
        }
        Ok(())
    }
}

/// The fail-closed gate retention calls before deleting platform images. `None` means
/// `host-capabilities.toml` is absent (a legacy or unenrolled install): deletion stays disabled.
pub fn platform_prune_allowed(record: Option<&CapabilityRecord>) -> Result<(), CapabilityError> {
    match record {
        Some(record) => record.check_platform_prune(),
        None => Err(CapabilityError::Missing),
    }
}

/// Why platform image deletion is disabled. Every variant is reported to the operator; none is
/// permission to clean up anyway.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CapabilityError {
    #[error(
        "{CAPABILITIES_FILE_NAME} is missing; platform image deletion stays disabled until the host is bootstrapped"
    )]
    Missing,
    #[error(
        "host protocol {0} is not {HOST_PROTOCOL_VERSION}; platform image deletion stays disabled"
    )]
    UnsupportedProtocol(u32),
    #[error(
        "host does not implement coordination feature {0}; platform image deletion stays disabled"
    )]
    MissingFeature(CoordinationFeature),
    #[error("invalid {CAPABILITIES_FILE_NAME}: {0}")]
    Invalid(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> StrictDigest {
        StrictDigest::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn endpoint() -> JournalEndpoint {
        JournalEndpoint {
            daemon_repository: Repository::new("ghcr.io/example/weglarka").unwrap(),
            daemon_digest: digest('a'),
            tools_digest: digest('a'),
            state_read: vec![17],
            state_write: 17,
            host_protocol: 1,
        }
    }

    fn transaction(stage: Stage) -> TransactionJournal {
        TransactionJournal {
            transaction_id: TransactionId::new("tx-1").unwrap(),
            stage,
            owner: OwnerIdentity {
                pid: 42,
                boot_id: "boot-1".into(),
                started_at: 1_700_000_000,
                handoff_deadline: Some(1_700_000_600),
            },
            old: endpoint(),
            target: JournalEndpoint {
                daemon_digest: digest('b'),
                tools_digest: digest('b'),
                ..endpoint()
            },
            release_set_digest: digest('c'),
            reservations: vec![OperationId::new("op-1").unwrap()],
            candidate: Some(CandidateSelection {
                generation: digest('b'),
                selector_epoch: 3,
            }),
            ack: None,
            selected_generation: None,
            reason: None,
            updated_at: 1_700_000_010,
        }
    }

    #[test]
    fn the_accepted_pointer_only_moves_forward() {
        let pointer = |sequence, byte| AcceptedPointer {
            sequence,
            release_set_digest: digest(byte),
            revision: "0123456789abcdef0123456789abcdef01234567".into(),
        };
        let mut journal = PlatformUpdate::default();
        journal.accept(Channel::Stable, pointer(5, 'a')).unwrap();
        let before = journal.to_toml().unwrap();
        // Older sequence, and the same sequence with another digest, are both refused.
        assert!(journal.accept(Channel::Stable, pointer(3, 'a')).is_err());
        assert!(journal.accept(Channel::Stable, pointer(5, 'b')).is_err());
        assert_eq!(journal.to_toml().unwrap(), before);
        // The same pointer again is idempotent; a higher sequence moves forward.
        journal.accept(Channel::Stable, pointer(5, 'a')).unwrap();
        journal.accept(Channel::Stable, pointer(6, 'b')).unwrap();
        assert_eq!(journal.accepted(Channel::Stable).unwrap().sequence, 6);
        // Channels are independent.
        journal.accept(Channel::Main, pointer(1, 'c')).unwrap();
    }

    #[test]
    fn journal_round_trips_and_keeps_the_accepted_pointer() {
        let mut journal = PlatformUpdate::default();
        journal
            .accept(
                Channel::Stable,
                AcceptedPointer {
                    sequence: 42,
                    release_set_digest: digest('c'),
                    revision: "0123456789abcdef0123456789abcdef01234567".into(),
                },
            )
            .unwrap();
        journal.transaction = Some(transaction(Stage::Prepared));
        let text = journal.to_toml().unwrap();
        let parsed = PlatformUpdate::parse(&text).unwrap();
        assert_eq!(parsed, journal);
        assert_eq!(parsed.accepted(Channel::Stable).unwrap().sequence, 42);
        assert_eq!(parsed.accepted(Channel::Main), None);
        assert!(!parsed.transaction.as_ref().unwrap().is_terminal());
    }

    #[test]
    fn unknown_format_stops_parsing() {
        let text = PlatformUpdate::default().to_toml().unwrap();
        let newer = text.replace("format_version = 1", "format_version = 2");
        assert_eq!(
            PlatformUpdate::parse(&newer).unwrap_err(),
            PlatformUpdateError::UnsupportedFormat(2)
        );
    }

    #[test]
    fn stage_names_and_terminals_match_the_contract() {
        assert!(Stage::HandoffFailed.is_terminal());
        for stage in [
            Stage::Preparing,
            Stage::Prepared,
            Stage::Handoff,
            Stage::Ack,
            Stage::SwitchingDaemon,
            Stage::DaemonHealthy,
            Stage::PanelTransition,
            Stage::CommitPersisted,
        ] {
            assert!(!stage.is_terminal(), "{stage:?}");
        }
        assert_eq!(
            serde_json::to_string(&Stage::BlockedRecovery).unwrap(),
            "\"blocked_recovery\""
        );
    }

    fn capabilities(features: &[CoordinationFeature]) -> CapabilityRecord {
        CapabilityRecord {
            format_version: FORMAT_VERSION,
            host_protocol: 1,
            features: features.iter().copied().collect(),
            active_generation: digest('a'),
            writer_boot_id: "boot-1".into(),
        }
    }

    #[test]
    fn platform_prune_requires_the_record_protocol_and_features() {
        assert_eq!(
            platform_prune_allowed(None).unwrap_err(),
            CapabilityError::Missing
        );
        let complete = capabilities(&REQUIRED_FOR_PLATFORM_PRUNE);
        complete.check_platform_prune().unwrap();
        let text = complete.to_toml().unwrap();
        assert_eq!(CapabilityRecord::parse(&text).unwrap(), complete);

        let mut old = complete.clone();
        old.host_protocol = 2;
        assert_eq!(
            old.check_platform_prune().unwrap_err(),
            CapabilityError::UnsupportedProtocol(2)
        );

        let missing = capabilities(&REQUIRED_FOR_PLATFORM_PRUNE[..3]);
        assert_eq!(
            missing.check_platform_prune().unwrap_err(),
            CapabilityError::MissingFeature(CoordinationFeature::ReservationPhases)
        );
    }
}
