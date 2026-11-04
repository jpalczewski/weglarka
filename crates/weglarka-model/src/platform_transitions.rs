//! Durable panel pins and panel transition records.
//!
//! Two files from
//! [`docs/contracts/platform-update-v1`](../../../docs/contracts/platform-update-v1/README.md):
//!
//! - `platform-pins.toml` is the authority for what an enrolled panel **should** run. Its effective
//!   digest feeds every image-resolution path before a tag pull. Unenrollment sets `active = false`
//!   and records `archived_at`; the entry is kept, never deleted.
//! - `platform-transitions.toml` is the idempotent retry and `GET` source after a restart. It keeps
//!   every nonterminal transition and the last [`MAX_TERMINAL_TRANSITIONS`] terminal ones.
//!
//! Both are strict, versioned and bounded. The engine is the only writer; commit order and
//! serialization are the engine's responsibility (see brief D), this module only makes the records
//! durable and comparable.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::app::InstanceName;
use crate::platform_update::TransactionId;
use crate::release_set::{Repository, StrictDigest};
use crate::size_limit;

/// Panel pin file in the shared state directory.
pub const PINS_FILE_NAME: &str = "platform-pins.toml";
/// Transition journal in the shared state directory.
pub const TRANSITIONS_FILE_NAME: &str = "platform-transitions.toml";
/// Version of both file formats.
pub const FORMAT_VERSION: u32 = 1;
/// Largest accepted file (each of the two).
pub const MAX_BYTES: usize = 1024 * 1024;
/// Terminal transitions retained; older ones are dropped by [`Transitions::record_terminal`].
pub const MAX_TERMINAL_TRANSITIONS: usize = 32;

/// One enrolled panel's pin. `revision` increases monotonically on every change, so a stale
/// transition request can be rejected without guessing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinEntry {
    pub instance: InstanceName,
    /// The panel's configured repository; must equal the selected panel repository.
    pub repository: Repository,
    /// Unix seconds when the operator enrolled the instance.
    pub enrolled_at: u64,
    /// `false` after explicit unenrollment; the entry is retained.
    pub active: bool,
    /// Unix seconds of unenrollment; present exactly when `active` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archived_at: Option<u64>,
    /// What should run. Resolution functions take this explicitly instead of re-deriving a digest
    /// from `AppState`.
    pub effective: StrictDigest,
    /// The rollback target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<StrictDigest>,
    /// Intent recorded before a deploy; cleared when the deploy completes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<StrictDigest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<TransactionId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_set_digest: Option<StrictDigest>,
    pub revision: u64,
}

/// `platform-pins.toml`, sorted by instance on write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pins {
    pub format_version: u32,
    #[serde(default)]
    pub pins: Vec<PinEntry>,
}

impl Default for Pins {
    fn default() -> Self {
        Self {
            format_version: FORMAT_VERSION,
            pins: Vec::new(),
        }
    }
}

impl Pins {
    pub fn new(pins: Vec<PinEntry>) -> Result<Self, TransitionsError> {
        let pins = Self {
            format_version: FORMAT_VERSION,
            pins,
        };
        pins.canonical()
    }

    pub fn get(&self, instance: &InstanceName) -> Option<&PinEntry> {
        self.pins.iter().find(|pin| &pin.instance == instance)
    }

    pub fn parse(src: &str) -> Result<Self, TransitionsError> {
        if let Err(over) = size_limit::check(src.len(), MAX_BYTES) {
            return Err(TransitionsError::TooLarge {
                file: PINS_FILE_NAME,
                size: over.size,
                limit: over.limit,
            });
        }
        let probe: FormatProbe = toml::from_str(src)?;
        check_format(probe.format_version)?;
        let pins: Self = toml::from_str(src)?;
        pins.canonical()
    }

    pub fn to_toml(&self) -> Result<String, TransitionsError> {
        Ok(toml::to_string(&self.canonical()?)?)
    }

    fn canonical(&self) -> Result<Self, TransitionsError> {
        check_format(Some(self.format_version))?;
        let mut pins = self.pins.clone();
        pins.sort_by_key(|pin| pin.instance.clone());
        for pair in pins.windows(2) {
            if pair[0].instance == pair[1].instance {
                return Err(TransitionsError::DuplicatePin(pair[0].instance.to_string()));
            }
        }
        for pin in &pins {
            if pin.active == pin.archived_at.is_some() {
                return Err(TransitionsError::Invalid(format!(
                    "pin {}: active must be false exactly when archived_at is set",
                    pin.instance
                )));
            }
        }
        Ok(Self {
            format_version: FORMAT_VERSION,
            pins,
        })
    }
}

/// Status reported by the unix-only panel transition API and stored in the journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionStatus {
    Pending,
    Running,
    Succeeded,
    RolledBack,
    Failed,
}

impl TransitionStatus {
    /// A terminal record is immutable and is what an idempotent retry returns.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            TransitionStatus::Succeeded | TransitionStatus::RolledBack | TransitionStatus::Failed
        )
    }
}

/// One panel transition. A terminal record carries the requested and actual digests, the pin
/// revision it was accepted at and a reason, so a retry after a restart returns the recorded answer
/// instead of redeploying.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionRecord {
    pub transaction_id: TransactionId,
    pub status: TransitionStatus,
    /// Resolved OCI manifest digest of the prepared release set.
    pub release_set_digest: StrictDigest,
    pub requested_digest: StrictDigest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual_digest: Option<StrictDigest>,
    /// The pin revision the request expected (and the record was accepted at).
    pub pin_revision: u64,
    /// `KnownBad` retried only when the operator asked for it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub retry_failed_release: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Unix seconds.
    pub created_at: u64,
    /// Unix seconds of the last durable write.
    pub updated_at: u64,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// `platform-transitions.toml`: nonterminal transitions plus bounded terminal history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transitions {
    pub format_version: u32,
    #[serde(default)]
    pub nonterminal: Vec<TransitionRecord>,
    #[serde(default)]
    pub terminal: Vec<TransitionRecord>,
}

impl Default for Transitions {
    fn default() -> Self {
        Self {
            format_version: FORMAT_VERSION,
            nonterminal: Vec::new(),
            terminal: Vec::new(),
        }
    }
}

impl Transitions {
    pub fn new(
        nonterminal: Vec<TransitionRecord>,
        terminal: Vec<TransitionRecord>,
    ) -> Result<Self, TransitionsError> {
        let transitions = Self {
            format_version: FORMAT_VERSION,
            nonterminal,
            terminal,
        };
        transitions.canonical()
    }

    /// Finds a transition by ID **before** any revision validation: an existing ID is answered
    /// from the record, never re-executed.
    pub fn find(&self, transaction_id: &TransactionId) -> Option<&TransitionRecord> {
        self.nonterminal
            .iter()
            .chain(self.terminal.iter())
            .find(|record| &record.transaction_id == transaction_id)
    }

    /// The one engine-owned deployment that may be running.
    pub fn active(&self) -> Option<&TransitionRecord> {
        self.nonterminal.first()
    }

    /// Records a terminal outcome and drops history past the bound. The caller persists the file.
    ///
    /// A terminal record is never replaced: a transaction ID that already has one is rejected with
    /// [`TransitionsError::DuplicateTransition`] (answer a retry from [`Transitions::find`]). The
    /// `terminal` list keeps recording order and the oldest entries are dropped first, so a wall
    /// clock that steps back cannot make the newest record the one that is trimmed.
    pub fn record_terminal(&mut self, record: TransitionRecord) -> Result<(), TransitionsError> {
        if !record.status.is_terminal() {
            return Err(TransitionsError::Invalid(format!(
                "transition {} has nonterminal status {:?}",
                record.transaction_id, record.status
            )));
        }
        if self
            .terminal
            .iter()
            .any(|existing| existing.transaction_id == record.transaction_id)
        {
            return Err(TransitionsError::DuplicateTransition(
                record.transaction_id.to_string(),
            ));
        }
        self.nonterminal
            .retain(|existing| existing.transaction_id != record.transaction_id);
        self.terminal.push(record);
        let excess = self.terminal.len().saturating_sub(MAX_TERMINAL_TRANSITIONS);
        self.terminal.drain(..excess);
        Ok(())
    }

    pub fn parse(src: &str) -> Result<Self, TransitionsError> {
        if let Err(over) = size_limit::check(src.len(), MAX_BYTES) {
            return Err(TransitionsError::TooLarge {
                file: TRANSITIONS_FILE_NAME,
                size: over.size,
                limit: over.limit,
            });
        }
        let probe: FormatProbe = toml::from_str(src)?;
        check_format(probe.format_version)?;
        let transitions: Self = toml::from_str(src)?;
        transitions.canonical()
    }

    pub fn to_toml(&self) -> Result<String, TransitionsError> {
        Ok(toml::to_string(&self.canonical()?)?)
    }

    fn canonical(&self) -> Result<Self, TransitionsError> {
        check_format(Some(self.format_version))?;
        if self.terminal.len() > MAX_TERMINAL_TRANSITIONS {
            return Err(TransitionsError::TooManyTerminal(self.terminal.len()));
        }
        for record in &self.nonterminal {
            if record.status.is_terminal() {
                return Err(TransitionsError::Invalid(format!(
                    "transition {} is terminal but stored as nonterminal",
                    record.transaction_id
                )));
            }
        }
        for record in &self.terminal {
            if !record.status.is_terminal() {
                return Err(TransitionsError::Invalid(format!(
                    "transition {} is nonterminal but stored as terminal",
                    record.transaction_id
                )));
            }
        }
        let mut ids = BTreeSet::new();
        for record in self.nonterminal.iter().chain(&self.terminal) {
            if !ids.insert(record.transaction_id.clone()) {
                return Err(TransitionsError::DuplicateTransition(
                    record.transaction_id.to_string(),
                ));
            }
        }
        let mut nonterminal = self.nonterminal.clone();
        nonterminal.sort_by_key(|a| a.created_at);
        // Recording order is the history order; `updated_at` is wall-clock and must not reorder it.
        let terminal = self.terminal.clone();
        Ok(Self {
            format_version: FORMAT_VERSION,
            nonterminal,
            terminal,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransitionsError {
    #[error("{file} is {size} bytes, the limit is {limit}")]
    TooLarge {
        file: &'static str,
        size: usize,
        limit: usize,
    },
    #[error("unsupported format_version {0}")]
    UnsupportedFormat(u32),
    #[error("duplicate pin for instance {0:?}")]
    DuplicatePin(String),
    #[error("duplicate transition {0:?}")]
    DuplicateTransition(String),
    #[error(
        "transitions file holds {0} terminal records, over the limit of {MAX_TERMINAL_TRANSITIONS}"
    )]
    TooManyTerminal(usize),
    #[error("invalid platform transitions: {0}")]
    Invalid(String),
    #[error("invalid TOML: {0}")]
    TomlDe(String),
    #[error("cannot serialize TOML: {0}")]
    TomlSer(String),
}

impl From<toml::de::Error> for TransitionsError {
    fn from(error: toml::de::Error) -> Self {
        Self::TomlDe(error.to_string())
    }
}

impl From<toml::ser::Error> for TransitionsError {
    fn from(error: toml::ser::Error) -> Self {
        Self::TomlSer(error.to_string())
    }
}

#[derive(Deserialize)]
struct FormatProbe {
    #[serde(default)]
    format_version: Option<u32>,
}

fn check_format(value: Option<u32>) -> Result<(), TransitionsError> {
    match value {
        Some(FORMAT_VERSION) => Ok(()),
        Some(other) => Err(TransitionsError::UnsupportedFormat(other)),
        None => Err(TransitionsError::Invalid("missing format_version".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> StrictDigest {
        StrictDigest::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn name(value: &str) -> InstanceName {
        InstanceName::new(value).unwrap()
    }

    fn pin() -> PinEntry {
        PinEntry {
            instance: name("panel"),
            repository: Repository::new("ghcr.io/example/weglarka-panel").unwrap(),
            enrolled_at: 1_700_000_000,
            active: true,
            archived_at: None,
            effective: digest('a'),
            previous: Some(digest('b')),
            pending: None,
            transaction_id: Some(TransactionId::new("tx-1").unwrap()),
            release_set_digest: Some(digest('c')),
            revision: 2,
        }
    }

    fn record(id: &str, status: TransitionStatus, updated_at: u64) -> TransitionRecord {
        TransitionRecord {
            transaction_id: TransactionId::new(id).unwrap(),
            status,
            release_set_digest: digest('c'),
            requested_digest: digest('b'),
            actual_digest: status.is_terminal().then(|| digest('b')),
            pin_revision: 2,
            retry_failed_release: false,
            reason: None,
            created_at: updated_at.saturating_sub(1),
            updated_at,
        }
    }

    #[test]
    fn pins_round_trip_and_keep_an_archived_entry() {
        let pins = Pins::new(vec![pin()]).unwrap();
        let text = pins.to_toml().unwrap();
        assert_eq!(Pins::parse(&text).unwrap(), pins);

        let mut archived = pin();
        archived.active = false;
        archived.archived_at = Some(1_700_000_100);
        let pins = Pins::new(vec![archived]).unwrap();
        let text = pins.to_toml().unwrap();
        assert_eq!(Pins::parse(&text).unwrap(), pins);
    }

    #[test]
    fn pins_reject_duplicates_and_inconsistent_archival() {
        assert_eq!(
            Pins::new(vec![pin(), pin()]).unwrap_err(),
            TransitionsError::DuplicatePin("panel".into())
        );
        let mut broken = pin();
        broken.archived_at = Some(1);
        assert!(matches!(
            Pins::new(vec![broken]).unwrap_err(),
            TransitionsError::Invalid(_)
        ));
    }

    #[test]
    fn transitions_round_trip_and_bound_terminal_history() {
        let transitions = Transitions::new(
            vec![record("tx-live", TransitionStatus::Running, 10)],
            vec![record("tx-old", TransitionStatus::Failed, 5)],
        )
        .unwrap();
        let text = transitions.to_toml().unwrap();
        assert_eq!(Transitions::parse(&text).unwrap(), transitions);

        assert_eq!(
            Transitions::new(
                vec![record("tx-same", TransitionStatus::Running, 10)],
                vec![record("tx-same", TransitionStatus::Succeeded, 11)],
            )
            .unwrap_err(),
            TransitionsError::DuplicateTransition("tx-same".into())
        );

        let mut transitions = Transitions::default();
        for i in 0..(MAX_TERMINAL_TRANSITIONS + 5) {
            transitions
                .record_terminal(record(
                    &format!("tx-{i}"),
                    TransitionStatus::Succeeded,
                    i as u64,
                ))
                .unwrap();
        }
        assert_eq!(transitions.terminal.len(), MAX_TERMINAL_TRANSITIONS);
        assert_eq!(
            transitions
                .terminal
                .first()
                .unwrap()
                .transaction_id
                .as_str(),
            "tx-5"
        );
        assert!(
            transitions
                .find(&TransactionId::new("tx-0").unwrap())
                .is_none()
        );
    }

    #[test]
    fn a_terminal_record_is_never_replaced_and_trimming_ignores_the_clock() {
        let mut transitions = Transitions::default();
        transitions
            .record_terminal(record("tx-a", TransitionStatus::Failed, 100))
            .unwrap();
        assert_eq!(
            transitions
                .record_terminal(record("tx-a", TransitionStatus::Succeeded, 200))
                .unwrap_err(),
            TransitionsError::DuplicateTransition("tx-a".into())
        );
        let kept = transitions
            .find(&TransactionId::new("tx-a").unwrap())
            .unwrap();
        assert_eq!(kept.status, TransitionStatus::Failed);

        // The clock steps back: later records carry smaller `updated_at`, yet the oldest go first.
        let mut transitions = Transitions::default();
        for i in 0..(MAX_TERMINAL_TRANSITIONS + 2) {
            transitions
                .record_terminal(record(
                    &format!("tx-{i}"),
                    TransitionStatus::Succeeded,
                    10_000 - i as u64,
                ))
                .unwrap();
        }
        let ids: Vec<_> = transitions
            .terminal
            .iter()
            .map(|r| r.transaction_id.as_str().to_owned())
            .collect();
        assert_eq!(ids.first().unwrap(), "tx-2");
        assert_eq!(
            ids.last().unwrap(),
            &format!("tx-{}", MAX_TERMINAL_TRANSITIONS + 1)
        );
        let text = transitions.to_toml().unwrap();
        assert_eq!(Transitions::parse(&text).unwrap(), transitions);
    }

    #[test]
    fn unknown_format_stops_parsing() {
        let text = Transitions::default().to_toml().unwrap();
        let newer = text.replace("format_version = 1", "format_version = 2");
        assert_eq!(
            Transitions::parse(&newer).unwrap_err(),
            TransitionsError::UnsupportedFormat(2)
        );
    }
}
