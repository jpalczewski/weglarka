//! `host-tools.toml` — the host-only generation selector.
//!
//! It selects the normal generation and records the candidate used for a handoff plus the
//! last-known-good recovery generation. Writes happen under the host-selection lock; every write is
//! atomic (tmp + file fsync + rename + directory fsync, mode 0600). A damaged selector is a visible
//! error, never a heuristic pick of the newest directory.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use weglarka_model::fsutil::write_atomic;
use weglarka_model::release_set::StrictDigest;

use crate::host::{
    BOOTSTRAP_MARKER, HOST_TOOLS_FILE, HOST_TOOLS_LOCK, HOST_TOOLS_MAX_BYTES, HostError,
    LEGACY_IMPORT_FILE, read_bounded, read_required,
};
use crate::lock::{self, LockError};

/// Format version of the selector.
pub const FORMAT_VERSION: u32 = 1;

/// `host-tools.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSelector {
    pub format_version: u32,
    /// Monotonic selector epoch. Every accepted selection change advances it.
    pub epoch: u64,
    /// The normal generation.
    pub active: StrictDigest,
    /// The last-known-good recovery generation. Absent before the first update; recovery then uses
    /// `active`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<StrictDigest>,
    /// A generation selected for an in-flight handoff.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate: Option<StrictDigest>,
}

#[derive(Debug, thiserror::Error)]
pub enum SelectorError {
    #[error(transparent)]
    Host(#[from] HostError),
    #[error("invalid {HOST_TOOLS_FILE}: {0}")]
    Parse(String),
    #[error("unsupported {HOST_TOOLS_FILE} format_version {0}")]
    UnsupportedFormat(u32),
    #[error("{HOST_TOOLS_FILE} has epoch 0; the initial selector epoch is 1")]
    ZeroEpoch,
    #[error("cannot encode {HOST_TOOLS_FILE}: {0}")]
    Encode(String),
    #[error(transparent)]
    Lock(#[from] LockError),
}

#[derive(Deserialize)]
struct FormatProbe {
    #[serde(default)]
    format_version: Option<u32>,
}

impl HostSelector {
    /// Bootstrap selector: generation 0 is active and is also the recovery generation.
    pub fn fresh(active: StrictDigest) -> Self {
        Self {
            format_version: FORMAT_VERSION,
            epoch: 1,
            active,
            previous: None,
            candidate: None,
        }
    }

    pub fn path(host_dir: &Path) -> PathBuf {
        host_dir.join(HOST_TOOLS_FILE)
    }

    pub fn load(host_dir: &Path) -> Result<Self, SelectorError> {
        let path = Self::path(host_dir);
        let text = read_required(&path, HOST_TOOLS_FILE, HOST_TOOLS_MAX_BYTES)?;
        let probe: FormatProbe =
            toml::from_str(&text).map_err(|e| SelectorError::Parse(e.to_string()))?;
        match probe.format_version {
            Some(FORMAT_VERSION) => {}
            Some(other) => return Err(SelectorError::UnsupportedFormat(other)),
            None => return Err(SelectorError::Parse("missing format_version".into())),
        }
        let selector: Self =
            toml::from_str(&text).map_err(|e| SelectorError::Parse(e.to_string()))?;
        selector.validate()?;
        Ok(selector)
    }

    pub fn load_optional(host_dir: &Path) -> Result<Option<Self>, SelectorError> {
        if !Self::path(host_dir).exists() {
            return Ok(None);
        }
        Self::load(host_dir).map(Some)
    }

    /// Recovery generation: the recorded last-known-good generation, or `active` before the first
    /// update.
    pub fn recovery(&self) -> &StrictDigest {
        self.previous.as_ref().unwrap_or(&self.active)
    }

    fn validate(&self) -> Result<(), SelectorError> {
        if self.format_version != FORMAT_VERSION {
            return Err(SelectorError::UnsupportedFormat(self.format_version));
        }
        if self.epoch == 0 {
            return Err(SelectorError::ZeroEpoch);
        }
        Ok(())
    }

    /// True when `digest` is referenced by active, previous or candidate.
    pub fn references(&self, digest: &StrictDigest) -> bool {
        self.active == *digest
            || self.previous.as_ref() == Some(digest)
            || self.candidate.as_ref() == Some(digest)
    }

    /// Selects a candidate and advances the epoch (the active generation does not change yet).
    pub fn select_candidate(&mut self, candidate: StrictDigest) {
        self.candidate = Some(candidate);
        self.epoch = self.epoch.saturating_add(1);
    }

    /// Promotes the candidate. Fails when the candidate changed under the caller (stale epoch).
    pub fn activate_candidate(&mut self, expected_epoch: u64) -> bool {
        if self.epoch != expected_epoch {
            return false;
        }
        let Some(candidate) = self.candidate.take() else {
            return false;
        };
        let previous = std::mem::replace(&mut self.active, candidate);
        self.previous = Some(previous);
        self.epoch = self.epoch.saturating_add(1);
        true
    }

    /// Records a new active generation for an explicit administrator selection.
    pub fn set_active(&mut self, active: StrictDigest) {
        if self.active != active {
            let previous = std::mem::replace(&mut self.active, active);
            self.previous = Some(previous);
            self.epoch = self.epoch.saturating_add(1);
        }
    }

    pub fn to_toml(&self) -> Result<String, SelectorError> {
        self.validate()?;
        toml::to_string(self).map_err(|e| SelectorError::Encode(e.to_string()))
    }

    /// Writes the selector atomically. Callers must hold [`lock_host_selection`].
    pub fn save(&self, host_dir: &Path) -> Result<(), SelectorError> {
        let text = self.to_toml()?;
        let path = Self::path(host_dir);
        write_atomic(&path, text.as_bytes(), 0o600).map_err(|source| {
            SelectorError::Host(HostError::Write {
                path: path.clone(),
                source,
            })
        })?;
        Ok(())
    }

    /// Reads, mutates and writes the selector under the host-selection lock.
    pub fn update(
        host_dir: &Path,
        mutate: impl FnOnce(&mut HostSelector) -> Result<(), SelectorError>,
    ) -> Result<HostSelector, SelectorError> {
        let _guard = lock_host_selection(host_dir)?;
        let mut selector = Self::load(host_dir)?;
        mutate(&mut selector)?;
        selector.save(host_dir)?;
        Ok(selector)
    }
}

/// Takes the host-selection lock.
pub fn lock_host_selection(host_dir: &Path) -> Result<lock::HostLock, SelectorError> {
    Ok(lock::lock(&host_dir.join(HOST_TOOLS_LOCK))?)
}

/// `bootstrap-complete.toml`: written only after every bootstrap step and both preflights passed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapMarker {
    pub format_version: u32,
    pub generation: StrictDigest,
    pub selector_epoch: u64,
    /// Unix seconds.
    pub completed_at: u64,
}

impl BootstrapMarker {
    pub fn path(host_dir: &Path) -> PathBuf {
        host_dir.join(BOOTSTRAP_MARKER)
    }

    pub fn load(host_dir: &Path) -> Result<Option<Self>, HostError> {
        let Some(text) = read_bounded(&Self::path(host_dir), BOOTSTRAP_MARKER, 4096)? else {
            return Ok(None);
        };
        let marker: Self = toml::from_str(&text).map_err(|e| HostError::Invalid {
            file: BOOTSTRAP_MARKER,
            message: e.to_string(),
        })?;
        if marker.format_version != FORMAT_VERSION {
            return Err(HostError::Invalid {
                file: BOOTSTRAP_MARKER,
                message: format!("unsupported format_version {}", marker.format_version),
            });
        }
        Ok(Some(marker))
    }

    pub fn save(&self, host_dir: &Path) -> Result<(), HostError> {
        let text = toml::to_string(self).map_err(|e| HostError::Invalid {
            file: BOOTSTRAP_MARKER,
            message: e.to_string(),
        })?;
        write_atomic(&Self::path(host_dir), text.as_bytes(), 0o600).map_err(|source| {
            HostError::Write {
                path: Self::path(host_dir),
                source,
            }
        })
    }
}

/// Host-only record of the `self-update.toml` identities imported during bootstrap. The shared
/// inventory/reservation writer consumes it; the launcher never rewrites shared provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyImport {
    pub format_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<String>,
    /// Unix seconds.
    pub imported_at: u64,
}

impl LegacyImport {
    pub fn path(host_dir: &Path) -> PathBuf {
        host_dir.join(LEGACY_IMPORT_FILE)
    }

    pub fn save(&self, host_dir: &Path) -> Result<(), HostError> {
        let text = toml::to_string(self).map_err(|e| HostError::Invalid {
            file: LEGACY_IMPORT_FILE,
            message: e.to_string(),
        })?;
        write_atomic(&Self::path(host_dir), text.as_bytes(), 0o600).map_err(|source| {
            HostError::Write {
                path: Self::path(host_dir),
                source,
            }
        })
    }

    pub fn load(host_dir: &Path) -> Result<Option<Self>, HostError> {
        let Some(text) = read_bounded(&Self::path(host_dir), LEGACY_IMPORT_FILE, 4096)? else {
            return Ok(None);
        };
        toml::from_str(&text)
            .map(Some)
            .map_err(|e| HostError::Invalid {
                file: LEGACY_IMPORT_FILE,
                message: e.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> StrictDigest {
        StrictDigest::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn selector() -> HostSelector {
        HostSelector {
            format_version: FORMAT_VERSION,
            epoch: 3,
            active: digest('a'),
            previous: Some(digest('b')),
            candidate: Some(digest('c')),
        }
    }

    #[test]
    fn selector_round_trips_and_names_the_recovery_generation() {
        let s = selector();
        let text = s.to_toml().unwrap();
        assert_eq!(HostSelector::load_after_parse(&text), s);
        assert_eq!(s.recovery(), &digest('b'));
        let fresh = HostSelector::fresh(digest('a'));
        assert_eq!(fresh.recovery(), &digest('a'));
        assert_eq!(fresh.epoch, 1);
    }

    impl HostSelector {
        fn load_after_parse(text: &str) -> Self {
            toml::from_str(text).unwrap()
        }
    }

    #[test]
    fn candidate_activation_is_epoch_guarded() {
        let mut s = HostSelector::fresh(digest('a'));
        s.select_candidate(digest('b'));
        assert_eq!(s.epoch, 2);
        assert!(!s.activate_candidate(1), "stale epoch must not win");
        assert!(s.activate_candidate(2));
        assert_eq!(s.active, digest('b'));
        assert_eq!(s.previous, Some(digest('a')));
        assert_eq!(s.candidate, None);
        assert_eq!(s.epoch, 3);
    }

    #[test]
    fn a_damaged_selector_is_an_error_not_a_newest_pick() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(HostSelector::path(dir.path()), "format_version = 9\n").unwrap();
        assert!(matches!(
            HostSelector::load(dir.path()),
            Err(SelectorError::UnsupportedFormat(9))
        ));
        std::fs::write(HostSelector::path(dir.path()), "not toml").unwrap();
        assert!(matches!(
            HostSelector::load(dir.path()),
            Err(SelectorError::Parse(_))
        ));
    }

    #[test]
    fn writes_are_atomic_and_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let s = selector();
        {
            let _guard = lock_host_selection(dir.path());
        }
        s.save(dir.path()).unwrap();
        let meta = std::fs::metadata(HostSelector::path(dir.path())).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(HostSelector::load(dir.path()).unwrap(), s);
    }
}
