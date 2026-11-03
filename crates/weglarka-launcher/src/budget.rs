//! Bounded, persisted attempt budgets.
//!
//! Two independent budgets keep a crash loop from running forever:
//!
//! - The daemon service launcher owns a start-attempt budget **per activation epoch** and records a
//!   blocked marker when it is exhausted, while staying alive so a new selection can start.
//! - The stable launcher records a recovery attempt **before** every recovery exec, so a failing
//!   recovery binary cannot be restarted forever and a process restart cannot reset the budget.
//!
//! Both files are host-only, atomic and mode 0600.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use weglarka_model::fsutil::write_atomic;

use crate::host::{HostError, RECOVERY_STATE_FILE, SERVICE_ATTEMPTS_FILE, read_bounded};

/// Format of both budget files.
pub const FORMAT_VERSION: u32 = 1;

/// `service-attempts.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceAttempts {
    pub format_version: u32,
    pub epoch: u64,
    pub attempts: u32,
    pub blocked: bool,
}

/// `recovery-state.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryState {
    pub format_version: u32,
    /// Transaction the budget belongs to; a different transaction starts a fresh budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction: Option<String>,
    pub attempts: u32,
    pub blocked: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum BudgetError {
    #[error(transparent)]
    Host(#[from] HostError),
    #[error("invalid {file}: {message}")]
    Parse { file: &'static str, message: String },
    #[error("the {0} attempt budget is exhausted")]
    Exhausted(&'static str),
}

/// Permission to start one daemon attempt. The counter is already durable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attempt {
    pub number: u32,
}

fn load_bounded<T: for<'de> Deserialize<'de>>(
    path: &Path,
    file: &'static str,
) -> Result<Option<T>, BudgetError> {
    let Some(text) = read_bounded(path, file, 4096)? else {
        return Ok(None);
    };
    toml::from_str(&text)
        .map(Some)
        .map_err(|e| BudgetError::Parse {
            file,
            message: e.to_string(),
        })
}

fn save<T: Serialize>(path: &Path, value: &T, file: &'static str) -> Result<(), BudgetError> {
    let text = toml::to_string(value).map_err(|e| BudgetError::Parse {
        file,
        message: e.to_string(),
    })?;
    write_atomic(path, text.as_bytes(), 0o600).map_err(|source| HostError::Write {
        path: path.to_owned(),
        source,
    })?;
    Ok(())
}

impl ServiceAttempts {
    pub fn path(host_dir: &Path) -> PathBuf {
        host_dir.join(SERVICE_ATTEMPTS_FILE)
    }

    pub fn load(host_dir: &Path, epoch: u64) -> Result<Self, BudgetError> {
        let stored: Option<Self> = load_bounded(&Self::path(host_dir), SERVICE_ATTEMPTS_FILE)?;
        Ok(match stored {
            Some(stored) if stored.format_version == FORMAT_VERSION && stored.epoch == epoch => {
                stored
            }
            _ => Self {
                format_version: FORMAT_VERSION,
                epoch,
                attempts: 0,
                blocked: false,
            },
        })
    }

    fn save(&self, host_dir: &Path) -> Result<(), BudgetError> {
        save(&Self::path(host_dir), self, SERVICE_ATTEMPTS_FILE)
    }
}

/// Counts one start attempt for `epoch` **before** the container is started.
pub fn note_service_attempt(
    host_dir: &Path,
    epoch: u64,
    max_attempts: u32,
) -> Result<Attempt, BudgetError> {
    let mut state = ServiceAttempts::load(host_dir, epoch)?;
    if state.blocked {
        return Err(BudgetError::Exhausted("daemon service"));
    }
    state.attempts = state.attempts.saturating_add(1);
    if state.attempts > max_attempts {
        state.blocked = true;
        state.save(host_dir)?;
        return Err(BudgetError::Exhausted("daemon service"));
    }
    state.save(host_dir)?;
    Ok(Attempt {
        number: state.attempts,
    })
}

/// Marks the current epoch as blocked without consuming another attempt.
pub fn block_service_epoch(host_dir: &Path, epoch: u64) -> Result<(), BudgetError> {
    let mut state = ServiceAttempts::load(host_dir, epoch)?;
    state.blocked = true;
    state.save(host_dir)
}

impl RecoveryState {
    pub fn path(host_dir: &Path) -> PathBuf {
        host_dir.join(RECOVERY_STATE_FILE)
    }

    pub fn load(host_dir: &Path, transaction: Option<&str>) -> Result<Self, BudgetError> {
        let stored: Option<Self> = load_bounded(&Self::path(host_dir), RECOVERY_STATE_FILE)?;
        Ok(match stored {
            Some(stored)
                if stored.format_version == FORMAT_VERSION
                    && stored.transaction.as_deref() == transaction =>
            {
                stored
            }
            _ => Self {
                format_version: FORMAT_VERSION,
                transaction: transaction.map(str::to_owned),
                attempts: 0,
                blocked: false,
            },
        })
    }

    fn save(&self, host_dir: &Path) -> Result<(), BudgetError> {
        save(&Self::path(host_dir), self, RECOVERY_STATE_FILE)
    }
}

/// Counts one recovery attempt **before** executing the recovery generation.
pub fn note_recovery_attempt(
    host_dir: &Path,
    transaction: Option<&str>,
    max_attempts: u32,
) -> Result<Attempt, BudgetError> {
    let mut state = RecoveryState::load(host_dir, transaction)?;
    if state.blocked {
        return Err(BudgetError::Exhausted("recovery"));
    }
    state.attempts = state.attempts.saturating_add(1);
    if state.attempts > max_attempts {
        state.blocked = true;
        state.save(host_dir)?;
        return Err(BudgetError::Exhausted("recovery"));
    }
    state.save(host_dir)?;
    Ok(Attempt {
        number: state.attempts,
    })
}

/// Clears the recovery budget for a new selection/transaction.
pub fn reset_recovery_budget(
    host_dir: &Path,
    transaction: Option<&str>,
) -> Result<(), BudgetError> {
    RecoveryState {
        format_version: FORMAT_VERSION,
        transaction: transaction.map(str::to_owned),
        attempts: 0,
        blocked: false,
    }
    .save(host_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_service_budget_is_per_epoch_and_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        for n in 1..=3 {
            assert_eq!(note_service_attempt(dir.path(), 4, 3).unwrap().number, n);
        }
        assert!(matches!(
            note_service_attempt(dir.path(), 4, 3),
            Err(BudgetError::Exhausted("daemon service"))
        ));
        // A process restart loads the durable blocked marker.
        assert!(ServiceAttempts::load(dir.path(), 4).unwrap().blocked);
        // A new selection (epoch) starts a fresh budget.
        assert_eq!(note_service_attempt(dir.path(), 5, 3).unwrap().number, 1);
    }

    #[test]
    fn the_recovery_budget_is_bound_to_the_transaction() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            note_recovery_attempt(dir.path(), Some("tx-1"), 2)
                .unwrap()
                .number,
            1
        );
        assert_eq!(
            note_recovery_attempt(dir.path(), Some("tx-1"), 2)
                .unwrap()
                .number,
            2
        );
        assert!(note_recovery_attempt(dir.path(), Some("tx-1"), 2).is_err());
        assert!(
            RecoveryState::load(dir.path(), Some("tx-1"))
                .unwrap()
                .blocked
        );
        // A new transaction resets the budget.
        assert_eq!(
            note_recovery_attempt(dir.path(), Some("tx-2"), 2)
                .unwrap()
                .number,
            1
        );
        reset_recovery_budget(dir.path(), Some("tx-2")).unwrap();
        assert_eq!(
            RecoveryState::load(dir.path(), Some("tx-2"))
                .unwrap()
                .attempts,
            0
        );
    }
}
