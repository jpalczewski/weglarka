//! Bounded, persisted attempt budgets.
//!
//! Two independent budgets keep a crash loop from running forever:
//!
//! - The daemon service launcher owns a start-attempt budget **per activation epoch** and records a
//!   blocked marker when it is exhausted, while staying alive so a new selection can start. A run
//!   longer than the stability threshold clears the counter, so only a crash loop exhausts it.
//! - The stable launcher records a recovery attempt **before** every recovery exec, so a failing
//!   recovery binary cannot be restarted forever and a process restart cannot reset the budget.
//!
//! Both files are host-only, atomic and mode 0600.

use std::path::{Path, PathBuf};
use std::time::Duration;

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

/// Whether a container run lasted long enough to count as healthy rather than a crash loop.
pub fn run_was_stable(ran: Duration, stable_after: Duration) -> bool {
    ran > stable_after
}

/// Delay before retry number `failures` (1-based): `base`, `2 × base`, `4 × base`, … never above
/// `cap`. No failures, no delay.
pub fn backoff_delay(failures: u32, base: Duration, cap: Duration) -> Duration {
    let Some(doublings) = failures.checked_sub(1) else {
        return Duration::ZERO;
    };
    // 2^31 × base is far beyond any cap; the clamp only keeps the shift defined.
    base.saturating_mul(1 << doublings.min(31)).min(cap)
}

impl ServiceAttempts {
    /// The budget after a run of `ran`: a stable run proves the epoch works, so the next crash
    /// starts counting from zero again. A short run changes nothing.
    pub fn after_run(&self, ran: Duration, stable_after: Duration) -> Self {
        if run_was_stable(ran, stable_after) {
            Self {
                attempts: 0,
                blocked: false,
                ..self.clone()
            }
        } else {
            self.clone()
        }
    }

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

/// Records that the daemon container ran for `ran`. A run longer than `stable_after` clears the
/// epoch's attempt counter (a daemon that survived a reboot or a long uptime is not a crash loop);
/// returns whether it did.
pub fn note_service_run(
    host_dir: &Path,
    epoch: u64,
    ran: Duration,
    stable_after: Duration,
) -> Result<bool, BudgetError> {
    let state = ServiceAttempts::load(host_dir, epoch)?;
    let after = state.after_run(ran, stable_after);
    if after != state {
        after.save(host_dir)?;
    }
    Ok(run_was_stable(ran, stable_after))
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
    fn only_a_run_longer_than_the_threshold_is_stable() {
        let after = Duration::from_secs(600);
        assert!(!run_was_stable(Duration::from_secs(599), after));
        assert!(!run_was_stable(after, after));
        assert!(run_was_stable(Duration::from_secs(601), after));
    }

    #[test]
    fn the_backoff_doubles_up_to_the_cap() {
        let (base, cap) = (Duration::from_secs(2), Duration::from_secs(60));
        let delays: Vec<u64> = (0..=8)
            .map(|n| backoff_delay(n, base, cap).as_secs())
            .collect();
        assert_eq!(delays, [0, 2, 4, 8, 16, 32, 60, 60, 60]);
        // Absurd failure counts neither overflow nor exceed the cap.
        assert_eq!(backoff_delay(u32::MAX, base, cap), cap);
    }

    #[test]
    fn a_stable_run_resets_the_counter_and_a_short_one_keeps_it() {
        let state = ServiceAttempts {
            format_version: FORMAT_VERSION,
            epoch: 4,
            attempts: 3,
            blocked: false,
        };
        let after = Duration::from_secs(600);
        assert_eq!(state.after_run(Duration::from_secs(5), after), state);
        let reset = state.after_run(Duration::from_secs(601), after);
        assert_eq!((reset.epoch, reset.attempts), (4, 0));
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
