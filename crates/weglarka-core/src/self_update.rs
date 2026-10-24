//! Self-update bookkeeping (issue #99, `docs/decisions/0027`): the state file shared by the
//! host-side switcher (`weglarka-daemon self-update`) and the daemon, plus the pure decision the
//! switcher makes before it replaces the image.
//!
//! The switcher pulls the configured tag, verifies the cosign signature and pins the digest in the
//! service definition; it records the digest as `pending` and restarts the service. On the next
//! start the daemon compares `pending` with the digest its own container really runs: a match
//! confirms the switch (`current`, with the old digest kept as `previous` — the rollback target);
//! a mismatch is reported instead of silently pretending the update happened.
//!
//! A switch also records the attempt itself (`switch_from`/`switch_to`/`switch_at`): the host-side
//! watchdog installed by `platform install` runs [`supervise`] every minute, so a switch that does
//! not become healthy within its deadline is reverted to `switch_from` — the digest restored in the
//! service definition (issue #100, `docs/decisions/0034`).
//!
//! The file is deliberately **tolerant** (`serde(default)`, unknown fields ignored, mode 0600): it
//! is internal bookkeeping, and a daemon from before this feature — or a newer one — must not be
//! stopped by a field it does not know. The strict TOMLs (`state.toml`, `apps.toml`) are versioned
//! separately: `state::SCHEMA_VERSION` plus the `schema_version` marker (ADR 0023), and the image
//! declares the version it writes in the OCI label `io.weglarka.state-schema`, so the switcher can
//! compare both before it replaces the image.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::app::Digest;

/// File in the state directory (mounted into the daemon and available to the host-side switcher).
pub const FILE_NAME: &str = "self-update.toml";
/// The file names the previous image and failures; owner-only.
pub const FILE_MODE: u32 = 0o600;

#[derive(Debug, thiserror::Error)]
pub enum SelfUpdateStateError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot write {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid {path}: {message}")]
    Parse { path: PathBuf, message: String },
}

/// The last refused or failed attempt (shown by `doctor`, kept until the next check).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SelfUpdateError {
    pub message: String,
    /// The digest the attempt concerned, when there was one.
    pub digest: Option<Digest>,
    /// Unix seconds.
    pub at: u64,
}

/// What the switcher and the daemon remember about the daemon image.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SelfUpdateState {
    /// Digest the daemon confirmed it was running at its last start.
    pub current: Option<Digest>,
    /// The digest that ran before `current` — the rollback target.
    pub previous: Option<Digest>,
    /// Digest pinned in the service definition; cleared once the daemon runs it.
    pub pending: Option<Digest>,
    /// Unix seconds of the `pending` request.
    pub pending_at: Option<u64>,
    /// Unix seconds of the last completed check; the check interval is measured from here.
    pub checked_at: Option<u64>,
    /// The last failed attempt.
    pub error: Option<SelfUpdateError>,
    /// Digest that was current when `switch_to` was applied — the automatic fallback target
    /// (issue #100). `None` while the running image is the one a switch started from.
    pub switch_from: Option<Digest>,
    /// Digest the switcher pinned in the service definition and is waiting to see healthy.
    pub switch_to: Option<Digest>,
    /// Unix seconds of the restart into `switch_to`; the health deadline is measured from here.
    pub switch_at: Option<u64>,
    /// Automatic fallbacks already attempted for this switch (the budget is one, issue #100).
    #[serde(skip_serializing_if = "is_zero")]
    pub switch_attempts: u32,
    /// The digest that failed and was replaced by the last automatic fallback (issue #100).
    pub fallback_from: Option<Digest>,
    /// The digest the last automatic fallback restored.
    pub fallback_to: Option<Digest>,
    /// Unix seconds of the last automatic fallback.
    pub fallback_at: Option<u64>,
}

/// `serde` helper: keeps the default `switch_attempts = 0` out of the written file.
fn is_zero(value: &u32) -> bool {
    *value == 0
}

/// What a startup confirmation found (the daemon turns it into an event / a log line).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confirmation {
    /// The switcher pinned `to`, and the daemon now runs it. `from` is the rollback target.
    Updated { from: Option<Digest>, to: Digest },
    /// The running digest changed without a pending request (a manual `platform install --image`).
    Adopted { from: Option<Digest>, to: Digest },
    /// A switch was requested but the container runs a different image.
    Pending { expected: Digest, actual: Digest },
    /// Nothing changed.
    Unchanged,
}

/// What the switcher should do with the freshly pulled digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The pulled digest is already the running or the pending one.
    UpToDate,
    /// Pin `to` and restart.
    Update { from: Option<Digest>, to: Digest },
    /// Do not touch the service definition; the message goes into the state file and the log.
    Refused(String),
}

/// One switch the host-side switcher applied and the daemon has not been seen healthy in yet
/// (issue #100, `docs/decisions/0034`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Switch {
    /// The digest that ran before the switch — the automatic fallback target.
    pub from: Option<Digest>,
    /// The digest pinned in the service definition.
    pub to: Digest,
    /// Unix seconds of the restart into `to`.
    pub at: u64,
    /// Automatic fallbacks already attempted for this switch.
    pub attempts: u32,
}

/// The last automatic fallback (issue #100): the digest that failed and the one restored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fallback {
    pub from: Digest,
    pub to: Digest,
    /// Unix seconds.
    pub at: u64,
}

/// How long a switched daemon gets to become healthy and how often it may be reverted
/// (issue #100).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FallbackPolicy {
    /// The new daemon must answer the health probe within this window after the switch restart.
    pub timeout: Duration,
    /// Automatic fallbacks per switch. More than one cannot help: the only target is the single
    /// digest recorded when the switch was applied.
    pub max_attempts: u32,
}

impl FallbackPolicy {
    /// Three minutes is enough for a `scratch` daemon whose startup is validation plus binding.
    pub const DEFAULT_TIMEOUT_SECS: u64 = 180;
    /// Shorter than this would race the container start itself.
    pub const MIN_TIMEOUT_SECS: u64 = 30;
    pub const MAX_TIMEOUT_SECS: u64 = 3600;
    /// One: `switch.from` is the only safe target, and a loop must not be possible.
    pub const DEFAULT_MAX_ATTEMPTS: u32 = 1;
}

impl Default for FallbackPolicy {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(Self::DEFAULT_TIMEOUT_SECS),
            max_attempts: Self::DEFAULT_MAX_ATTEMPTS,
        }
    }
}

/// What the watchdog should do about a switch that is not confirmed healthy yet (issue #100).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Supervision {
    /// Nothing in flight: no switch to supervise.
    Idle,
    /// The health probe answered — the switch is good and the attempt can be forgotten.
    Healthy,
    /// The probe has not answered yet and the deadline has not passed.
    Waiting { remaining: Duration },
    /// The deadline passed without a healthy probe: restore `target` in the service definition.
    FallBack { target: Digest },
    /// Nothing can (or may) be corrected automatically; the reason is reported, the service is
    /// left exactly as it is.
    GiveUp { reason: String },
}

/// Unix seconds — scheduling and "how old is this", not a precise timestamp format.
pub fn secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

pub fn path(state_dir: &Path) -> PathBuf {
    state_dir.join(FILE_NAME)
}

pub fn load(state_dir: &Path) -> Result<SelfUpdateState, SelfUpdateStateError> {
    let path = path(state_dir);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(SelfUpdateState::default()),
        Err(source) => return Err(SelfUpdateStateError::Read { path, source }),
    };
    toml::from_str(&text).map_err(|e| SelfUpdateStateError::Parse {
        path,
        message: e.to_string(),
    })
}

pub fn save(state_dir: &Path, state: &SelfUpdateState) -> Result<(), SelfUpdateStateError> {
    let path = path(state_dir);
    let text = toml::to_string(state).map_err(|e| SelfUpdateStateError::Parse {
        path: path.clone(),
        message: e.to_string(),
    })?;
    crate::state::write_atomic(&path, text.as_bytes(), FILE_MODE)
        .map_err(|source| SelfUpdateStateError::Write { path, source })
}

/// The schema before versioning and before the image label: `apps.toml`/`state.toml` without a
/// `schema_version` marker, and images that do not carry `io.weglarka.state-schema`.
pub const IMPLICIT_SCHEMA: u32 = 1;

impl SelfUpdateState {
    /// The check interval is measured from the last completed check; a missing one is due.
    pub fn is_due(&self, interval: Duration, now: SystemTime) -> bool {
        match self.checked_at {
            None => true,
            Some(at) => secs(now).saturating_sub(at) >= interval.as_secs(),
        }
    }

    /// A previous attempt with this digest already failed — do not fetch the registry again for it
    /// until the tag moves (the switcher clears the error when the digest changes).
    pub fn failed_for(&self, digest: &Digest) -> bool {
        self.error
            .as_ref()
            .is_some_and(|e| e.digest.as_ref() == Some(digest))
    }

    pub fn record_check(&mut self, now: SystemTime) {
        self.checked_at = Some(secs(now));
    }

    pub fn record_error(
        &mut self,
        message: impl Into<String>,
        digest: Option<Digest>,
        now: SystemTime,
    ) {
        self.error = Some(SelfUpdateError {
            message: message.into(),
            digest,
            at: secs(now),
        });
        self.record_check(now);
    }

    /// Forgets the previous failure (a different digest is being tried).
    pub fn clear_error(&mut self) {
        self.error = None;
    }

    /// Reconciles `pending` with the digest this daemon really runs; see [`Confirmation`].
    pub fn confirm(&mut self, running: &Digest) -> Confirmation {
        match self.pending.clone() {
            Some(pending) if &pending == running => {
                let from = self.current.take();
                self.current = Some(running.clone());
                self.previous = from.clone();
                self.pending = None;
                self.pending_at = None;
                Confirmation::Updated {
                    from,
                    to: running.clone(),
                }
            }
            Some(pending) => Confirmation::Pending {
                expected: pending,
                actual: running.clone(),
            },
            None if self.current.as_ref() == Some(running) => Confirmation::Unchanged,
            None => {
                let from = self.current.take();
                self.current = Some(running.clone());
                self.previous = from.clone();
                Confirmation::Adopted {
                    from,
                    to: running.clone(),
                }
            }
        }
    }

    /// The switch the switcher applied and the daemon has not been seen healthy in yet.
    ///
    /// Both the pinned digest and the restart time are required: a half-written record (a file
    /// from a version that knew only one of them) must not look like a switch whose deadline has
    /// already passed.
    pub fn active_switch(&self) -> Option<Switch> {
        Some(Switch {
            from: self.switch_from.clone(),
            to: self.switch_to.clone()?,
            at: self.switch_at?,
            attempts: self.switch_attempts,
        })
    }

    /// Records the switch the host-side switcher is about to apply (issue #100): it becomes the
    /// `pending` digest and the automatic-fallback anchor. A new switch starts with a full budget
    /// and no fallback history from the previous one.
    pub fn begin_switch(&mut self, from: Option<Digest>, to: Digest, now: SystemTime) {
        self.pending = Some(to.clone());
        self.pending_at = Some(secs(now));
        self.switch_from = from;
        self.switch_to = Some(to);
        self.switch_at = Some(secs(now));
        self.switch_attempts = 0;
        self.fallback_from = None;
        self.fallback_to = None;
        self.fallback_at = None;
    }

    /// Forgets the switch attempt: the daemon confirmed it, or the watchdog handled it.
    ///
    /// `pending`/`pending_at` are deliberately left alone: `pending` belongs to the switch
    /// confirmation, and a switch the watchdog gave up on may still be confirmed by the daemon.
    pub fn clear_switch(&mut self) {
        self.switch_from = None;
        self.switch_to = None;
        self.switch_at = None;
        self.switch_attempts = 0;
    }

    /// Records the automatic fallback from `failed` back to `target` and pins `target` as the new
    /// `pending` digest, so the next daemon start confirms the restored image (issue #100).
    ///
    /// The fallback restart becomes the new attempt's start — the restored image gets its own full
    /// deadline — and it counts against the switch budget: a fallback that does not come up ends in
    /// a report, never in another restart.
    pub fn record_fallback(&mut self, failed: Digest, target: Digest, now: SystemTime) {
        self.switch_attempts = self.switch_attempts.saturating_add(1);
        self.switch_at = Some(secs(now));
        self.fallback_from = Some(failed);
        self.fallback_to = Some(target.clone());
        self.fallback_at = Some(secs(now));
        self.pending = Some(target);
        self.pending_at = Some(secs(now));
    }

    /// The last automatic fallback, for `doctor` and the daemon's confirmation event (issue #100).
    pub fn last_fallback(&self) -> Option<Fallback> {
        Some(Fallback {
            from: self.fallback_from.clone()?,
            to: self.fallback_to.clone()?,
            at: self.fallback_at?,
        })
    }
}

/// Whether the pulled digest may replace the running one.
///
/// `image_schema` is the OCI label `io.weglarka.state-schema` of the pulled image and
/// `state_schema` the version the state files are at (`schema_version` in `state.toml`, i.e.
/// `state::SCHEMA_VERSION`; a file without the marker is the implicit v1).
///
/// A **missing** value on either side means "before versioning existed", i.e. [`IMPLICIT_SCHEMA`]: an
/// image from before the label can read v1 state, so installing it on v1 state is an ordinary
/// upgrade, while installing it on migrated state is a downgrade and gets refused.
pub fn decide(
    state: &SelfUpdateState,
    pulled: &Digest,
    image_schema: Option<u32>,
    state_schema: Option<u32>,
) -> Decision {
    if state.current.as_ref() == Some(pulled) || state.pending.as_ref() == Some(pulled) {
        return Decision::UpToDate;
    }
    let image = image_schema.unwrap_or(IMPLICIT_SCHEMA);
    let current = state_schema.unwrap_or(IMPLICIT_SCHEMA);
    if image < current {
        return Decision::Refused(format!(
            "the image writes state schema {image}, but the state is already at schema {current}: \
             a downgrade across a schema bump would lose fields (restore a state backup, or pass \
             --force if you know the older image reads it)"
        ));
    }
    Decision::Update {
        from: state.current.clone(),
        to: pulled.clone(),
    }
}

/// Decides the supervisor's next step from the persisted switch and a health observation
/// (issue #100, `docs/decisions/0034`).
///
/// `healthy` is the outcome of the host-side probe of the admin API; `now` is injected so the tests
/// are deterministic, like [`SelfUpdateState::is_due`] and [`decide`]. The function is pure — it
/// never writes and never restarts anything — so the watchdog's whole policy is one testable table.
///
/// The deadline counts from the switch restart (or from the fallback restart, when one was
/// attempted): a switch that does not answer the probe in time is reverted to `switch.from`, and the
/// attempt budget stops a fallback that does not come up from restarting in a loop.
pub fn supervise(
    state: &SelfUpdateState,
    healthy: bool,
    now: SystemTime,
    policy: &FallbackPolicy,
) -> Supervision {
    let Some(switch) = state.active_switch() else {
        return Supervision::Idle;
    };
    if healthy {
        return Supervision::Healthy;
    }
    let timeout = policy.timeout.as_secs();
    let age = secs(now).saturating_sub(switch.at);
    if age < timeout {
        return Supervision::Waiting {
            remaining: Duration::from_secs(timeout - age),
        };
    }
    if switch.attempts >= policy.max_attempts {
        return Supervision::GiveUp {
            reason: format!(
                "the switch to {} did not become healthy within {timeout}s and the automatic \
                 fallback budget is exhausted ({} attempt(s)); inspect the journal of \
                 weglarka-watchdog.service and run `weglarka-daemon self-update --rollback` or \
                 install a working image",
                switch.to, switch.attempts
            ),
        };
    }
    match switch.from {
        Some(from) if from != switch.to => Supervision::FallBack { target: from },
        Some(_) => Supervision::GiveUp {
            reason: format!(
                "the switch to {} did not become healthy within {timeout}s, but its fallback \
                 target is the same digest — install a working image with \
                 `weglarka-daemon platform install --image <ref>`",
                switch.to
            ),
        },
        None => Supervision::GiveUp {
            reason: format!(
                "the switch to {} did not become healthy within {timeout}s, but no previous image \
                 is recorded to fall back to — install a working image with \
                 `weglarka-daemon platform install --image <ref>`",
                switch.to
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn digest(c: char) -> Digest {
        Digest::new(format!("sha256:{}", c.to_string().repeat(64))).unwrap()
    }

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn missing_file_is_empty_and_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load(dir.path()).unwrap(), SelfUpdateState::default());

        let state = SelfUpdateState {
            current: Some(digest('a')),
            previous: Some(digest('b')),
            pending: Some(digest('c')),
            pending_at: Some(100),
            checked_at: Some(200),
            error: Some(SelfUpdateError {
                message: "unsigned image".into(),
                digest: Some(digest('d')),
                at: 150,
            }),
            ..SelfUpdateState::default()
        };
        save(dir.path(), &state).unwrap();
        assert_eq!(load(dir.path()).unwrap(), state);
        let mode = fs::metadata(path(dir.path())).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, FILE_MODE);
    }

    #[test]
    fn unknown_fields_are_tolerated_and_corruption_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            path(dir.path()),
            "current = \"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n\
             future_field = 1\n",
        )
        .unwrap();
        assert_eq!(load(dir.path()).unwrap().current, Some(digest('a')));

        fs::write(path(dir.path()), "not toml").unwrap();
        let err = load(dir.path()).unwrap_err();
        assert!(
            matches!(&err, SelfUpdateStateError::Parse { path, .. } if path.ends_with(FILE_NAME)),
            "{err}"
        );
    }

    #[test]
    fn the_interval_is_measured_from_the_last_check() {
        let mut state = SelfUpdateState::default();
        assert!(state.is_due(Duration::from_secs(3600), at(10_000)));
        state.record_check(at(10_000));
        assert!(!state.is_due(Duration::from_secs(3600), at(10_000 + 3599)));
        assert!(state.is_due(Duration::from_secs(3600), at(10_000 + 3600)));
    }

    #[test]
    fn confirmation_tracks_current_previous_and_pending() {
        // First start ever: the image is adopted, nothing to roll back to.
        let mut state = SelfUpdateState::default();
        assert_eq!(
            state.confirm(&digest('a')),
            Confirmation::Adopted {
                from: None,
                to: digest('a')
            }
        );
        assert_eq!(state.current, Some(digest('a')));

        // The switcher pinned b; the daemon restarted into it.
        state.pending = Some(digest('b'));
        state.pending_at = Some(1);
        assert_eq!(
            state.confirm(&digest('b')),
            Confirmation::Updated {
                from: Some(digest('a')),
                to: digest('b')
            }
        );
        assert_eq!(state.current, Some(digest('b')));
        assert_eq!(state.previous, Some(digest('a')));
        assert!(state.pending.is_none() && state.pending_at.is_none());

        // Same image again: nothing changed.
        assert_eq!(state.confirm(&digest('b')), Confirmation::Unchanged);

        // The switch did not take effect: the pending digest stays for `doctor`.
        state.pending = Some(digest('c'));
        assert_eq!(
            state.confirm(&digest('b')),
            Confirmation::Pending {
                expected: digest('c'),
                actual: digest('b')
            }
        );
        assert_eq!(state.pending, Some(digest('c')));
    }

    #[test]
    fn decisions_cover_up_to_date_upgrade_and_schema_downgrade() {
        let mut state = SelfUpdateState::default();
        assert_eq!(
            decide(&state, &digest('a'), None, None),
            Decision::Update {
                from: None,
                to: digest('a')
            }
        );

        state.current = Some(digest('a'));
        assert_eq!(decide(&state, &digest('a'), None, None), Decision::UpToDate);
        state.pending = Some(digest('b'));
        assert_eq!(decide(&state, &digest('b'), None, None), Decision::UpToDate);
        state.pending = None;

        // Upgrading: the state has no version yet (pre-#98 install) or the image matches it.
        assert!(matches!(
            decide(&state, &digest('b'), Some(1), None),
            Decision::Update { .. }
        ));
        assert!(matches!(
            decide(&state, &digest('b'), Some(2), Some(2)),
            Decision::Update { .. }
        ));
        // A missing label means "before the label", i.e. v1: still an upgrade on v1 state…
        assert!(matches!(
            decide(&state, &digest('b'), None, None),
            Decision::Update { .. }
        ));
        assert!(matches!(
            decide(&state, &digest('b'), None, Some(IMPLICIT_SCHEMA)),
            Decision::Update { .. }
        ));
        // …and a downgrade once the state has moved on.
        assert!(matches!(
            decide(&state, &digest('b'), None, Some(2)),
            Decision::Refused(_)
        ));

        // Downgrade across a schema bump is refused with an explanation.
        match decide(&state, &digest('b'), Some(1), Some(2)) {
            Decision::Refused(message) => {
                assert!(
                    message.contains("schema 1") && message.contains("schema 2"),
                    "{message}"
                );
                assert!(message.contains("--force"), "{message}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn the_containerfile_declares_the_state_schema_label() {
        // The switcher reads this label to decide whether the new image can read the state; a
        // Containerfile that drifts from `state::SCHEMA_VERSION` would make it compare apples to
        // oranges (ADR 0023 for the file version, ADR 0027 for the switcher).
        let containerfile = include_str!("../../../Containerfile");
        let mut declared = containerfile
            .lines()
            .filter_map(|line| line.trim().strip_prefix("ARG STATE_SCHEMA="));
        let first = declared
            .next()
            .expect("Containerfile: ARG STATE_SCHEMA=<N>");
        assert_eq!(
            first.parse::<u32>().unwrap(),
            crate::state::SCHEMA_VERSION,
            "ARG STATE_SCHEMA must equal state::SCHEMA_VERSION"
        );
        assert!(
            declared.next().is_none(),
            "exactly one ARG STATE_SCHEMA line"
        );
        assert!(
            containerfile.contains("io.weglarka.state-schema=\"${STATE_SCHEMA}\""),
            "the label fed from that ARG must be present"
        );
    }

    #[test]
    fn failures_are_tied_to_the_digest() {
        let mut state = SelfUpdateState::default();
        assert!(!state.failed_for(&digest('a')));
        state.record_error("unsigned", Some(digest('a')), at(5));
        assert!(state.failed_for(&digest('a')));
        assert!(!state.failed_for(&digest('b')));
        assert_eq!(state.checked_at, Some(5));
        state.clear_error();
        assert!(!state.failed_for(&digest('a')));
    }

    #[test]
    fn the_switch_and_fallback_records_survive_a_save() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = SelfUpdateState::default();
        state.begin_switch(Some(digest('a')), digest('b'), at(1_000));
        state.record_fallback(digest('b'), digest('a'), at(1_400));
        save(dir.path(), &state).unwrap();

        let loaded = load(dir.path()).unwrap();
        assert_eq!(loaded, state);
        assert_eq!(
            loaded.active_switch(),
            Some(Switch {
                from: Some(digest('a')),
                to: digest('b'),
                at: 1_400,
                attempts: 1,
            })
        );
        assert_eq!(
            loaded.last_fallback(),
            Some(Fallback {
                from: digest('b'),
                to: digest('a'),
                at: 1_400,
            })
        );
    }

    #[test]
    fn a_state_file_from_before_the_supervisor_has_no_switch() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            path(dir.path()),
            format!("current = \"{}\"\n", digest('a').as_str()),
        )
        .unwrap();
        let state = load(dir.path()).unwrap();
        assert!(state.active_switch().is_none());
        assert!(state.last_fallback().is_none());

        // A half-written record is not a switch whose deadline has already passed.
        fs::write(
            path(dir.path()),
            format!("switch_to = \"{}\"\n", digest('b').as_str()),
        )
        .unwrap();
        assert!(load(dir.path()).unwrap().active_switch().is_none());
    }

    #[test]
    fn a_new_switch_starts_with_a_full_budget_and_no_fallback_history() {
        let mut state = SelfUpdateState::default();
        state.begin_switch(Some(digest('a')), digest('b'), at(1_000));
        assert_eq!(state.pending, Some(digest('b')));
        assert_eq!(state.pending_at, Some(1_000));
        let switch = state.active_switch().unwrap();
        assert_eq!(switch.from, Some(digest('a')));
        assert_eq!(switch.attempts, 0);
        assert_eq!(state.last_fallback(), None);

        // The fallback pins the restored image and gets a deadline of its own...
        state.record_fallback(digest('b'), digest('a'), at(1_400));
        assert_eq!(state.pending, Some(digest('a')));
        assert_eq!(state.pending_at, Some(1_400));
        assert_eq!(state.active_switch().unwrap().at, 1_400);
        assert_eq!(state.active_switch().unwrap().attempts, 1);
        // ...and the next switch starts that history over.
        state.begin_switch(Some(digest('a')), digest('c'), at(2_000));
        assert_eq!(state.active_switch().unwrap().attempts, 0);
        assert_eq!(state.last_fallback(), None);
        state.clear_switch();
        assert!(state.active_switch().is_none());
        // `clear_switch` leaves the switch confirmation to the daemon.
        assert_eq!(state.pending, Some(digest('c')));
    }

    #[test]
    fn a_switch_waits_for_its_deadline_then_falls_back_once() {
        let policy = FallbackPolicy::default();
        let mut state = SelfUpdateState::default();
        state.begin_switch(Some(digest('a')), digest('b'), at(1_000));

        // During the deadline the watchdog only waits...
        assert_eq!(
            supervise(&state, false, at(1_060), &policy),
            Supervision::Waiting {
                remaining: Duration::from_secs(180 - 60)
            }
        );
        // ...except when the probe answers, which settles the switch immediately.
        assert_eq!(
            supervise(&state, true, at(1_060), &policy),
            Supervision::Healthy
        );
        // Past the deadline (inclusive) the previous digest is restored.
        assert_eq!(
            supervise(&state, false, at(1_180), &policy),
            Supervision::FallBack {
                target: digest('a')
            }
        );

        state.record_fallback(digest('b'), digest('a'), at(1_200));
        // The restored image gets a fresh deadline.
        assert_eq!(
            supervise(&state, false, at(1_260), &policy),
            Supervision::Waiting {
                remaining: Duration::from_secs(120)
            }
        );
        // When it does not come up either, the budget is exhausted: report, never restart again.
        match supervise(&state, false, at(1_400), &policy) {
            Supervision::GiveUp { reason } => {
                assert!(reason.contains("budget"), "{reason}");
                assert!(reason.contains("--rollback"), "{reason}");
            }
            other => panic!("expected GiveUp, got {other:?}"),
        }
        // A probe that answers after all is healthy, whatever the budget says.
        assert_eq!(
            supervise(&state, true, at(1_400), &policy),
            Supervision::Healthy
        );
    }

    #[test]
    fn supervision_cannot_fall_back_without_a_previous_digest() {
        let policy = FallbackPolicy::default();
        let mut state = SelfUpdateState::default();
        // The first install has nothing to go back to.
        state.begin_switch(None, digest('b'), at(1_000));
        match supervise(&state, false, at(1_180), &policy) {
            Supervision::GiveUp { reason } => {
                assert!(reason.contains("no previous image"), "{reason}");
            }
            other => panic!("expected GiveUp, got {other:?}"),
        }
        // A switch whose "previous" is the failed digest cannot be reverted either.
        state.begin_switch(Some(digest('b')), digest('b'), at(1_000));
        match supervise(&state, false, at(1_180), &policy) {
            Supervision::GiveUp { reason } => {
                assert!(reason.contains("same digest"), "{reason}");
            }
            other => panic!("expected GiveUp, got {other:?}"),
        }
        // Nothing in flight means nothing to do, healthy or not.
        assert_eq!(
            supervise(&SelfUpdateState::default(), false, at(9_999), &policy),
            Supervision::Idle
        );
    }

    #[test]
    fn a_custom_timeout_moves_the_deadline() {
        let policy = FallbackPolicy {
            timeout: Duration::from_secs(30),
            max_attempts: 1,
        };
        let mut state = SelfUpdateState::default();
        state.begin_switch(Some(digest('a')), digest('b'), at(1_000));
        assert!(matches!(
            supervise(&state, false, at(1_029), &policy),
            Supervision::Waiting { .. }
        ));
        assert!(matches!(
            supervise(&state, false, at(1_030), &policy),
            Supervision::FallBack { .. }
        ));
    }
}
