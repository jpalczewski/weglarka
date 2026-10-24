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
}
