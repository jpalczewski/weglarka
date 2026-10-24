//! Bounded, persistent memory of handled webhook delivery ids (issue #41).
//!
//! The set is a safety net, not a source of truth: GitHub/Forgejo redeliver an event after a restart
//! (self-update, reboot, `platform install`), and without the ids the daemon would pull and redeploy
//! again — which can undo a manual pin.
//!
//! The ids live in their own file in the state directory (`<state dir>/webhook-deliveries.toml`,
//! mode 0600) instead of `state.toml`: a new field there would break a rollback to an older daemon
//! (`deny_unknown_fields`, ADR 0023) and need a schema bump, while an older daemon simply ignores
//! this file (ADR 0035). It is written atomically by the engine (the only writer) and read
//! tolerantly: a missing file is an empty set, an unreadable or malformed one is logged and treated
//! as empty — bookkeeping must never stop the daemon from starting.

use std::collections::{HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// File in the state directory.
pub const FILE_NAME: &str = "webhook-deliveries.toml";
/// Internal bookkeeping, like `self-update.toml` and `notifications.toml`.
pub const FILE_MODE: u32 = 0o600;
/// Ids remembered before the oldest is dropped.
pub const DEFAULT_CAP: usize = 256;

/// On-disk shape: oldest first, so an over-long file keeps its newest ids.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct DeliveryLog {
    deliveries: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
enum DeliveryLogError {
    #[error("cannot serialize the delivery log: {0}")]
    Serialize(#[from] toml::ser::Error),
    #[error("cannot write {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// Bounded memory of recently seen `delivery_id`s, persisted when it has a path.
pub struct DeliveryDedup {
    cap: usize,
    order: VecDeque<String>,
    seen: HashSet<String>,
    /// `None` = in-memory only (pure unit tests); the engine always loads a file.
    path: Option<PathBuf>,
}

impl DeliveryDedup {
    /// In-memory only. The engine uses [`DeliveryDedup::load`]; this is for pure unit tests.
    pub fn new(cap: usize) -> Self {
        Self {
            // A zero cap would insert and then never evict consistently.
            cap: cap.max(1),
            order: VecDeque::new(),
            seen: HashSet::new(),
            path: None,
        }
    }

    /// Loads the ids persisted at `path`, keeping the newest `cap` ones.
    ///
    /// A missing file is an empty set. A file that cannot be read or parsed is logged and treated
    /// as empty — the next accepted delivery rewrites it (this is bookkeeping, not state).
    pub fn load(path: impl Into<PathBuf>, cap: usize) -> Self {
        let path = path.into();
        let mut dedup = Self {
            path: Some(path.clone()),
            ..Self::new(cap)
        };
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return dedup,
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "cannot read the webhook delivery log; starting with an empty set"
                );
                return dedup;
            }
        };
        // An empty or comment-only file is a valid empty set; do not rely on the TOML parser here.
        if text.trim().is_empty() {
            return dedup;
        }
        match toml::from_str::<DeliveryLog>(&text) {
            Ok(log) => {
                for id in log.deliveries {
                    // `remember`, not `check_and_insert`: loading must not write.
                    dedup.remember(&id);
                }
            }
            Err(e) => tracing::warn!(
                path = %path.display(),
                error = %e,
                "ignoring a malformed webhook delivery log; it is rewritten on the next delivery"
            ),
        }
        dedup
    }

    /// The file this set is persisted to, if any.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// `true` if the identifier was already seen; otherwise remembers it (and persists it).
    pub fn check_and_insert(&mut self, id: &str) -> bool {
        let duplicate = self.remember(id);
        if !duplicate {
            self.save();
        }
        duplicate
    }

    /// Memory only: `true` if the identifier was already seen.
    fn remember(&mut self, id: &str) -> bool {
        if self.seen.contains(id) {
            return true;
        }
        if self.order.len() == self.cap
            && let Some(old) = self.order.pop_front()
        {
            self.seen.remove(&old);
        }
        self.order.push_back(id.to_owned());
        self.seen.insert(id.to_owned());
        false
    }

    fn save(&self) {
        let Some(path) = &self.path else {
            return;
        };
        if let Err(e) = self.write(path) {
            // The in-memory set still works for this process; a redelivery after the next restart
            // is processed again — the pre-#41 behaviour. Never fail the webhook because of it.
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "cannot persist the webhook delivery log"
            );
        }
    }

    fn write(&self, path: &Path) -> Result<(), DeliveryLogError> {
        let log = DeliveryLog {
            deliveries: self.order.iter().cloned().collect(),
        };
        let text = toml::to_string(&log)?;
        crate::state::write_atomic(path, text.as_bytes(), FILE_MODE).map_err(|source| {
            DeliveryLogError::Write {
                path: path.to_owned(),
                source,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn dedup_is_bounded() {
        let mut d = DeliveryDedup::new(2);
        assert!(!d.check_and_insert("a"));
        assert!(d.check_and_insert("a"));
        assert!(!d.check_and_insert("b"));
        assert!(!d.check_and_insert("c")); // evicts "a"
        assert!(!d.check_and_insert("a"));
    }

    #[test]
    fn persists_ids_and_drops_the_oldest() {
        let dir = tempdir();
        let path = dir.path().join(FILE_NAME);
        let mut d = DeliveryDedup::load(&path, 2);
        assert!(!d.check_and_insert("a"));
        assert!(!d.check_and_insert("b"));
        assert!(!d.check_and_insert("c")); // evicts "a"
        // A restart (a new in-memory set over the same file) loads exactly what was written.
        let mut again = DeliveryDedup::load(&path, 2);
        assert!(again.check_and_insert("c"));
        assert!(again.check_and_insert("b"));
        assert!(!again.check_and_insert("a"));
    }

    #[test]
    fn missing_file_is_an_empty_set_and_is_not_created_by_loading() {
        let dir = tempdir();
        let path = dir.path().join(FILE_NAME);
        let d = DeliveryDedup::load(&path, 2);
        assert_eq!(d.path(), Some(path.as_path()));
        assert!(!path.exists());
    }

    #[test]
    fn writes_mode_0600() {
        let dir = tempdir();
        let path = dir.path().join(FILE_NAME);
        let mut d = DeliveryDedup::load(&path, 2);
        assert!(!d.check_and_insert("d-1"));
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, FILE_MODE);
    }

    #[test]
    fn load_trims_a_bloated_file_to_the_newest_ids() {
        let dir = tempdir();
        let path = dir.path().join(FILE_NAME);
        fs::write(&path, "deliveries = [\"1\", \"2\", \"3\", \"4\"]\n").unwrap();
        let mut d = DeliveryDedup::load(&path, 2);
        assert!(d.check_and_insert("4"));
        assert!(d.check_and_insert("3"));
        assert!(!d.check_and_insert("2"));
    }

    #[test]
    fn empty_or_malformed_file_is_ignored_and_rewritten() {
        let dir = tempdir();
        let path = dir.path().join(FILE_NAME);
        for broken in ["", "   \n", "this is not toml"] {
            fs::write(&path, broken).unwrap();
            let mut d = DeliveryDedup::load(&path, 2);
            assert!(!d.check_and_insert("x"), "{broken:?}");
            let text = fs::read_to_string(&path).unwrap();
            assert!(text.contains("\"x\""), "{broken:?} -> {text}");
        }
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let dir = tempdir();
        let path = dir.path().join(FILE_NAME);
        fs::write(&path, "deliveries = [\"x\"]\nfuture = 1\n").unwrap();
        let mut d = DeliveryDedup::load(&path, 2);
        assert!(d.check_and_insert("x"));
    }
}
