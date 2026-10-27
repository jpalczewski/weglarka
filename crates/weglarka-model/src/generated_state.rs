//! What the generated-config pipeline last did, per generator (#212): `<state dir>/generated.toml`.
//!
//! Like `webhook-deliveries.toml` (ADR 0035) this lives outside `state.toml`: a new field there
//! would break a rollback through `deny_unknown_fields` and need a schema bump, while an older
//! daemon simply ignores this file. It is read tolerantly — a missing file is empty, an unreadable
//! or malformed one is logged and treated as empty, so bookkeeping can never stop the daemon from
//! starting — and written atomically, mode 0600, by the engine (the only writer).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::generated::Fingerprint;

/// File in the state directory.
pub const FILE_NAME: &str = "generated.toml";
pub const FILE_MODE: u32 = 0o600;
/// Bytes of validator output kept in the state and in the event (the tail: errors come last).
pub const OUTPUT_LIMIT: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LastResult {
    /// Nothing recorded yet.
    #[default]
    None,
    Applied,
    /// The validator rejected the render; `current` was left alone.
    Invalid,
    /// The consumer failed its health gate and `current` went back to the previous version.
    RolledBack,
}

/// The pipeline's record for one generator id. Unknown fields are ignored (a newer daemon's file).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneratorRecord {
    /// Fingerprint of the version the consumer is running (or will read on its next start).
    pub applied: Option<String>,
    /// `false` when the version was applied without running the validator (bootstrap).
    pub validated: bool,
    pub last_result: LastResult,
    /// Tail of the validator output or the apply error behind a non-`Applied` result.
    pub last_error: Option<String>,
}

impl GeneratorRecord {
    pub fn applied_fingerprint(&self) -> Option<Fingerprint> {
        self.applied.as_deref().and_then(Fingerprint::parse)
    }
}

/// On-disk shape; the map is keyed by generator id.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneratedState {
    pub generators: BTreeMap<String, GeneratorRecord>,
}

#[derive(Debug, thiserror::Error)]
pub enum GeneratedStateError {
    #[error("cannot serialize {FILE_NAME}: {0}")]
    Serialize(#[from] toml::ser::Error),
    #[error("cannot write {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl GeneratedState {
    pub fn load(path: &Path) -> Self {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Self::default(),
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "cannot read the generated-config state; starting empty");
                return Self::default();
            }
        };
        if text.trim().is_empty() {
            return Self::default();
        }
        toml::from_str(&text).unwrap_or_else(|e| {
            tracing::warn!(path = %path.display(), error = %e, "ignoring a malformed generated-config state; it is rewritten on the next apply");
            Self::default()
        })
    }

    pub fn save(&self, path: &Path) -> Result<(), GeneratedStateError> {
        let text = toml::to_string(self)?;
        crate::fsutil::write_atomic(path, text.as_bytes(), FILE_MODE).map_err(|source| {
            GeneratedStateError::Write {
                path: path.to_owned(),
                source,
            }
        })
    }

    pub fn get(&self, id: &str) -> Option<&GeneratorRecord> {
        self.generators.get(id)
    }

    pub fn entry(&mut self, id: &str) -> &mut GeneratorRecord {
        self.generators.entry(id.to_owned()).or_default()
    }
}

/// The last [`OUTPUT_LIMIT`] bytes of `output`, cut on a character boundary.
pub fn tail(output: &str) -> &str {
    if output.len() <= OUTPUT_LIMIT {
        return output;
    }
    let mut start = output.len() - OUTPUT_LIMIT;
    while !output.is_char_boundary(start) {
        start += 1;
    }
    &output[start..]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn missing_empty_and_malformed_files_load_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        assert_eq!(GeneratedState::load(&path), GeneratedState::default());
        fs::write(&path, "  \n").unwrap();
        assert_eq!(GeneratedState::load(&path), GeneratedState::default());
        fs::write(&path, "generators = 3 = oops").unwrap();
        assert_eq!(GeneratedState::load(&path), GeneratedState::default());
    }

    #[test]
    fn round_trips_with_mode_0600_and_ignores_unknown_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let mut state = GeneratedState::default();
        let rec = state.entry("identity");
        rec.applied = Some("a".repeat(64));
        rec.validated = true;
        rec.last_result = LastResult::Applied;
        state.save(&path).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(GeneratedState::load(&path), state);
        assert!(
            state
                .get("identity")
                .unwrap()
                .applied_fingerprint()
                .is_some()
        );

        fs::write(
            &path,
            "future = 1\n[generators.identity]\nfuture_field = true\n",
        )
        .unwrap();
        assert!(GeneratedState::load(&path).get("identity").is_some());
    }

    #[test]
    fn tail_keeps_the_end_on_a_char_boundary() {
        assert_eq!(tail("short"), "short");
        let long = format!("{}{}", "x".repeat(OUTPUT_LIMIT), "ż");
        let t = tail(&long);
        assert!(t.len() <= OUTPUT_LIMIT);
        assert!(t.ends_with('ż'));
    }
}
