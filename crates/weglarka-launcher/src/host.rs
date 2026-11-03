//! Host-only paths and file names shared by the launcher and the host adapters.
//!
//! The host-only directory is configured at installation time and is deliberately outside every
//! daemon bind mount. The launcher accepts only absolute paths without `..`, derives every other
//! path from this root, and validates generation directory names as lower-case hex digests rather
//! than treating them as arbitrary paths.

use std::path::{Component, Path, PathBuf};

use weglarka_model::release_set::StrictDigest;

/// Default host-only directory. Installation may override it (`platform bootstrap --host-dir`).
pub const DEFAULT_HOST_DIR: &str = "/var/lib/weglarka-host";
/// Host protocol implemented by this launcher and by the v1 contract.
pub const HOST_PROTOCOL_VERSION: u32 = 1;

/// Stable launcher binary inside the host-only directory.
pub const LAUNCHER_FILE: &str = "weglarka-launcher";
/// Generation directories.
pub const GENERATIONS_DIR: &str = "generations";
/// Manifest written into every generation directory.
pub const GENERATION_MANIFEST: &str = "manifest.toml";
/// The two host binaries (host tools names from the descriptor).
pub const HOST_DAEMON_FILE: &str = "weglarka-daemon";
pub const HOST_CLI_FILE: &str = "weglarka";

/// `host-tools.toml` and its short lock.
pub const HOST_TOOLS_FILE: &str = "host-tools.toml";
pub const HOST_TOOLS_LOCK: &str = "host-tools.lock";
/// Largest accepted selector.
pub const HOST_TOOLS_MAX_BYTES: usize = 64 * 1024;

/// `platform-service.toml` and its short lock.
pub const SERVICE_SELECTION_FILE: &str = "platform-service.toml";
pub const SERVICE_SELECTION_LOCK: &str = "platform-service.lock";
/// Largest accepted service selection.
pub const SERVICE_SELECTION_MAX_BYTES: usize = 256 * 1024;

/// Shared `runtime-jobs.toml` (written by the adapter, read by the jobs).
pub const RUNTIME_JOBS_FILE: &str = "runtime-jobs.toml";
pub const RUNTIME_JOBS_LOCK: &str = "runtime-jobs.lock";
pub const RUNTIME_JOBS_MAX_BYTES: usize = 64 * 1024;

/// Marker written only after bootstrap completed and preflight passed.
pub const BOOTSTRAP_MARKER: &str = "bootstrap-complete.toml";
/// Imported protections from the retired legacy `self-update.toml` (host-only record; the shared
/// inventory/reservation writer consumes it).
pub const LEGACY_IMPORT_FILE: &str = "legacy-import.toml";
/// Bounded recovery attempt budget (persisted before every recovery exec).
pub const RECOVERY_STATE_FILE: &str = "recovery-state.toml";
/// Bounded daemon start-attempt budget for one activation epoch.
pub const SERVICE_ATTEMPTS_FILE: &str = "service-attempts.toml";

#[derive(Debug, thiserror::Error)]
pub enum HostError {
    #[error("host-only directory must be an absolute path (got {0:?})")]
    NotAbsolute(PathBuf),
    #[error("host-only directory must not contain '..' (got {0:?})")]
    ParentComponent(PathBuf),
    #[error("host-only directory must not be the filesystem root")]
    Root,
    #[error("invalid generation directory name {0:?}: expected 64 lower-case hex characters")]
    InvalidGenerationName(String),
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
    #[error("{path} is not a regular file")]
    NotRegular { path: PathBuf },
    #[error("{path} is a symlink; host tools are never followed")]
    Symlink { path: PathBuf },
    #[error("{path} has mode {mode:o}, expected {expected:o}")]
    Mode {
        path: PathBuf,
        mode: u32,
        expected: u32,
    },
    #[error("invalid {file}: {message}")]
    Invalid { file: &'static str, message: String },
    #[error("{file} is {size} bytes, the limit is {limit}")]
    TooLarge {
        file: &'static str,
        size: usize,
        limit: usize,
    },
}

/// Normalises and validates an installation-configured host-only root.
pub fn validate_host_dir(path: &Path) -> Result<PathBuf, HostError> {
    if !path.is_absolute() {
        return Err(HostError::NotAbsolute(path.to_owned()));
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(HostError::ParentComponent(path.to_owned()));
    }
    if path.components().all(|c| matches!(c, Component::RootDir)) {
        return Err(HostError::Root);
    }
    Ok(path.to_owned())
}

/// Directory name for a digest: the lower-case hex part only (never an arbitrary path).
pub fn generation_name(digest: &StrictDigest) -> String {
    digest
        .as_str()
        .strip_prefix("sha256:")
        .unwrap_or(digest.as_str())
        .to_owned()
}

/// Parses a generation directory name back into a strict digest.
pub fn parse_generation_name(name: &str) -> Result<StrictDigest, HostError> {
    let valid = name.len() == 64
        && name
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !valid {
        return Err(HostError::InvalidGenerationName(name.to_owned()));
    }
    StrictDigest::new(format!("sha256:{name}"))
        .map_err(|_| HostError::InvalidGenerationName(name.to_owned()))
}

/// Reads a bounded UTF-8 file.
pub fn read_bounded(
    path: &Path,
    file: &'static str,
    limit: usize,
) -> Result<Option<String>, HostError> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(HostError::Read {
                path: path.to_owned(),
                source,
            });
        }
    };
    if !metadata.is_file() {
        return Err(HostError::NotRegular {
            path: path.to_owned(),
        });
    }
    if metadata.len() > limit as u64 {
        return Err(HostError::TooLarge {
            file,
            size: usize::try_from(metadata.len()).unwrap_or(usize::MAX),
            limit,
        });
    }
    std::fs::read_to_string(path)
        .map(Some)
        .map_err(|source| HostError::Read {
            path: path.to_owned(),
            source,
        })
}

/// Reads a bounded UTF-8 file that must exist.
pub fn read_required(path: &Path, file: &'static str, limit: usize) -> Result<String, HostError> {
    read_bounded(path, file, limit)?.ok_or_else(|| HostError::Read {
        path: path.to_owned(),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "file not found"),
    })
}

/// Shared state directory derived from the current host configuration. The launcher only reads
/// `weglarka.toml` here (never `apps.toml`).
pub fn shared_state_dir(config_path: &Path) -> Result<PathBuf, HostError> {
    let text = read_required(config_path, "weglarka.toml", 1024 * 1024)?;
    let host = weglarka_model::config::HostConfig::from_toml_str(&text).map_err(|e| {
        HostError::Invalid {
            file: "weglarka.toml",
            message: e.to_string(),
        }
    })?;
    let config_dir = config_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let state = host.state.dir_or(config_dir);
    Ok(if state.is_absolute() {
        state
    } else {
        config_dir.join(state)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> StrictDigest {
        StrictDigest::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    #[test]
    fn host_roots_are_absolute_and_free_of_parent_components() {
        assert!(validate_host_dir(Path::new("relative")).is_err());
        assert!(validate_host_dir(Path::new("/var/lib/../etc")).is_err());
        assert!(validate_host_dir(Path::new("/")).is_err());
        assert_eq!(
            validate_host_dir(Path::new("/var/lib/weglarka-host")).unwrap(),
            PathBuf::from("/var/lib/weglarka-host")
        );
    }

    #[test]
    fn generation_names_are_hex_digests_only() {
        let d = digest('a');
        let name = generation_name(&d);
        assert_eq!(name, "a".repeat(64));
        assert_eq!(parse_generation_name(&name).unwrap(), d);
        for bad in ["", "abc", &"A".repeat(64), &"g".repeat(64), "../escape"] {
            assert!(parse_generation_name(bad).is_err(), "{bad:?}");
        }
    }
}
