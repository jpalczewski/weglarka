//! Short host-only file locks.
//!
//! Host selection and service selection have separate locks and no code path acquires both. The
//! locks are advisory `flock`s on files next to the state (mode 0600). Reads are lock-free because
//! every writer replaces the file atomically.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error("cannot open {path}: {source}")]
    Open {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot lock {path}: {source}")]
    Lock {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{path} is already held by another host process")]
    Busy { path: PathBuf },
}

/// A held advisory lock. Dropping the value releases it.
#[derive(Debug)]
pub struct HostLock {
    _file: File,
}

/// Refuses a lock path that is a symlink. The host directory is group-writable for the runtime user,
/// and root also takes these locks (bootstrap), so following a planted link would create or open a
/// file of the attacker's choosing with root's rights.
fn refuse_symlink(path: &Path) -> Result<(), LockError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(LockError::Open {
            path: path.to_owned(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "lock path is a symlink"),
        }),
        _ => Ok(()),
    }
}

/// Takes `path` without blocking. `Ok(None)` means another process holds it.
pub fn try_lock(path: &Path) -> Result<Option<HostLock>, LockError> {
    refuse_symlink(path)?;
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .map_err(|source| LockError::Open {
            path: path.to_owned(),
            source,
        })?;
    match file.try_lock() {
        Ok(()) => Ok(Some(HostLock { _file: file })),
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(std::fs::TryLockError::Error(source)) => Err(LockError::Lock {
            path: path.to_owned(),
            source,
        }),
    }
}

/// Takes `path`, waiting for the current holder to finish.
pub fn lock(path: &Path) -> Result<HostLock, LockError> {
    if let Some(lock) = try_lock(path)? {
        return Ok(lock);
    }
    refuse_symlink(path)?;
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .map_err(|source| LockError::Open {
            path: path.to_owned(),
            source,
        })?;
    file.lock().map_err(|source| LockError::Lock {
        path: path.to_owned(),
        source,
    })?;
    Ok(HostLock { _file: file })
}

/// Whether a lock file is currently held. Used by bootstrap to refuse while a legacy runner
/// participant (or another host run) is alive.
pub fn is_held(path: &Path) -> Result<bool, LockError> {
    if !path.exists() {
        return Ok(false);
    }
    Ok(try_lock(path)?.is_none())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_symlinked_lock_path_is_refused_and_nothing_is_created_behind_it() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("created-by-the-lock");
        let link = dir.path().join("x.lock");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(try_lock(&link).is_err());
        assert!(lock(&link).is_err());
        assert!(!target.exists());
    }

    #[test]
    fn a_second_try_lock_reports_busy_and_drop_releases() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.lock");
        let first = try_lock(&path).unwrap().expect("first lock");
        assert!(try_lock(&path).unwrap().is_none());
        assert!(is_held(&path).unwrap());
        drop(first);
        assert!(!is_held(&path).unwrap());
        assert!(try_lock(&path).unwrap().is_some());
    }
}
