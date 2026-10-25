//! Allowlisted read-only host mounts (`host_mounts`, issue #178,
//! `docs/decisions/0045-host-mounts.md`).
//!
//! The operator lists absolute paths in `[runtime] host_mounts`; an app may mount one of them
//! read-only. The rule is deliberately strict: the app's `source` must equal an allowlist entry
//! **exactly** (no prefix match), and the entry must resolve to itself — a symlink anywhere in the
//! path (an entry that is a link, or a parent that is) is refused, so what the operator approved is
//! what gets mounted. The canonical path is what libpod binds.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::app::{AppSpec, HostMount};
use crate::config_mounts::Resolved;

/// A host mount that cannot be mounted.
#[derive(Debug, thiserror::Error)]
pub enum HostMountError {
    #[error("host mount source {path:?} is not in `[runtime] host_mounts` in weglarka.toml")]
    NotAllowed { path: String },
    #[error("host mount source {path:?} does not exist on the host")]
    NotFound { path: String },
    #[error("host mount source {path:?} resolves to {resolved:?}; symlinks are not followed")]
    Redirected { path: String, resolved: PathBuf },
    #[error("host mount source {path:?} is not a regular file or a directory")]
    NotFileOrDir { path: String },
    #[error("i/o error on {path:?}: {reason}")]
    Io { path: String, reason: String },
}

/// State of one declared host mount as the operator sees it (`apps show`/`doctor`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostMountStatus {
    Ok,
    /// The source is not an entry of the allowlist.
    NotAllowed,
    Missing,
    /// The path resolves somewhere else (symlink).
    Redirected,
    NotFileOrDir,
    Unreadable,
}

/// One declared host mount with its status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostMountView {
    pub source: String,
    pub target: String,
    pub status: HostMountStatus,
    pub detail: Option<String>,
}

/// Pure check of the allowlist (no I/O): every host mount of `spec` must be an exact entry.
/// Used when the spec is written, so a bad source is a 400 instead of a blocked app later.
pub fn check_allowed(allowlist: &[PathBuf], spec: &AppSpec) -> Result<(), HostMountError> {
    for mount in &spec.host_mounts {
        allowed(allowlist, mount)?;
    }
    Ok(())
}

fn allowed(allowlist: &[PathBuf], mount: &HostMount) -> Result<(), HostMountError> {
    if allowlist
        .iter()
        .any(|e| e.as_os_str() == mount.source.as_str())
    {
        Ok(())
    } else {
        Err(HostMountError::NotAllowed {
            path: mount.source.clone(),
        })
    }
}

/// A requested group that is not in `[runtime] group_add`.
#[derive(Debug, thiserror::Error)]
#[error("group {group:?} is not in `[runtime] group_add` in weglarka.toml")]
pub struct GroupNotAllowed {
    pub group: String,
}

/// Pure check: every `group_add` entry of `spec` must be on the operator's allowlist.
pub fn check_groups(allowlist: &[String], spec: &AppSpec) -> Result<(), GroupNotAllowed> {
    match spec.group_add.iter().find(|g| !allowlist.contains(g)) {
        None => Ok(()),
        Some(group) => Err(GroupNotAllowed {
            group: group.clone(),
        }),
    }
}

/// Resolves every host mount of `spec`; fails on the first unmountable one (a deploy must not start
/// with a partially mounted spec).
pub fn resolve_all(allowlist: &[PathBuf], spec: &AppSpec) -> Result<Vec<Resolved>, HostMountError> {
    spec.host_mounts
        .iter()
        .map(|mount| {
            allowed(allowlist, mount)?;
            Ok(Resolved {
                source: resolve_one(Path::new(&mount.source))?,
                target: mount.target.clone(),
            })
        })
        .collect()
}

/// [`resolve_all`] as a never-failing report, one entry per declared mount, in spec order.
pub fn describe(allowlist: &[PathBuf], spec: &AppSpec) -> Vec<HostMountView> {
    spec.host_mounts
        .iter()
        .map(|mount| {
            let result =
                allowed(allowlist, mount).and_then(|()| resolve_one(Path::new(&mount.source)));
            let (status, detail) = match result {
                Ok(_) => (HostMountStatus::Ok, None),
                Err(e) => (
                    match &e {
                        HostMountError::NotAllowed { .. } => HostMountStatus::NotAllowed,
                        HostMountError::NotFound { .. } => HostMountStatus::Missing,
                        HostMountError::Redirected { .. } => HostMountStatus::Redirected,
                        HostMountError::NotFileOrDir { .. } => HostMountStatus::NotFileOrDir,
                        HostMountError::Io { .. } => HostMountStatus::Unreadable,
                    },
                    Some(e.to_string()),
                ),
            };
            HostMountView {
                source: mount.source.clone(),
                target: mount.target.clone(),
                status,
                detail,
            }
        })
        .collect()
}

fn resolve_one(path: &Path) -> Result<PathBuf, HostMountError> {
    let shown = path.display().to_string();
    let canonical = path.canonicalize().map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => HostMountError::NotFound {
            path: shown.clone(),
        },
        _ => HostMountError::Io {
            path: shown.clone(),
            reason: e.to_string(),
        },
    })?;
    if canonical != path {
        return Err(HostMountError::Redirected {
            path: shown,
            resolved: canonical,
        });
    }
    let meta = fs::metadata(&canonical).map_err(|e| HostMountError::Io {
        path: shown.clone(),
        reason: e.to_string(),
    })?;
    if !(meta.is_file() || meta.is_dir()) {
        return Err(HostMountError::NotFileOrDir { path: shown });
    }
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(sources: &[&str]) -> AppSpec {
        let mut spec: AppSpec =
            toml::from_str("image = \"ghcr.io/example/app:1\"\nport = 80\n").unwrap();
        spec.host_mounts = sources
            .iter()
            .map(|s| HostMount {
                source: (*s).to_owned(),
                target: "/data".to_owned(),
            })
            .collect();
        spec
    }

    #[test]
    fn exact_match_resolves_and_prefix_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        fs::create_dir(root.join("journal")).unwrap();
        let entry = root.join("journal");
        let list = vec![entry.clone()];
        let ok = spec(&[entry.to_str().unwrap()]);
        assert_eq!(resolve_all(&list, &ok).unwrap()[0].source, entry);
        let child = root.join("journal/sub");
        fs::create_dir(&child).unwrap();
        let bad = spec(&[child.to_str().unwrap()]);
        assert!(matches!(
            resolve_all(&list, &bad),
            Err(HostMountError::NotAllowed { .. })
        ));
        assert!(check_allowed(&list, &bad).is_err());
    }

    #[test]
    fn symlink_entry_is_refused_and_missing_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        fs::create_dir(root.join("real")).unwrap();
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
        let link = root.join("link");
        let gone = root.join("gone");
        let list = vec![link.clone(), gone.clone()];
        assert!(matches!(
            resolve_all(&list, &spec(&[link.to_str().unwrap()])),
            Err(HostMountError::Redirected { .. })
        ));
        let views = describe(&list, &spec(&[gone.to_str().unwrap(), "/etc/shadow"]));
        assert_eq!(views[0].status, HostMountStatus::Missing);
        assert_eq!(views[1].status, HostMountStatus::NotAllowed);
    }
}
