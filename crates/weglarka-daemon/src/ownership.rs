//! Ownership of the host-only directory after `platform bootstrap`.
//!
//! Bootstrap runs as root, the launcher jobs run as the runtime user, so what each side may modify
//! decides what root can later be tricked into executing or chowning:
//!
//! - **root owns the code**: the launcher and everything under `generations/` (binaries and
//!   manifests). Bootstrap runs a preflight of a generation as root, so a binary the runtime user can
//!   swap would be executed as root.
//! - **the runtime user owns state only**: the selector, locks, service selection and the other
//!   regular files directly in the host directory. They are flat; nothing below them is ever walked.
//! - **the host directory itself** is `root:<runtime group>` with mode `1770`: the group may create and
//!   replace its own files, but the sticky bit stops it from renaming or unlinking the root-owned
//!   launcher and `generations/` entries.
//!
//! Ownership is changed with `lchown` on entries that `symlink_metadata` reported as non-symlinks, and
//! symlinks are never followed or descended into: a link the runtime user plants (`x -> /etc`) is
//! left alone instead of handing its target to that user.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use weglarka_launcher::host::{GENERATIONS_DIR, LAUNCHER_FILE};

/// Mode of the host directory: group-writable with the sticky bit (see the module documentation).
pub const HOST_DIR_MODE: u32 = 0o1770;

/// Changes owner and group without following a symlink at `path`.
pub fn lchown(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
    std::os::unix::fs::lchown(path, Some(uid), Some(gid))
}

/// Applies the ownership model to `host_dir`. `chown` is the ownership primitive ([`lchown`] in
/// production); a failure on `host_dir` itself aborts (an unprivileged bootstrap cannot chown), a
/// failure on a nested entry is counted and returned so the caller can report it.
pub fn apply<F>(
    host_dir: &Path,
    runtime_uid: u32,
    runtime_gid: u32,
    chown: &mut F,
) -> io::Result<usize>
where
    F: FnMut(&Path, u32, u32) -> io::Result<()>,
{
    let metadata = std::fs::symlink_metadata(host_dir)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a directory", host_dir.display()),
        ));
    }
    chown(host_dir, 0, runtime_gid)?;
    std::fs::set_permissions(host_dir, std::fs::Permissions::from_mode(HOST_DIR_MODE))?;

    let mut failures = 0;
    for entry in std::fs::read_dir(host_dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = std::fs::symlink_metadata(&path)?.file_type();
        if file_type.is_symlink() {
            continue;
        }
        let name = entry.file_name();
        if name == LAUNCHER_FILE {
            if !file_type.is_file() || chown(&path, 0, 0).is_err() {
                failures += 1;
            }
        } else if name == GENERATIONS_DIR {
            if !file_type.is_dir() {
                failures += 1;
            } else {
                failures += root_tree(&path, chown);
            }
        } else if file_type.is_file() && chown(&path, runtime_uid, runtime_gid).is_err() {
            // Regular state file. Anything else (a directory the runtime user made) is its own already.
            failures += 1;
        }
    }
    Ok(failures)
}

/// Makes `dir` and everything below it root-owned and readable by the runtime user (directories
/// `0755`, manifests `0644`; the tool binaries are already `0755`). Symlinks are skipped, not followed.
fn root_tree<F>(dir: &Path, chown: &mut F) -> usize
where
    F: FnMut(&Path, u32, u32) -> io::Result<()>,
{
    let mut failures = 0;
    if chown(dir, 0, 0).is_err()
        || std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).is_err()
    {
        failures += 1;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return failures + 1;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            failures += 1;
            continue;
        };
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            failures += root_tree(&path, chown);
        } else if file_type.is_file() {
            let mode = if metadata.permissions().mode() & 0o111 != 0 {
                0o755
            } else {
                0o644
            };
            if chown(&path, 0, 0).is_err()
                || std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).is_err()
            {
                failures += 1;
            }
        }
    }
    failures
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    use super::*;

    fn tree() -> (tempfile::TempDir, tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let host = dir.path().join("host");
        std::fs::create_dir_all(host.join(GENERATIONS_DIR).join("g1")).unwrap();
        std::fs::write(host.join(LAUNCHER_FILE), b"launcher").unwrap();
        std::fs::write(host.join("host-tools.toml"), b"x").unwrap();
        std::fs::write(
            host.join(GENERATIONS_DIR).join("g1").join("manifest.toml"),
            b"m",
        )
        .unwrap();
        std::fs::write(
            host.join(GENERATIONS_DIR)
                .join("g1")
                .join("weglarka-daemon"),
            b"d",
        )
        .unwrap();
        std::fs::set_permissions(
            host.join(GENERATIONS_DIR)
                .join("g1")
                .join("weglarka-daemon"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        (dir, outside, host)
    }

    fn recorded(host: &Path) -> (Vec<(PathBuf, u32, u32)>, usize) {
        let mut calls = Vec::new();
        let failures = apply(host, 1000, 1001, &mut |path: &Path, uid, gid| {
            calls.push((path.to_owned(), uid, gid));
            Ok(())
        })
        .unwrap();
        (calls, failures)
    }

    #[test]
    fn state_belongs_to_the_runtime_user_and_code_to_root() {
        let (_dir, _outside, host) = tree();
        let (calls, failures) = recorded(&host);
        assert_eq!(failures, 0);
        let owner = |path: PathBuf| {
            calls
                .iter()
                .find(|(p, _, _)| *p == path)
                .map(|(_, uid, gid)| (*uid, *gid))
        };
        assert_eq!(owner(host.clone()), Some((0, 1001)));
        assert_eq!(owner(host.join(LAUNCHER_FILE)), Some((0, 0)));
        assert_eq!(owner(host.join("host-tools.toml")), Some((1000, 1001)));
        let generations = host.join(GENERATIONS_DIR);
        assert_eq!(owner(generations.clone()), Some((0, 0)));
        assert_eq!(owner(generations.join("g1")), Some((0, 0)));
        assert_eq!(
            owner(generations.join("g1").join("weglarka-daemon")),
            Some((0, 0))
        );
        assert_eq!(
            std::fs::metadata(&host).unwrap().permissions().mode() & 0o7777,
            HOST_DIR_MODE
        );
        let manifest = generations.join("g1").join("manifest.toml");
        assert_eq!(
            std::fs::metadata(manifest).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }

    #[test]
    fn symlinks_are_neither_followed_nor_descended_into() {
        let (_dir, outside, host) = tree();
        let victim = outside.path().join("etc");
        std::fs::create_dir(&victim).unwrap();
        std::fs::write(victim.join("passwd"), b"root").unwrap();
        // A runtime-user plant next to its state, and one inside the code tree.
        symlink(&victim, host.join("x")).unwrap();
        symlink(&victim, host.join(GENERATIONS_DIR).join("g1").join("y")).unwrap();
        symlink(outside.path().join("etc"), host.join("loose")).unwrap();

        let (calls, failures) = recorded(&host);
        assert_eq!(failures, 0);
        for (path, _, _) in &calls {
            assert!(
                !path.starts_with(outside.path()),
                "{} is outside the host directory",
                path.display()
            );
            let metadata = std::fs::symlink_metadata(path).unwrap();
            assert!(
                !metadata.file_type().is_symlink(),
                "a symlink was chowned: {}",
                path.display()
            );
        }
        assert!(!calls.iter().any(|(p, _, _)| p.ends_with("passwd")));
    }

    #[test]
    fn an_unprivileged_host_directory_chown_aborts_before_any_mode_change() {
        let (_dir, _outside, host) = tree();
        let before = std::fs::metadata(&host).unwrap().permissions().mode();
        let error = apply(&host, 1000, 1001, &mut |_: &Path, _, _| {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            std::fs::metadata(&host).unwrap().permissions().mode(),
            before
        );
    }
}
