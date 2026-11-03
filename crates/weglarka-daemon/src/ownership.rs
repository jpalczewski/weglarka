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
//! left alone instead of handing its target to that user. The only path handed to the runtime user is
//! a final component directly in the host directory (`lchown` does not follow it); everything below
//! `generations/` is only ever given to root, and no mode is changed by path. The host directory's own
//! mode is set through a descriptor whose identity was checked against the path.

use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
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
    // Pin the host directory by descriptor: open it, then require that the path still names the very
    // same directory (not a symlink swapped in meanwhile). The mode is set through the descriptor, so
    // it can never land on a symlink's target.
    let pinned = std::fs::File::open(host_dir)?;
    let opened = pinned.metadata()?;
    let named = std::fs::symlink_metadata(host_dir)?;
    if named.file_type().is_symlink()
        || !named.is_dir()
        || !opened.is_dir()
        || (named.dev(), named.ino()) != (opened.dev(), opened.ino())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a plain directory", host_dir.display()),
        ));
    }
    chown(host_dir, 0, runtime_gid)?;
    pinned.set_permissions(std::fs::Permissions::from_mode(HOST_DIR_MODE))?;

    let mut failures = 0;
    // The code entries are handled by name, not by whatever `read_dir` returns, so an entry that
    // vanishes or errors during the listing can never skip them.
    match std::fs::symlink_metadata(host_dir.join(LAUNCHER_FILE)) {
        Ok(m) if m.file_type().is_file() => {
            failures += usize::from(chown(&host_dir.join(LAUNCHER_FILE), 0, 0).is_err());
        }
        Ok(m) if m.file_type().is_symlink() => {}
        Ok(_) => failures += 1,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(_) => failures += 1,
    }
    match std::fs::symlink_metadata(host_dir.join(GENERATIONS_DIR)) {
        Ok(m) if m.file_type().is_dir() => {
            failures += root_tree(&host_dir.join(GENERATIONS_DIR), chown);
        }
        Ok(m) if m.file_type().is_symlink() => {}
        Ok(_) => failures += 1,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(_) => failures += 1,
    }

    // Everything else is runtime state: regular files, one level, `lchown` of the final component.
    let Ok(entries) = std::fs::read_dir(host_dir) else {
        return Ok(failures + 1);
    };
    for entry in entries {
        let Ok(entry) = entry else {
            failures += 1;
            continue;
        };
        if entry.file_name() == LAUNCHER_FILE || entry.file_name() == GENERATIONS_DIR {
            continue;
        }
        let path = entry.path();
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            failures += 1;
            continue;
        };
        // Symlinks are left alone; a file with other hard links could be someone else's inode, so it is
        // reported instead of handed over. Directories the runtime user made are its own already.
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            continue;
        }
        if metadata.nlink() > 1 || chown(&path, runtime_uid, runtime_gid).is_err() {
            failures += 1;
        }
    }
    Ok(failures)
}

/// Makes `dir` and everything below it root-owned. Only `lchown` to `root:root` happens here: it never
/// follows a symlink at the final component, and handing something to root is never an escalation.
/// Modes are not touched (a path-based chmod follows symlinks): the generation store already creates
/// `generations/` and its directories `0755` and manifests `0644`, and the tool binaries `0755`.
/// Symlinks are skipped, not followed.
fn root_tree<F>(dir: &Path, chown: &mut F) -> usize
where
    F: FnMut(&Path, u32, u32) -> io::Result<()>,
{
    let mut failures = usize::from(chown(dir, 0, 0).is_err());
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
        } else if file_type.is_file() && chown(&path, 0, 0).is_err() {
            failures += 1;
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
    fn a_state_file_with_another_hard_link_is_reported_not_handed_over() {
        let (_dir, outside, host) = tree();
        let foreign = outside.path().join("shadow");
        std::fs::write(&foreign, b"x").unwrap();
        std::fs::hard_link(&foreign, host.join("linked")).unwrap();
        let (calls, failures) = recorded(&host);
        assert_eq!(failures, 1);
        assert!(!calls.iter().any(|(p, _, _)| p.ends_with("linked")));
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
