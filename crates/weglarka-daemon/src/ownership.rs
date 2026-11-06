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
//! a regular file directly in the host directory, changed through a verified descriptor; everything below
//! `generations/` is only ever given to root, and no mode is changed by path. The host directory's own
//! mode is set through a descriptor whose identity was checked against the path.

use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use weglarka_launcher::host::{GENERATIONS_DIR, LAUNCHER_FILE};

/// What [`apply`] could not do. Code failures leave something root executes under someone else's
/// control and must stop the bootstrap; state failures are entries the runtime user itself planted or
/// controls (an extra hard link, a file that changed under the walk) and are only reported, so the
/// runtime user cannot block a root bootstrap by planting one.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    pub code: usize,
    pub state: usize,
}

/// Mode of the host directory: group-writable with the sticky bit (see the module documentation).
pub const HOST_DIR_MODE: u32 = 0o1770;

/// Changes owner and group of `path` without ever acting on a symlink or on an inode with other hard
/// links. Directories use `lchown` (the final component is not followed). A regular file is opened,
/// its identity (device and inode) is required to equal what `path` names both before and after the
/// open, it must have exactly one link, and the change goes through the descriptor, so a name
/// swapped for a symlink or a hard link in between can never redirect it.
pub fn lchown(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
    let named = std::fs::symlink_metadata(path)?;
    if named.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is a symlink", path.display()),
        ));
    }
    if named.is_dir() {
        return std::os::unix::fs::lchown(path, Some(uid), Some(gid));
    }
    if !named.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    let file = std::fs::File::open(path)?;
    let opened = file.metadata()?;
    let again = std::fs::symlink_metadata(path)?;
    let same =
        |a: &std::fs::Metadata, b: &std::fs::Metadata| (a.dev(), a.ino()) == (b.dev(), b.ino());
    if !opened.is_file()
        || opened.nlink() != 1
        || again.file_type().is_symlink()
        || !same(&named, &opened)
        || !same(&again, &opened)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} changed while it was being examined", path.display()),
        ));
    }
    std::os::unix::fs::fchown(&file, Some(uid), Some(gid))
}

/// Applies the ownership model to `host_dir`. `chown` is the ownership primitive ([`lchown`] in
/// production); a failure on `host_dir` itself aborts (an unprivileged bootstrap cannot chown), a
/// failure on a nested entry is counted and returned so the caller can report it.
pub fn apply<F>(
    host_dir: &Path,
    runtime_uid: u32,
    runtime_gid: u32,
    chown: &mut F,
) -> io::Result<Outcome>
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

    let mut outcome = Outcome::default();
    // The code entries are handled by name, not by whatever `read_dir` returns, so an entry that
    // vanishes or errors during the listing can never skip them. A symlink or anything else standing
    // in for the launcher or `generations/` is a code failure.
    match std::fs::symlink_metadata(host_dir.join(LAUNCHER_FILE)) {
        Ok(m) if m.file_type().is_file() => {
            outcome.code += usize::from(chown(&host_dir.join(LAUNCHER_FILE), 0, 0).is_err());
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        _ => outcome.code += 1,
    }
    match std::fs::symlink_metadata(host_dir.join(GENERATIONS_DIR)) {
        Ok(m) if m.file_type().is_dir() => {
            outcome.code += root_tree(&host_dir.join(GENERATIONS_DIR), chown);
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        _ => outcome.code += 1,
    }

    // Everything else is runtime state: regular files, one level, owner changed through a verified
    // descriptor. Trouble here is the runtime user's own doing and is reported, not fatal.
    let Ok(entries) = std::fs::read_dir(host_dir) else {
        outcome.code += 1;
        return Ok(outcome);
    };
    for entry in entries {
        let Ok(entry) = entry else {
            outcome.state += 1;
            continue;
        };
        if entry.file_name() == LAUNCHER_FILE || entry.file_name() == GENERATIONS_DIR {
            continue;
        }
        let path = entry.path();
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            outcome.state += 1;
            continue;
        };
        // Symlinks are left alone; a file with other hard links could be someone else's inode, so it is
        // reported instead of handed over. Directories the runtime user made are its own already.
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            continue;
        }
        if metadata.nlink() > 1 || chown(&path, runtime_uid, runtime_gid).is_err() {
            outcome.state += 1;
        }
    }
    Ok(outcome)
}

/// Makes `dir` and everything below it root-owned. Only a change to `root:root` happens here, never
/// through a symlink, and handing something to root is never an escalation.
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
        // Code root executes must not be writable by anyone else: report group/world write and
        // setuid/setgid bits instead of silently accepting them.
        if metadata.permissions().mode() & 0o7022 != 0 {
            failures += 1;
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

    /// Sets `mode` on `path` explicitly, so the fixture never depends on the caller's umask.
    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// A host directory as the generation store leaves it: code directories `0755`, manifests
    /// `0644`, binaries `0755`. Every mode is set after creation, never taken from the umask (a
    /// `0002` umask would make the code tree group-writable, which [`root_tree`] reports).
    fn tree() -> (tempfile::TempDir, tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let host = dir.path().join("host");
        let generations = host.join(GENERATIONS_DIR);
        let g1 = generations.join("g1");
        std::fs::create_dir_all(&g1).unwrap();
        std::fs::write(host.join(LAUNCHER_FILE), b"launcher").unwrap();
        std::fs::write(host.join("host-tools.toml"), b"x").unwrap();
        std::fs::write(g1.join("manifest.toml"), b"m").unwrap();
        std::fs::write(g1.join("weglarka-daemon"), b"d").unwrap();
        for (path, mode) in [
            (host.clone(), 0o755),
            (host.join(LAUNCHER_FILE), 0o755),
            (host.join("host-tools.toml"), 0o644),
            (generations, 0o755),
            (g1.clone(), 0o755),
            (g1.join("manifest.toml"), 0o644),
            (g1.join("weglarka-daemon"), 0o755),
        ] {
            chmod(&path, mode);
        }
        (dir, outside, host)
    }

    fn recorded(host: &Path) -> (Vec<(PathBuf, u32, u32)>, Outcome) {
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
        assert_eq!(failures, Outcome::default());
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
        assert_eq!(failures, Outcome::default());
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
    fn world_writable_code_is_reported() {
        let (_dir, _outside, host) = tree();
        let binary = host
            .join(GENERATIONS_DIR)
            .join("g1")
            .join("weglarka-daemon");
        chmod(&binary, 0o757);
        let (_calls, failures) = recorded(&host);
        assert_eq!(failures, Outcome { code: 1, state: 0 });
    }

    #[test]
    fn the_production_chown_refuses_symlinks_and_hard_links() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"x").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join("link")).unwrap();
        std::fs::hard_link(&target, dir.path().join("hard")).unwrap();
        let (uid, gid) = {
            let m = std::fs::metadata(&target).unwrap();
            (m.uid(), m.gid())
        };
        for name in ["link", "hard", "target"] {
            // `target` now has two links, so even it is refused.
            assert!(lchown(&dir.path().join(name), uid, gid).is_err(), "{name}");
        }
        let plain = dir.path().join("plain");
        std::fs::write(&plain, b"x").unwrap();
        lchown(&plain, uid, gid).expect("a plain file owned by the caller");
    }

    #[test]
    fn a_state_file_with_another_hard_link_is_reported_not_handed_over() {
        let (_dir, outside, host) = tree();
        let foreign = outside.path().join("shadow");
        std::fs::write(&foreign, b"x").unwrap();
        std::fs::hard_link(&foreign, host.join("linked")).unwrap();
        let (calls, failures) = recorded(&host);
        assert_eq!(failures, Outcome { code: 0, state: 1 });
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
