//! Layout of the daemon-owned ingress request logs (issues #502, #555; ADR 0070).
//!
//! One place knows the file names (`access.log`, `error.log`, the dated `access-YYYY-MM-DD.log`
//! files the retention worker rotates them into), where the directory is mounted inside the nginx
//! container, and how the directory is created. The daemon joins a [`LogDir`] with its host root,
//! the nginx config generator joins it with [`NGINX_DIR`], so both sides name the same files.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Where the log directory is mounted inside the nginx container. It is a writable bind mount from
/// `<state dir>/ingress-logs`; nginx writes the access and error logs here, so the daemon (not
/// Podman) owns their retention.
pub const NGINX_DIR: &str = "/var/log/weglarka";

/// Length of a `YYYY-MM-DD` date.
const DATE_LEN: usize = 10;

/// The two files nginx writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogKind {
    Access,
    Error,
}

impl LogKind {
    /// Both kinds, in the order the files are rotated.
    pub const ALL: [LogKind; 2] = [LogKind::Access, LogKind::Error];

    /// File name stem: `access` or `error`.
    pub fn stem(self) -> &'static str {
        match self {
            Self::Access => "access",
            Self::Error => "error",
        }
    }
}

/// A log directory relative to the log root; joined with the host root (daemon) or with
/// [`NGINX_DIR`] (nginx config), so both sides name the same files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogDir {
    rel: PathBuf,
}

/// The root itself: today's only log directory.
pub fn shared() -> LogDir {
    LogDir {
        rel: PathBuf::new(),
    }
}

impl LogDir {
    /// The file nginx currently writes: `access.log` / `error.log`.
    pub fn current(&self, kind: LogKind) -> PathBuf {
        self.rel.join(format!("{}.log", kind.stem()))
    }

    /// The file a day was rotated into: `access-YYYY-MM-DD.log`.
    pub fn dated(&self, kind: LogKind, date: &str) -> PathBuf {
        self.rel.join(format!("{}-{date}.log", kind.stem()))
    }

    /// Completed (rotated) regular files in this directory under `root`, as `(kind, UTC date, path)`
    /// with `path` already joined with `root`. Symlinks and directories are skipped. A missing
    /// directory is an error (`NotFound`), so the caller decides what that means.
    pub fn completed(&self, root: &Path) -> io::Result<Vec<(LogKind, String, PathBuf)>> {
        let mut found = Vec::new();
        for entry in fs::read_dir(root.join(&self.rel))? {
            let entry = entry?;
            let name = entry.file_name();
            let Some((kind, date)) = parse_completed(&name.to_string_lossy()) else {
                continue;
            };
            if entry.file_type()?.is_file() {
                found.push((kind, date, entry.path()));
            }
        }
        Ok(found)
    }
}

/// `(kind, date)` encoded in `access-YYYY-MM-DD.log` / `error-YYYY-MM-DD[.N].log`; `None` for
/// anything else (including an invalid date).
fn parse_completed(name: &str) -> Option<(LogKind, String)> {
    let (kind, rest) = if let Some(rest) = name.strip_prefix("access-") {
        (LogKind::Access, rest)
    } else {
        (LogKind::Error, name.strip_prefix("error-")?)
    };
    if rest.len() < DATE_LEN + ".log".len() || !rest.is_char_boundary(DATE_LEN) {
        return None;
    }
    let (date, tail) = rest.split_at(DATE_LEN);
    let tail = tail.strip_prefix('.')?;
    if tail != "log" && !tail.ends_with(".log") {
        return None;
    }
    parse_date(date)?;
    Some((kind, date.to_owned()))
}

/// `YYYY-MM-DD` to days since 1970-01-01 (Hinnant's `days_from_civil`); `None` for an invalid date.
pub fn parse_date(date: &str) -> Option<i64> {
    if date.len() != DATE_LEN || date.as_bytes()[4] != b'-' || date.as_bytes()[7] != b'-' {
        return None;
    }
    let number = |range: std::ops::Range<usize>| -> Option<i64> {
        let part = date.get(range)?;
        if part.bytes().all(|b| b.is_ascii_digit()) {
            part.parse().ok()
        } else {
            None
        }
    };
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let month_len = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if !(1..=month_len).contains(&day) {
        return None;
    }
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

/// Mode of every log directory: owner full access, the owner's group may read and list, nobody else
/// has any access (ADR 0072).
pub const DIR_MODE: u32 = 0o750;

/// The mode `ensure_dir` must set on a directory that currently has `current`, or `None` when it is
/// already right. Anything that is not exactly [`DIR_MODE`] is replaced: `0700` (every install before
/// ADR 0072) is widened once, `o` bits and `g+w` are tightened. A correct directory is left alone
/// because `chmod` resets a POSIX ACL mask, which would undo an administrator's deliberate ACL.
pub fn mode_change(current: u32) -> Option<u32> {
    (current & 0o7777 != DIR_MODE).then_some(DIR_MODE)
}

/// Creates a log directory (and parents) and makes sure it has mode [`DIR_MODE`] (`0750`). The one
/// permission helper: the ingress apply and the retention worker both call it, so the mode cannot
/// drift between them; it takes any path, so per-app subdirectories use it as well.
///
/// The daemon's user owns the directory and the files in it (container uid 0 of nginx, mapped to
/// the same host user). The group is the runtime user's primary group, which a log reader reaches
/// with `keep-groups` (ADR 0072); nginx's worker (uid 101) has no access, because it inherits the
/// descriptors the master opened.
pub fn ensure_dir(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let current = fs::metadata(path)?.permissions().mode();
        if let Some(mode) = mode_change(current) {
            fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_match_what_nginx_and_the_worker_use() {
        let dir = shared();
        assert_eq!(dir.current(LogKind::Access), Path::new("access.log"));
        assert_eq!(dir.current(LogKind::Error), Path::new("error.log"));
        assert_eq!(
            dir.dated(LogKind::Access, "2026-11-04"),
            Path::new("access-2026-11-04.log")
        );
        // The shared directory joins cleanly, without a trailing slash.
        assert_eq!(
            Path::new(NGINX_DIR).join(dir.current(LogKind::Access)),
            Path::new("/var/log/weglarka/access.log")
        );
    }

    #[test]
    fn completed_file_names() {
        let access = |d: &str| Some((LogKind::Access, d.to_owned()));
        for (name, want) in [
            ("access-2026-11-04.log", access("2026-11-04")),
            ("access-2026-11-04.1.log", access("2026-11-04")),
            (
                "error-2026-11-04.log",
                Some((LogKind::Error, "2026-11-04".to_owned())),
            ),
            ("access.log", None),
            ("access-2026-11-04", None),
            ("access-2026-13-04.log", None),
            ("access-2026-11-04.txt", None),
            ("other-2026-11-04.log", None),
            ("access-ééééé.log", None),
        ] {
            assert_eq!(parse_completed(name), want, "{name}");
        }
    }

    #[test]
    fn dates_parse() {
        assert_eq!(parse_date("1970-01-01"), Some(0));
        assert_eq!(parse_date("2024-02-29"), Some(19_782));
        assert_eq!(parse_date("2024-02-30"), None);
        assert_eq!(parse_date("2026-11-4"), None);
    }

    #[test]
    fn completed_lists_only_regular_rotated_files() {
        let tmp = tempfile::tempdir().unwrap();
        for name in [
            "access.log",
            "error.log",
            "access-2026-11-03.log",
            "error-2026-11-03.log",
            ".logdate",
        ] {
            fs::write(tmp.path().join(name), b"x").unwrap();
        }
        fs::create_dir(tmp.path().join("access-2026-11-02.log")).unwrap();
        let mut got = shared().completed(tmp.path()).unwrap();
        got.sort_by_key(|(_, date, path)| (date.clone(), path.clone()));
        assert_eq!(got.len(), 2);
        assert!(got.iter().any(|(k, d, p)| *k == LogKind::Access
            && d == "2026-11-03"
            && p == &tmp.path().join("access-2026-11-03.log")));
        assert!(shared().completed(&tmp.path().join("missing")).is_err());
    }

    #[test]
    fn mode_decision() {
        assert_eq!(
            mode_change(0o040_700 & 0o7777),
            Some(0o750),
            "0700 is widened once"
        );
        assert_eq!(mode_change(0o755), Some(0o750), "world bits are cleared");
        assert_eq!(mode_change(0o770), Some(0o750), "group write is cleared");
        assert_eq!(mode_change(0o777), Some(0o750));
        assert_eq!(
            mode_change(0o2750),
            Some(0o750),
            "setgid is not part of the mode"
        );
        assert_eq!(
            mode_change(0o750),
            None,
            "a correct directory is left alone"
        );
        assert_eq!(mode_change(0o040_750), None, "file type bits are ignored");
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[cfg(unix)]
    #[test]
    fn ensure_dir_creates_0750_and_normalises_others() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("a").join("logs");
        ensure_dir(&dir).unwrap();
        assert_eq!(mode_of(&dir), 0o750);
        for old in [0o700, 0o755, 0o770] {
            fs::set_permissions(&dir, fs::Permissions::from_mode(old)).unwrap();
            ensure_dir(&dir).unwrap();
            assert_eq!(mode_of(&dir), 0o750, "from {old:o}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn ensure_dir_does_not_touch_a_correct_directory() {
        use std::os::unix::fs::MetadataExt;
        use std::time::Duration;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("logs");
        ensure_dir(&dir).unwrap();
        let before = fs::metadata(&dir).unwrap();
        // `chmod` updates ctime even when the mode is unchanged, so an untouched ctime shows that no
        // `chmod` ran (which would also reset an ACL mask).
        std::thread::sleep(Duration::from_millis(20));
        ensure_dir(&dir).unwrap();
        let after = fs::metadata(&dir).unwrap();
        assert_eq!(
            (before.ctime(), before.ctime_nsec()),
            (after.ctime(), after.ctime_nsec())
        );
    }
}
