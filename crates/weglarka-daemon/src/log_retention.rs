//! Retention of the daemon-owned ingress request logs (issue #502, ADR 0070).
//!
//! nginx writes `access.log` and `error.log` into `<state dir>/ingress-logs` (a writable bind mount,
//! `0700`, owned by the daemon's user). The daemon rotates the two files once per UTC day and deletes
//! completed files after `[logs] retention`. The access log contains visitor IP addresses, which is
//! why this is the daemon's job and not Podman's: the container runtime only offers size-based
//! rotation, not a retention period.
//!
//! The rotation is a rename followed by `IngressManager::reopen_logs()` (`SIGHUP`). `SIGUSR1` is not
//! enough: nginx's worker (uid 101) would reopen the path itself, and it cannot read a directory and
//! a file owned by the daemon user. `SIGHUP` reopens in the master (container uid 0, the daemon user)
//! and new workers inherit the descriptors.
//!
//! **Guarantee.** A completed daily file is deleted once its UTC date is at least `retention` days
//! before today. Lines written after the last rotation can therefore live up to one day longer than
//! `retention`; after a daemon outage the first rotation groups the backlog in the file of its last
//! write, so those lines can live longer. Both bounds are documented in `docs/guides/log-retention.md`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use tokio::sync::watch;
use tokio::task::JoinHandle;
use weglarka_model::config::LogRetention;
use weglarka_model::fsutil::write_atomic;
use weglarka_model::ingress_logs::parse_date;
use weglarka_model::ingress_logs::{self, LogKind, ensure_dir};
use weglarka_model::podman::PodmanClient;
use weglarka_model::secrets::rfc3339_utc;

use crate::ingress::IngressManager;

/// Sidecar with the UTC date the current files belong to. It keeps a restart after midnight from
/// merging two days into one rotated file.
const LOG_DATE_MARKER: &str = ".logdate";
/// How often the worker checks whether a day boundary passed. One hour bounds the delay; the check
/// itself is a directory scan of at most `retention + 1` files.
const PERIOD: Duration = Duration::from_secs(3600);
/// Length of a `YYYY-MM-DD` date.
const DATE_LEN: usize = 10;

/// What one retention pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// At least one current log was renamed.
    pub rotated: bool,
    /// Completed files removed by this pass.
    pub deleted: u64,
    /// Bytes of the files removed by this pass.
    pub freed_bytes: u64,
    /// Log files that remain in the directory (current and completed).
    pub files: u64,
    /// Bytes of the log files that remain.
    pub bytes: u64,
}

/// Last pass, for `doctor`. The error is detail text and never contains log content.
#[derive(Debug, Clone)]
pub struct Pass {
    pub at: SystemTime,
    pub report: Report,
    pub error: Option<String>,
}

/// Shared status of the background worker.
#[derive(Debug, Default)]
pub struct Status {
    last: Mutex<Option<Pass>>,
}

impl Status {
    fn record(&self, pass: Pass) {
        *self.last.lock().unwrap_or_else(|e| e.into_inner()) = Some(pass);
    }

    pub fn last(&self) -> Option<Pass> {
        self.last.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

/// Starts the hourly retention worker. The first pass runs immediately, so a restart also rotates
/// a backlog and prunes expired files before waiting for the next tick.
pub fn spawn<P: PodmanClient + 'static>(
    ingress: Arc<IngressManager<P>>,
    dir: PathBuf,
    retention: LogRetention,
    status: Arc<Status>,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut reopen_pending = false;
        loop {
            let path = dir.clone();
            let result = tokio::task::spawn_blocking(move || {
                retention_pass(&path, SystemTime::now(), retention)
            })
            .await;
            let (report, mut error) = match result {
                Ok(Ok(report)) => (report, None),
                Ok(Err(error)) => (Report::default(), Some(error.to_string())),
                Err(error) => (Report::default(), Some(error.to_string())),
            };
            // A rename is not the only reason to ask nginx to reopen: after a crash between the
            // rename and the HUP, the marker already says "today" and no file is named access.log.
            // Without this check nginx could keep writing to the rotated file (and the pruner would
            // eventually unlink it) until the next config reload.
            if needs_reopen(&dir, report.rotated) {
                reopen_pending = true;
            }
            if reopen_pending {
                match ingress.reopen_logs().await {
                    Ok(()) => reopen_pending = false,
                    Err(e) => {
                        error = Some(format!("reopening nginx logs: {e}"));
                        tracing::warn!(error = %e, "cannot reopen nginx logs after rotation; will retry");
                    }
                }
            }
            if report.rotated || report.deleted > 0 || error.is_some() {
                tracing::info!(
                    rotated = report.rotated,
                    deleted = report.deleted,
                    freed_bytes = report.freed_bytes,
                    files = report.files,
                    bytes = report.bytes,
                    error = error.as_deref().unwrap_or(""),
                    "ingress log retention pass"
                );
            } else {
                tracing::debug!(
                    files = report.files,
                    bytes = report.bytes,
                    "ingress log retention: nothing to do"
                );
            }
            status.record(Pass {
                at: SystemTime::now(),
                report,
                error,
            });
            tokio::select! {
                _ = tokio::time::sleep(PERIOD) => {}
                _ = shutdown.changed() => return,
            }
        }
    })
}

/// Whether nginx has to reopen its log files: a rotation just happened, or one of the two current
/// files is missing even though the marker says the day was rotated. The second case is the recovery
/// path for a crash between `rename` and `SIGHUP`.
fn needs_reopen(dir: &Path, rotated: bool) -> bool {
    rotated
        || LogKind::ALL
            .iter()
            .any(|&kind| !dir.join(layout().current(kind)).is_file())
}

/// One pass, pure enough to test with a fixed clock: rotate if the current files belong to an
/// earlier UTC day, prune completed files, and report what is left.
pub fn retention_pass(dir: &Path, now: SystemTime, retention: LogRetention) -> io::Result<Report> {
    ensure_dir(dir)?;
    let today = utc_date(now);
    let rotated = rotate_if_due(dir, &today)?;
    let (mut deleted, mut freed_bytes) = (0, 0);
    if let Some(days) = retention.days() {
        let (n, bytes) = prune(dir, &today, days)?;
        deleted = n;
        freed_bytes = bytes;
    }
    let (files, bytes) = scan(dir)?;
    Ok(Report {
        rotated,
        deleted,
        freed_bytes,
        files,
        bytes,
    })
}

/// Renames the current files when the sidecar says they belong to an earlier UTC day. Returns
/// whether anything was renamed.
fn rotate_if_due(dir: &Path, today: &str) -> io::Result<bool> {
    let marker = dir.join(LOG_DATE_MARKER);
    let recorded = fs::read_to_string(&marker)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| parse_date(s).is_some());
    let logical = match recorded {
        Some(date) => date,
        None => current_mtime_date(dir, today),
    };
    if logical == today {
        write_marker(&marker, today)?;
        return Ok(false);
    }

    let mut rotated = false;
    for kind in LogKind::ALL {
        let source = dir.join(layout().current(kind));
        let meta = match fs::symlink_metadata(&source) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        if !meta.file_type().is_file() || meta.len() == 0 {
            continue;
        }
        let target = dated_path(dir, kind, &logical);
        fs::rename(&source, &target)?;
        rotated = true;
    }
    write_marker(&marker, today)?;
    Ok(rotated)
}

/// Date of the current file when there is no sidecar yet (the first run after an upgrade, or a
/// directory restored from a backup). When neither file exists the current day is the answer.
fn current_mtime_date(dir: &Path, today: &str) -> String {
    for kind in LogKind::ALL {
        if let Ok(meta) = fs::metadata(dir.join(layout().current(kind)))
            && let Ok(modified) = meta.modified()
        {
            return utc_date(modified);
        }
    }
    today.to_owned()
}

/// `access-YYYY-MM-DD.log`, with `.1`, `.2`, … appended only when a crash left the same date behind.
fn dated_path(dir: &Path, kind: LogKind, date: &str) -> PathBuf {
    let stem = kind.stem();
    let first = dir.join(layout().dated(kind, date));
    if !first.exists() {
        return first;
    }
    for n in 1..=1000 {
        let candidate = dir.join(format!("{stem}-{date}.{n}.log"));
        if !candidate.exists() {
            return candidate;
        }
    }
    // Practically unreachable; a timestamp keeps the data instead of overwriting it.
    let stamp = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    dir.join(format!("{stem}-{date}.{stamp}.log"))
}

fn write_marker(marker: &Path, today: &str) -> io::Result<()> {
    // Atomic (temp + rename) and therefore not fooled by a symlink a compromised nginx master could
    // place at `.logdate`. The date is generated here (digits and dashes), never taken from a request.
    write_atomic(marker, format!("{today}\n").as_bytes(), 0o600)
}

/// Deletes completed files whose UTC date is at least `days` days before `today`. Returns the count
/// and the bytes freed.
fn prune(dir: &Path, today: &str, days: u32) -> io::Result<(u64, u64)> {
    let today = parse_date(today).unwrap_or(0);
    let mut files = 0;
    let mut bytes = 0;
    for (_, date, path) in layout().completed(dir)? {
        let Some(date) = parse_date(&date) else {
            continue;
        };
        if today - date < i64::from(days) {
            continue;
        }
        let meta = fs::symlink_metadata(&path)?;
        fs::remove_file(&path)?;
        files += 1;
        bytes += meta.len();
    }
    Ok((files, bytes))
}

/// Counts the current and completed log files and their total size, for `doctor`.
pub fn scan(dir: &Path) -> io::Result<(u64, u64)> {
    let completed = match layout().completed(dir) {
        Ok(completed) => completed,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((0, 0)),
        Err(e) => return Err(e),
    };
    let mut files = 0;
    let mut bytes = 0;
    let current = LogKind::ALL
        .iter()
        .map(|&kind| dir.join(layout().current(kind)));
    for path in current.chain(completed.into_iter().map(|(_, _, path)| path)) {
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_file() => {
                files += 1;
                bytes += meta.len();
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok((files, bytes))
}

/// The directory layout the worker operates on.
fn layout() -> ingress_logs::LogDir {
    ingress_logs::shared()
}

/// UTC calendar date (`YYYY-MM-DD`) of a `SystemTime`.
pub(crate) fn utc_date(now: SystemTime) -> String {
    rfc3339_utc(now)[..DATE_LEN].to_owned()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;

    const ACCESS_LOG: &str = "access.log";
    const ERROR_LOG: &str = "error.log";

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn create(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
    }

    #[test]
    fn utc_dates_round_trip() {
        assert_eq!(utc_date(UNIX_EPOCH), "1970-01-01");
        assert_eq!(parse_date("1970-01-01"), Some(0));
        assert_eq!(parse_date("2024-02-29"), Some(19_782));
        assert_eq!(parse_date("2024-02-30"), None);
        assert_eq!(parse_date("2026-11-04"), Some(20_761));
        assert_eq!(parse_date("2026-11-4"), None);
        assert_eq!(parse_date("2026-11-04x"), None);
    }

    #[test]
    fn prune_deletes_only_completed_files_at_least_n_days_old() {
        let d = dir();
        create(&d.path().join("access-2026-10-04.log"), b"old");
        create(&d.path().join("access-2026-10-05.log"), b"old");
        create(&d.path().join("access-2026-10-06.log"), b"keep");
        create(&d.path().join("access-2026-11-04.log"), b"today");
        create(&d.path().join("error-2026-10-04.log"), b"old");
        create(&d.path().join("access.log"), b"current");
        create(&d.path().join("notes.txt"), b"not a log");
        // The current files belong to the pass's day; without the marker the rotation would read
        // the real mtime of `access.log` and rotate it on any other day.
        fs::write(d.path().join(LOG_DATE_MARKER), "2026-11-04\n").unwrap();

        let report = retention_pass(d.path(), at(1_793_750_400), LogRetention::Days(30)).unwrap();
        // 2026-11-04 minus 30 days is 2026-10-05; files dated on or before it are gone.
        assert!(!d.path().join("access-2026-10-04.log").exists());
        assert!(!d.path().join("access-2026-10-05.log").exists());
        assert!(!d.path().join("error-2026-10-04.log").exists());
        assert!(d.path().join("access-2026-10-06.log").exists());
        assert!(d.path().join("access-2026-11-04.log").exists());
        assert!(d.path().join("access.log").exists());
        assert!(d.path().join("notes.txt").exists());
        assert_eq!(report.deleted, 3);
    }

    #[test]
    fn unlimited_never_deletes_but_still_rotates() {
        let d = dir();
        create(&d.path().join("access-2020-01-01.log"), b"old");
        create(&d.path().join(ACCESS_LOG), b"current");
        fs::write(d.path().join(LOG_DATE_MARKER), "2026-11-03\n").unwrap();

        let report = retention_pass(
            d.path(),
            at(1_793_750_400),
            LogRetention::Unlimited(weglarka_model::config::Unlimited::Unlimited),
        )
        .unwrap();
        assert!(report.rotated);
        assert_eq!(report.deleted, 0);
        assert!(d.path().join("access-2020-01-01.log").exists());
        assert!(d.path().join("access-2026-11-03.log").exists());
        assert!(!d.path().join(ACCESS_LOG).exists());
        assert_eq!(
            fs::read_to_string(d.path().join(LOG_DATE_MARKER)).unwrap(),
            "2026-11-04\n"
        );
    }

    #[test]
    fn a_restart_after_midnight_rotates_to_the_recorded_day() {
        let d = dir();
        create(
            &d.path().join(ACCESS_LOG),
            b"yesterday and a little of today",
        );
        create(&d.path().join(ERROR_LOG), b"error");
        fs::write(d.path().join(LOG_DATE_MARKER), "2026-11-03\n").unwrap();

        let report = retention_pass(d.path(), at(1_793_750_400), LogRetention::Days(30)).unwrap();
        assert!(report.rotated);
        assert!(d.path().join("access-2026-11-03.log").exists());
        assert!(d.path().join("error-2026-11-03.log").exists());
        assert!(!d.path().join(ACCESS_LOG).exists());
        assert_eq!(
            fs::read_to_string(d.path().join(LOG_DATE_MARKER)).unwrap(),
            "2026-11-04\n"
        );
    }

    #[test]
    fn missing_current_files_force_a_reopen() {
        let d = dir();
        assert!(super::needs_reopen(d.path(), false));
        create(&d.path().join(ACCESS_LOG), b"access");
        assert!(
            super::needs_reopen(d.path(), false),
            "error.log is still missing"
        );
        create(&d.path().join(ERROR_LOG), b"error");
        assert!(!super::needs_reopen(d.path(), false));
        assert!(
            super::needs_reopen(d.path(), true),
            "a rotation always reopens"
        );
    }

    #[test]
    fn the_same_day_is_not_rotated_twice() {
        let d = dir();
        create(&d.path().join(ACCESS_LOG), b"today");
        fs::write(d.path().join(LOG_DATE_MARKER), "2026-11-04\n").unwrap();

        let report = retention_pass(d.path(), at(1_793_750_400), LogRetention::Days(30)).unwrap();
        assert!(!report.rotated);
        assert!(d.path().join(ACCESS_LOG).exists());
    }

    #[test]
    fn a_collision_gets_a_suffix_instead_of_overwriting() {
        let d = dir();
        create(&d.path().join(ACCESS_LOG), b"new");
        create(&d.path().join("access-2026-11-03.log"), b"old");
        fs::write(d.path().join(LOG_DATE_MARKER), "2026-11-03\n").unwrap();

        retention_pass(d.path(), at(1_793_750_400), LogRetention::Days(30)).unwrap();
        assert_eq!(
            fs::read(d.path().join("access-2026-11-03.log")).unwrap(),
            b"old"
        );
        assert!(d.path().join("access-2026-11-03.1.log").exists());
    }
}
