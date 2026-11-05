//! `weglarka-daemon supervise` — the host-side watchdog: the self-update fallback of a switch in
//! flight (issue #100, `docs/decisions/0034`) and the conmon check of the app containers (issue #470).
//!
//! The switcher pins a new digest in the service definition and restarts the service; the daemon
//! inside the container cannot tell whether that image ever came up. This module runs from the user
//! timer `weglarka-watchdog.timer` (every minute, installed by `platform install`): it takes the
//! host-side state lock, asks the admin API for `GET /v1/health` over the unix socket, and hands the
//! observation to [`crate::self_update::watch`], which turns the pure decision of
//! `weglarka_model::self_update::supervise` into a pinned rollback — the previous digest restored in
//! the service definition and the service restarted.
//!
//! The same wake-up is the one place that can see a dead container conmon: libpod keeps reporting such
//! a container as `running`, and the daemon (in a container) cannot reach the host's PIDs. The check
//! runs from here, independently of `[self_update]`, and records what it found for `doctor`
//! ([`crate::conmon`]).
//!
//! It also records whether the systemd user manager holds every group `/etc/group` gives the runtime
//! user (issue #191, [`record_user_groups`]): `group_add` containers inherit the manager's credentials,
//! and only the host can read them.
//!
//! Everything that needs a decision is in `weglarka-model` (`self_update`; pure, injected clock) and
//! in [`crate::conmon`]; this module is the thin host-side I/O around them: lock, probe and the two
//! commands the fallback needs.

use std::path::Path;
use std::time::{Duration, SystemTime};

use weglarka_api::endpoints;
use weglarka_engine::platform::Platform;
use weglarka_model::podman::PodmanClient;
use weglarka_model::self_update::secs;
use weglarka_model::user_groups::{self, UserGroupsState};

use crate::conmon;
use crate::self_update::{self, WatchReport};
use crate::settings::Settings;

/// How long the probe waits for an answer before treating the daemon as "not healthy yet".
///
/// Short on purpose: the deadline, not the probe, is what decides the fallback, and the watchdog runs
/// once a minute.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound of the conmon check (one libpod listing plus an inspect per suspect). The libpod
/// client has no request timeout, and a stuck libpod (a container lock held by a hung stop) must not
/// hold the run until systemd kills the oneshot: the check is then reported as unavailable.
pub const CONMON_CHECK_TIMEOUT: Duration = Duration::from_secs(30);

/// Outcome of one watchdog wake-up: the conmon check of the containers (issue #470) and the
/// supervision of a self-update switch in flight (issue #100).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub conmon: conmon::Summary,
    pub watch: WatchReport,
}

impl Report {
    /// `false` only for the self-update outcomes that need the operator: a dead conmon is reported by
    /// `doctor` (and repaired by hand), and failing the timer every minute would add noise, not work.
    pub fn is_success(&self) -> bool {
        self.watch.is_success()
    }
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}; {}", self.conmon, self.watch)
    }
}

/// One watchdog run: supervise a self-update switch first — when the fallback is on and no other
/// host-side run holds the lock, probe the daemon and decide — then check the conmons.
///
/// The order matters: the fallback is time-critical and its deadline arithmetic uses `now`, while
/// the conmon check asks libpod, which can hang. The check gets its own clock (`now` plus the time
/// the switch took) and [`CONMON_CHECK_TIMEOUT`]; a failed switch still lets it run.
pub async fn run<P, Pl>(
    podman: &P,
    platform: &Pl,
    settings: &Settings,
    now: SystemTime,
) -> Result<Report, self_update::Error>
where
    P: PodmanClient,
    Pl: Platform,
{
    let started = std::time::Instant::now();
    let watch = supervise_switch(podman, platform, settings, now).await;
    let conmon = check_conmons(podman, settings, now + started.elapsed()).await;
    Ok(Report {
        conmon,
        watch: watch?,
    })
}

/// [`conmon::check`] bounded by [`CONMON_CHECK_TIMEOUT`].
async fn check_conmons<P: PodmanClient>(
    podman: &P,
    settings: &Settings,
    now: SystemTime,
) -> conmon::Summary {
    let liveness = conmon::ProcConmon::host();
    let check = conmon::check(podman, &liveness, &settings.paths.state_dir, secs(now));
    match tokio::time::timeout(CONMON_CHECK_TIMEOUT, check).await {
        Ok(summary) => summary,
        Err(_) => {
            tracing::warn!(
                timeout_secs = CONMON_CHECK_TIMEOUT.as_secs(),
                "libpod did not answer the conmon check in time"
            );
            conmon::Summary::Unavailable {
                reason: format!(
                    "libpod did not answer within {}s",
                    CONMON_CHECK_TIMEOUT.as_secs()
                ),
            }
        }
    }
}

/// The self-update half of the run (issue #100): skip when the feature is off or another run is
/// active, probe the daemon's health, then decide.
async fn supervise_switch<P, Pl>(
    podman: &P,
    platform: &Pl,
    settings: &Settings,
    now: SystemTime,
) -> Result<WatchReport, self_update::Error>
where
    P: PodmanClient,
    Pl: Platform,
{
    let Some(config) = settings.host.self_update.as_ref() else {
        return Ok(WatchReport::Disabled);
    };
    if !config.enabled || !config.fallback {
        return Ok(WatchReport::Disabled);
    }
    // Held until the end of this function: a switch that lands mid-run must not interleave.
    let Some(_lock) = self_update::lock_state(&settings.paths.state_dir)? else {
        tracing::info!("another self-update run is active; skipping this watchdog wake-up");
        return Ok(WatchReport::Locked);
    };
    let healthy = probe_health(&settings.host.admin.socket, PROBE_TIMEOUT).await;
    tracing::debug!(
        healthy,
        socket = %settings.host.admin.socket.display(),
        "self-update watchdog probe"
    );
    self_update::watch(podman, platform, settings, healthy, now).await
}

/// Host files of the group check (issue #191).
const PASSWD_FILE: &str = "/etc/passwd";
const GROUP_FILE: &str = "/etc/group";

/// Records the supplementary groups the runtime user is in according to `/etc/group` but that the user
/// manager's credentials lack (issue #191, `weglarka_model::user_groups`).
///
/// Synchronous local file I/O that needs neither Podman nor `[self_update]`, so `main` runs it before
/// anything that can fail; it never fails itself (a failed write is logged). The user manager is the
/// process systemd names in `MANAGERPID` when it starts the watchdog unit; without it (a manual run,
/// cron) the check records nothing, so it cannot overwrite a real finding with the fresh credentials
/// of a login. Returns the finding it recorded, `None` when the host cannot answer the question.
pub fn record_user_groups(settings: &Settings, now: SystemTime) -> Option<UserGroupsState> {
    let manager = manager_status_path(std::env::var("MANAGERPID").ok().as_deref())?;
    let observed = inspect_host_files(&manager, &settings.host.runtime.user, now)?;
    let previous = user_groups::load(&settings.paths.state_dir).ok().flatten();
    let next = observed.after(previous.as_ref());
    let changed = previous
        .as_ref()
        .is_none_or(|previous| previous.since != next.since);
    if let Err(e) = user_groups::save(&settings.paths.state_dir, &next) {
        tracing::warn!(error = %e, "cannot record the user manager group check");
    } else if changed && next.is_stale() {
        tracing::warn!(
            uid = next.uid,
            missing = %next.names().join(","),
            "the user manager does not hold every group of the runtime user; restart user@<uid>"
        );
    } else if changed {
        tracing::info!("the user manager holds every group of the runtime user");
    }
    Some(next)
}

/// `/proc/<MANAGERPID>/status`; `None` for an unset or non-numeric value.
fn manager_status_path(manager_pid: Option<&str>) -> Option<std::path::PathBuf> {
    let pid: u32 = manager_pid?.trim().parse().ok()?;
    Some(Path::new("/proc").join(pid.to_string()).join("status"))
}

/// Reads the three host files and hands them to the pure comparison.
fn inspect_host_files(manager: &Path, user: &str, now: SystemTime) -> Option<UserGroupsState> {
    let read = |path: &Path| {
        std::fs::read_to_string(path)
            .map_err(|e| tracing::debug!(path = %path.display(), error = %e, "skipping the user manager group check"))
            .ok()
    };
    let passwd = read(Path::new(PASSWD_FILE))?;
    let group_file = read(Path::new(GROUP_FILE))?;
    let status = read(manager)?;
    user_groups::inspect(&passwd, &group_file, &status, user, secs(now))
}

/// Asks the admin API for `GET /v1/health` over its unix socket.
///
/// `true` only for a `200` answer within `timeout`: a refused connection, a stale socket file left by
/// a killed daemon, or a daemon that answers too late all mean "not healthy yet", which is exactly
/// what the fallback deadline is for. This is a readiness probe of the daemon's own API, never a
/// check of the apps.
pub async fn probe_health(socket: &Path, timeout: Duration) -> bool {
    match tokio::time::timeout(timeout, ask_health(socket)).await {
        Ok(healthy) => healthy,
        Err(_) => {
            tracing::debug!(socket = %socket.display(), "health probe timed out");
            false
        }
    }
}

async fn ask_health(socket: &Path) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let Ok(mut stream) = tokio::net::UnixStream::connect(socket).await else {
        return false;
    };
    // A minimal HTTP/1.1 request: the endpoint is our own and takes no body, so no client stack is
    // worth linking into the daemon binary for one line.
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        endpoints::HEALTH.path
    );
    if stream.write_all(request.as_bytes()).await.is_err() || stream.flush().await.is_err() {
        return false;
    }
    // Only the status line matters; the read is capped so a misbehaving server cannot make the
    // watchdog read forever.
    let mut buf = [0u8; 256];
    let mut filled = 0;
    while filled < buf.len() {
        match stream.read(&mut buf[filled..]).await {
            Ok(0) => break,
            Ok(n) => {
                filled += n;
                if buf[..filled].windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => return false,
        }
    }
    status_is_ok(&buf[..filled])
}

/// `HTTP/1.1 200 OK` → `true`; anything else (including a non-HTTP answer) → `false`.
fn status_is_ok(response: &[u8]) -> bool {
    String::from_utf8_lossy(response)
        .split_whitespace()
        .nth(1)
        .is_some_and(|code| code == "200")
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use weglarka_engine::platform::{PlatformError, ServiceSpec, ServiceStatus, UnitFile};
    use weglarka_model::config::PlatformKind;

    use crate::self_update::lock_state;

    async fn serve(dir: &Path, answer: &'static [u8]) -> std::path::PathBuf {
        use tokio::io::AsyncWriteExt;

        let socket = dir.join("admin.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let answer = answer.to_vec();
                tokio::spawn(async move {
                    let _ = stream.write_all(&answer).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        socket
    }

    #[tokio::test]
    async fn the_probe_accepts_a_200_answer_from_the_admin_socket() {
        let dir = tempfile::tempdir().unwrap();
        let socket = serve(
            dir.path(),
            b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{}",
        )
        .await;
        assert!(probe_health(&socket, Duration::from_secs(2)).await);
    }

    #[tokio::test]
    async fn the_probe_rejects_an_error_answer_a_stale_socket_and_a_silent_server() {
        let dir = tempfile::tempdir().unwrap();
        let socket = serve(
            dir.path(),
            b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n",
        )
        .await;
        assert!(!probe_health(&socket, Duration::from_secs(2)).await);

        // No listener at all: the file left by a killed daemon (connect refused).
        assert!(!probe_health(&dir.path().join("missing.sock"), Duration::from_secs(1)).await);

        // A server that never answers must not hang the watchdog.
        let silent = tokio::net::UnixListener::bind(dir.path().join("silent.sock")).unwrap();
        tokio::spawn(async move {
            let (stream, _) = silent.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(60)).await;
            drop(stream);
        });
        assert!(!probe_health(&dir.path().join("silent.sock"), Duration::from_millis(200)).await);
    }

    #[test]
    fn status_parsing_is_strict_about_the_code() {
        assert!(status_is_ok(b"HTTP/1.1 200 OK\r\n\r\n"));
        assert!(!status_is_ok(b"HTTP/1.1 204 No Content\r\n\r\n"));
        assert!(!status_is_ok(b"garbage"));
        assert!(!status_is_ok(b""));
    }

    #[tokio::test]
    async fn the_state_lock_keeps_two_host_side_runs_apart() {
        let dir = tempfile::tempdir().unwrap();
        let first = lock_state(dir.path()).unwrap();
        assert!(first.is_some(), "the first run takes the lock");
        assert!(
            lock_state(dir.path()).unwrap().is_none(),
            "a second run does not"
        );
        drop(first);
        assert!(
            lock_state(dir.path()).unwrap().is_some(),
            "the lock is released with the run"
        );
    }

    #[test]
    fn only_a_numeric_manager_pid_names_a_status_file() {
        assert_eq!(
            manager_status_path(Some("1234")),
            Some(std::path::PathBuf::from("/proc/1234/status"))
        );
        assert_eq!(manager_status_path(None), None, "not started by systemd");
        assert_eq!(manager_status_path(Some("")), None);
        assert_eq!(manager_status_path(Some("../self")), None);
    }

    /// Issue #191 on this machine: the status of this test process is not a user manager's file, but
    /// its uid decides whether the comparison runs at all.
    #[test]
    fn a_status_of_another_uid_is_not_compared() {
        let dir = tempfile::tempdir().unwrap();
        let status = dir.path().join("status");
        std::fs::write(&status, "Name:\tsystemd\nUid:\t0\t0\t0\t0\nGroups:\t\n").unwrap();
        assert_eq!(
            inspect_host_files(&status, "root", SystemTime::UNIX_EPOCH).map(|s| s.uid),
            Some(0),
            "root's own manager is compared"
        );
        // Every host has a `nobody`-like user that is not root; pick the first non-root entry.
        let passwd = std::fs::read_to_string(PASSWD_FILE).unwrap();
        let other = passwd
            .lines()
            .find_map(|line| {
                let mut f = line.split(':');
                let name = f.next()?;
                let uid: u32 = f.nth(1)?.parse().ok()?;
                (uid != 0).then(|| name.to_owned())
            })
            .expect("a non-root user in /etc/passwd");
        assert_eq!(
            inspect_host_files(&status, &other, SystemTime::UNIX_EPOCH),
            None
        );
    }

    /// Every method is a bug: without `[self_update]` the run must not touch the service manager.
    struct NoPlatform;

    impl Platform for NoPlatform {
        fn kind(&self) -> PlatformKind {
            unreachable!()
        }
        async fn runtime_socket(&self, _: &str) -> Result<std::path::PathBuf, PlatformError> {
            unreachable!()
        }
        async fn install_service(&self, _: &ServiceSpec) -> Result<(), PlatformError> {
            unreachable!()
        }
        async fn remove_service(&self, _: &str) -> Result<(), PlatformError> {
            unreachable!()
        }
        async fn service_status(&self, _: &str) -> Result<ServiceStatus, PlatformError> {
            unreachable!()
        }
        async fn install_user_units(&self, _: &[UnitFile]) -> Result<(), PlatformError> {
            unreachable!()
        }
        async fn remove_user_units(&self, _: &[&str]) -> Result<(), PlatformError> {
            unreachable!()
        }
        async fn restart_service(&self, _: &str) -> Result<(), PlatformError> {
            unreachable!()
        }
        async fn reset_failed(&self, _: &str) -> Result<(), PlatformError> {
            unreachable!()
        }
        async fn set_timer(&self, _: &str, _: bool) -> Result<(), PlatformError> {
            unreachable!()
        }
        async fn remove_launcher_setup(&self) -> Result<(), PlatformError> {
            unreachable!()
        }
    }

    fn settings_without_self_update(dir: &Path) -> Settings {
        use weglarka_model::config::HostConfig;

        let host = HostConfig::from_toml_str(&format!(
            "[ingress]\nmode = \"behind\"\nbind = \"127.0.0.1:18080\"\n\
             [admin]\nsocket = \"{root}/admin.sock\"\n\
             [webhook]\nlisten = \"127.0.0.1:0\"\ndomain = \"hooks.example.eu\"\n\
             [state]\ndir = \"{root}/state\"\n",
            root = dir.display()
        ))
        .unwrap();
        let settings = Settings::from_host(host, dir.join("weglarka.toml"));
        std::fs::create_dir_all(&settings.paths.state_dir).unwrap();
        settings
    }

    /// Issue #470: the conmon check must run even on a host without `[self_update]` — that section is
    /// about Węglarka's own image, and the app containers are broken either way.
    #[tokio::test]
    async fn a_host_without_self_update_still_gets_the_conmon_check() {
        let dir = tempfile::tempdir().unwrap();
        let settings = settings_without_self_update(dir.path());

        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let fake = weglarka_engine::testing::FakePodman::new();
        let report = run(&fake, &NoPlatform, &settings, now).await.unwrap();
        assert_eq!(report.watch, WatchReport::Disabled);
        assert_eq!(report.conmon, conmon::Summary::Ok { checked: 0 });
        assert!(report.is_success());
        let recorded = conmon::load(&settings.paths.state_dir).expect("the run records the check");
        assert_eq!(recorded.checked_at, Some(1_000));
        assert!(recorded.affected.is_empty());
    }

    /// A libpod that never answers the listing must not hold the run until systemd kills it: the
    /// switch half runs first, and the conmon check gives up after [`CONMON_CHECK_TIMEOUT`].
    #[tokio::test(start_paused = true)]
    async fn a_hanging_libpod_does_not_hold_the_watchdog() {
        let dir = tempfile::tempdir().unwrap();
        let settings = settings_without_self_update(dir.path());
        let fake = weglarka_engine::testing::FakePodman::new();
        fake.set_list_hangs(true);

        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let report = run(&fake, &NoPlatform, &settings, now).await.unwrap();
        assert_eq!(report.watch, WatchReport::Disabled);
        assert!(
            matches!(&report.conmon, conmon::Summary::Unavailable { reason } if reason.contains("30s")),
            "{report}"
        );
        assert!(report.is_success());
        assert!(
            conmon::load(&settings.paths.state_dir).is_none(),
            "nothing is recorded without an answer"
        );
    }
}
