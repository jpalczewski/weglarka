//! Detection of app containers that libpod reports as `running` while their conmon is dead
//! (issue #470).
//!
//! Measured on rootless Podman 6.1.3: after a container's conmon is killed, `inspect` and
//! `/containers/json` keep reporting `running` with the stale `State.ConmonPid`, and the health
//! status freezes at its last value because the health timer lived in the conmon's unit. Nothing
//! derived from libpod state can see that, and the daemon runs in a container, so it cannot reach
//! the host's PIDs. The host-side watchdog (`weglarka-daemon supervise`, every minute from
//! `weglarka-watchdog.timer`) can: it checks that every running app container's conmon PID is still
//! a live `conmon` and records the affected instances in `<state dir>/conmon-check.toml`, which the
//! daemon's `doctor` reads as the check `podman.conmon`.
//!
//! The file is deliberately **outside** the state schema: it is a host-side observation whose loss
//! costs nothing (the next watchdog run rewrites it a minute later), the watchdog — not the engine —
//! is its writer, and a new field in `state.toml` would break a rollback to an older daemon
//! (`deny_unknown_fields`, ADR 0023). It follows `webhook-deliveries.toml` (ADR 0035): no schema
//! marker, mode 0600, atomic write, tolerant read.
//!
//! Report only: nothing here repairs anything. `weglarka apps reload <app> --recreate` gives the
//! container a fresh conmon (a plain reload only signals an app with `reload_signal`); an automatic
//! repair is a follow-up (issue #470).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use weglarka_api::{CheckStatus, DoctorCheck};
use weglarka_model::app::InstanceName;
use weglarka_model::fsutil;
use weglarka_model::labels;
use weglarka_model::podman::{ContainerFilter, ContainerInfo, ContainerState, PodmanClient};

/// `/proc` of the host the watchdog runs on: never configurable, and only the watchdog reads it.
pub const PROC_ROOT: &str = "/proc";

/// File in the state directory (written by the watchdog, read by `doctor`).
pub const FILE_NAME: &str = "conmon-check.toml";
/// Internal bookkeeping, like `self-update.toml`.
pub const FILE_MODE: u32 = 0o600;

/// `comm` of a conmon process: the kernel's name of the executable, truncated to 15 bytes, never a
/// command line — so no argument of another process can pass for it.
pub const CONMON_COMM: &str = "conmon";

/// How old a report may be before `doctor` stops trusting it. The watchdog runs once a minute, so a
/// report older than this means the timer is not running any more; the check says that instead of
/// reporting a stale "all clear".
pub const STALE_AFTER_SECS: u64 = 300;

/// One host-side observation, as the watchdog writes it and `doctor` reads it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Report {
    /// Unix seconds of the observation ([`weglarka_model::self_update::secs`]); `None` in a file
    /// written by hand.
    pub checked_at: Option<u64>,
    /// Instances whose running container has no live conmon, sorted and deduplicated.
    pub affected: Vec<String>,
}

impl Report {
    /// How old the observation is, in seconds; `None` for a file without a timestamp.
    fn age_secs(&self, now: u64) -> Option<u64> {
        self.checked_at.map(|at| now.saturating_sub(at))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    #[error("cannot serialize the conmon report: {0}")]
    Serialize(#[from] toml::ser::Error),
    #[error("cannot write {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
}

pub fn path(state_dir: &Path) -> PathBuf {
    state_dir.join(FILE_NAME)
}

/// The recorded observation, or `None` when there is none to trust: never written (the watchdog is
/// not installed or has not run yet), unreadable, or malformed. A malformed file is logged and
/// treated as absent — this is bookkeeping, and the next watchdog run rewrites it.
pub fn load(state_dir: &Path) -> Option<Report> {
    let path = path(state_dir);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "cannot read the host-side conmon check; treating it as absent"
            );
            return None;
        }
    };
    if text.trim().is_empty() {
        return None;
    }
    match toml::from_str::<Report>(&text) {
        // The file is the watchdog's, but `doctor` (also at the `read` scope) prints its names: only
        // valid instance names leave it, whatever else a hand-edited file holds.
        Ok(mut report) => {
            report
                .affected
                .retain(|name| InstanceName::new(name.as_str()).is_ok());
            Some(report)
        }
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "ignoring a malformed host-side conmon check; it is rewritten on the next watchdog run"
            );
            None
        }
    }
}

/// Records one observation atomically (mode 0600), replacing the previous one.
pub fn record(state_dir: &Path, report: &Report) -> Result<(), ReportError> {
    let path = path(state_dir);
    let text = toml::to_string(report)?;
    fsutil::write_atomic(&path, text.as_bytes(), FILE_MODE)
        .map_err(|source| ReportError::Write { path, source })
}

/// Whether a conmon PID is still alive. Injected so that the decision logic is pure and the tests
/// never touch the machine's `/proc`.
pub trait ConmonLiveness: Send + Sync {
    fn is_alive(&self, pid: u32) -> bool;
}

/// The real probe: `/proc/<pid>/comm` must exist and read `conmon`.
///
/// `kill(pid, 0)` alone would accept a recycled PID of an unrelated process; the `comm` check is what
/// makes "the conmon of this container" honest.
pub struct ProcConmon {
    root: PathBuf,
}

impl ProcConmon {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The `/proc` of the host the watchdog runs on.
    pub fn host() -> Self {
        Self::new(PROC_ROOT)
    }
}

impl ConmonLiveness for ProcConmon {
    fn is_alive(&self, pid: u32) -> bool {
        // A comma-free, single-segment join: `comm` of another user's process is unreadable, which is
        // correctly "not our conmon".
        match std::fs::read_to_string(self.root.join(pid.to_string()).join("comm")) {
            Ok(comm) => comm.trim_end() == CONMON_COMM,
            Err(_) => false,
        }
    }
}

/// What one pass over the container list found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Observation {
    /// Running app containers whose conmon PID was probed.
    pub checked: usize,
    /// App containers whose conmon is gone, sorted by instance; one per instance.
    pub suspects: Vec<Suspect>,
}

impl Observation {
    /// The instances of [`Self::suspects`], in order.
    pub fn affected(&self) -> Vec<String> {
        self.suspects.iter().map(|s| s.instance.clone()).collect()
    }
}

/// One running app container without a live conmon, as seen by one listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suspect {
    pub instance: String,
    pub container: String,
    pub conmon_pid: u32,
}

/// Probes the conmon of every running app container.
///
/// Only an app's **main** container counts (`labels::container_name` of a valid instance label): the
/// remedy `doctor` prints acts on that container, so a blue-green challenger or a retiring copy
/// reported under the app's name would send the operator to fix the wrong one. One-off
/// `run`/`forward`/import containers are skipped like in `resources::identify`, and so is any
/// container whose label is not a valid instance name (its text would end up in the report). Only
/// containers libpod reports as `running` are probed: a stopped, created or exited container has no
/// conmon to lose. A running container that libpod reports without a conmon PID is skipped rather
/// than guessed at: `None` is "libpod said nothing", not evidence of a dead conmon.
pub fn observe(containers: &[ContainerInfo], liveness: &impl ConmonLiveness) -> Observation {
    let mut observation = Observation::default();
    let mut probed: Vec<Suspect> = containers
        .iter()
        .filter(|c| c.state == ContainerState::Running)
        .filter(|c| {
            ![labels::RUN, labels::FORWARD, labels::IMPORT_FOR]
                .iter()
                .any(|marker| c.labels.contains_key(*marker))
        })
        .filter_map(|c| {
            let instance = InstanceName::new(c.labels.get(labels::INSTANCE)?.as_str()).ok()?;
            if c.name != labels::container_name(&instance) {
                return None;
            }
            Some(Suspect {
                instance: instance.as_str().to_owned(),
                container: c.name.clone(),
                conmon_pid: c.conmon_pid?,
            })
        })
        .collect();
    // One order everywhere: the report is written as text, and a stable order keeps diffs readable.
    probed.sort_by(|a, b| a.instance.cmp(&b.instance));
    for suspect in probed {
        observation.checked += 1;
        if !liveness.is_alive(suspect.conmon_pid) {
            observation.suspects.push(suspect);
        }
    }
    observation
}

/// Drops the suspects that changed since the listing: a container stopped (a deploy, a reload) or
/// restarted with a new conmon between the listing and the `/proc` read is not a dead conmon. A
/// suspect stays only when a fresh inspect still says `running` with the same conmon PID, and that
/// PID is still not a live conmon; a failed inspect drops it too (the next run looks again).
async fn confirm<P: PodmanClient>(
    podman: &P,
    liveness: &impl ConmonLiveness,
    suspects: Vec<Suspect>,
) -> Vec<Suspect> {
    let mut confirmed = Vec::new();
    for suspect in suspects {
        let still = podman
            .container_inspect(&suspect.container)
            .await
            .is_ok_and(|c| {
                c.state == ContainerState::Running && c.conmon_pid == Some(suspect.conmon_pid)
            });
        if still && !liveness.is_alive(suspect.conmon_pid) {
            confirmed.push(suspect);
        }
    }
    confirmed
}

/// Outcome of one watchdog run of the check; the caller prints it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Summary {
    /// Every probed app container has a live conmon.
    Ok { checked: usize },
    /// These instances have a running container without a live conmon.
    Affected { instances: Vec<String> },
    /// libpod could not be asked; nothing was recorded.
    Unavailable { reason: String },
}

impl std::fmt::Display for Summary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ok { checked: 0 } => f.write_str("no running app container to check"),
            Self::Ok { checked } => write!(
                f,
                "{checked} running app container(s) checked, every conmon alive"
            ),
            Self::Affected { instances } => write!(
                f,
                "no live conmon for {} — `weglarka apps reload <app> --recreate` gives the container a fresh one",
                instances.join(", ")
            ),
            Self::Unavailable { reason } => write!(f, "conmon check skipped: {reason}"),
        }
    }
}

/// One watchdog run of the check: list the containers, probe the conmons, record the observation.
///
/// A failed listing is reported, not fatal: the self-update supervision of the same run must still
/// happen, and the previous report stays on disk (an old "all clear" is caught by
/// [`STALE_AFTER_SECS`]).
pub async fn check<P: PodmanClient>(
    podman: &P,
    liveness: &impl ConmonLiveness,
    state_dir: &Path,
    now: u64,
) -> Summary {
    let containers = match podman.container_list(&ContainerFilter::default()).await {
        Ok(containers) => containers,
        Err(e) => {
            tracing::warn!(error = %e, "cannot list the containers for the conmon check");
            return Summary::Unavailable {
                reason: e.to_string(),
            };
        }
    };
    let mut observation = observe(&containers, liveness);
    observation.suspects = confirm(podman, liveness, observation.suspects).await;
    let affected = observation.affected();
    let report = Report {
        checked_at: Some(now),
        affected: affected.clone(),
    };
    if let Err(e) = record(state_dir, &report) {
        tracing::warn!(error = %e, "cannot record the host-side conmon check");
    }
    if affected.is_empty() {
        Summary::Ok {
            checked: observation.checked,
        }
    } else {
        tracing::warn!(
            instances = %affected.join(", "),
            "container reported as running without a live conmon (issue #470)"
        );
        Summary::Affected {
            instances: affected,
        }
    }
}

/// The `doctor` line for one recorded observation (pure: the caller loads the file and passes the
/// clock).
///
/// `fail`, not `warn`: the container keeps answering "running" while nothing keeps it alive — its
/// log, its health timer and its DNS registration are all gone — so the operator has to act. The
/// failure outranks a stale report, but says how old it is and, once stale, that the watchdog has
/// stopped looking: a repaired app stays listed until the next run.
///
/// The remedy is `apps reload --recreate`, not a plain reload: an app with `reload_signal` only gets
/// the signal, which does not give the container a fresh conmon.
pub fn doctor_check(report: Option<&Report>, path: &Path, now: u64) -> DoctorCheck {
    const ID: &str = "podman.conmon";
    const TIMER_HINT: &str = "the check runs from the host-side watchdog; `platform install` installs weglarka-watchdog.timer";
    let Some(report) = report else {
        return DoctorCheck::info(
            ID,
            format!("no host-side conmon check yet ({})", path.display()),
        )
        .with_hint(TIMER_HINT);
    };
    let age = report.age_secs(now);
    if !report.affected.is_empty() {
        let seen = age.map_or_else(String::new, |age| format!("; checked {age}s ago"));
        let recreate = format!(
            "recreate each one: {}",
            report
                .affected
                .iter()
                .map(|app| format!("`weglarka apps reload {app} --recreate`"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let hint = match age {
            Some(age) if age > STALE_AFTER_SECS => format!("{recreate}; {TIMER_HINT}"),
            _ => recreate,
        };
        return DoctorCheck::fail(
            ID,
            format!(
                "no live conmon for: {} (reported as running by libpod, but nothing keeps them alive{seen})",
                report.affected.join(", ")
            ),
        )
        .with_hint(hint);
    }
    match age {
        Some(age) if age > STALE_AFTER_SECS => DoctorCheck::new(
            ID,
            CheckStatus::Warn,
            format!(
                "the last host-side conmon check is {age}s old (it runs every minute); a dead conmon would be invisible"
            ),
        )
        .with_hint(TIMER_HINT),
        Some(age) => DoctorCheck::ok(
            ID,
            format!("every running app container has a live conmon (checked {age}s ago)"),
        ),
        None => DoctorCheck::ok(
            ID,
            format!("every running app container has a live conmon ({})", path.display()),
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    /// A liveness probe with a fixed set of live PIDs: the detection logic is pure, so no test reads
    /// the machine's `/proc`.
    struct Alive(Vec<u32>);

    impl ConmonLiveness for Alive {
        fn is_alive(&self, pid: u32) -> bool {
            self.0.contains(&pid)
        }
    }

    fn container(name: &str, state: ContainerState, conmon_pid: Option<u32>) -> ContainerInfo {
        ContainerInfo {
            id: format!("id-{name}"),
            name: name.to_owned(),
            image: "example.com/app:1".to_owned(),
            image_id: "sha256:0".to_owned(),
            labels: BTreeMap::from([(labels::INSTANCE.to_owned(), name.to_owned())]),
            state,
            exit_code: None,
            health: None,
            restarts: 0,
            started_at: None,
            networks: Vec::new(),
            addresses: Vec::new(),
            published_ports: Vec::new(),
            memory_limit: None,
            oom_killed: false,
            conmon_pid,
        }
    }

    #[test]
    fn a_running_container_without_a_live_conmon_is_reported_by_instance() {
        let containers = [
            container("ok", ContainerState::Running, Some(10)),
            container("dead", ContainerState::Running, Some(20)),
            // Not running: no conmon to lose, whatever the stale PID says.
            container("stopped", ContainerState::Exited, Some(30)),
            container("never", ContainerState::Created, Some(40)),
            // libpod reports nothing: skipped, not guessed at.
            container("unknown", ContainerState::Running, None),
        ];
        let observation = observe(&containers, &Alive(vec![10]));
        assert_eq!(observation.checked, 2);
        assert_eq!(observation.affected(), ["dead"]);
    }

    #[test]
    fn a_container_without_the_instance_label_is_not_an_app_container() {
        let mut one_off = container("wg-run.ntfy.tok", ContainerState::Running, Some(20));
        one_off.labels.clear();
        one_off
            .labels
            .insert(labels::RUN.to_owned(), "true".to_owned());
        let observation = observe(&[one_off], &Alive(Vec::new()));
        assert_eq!(observation.checked, 0);
        assert!(observation.affected().is_empty());
    }

    #[test]
    fn only_the_main_container_of_a_valid_instance_is_probed() {
        let app = InstanceName::new("app").unwrap();
        // A blue-green deploy leaves the challenger and the retiring container next to the main one:
        // `apps reload app` would act on the main one, so only that one may be reported as `app`.
        let mut challenger = container(
            &labels::challenger_name(&app),
            ContainerState::Running,
            Some(21),
        );
        challenger
            .labels
            .insert(labels::INSTANCE.to_owned(), "app".to_owned());
        let mut retiring = container(
            &labels::retiring_name(&app),
            ContainerState::Running,
            Some(22),
        );
        retiring
            .labels
            .insert(labels::INSTANCE.to_owned(), "app".to_owned());
        // A label that is not an instance name never reaches the report.
        let mut forged = container("forged", ContainerState::Running, Some(23));
        forged
            .labels
            .insert(labels::INSTANCE.to_owned(), "`x`\nrm -rf".to_owned());
        let containers = [
            container("app", ContainerState::Running, Some(20)),
            challenger,
            retiring,
            forged,
        ];
        let observation = observe(&containers, &Alive(Vec::new()));
        assert_eq!(observation.checked, 1);
        assert_eq!(observation.affected(), ["app"]);
        assert_eq!(observation.suspects[0].container, "app");
    }

    #[test]
    fn the_probe_requires_the_pid_of_a_conmon_and_not_a_recycled_pid() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let write = |pid: u32, comm: &str| {
            std::fs::create_dir_all(root.join(pid.to_string())).unwrap();
            std::fs::write(root.join(pid.to_string()).join("comm"), comm).unwrap();
        };
        write(10, "conmon\n");
        write(11, "nginx\n");
        let probe = ProcConmon::new(root);
        assert!(probe.is_alive(10));
        assert!(!probe.is_alive(11), "a recycled PID of another process");
        assert!(!probe.is_alive(12), "a PID that is not running");
    }

    #[test]
    fn the_report_round_trips_and_a_malformed_file_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load(dir.path()).is_none(), "nothing written yet");
        record(
            dir.path(),
            &Report {
                checked_at: Some(1_000),
                affected: vec!["ntfy".to_owned()],
            },
        )
        .unwrap();
        let loaded = load(dir.path()).unwrap();
        assert_eq!(loaded.checked_at, Some(1_000));
        assert_eq!(loaded.affected, ["ntfy"]);
        // Mode 0600: the file lists app names, and the state directory is group- and world-readable.
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path(dir.path()))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, FILE_MODE);

        // A hand-edited file cannot smuggle free text into `doctor`.
        std::fs::write(
            path(dir.path()),
            "checked_at = 1\naffected = [\"ntfy\", \"`x` rm\"]\n",
        )
        .unwrap();
        assert_eq!(load(dir.path()).unwrap().affected, ["ntfy"]);

        std::fs::write(path(dir.path()), "not toml at all [").unwrap();
        assert!(load(dir.path()).is_none());
    }

    #[tokio::test]
    async fn the_check_records_an_empty_report_when_every_conmon_lives() {
        use weglarka_engine::testing::FakePodman;

        let dir = tempfile::tempdir().unwrap();
        let fake = FakePodman::new();
        // FakePodman containers report no conmon PID, so nothing is probed and nothing is affected.
        let summary = check(&fake, &Alive(Vec::new()), dir.path(), 7).await;
        assert_eq!(summary, Summary::Ok { checked: 0 });
        let recorded = load(dir.path()).unwrap();
        assert_eq!(recorded.checked_at, Some(7));
        assert!(recorded.affected.is_empty());
    }

    /// A fake with one running app container `app` whose conmon PID is `pid`.
    async fn fake_with_app(pid: u32) -> weglarka_engine::testing::FakePodman {
        use futures_util::StreamExt;
        let fake = weglarka_engine::testing::FakePodman::new();
        let _: Vec<_> = fake.image_pull("example.com/app:1").collect().await;
        fake.add_foreign_container("app", "example.com/app:1");
        fake.set_container_labels(
            "app",
            BTreeMap::from([(labels::INSTANCE.to_owned(), "app".to_owned())]),
        );
        fake.set_conmon_pid("app", Some(pid));
        fake
    }

    #[tokio::test]
    async fn the_check_records_a_running_app_whose_conmon_is_gone() {
        let dir = tempfile::tempdir().unwrap();
        let fake = fake_with_app(20).await;
        let summary = check(&fake, &Alive(Vec::new()), dir.path(), 7).await;
        assert_eq!(
            summary,
            Summary::Affected {
                instances: vec!["app".to_owned()]
            }
        );
        assert_eq!(load(dir.path()).unwrap().affected, ["app"]);

        // The same container with a live conmon is clean.
        let summary = check(&fake, &Alive(vec![20]), dir.path(), 8).await;
        assert_eq!(summary, Summary::Ok { checked: 1 });
        assert!(load(dir.path()).unwrap().affected.is_empty());
    }

    /// The container got a new conmon between the listing and the `/proc` read (a restart): the
    /// re-inspect sees another PID, so the old one is not reported.
    struct Restarted<'a>(&'a weglarka_engine::testing::FakePodman);

    impl ConmonLiveness for Restarted<'_> {
        fn is_alive(&self, pid: u32) -> bool {
            self.0.set_conmon_pid("app", Some(21));
            pid == 21
        }
    }

    #[tokio::test]
    async fn a_container_that_changed_after_the_listing_is_not_reported() {
        let dir = tempfile::tempdir().unwrap();
        let fake = fake_with_app(20).await;
        let summary = check(&fake, &Restarted(&fake), dir.path(), 7).await;
        assert_eq!(summary, Summary::Ok { checked: 1 });
        assert!(load(dir.path()).unwrap().affected.is_empty());
    }

    #[test]
    fn doctor_fails_with_the_reload_command_and_is_quiet_without_data() {
        let path = Path::new("/state/conmon-check.toml");
        let empty = Report {
            checked_at: Some(1_000),
            affected: Vec::new(),
        };
        let ok = doctor_check(Some(&empty), path, 1_030);
        assert_eq!(ok.id, "podman.conmon");
        assert_eq!(ok.status, CheckStatus::Ok);
        assert_eq!(
            ok.message,
            "every running app container has a live conmon (checked 30s ago)"
        );

        let dead = Report {
            checked_at: Some(1_000),
            affected: vec!["blog".to_owned(), "ntfy".to_owned()],
        };
        let fail = doctor_check(Some(&dead), path, 1_030);
        assert_eq!(fail.status, CheckStatus::Fail);
        assert_eq!(
            fail.hint.as_deref(),
            Some(
                "recreate each one: `weglarka apps reload blog --recreate`, `weglarka apps reload ntfy --recreate`"
            )
        );
        assert!(fail.message.contains("blog, ntfy"));
        assert!(fail.message.contains("checked 30s ago"), "{}", fail.message);

        // No file at all: the watchdog is not installed (or has not run yet) — advice, not a failure.
        let absent = doctor_check(None, path, 1_030);
        assert_eq!(absent.status, CheckStatus::Info);
        assert!(absent.message.contains("/state/conmon-check.toml"));

        // A dead conmon outranks a stale report: the failure is the operator's problem.
        // ... but it says how old it is, and that the watchdog stopped looking.
        let stale = doctor_check(Some(&dead), path, 9_999);
        assert_eq!(stale.status, CheckStatus::Fail);
        assert!(
            stale.message.contains("checked 8999s ago"),
            "{}",
            stale.message
        );
        assert!(
            stale
                .hint
                .as_deref()
                .unwrap()
                .contains("weglarka-watchdog.timer")
        );

        let stale_ok = doctor_check(Some(&empty), path, 9_999);
        assert_eq!(stale_ok.status, CheckStatus::Warn);
        assert!(stale_ok.message.contains("8999s old"));
    }
}
