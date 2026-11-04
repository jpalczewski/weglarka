//! Foreground daemon container runner (`daemon-service` role).
//!
//! OpenRC's `supervise-daemon` runs the launcher as the runtime user; the launcher reads the
//! immutable `platform-service.toml` selection and starts the rootless container directly. It never
//! sources shell state and never needs root.
//!
//! Activation writes a new selection and stops the old container by ID. The supervised runner then
//! exits, the supervisor restarts it, and it reads the new selection. A re-read after `podman
//! create` ensures a slow pull cannot start the previous digest; an epoch mismatch removes the
//! just-created container and loops. Start attempts are bounded per epoch (persisted before each
//! start), and on exhaustion the process stays alive waiting for a new selection instead of leaving
//! the service permanently inactive. A container that runs longer than `stable_after` resets the
//! counter, so a reboot or a rare crash never exhausts it; consecutive failures back off
//! exponentially up to a cap. Without any selection, at start or after it vanishes, the launcher
//! exits non-zero and the supervisor restarts it.

use std::io;
use std::path::PathBuf;
use std::process::ExitStatus;
use std::time::{Duration, Instant};

use crate::budget::{
    BudgetError, backoff_delay, block_service_epoch, note_service_attempt, note_service_run,
    run_was_stable,
};
use crate::inspect;
use crate::selection::{PlatformService, SelectionError};

/// Output of a command the runner executes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Runs fixed programs with fixed argument vectors. Substituted in tests.
pub trait CommandRunner {
    fn run(&self, program: &str, args: &[String], env: &[(String, String)]) -> io::Result<Output>;

    /// Runs to completion with inherited stdio (long-running `podman start -a` / `wait`).
    fn status(
        &self,
        program: &str,
        args: &[String],
        env: &[(String, String)],
    ) -> io::Result<ExitStatus>;
}

/// Real process runner.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcessRunner;

impl CommandRunner for ProcessRunner {
    fn run(&self, program: &str, args: &[String], env: &[(String, String)]) -> io::Result<Output> {
        let output = std::process::Command::new(program)
            .args(args)
            .envs(env.iter().map(|(k, v)| (k, v)))
            .output()?;
        Ok(Output {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        })
    }

    fn status(
        &self,
        program: &str,
        args: &[String],
        env: &[(String, String)],
    ) -> io::Result<ExitStatus> {
        std::process::Command::new(program)
            .args(args)
            .envs(env.iter().map(|(k, v)| (k, v)))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status()
    }
}

/// Time source of the service loop, substituted in tests so they neither sleep nor wait for a
/// container to run for minutes.
pub trait Clock {
    /// Monotonic time since an arbitrary fixed origin.
    fn now(&self) -> Duration;

    /// Blocks the calling thread for `duration`.
    fn sleep(&self, duration: Duration);
}

/// The real monotonic clock.
#[derive(Debug, Clone, Copy)]
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }

    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// What the runtime currently has for the daemon container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerState {
    pub id: String,
    pub epoch: Option<u64>,
    pub running: bool,
}

/// One step of the service loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Same epoch and running: wait for the supervised container to exit.
    Wait { id: String },
    /// Same epoch but stopped: attach/start it again.
    Start { id: String },
    /// No container at all.
    Create,
    /// A container from another (or unknown) epoch: remove it, then create.
    RemoveAndCreate { id: String },
    /// The per-epoch budget is exhausted: stay alive and wait for a new selection.
    Blocked { epoch: u64 },
}

/// Pure decision used by the loop and the tests.
pub fn plan_step(
    selection: &PlatformService,
    observed: Option<&ContainerState>,
    attempts_exhausted: bool,
) -> Step {
    match observed {
        Some(container) if container.epoch == Some(selection.epoch) => {
            if container.running {
                Step::Wait {
                    id: container.id.clone(),
                }
            } else if attempts_exhausted {
                Step::Blocked {
                    epoch: selection.epoch,
                }
            } else {
                Step::Start {
                    id: container.id.clone(),
                }
            }
        }
        Some(container) => Step::RemoveAndCreate {
            id: container.id.clone(),
        },
        None => {
            if attempts_exhausted {
                Step::Blocked {
                    epoch: selection.epoch,
                }
            } else {
                Step::Create
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error(transparent)]
    Selection(#[from] SelectionError),
    #[error(transparent)]
    Budget(#[from] BudgetError),
    #[error(
        "no service selection at {}; exiting so the supervisor restarts the launcher once \
         activation has written one",
        path.display()
    )]
    NoSelection { path: PathBuf },
    #[error("podman {args}: {message}")]
    Podman { args: String, message: String },
    #[error("podman {args}: {source}")]
    Io {
        args: String,
        source: std::io::Error,
    },
}

/// Options of one `daemon-service` run.
#[derive(Debug, Clone)]
pub struct ServiceOptions {
    pub host_dir: PathBuf,
    pub runtime_dir: PathBuf,
    pub podman: String,
    /// How often a blocked runner re-reads the selection while it waits for a new one.
    pub poll: Duration,
    pub max_attempts: u32,
    /// A container run longer than this resets the epoch's attempt counter and the backoff.
    pub stable_after: Duration,
    /// Delay after the first failure; it doubles with every further consecutive failure.
    pub backoff_base: Duration,
    /// Upper bound of the delay.
    pub backoff_cap: Duration,
}

fn env(options: &ServiceOptions) -> Vec<(String, String)> {
    vec![(
        "XDG_RUNTIME_DIR".to_owned(),
        options.runtime_dir.display().to_string(),
    )]
}

/// Inspects the named container. `Ok(None)` means Podman reports no such container.
pub fn inspect(
    runner: &impl CommandRunner,
    options: &ServiceOptions,
    service: &str,
) -> Result<Option<ContainerState>, ServiceError> {
    let args = inspect::container_args(service);
    let output = runner
        .run(&options.podman, &args, &env(options))
        .map_err(|source| ServiceError::Io {
            args: args.join(" "),
            source,
        })?;
    if !output.success {
        if inspect::is_absent(&output.stderr) {
            return Ok(None);
        }
        return Err(ServiceError::Podman {
            args: args.join(" "),
            message: output.stderr,
        });
    }
    Ok(
        inspect::parse_inspect(&output.stdout).map(|container| ContainerState {
            id: container.id,
            epoch: container.epoch,
            running: container.running,
        }),
    )
}

/// Sleeps for the next backoff step after one more consecutive failure.
fn back_off(clock: &impl Clock, options: &ServiceOptions, failures: &mut u32) {
    *failures = failures.saturating_add(1);
    clock.sleep(backoff_delay(
        *failures,
        options.backoff_base,
        options.backoff_cap,
    ));
}

/// Settles the budget after a container run of `ran`; a stable run also ends the backoff.
/// Returns whether the run was stable.
fn note_run(options: &ServiceOptions, epoch: u64, ran: Duration, failures: &mut u32) -> bool {
    if !run_was_stable(ran, options.stable_after) {
        return false;
    }
    match note_service_run(&options.host_dir, epoch, ran, options.stable_after) {
        Ok(_) => log_line(&format!(
            "the daemon container ran for {}s; the attempt budget for epoch {epoch} is reset",
            ran.as_secs()
        )),
        Err(error) => log_line(&format!("cannot reset the attempt budget: {error}")),
    }
    *failures = 0;
    true
}

/// Runs the foreground service loop until the process is stopped by the init system, or fails
/// when the service selection is missing so the supervisor restarts the launcher.
pub fn run_service(
    runner: &impl CommandRunner,
    clock: &impl Clock,
    options: &ServiceOptions,
) -> Result<(), ServiceError> {
    // Consecutive failures since the last stable run; they drive the backoff.
    let mut failures = 0u32;
    loop {
        let selection = match PlatformService::load(&options.host_dir) {
            Ok(Some(selection)) => selection,
            Ok(None) => return Err(no_selection(options)),
            Err(error) => {
                log_line(&format!("cannot read the service selection: {error}"));
                back_off(clock, options, &mut failures);
                continue;
            }
        };
        let observed = match inspect(runner, options, &selection.service) {
            Ok(observed) => observed,
            Err(error) => {
                // A missing socket at boot must not kill the supervised service.
                log_line(&format!("cannot observe the daemon container: {error}"));
                back_off(clock, options, &mut failures);
                continue;
            }
        };
        let attempts = crate::budget::ServiceAttempts::load(&options.host_dir, selection.epoch)
            .map(|state| state.blocked)
            .unwrap_or(false);
        match plan_step(&selection, observed.as_ref(), attempts) {
            Step::Wait { id } => {
                let started = clock.now();
                let waited =
                    runner.status(&options.podman, &["wait".to_owned(), id], &env(options));
                if waited.is_ok_and(|status| status.success()) {
                    let ran = clock.now().saturating_sub(started);
                    note_run(options, selection.epoch, ran, &mut failures);
                } else {
                    // A failing `podman wait` returns at once; do not spin on it.
                    back_off(clock, options, &mut failures);
                }
            }
            Step::Start { id } => {
                match note_service_attempt(&options.host_dir, selection.epoch, options.max_attempts)
                {
                    Ok(attempt) => {
                        log_line(&format!(
                            "starting the existing daemon container (attempt {})",
                            attempt.number
                        ));
                        let started = clock.now();
                        let _ = runner.status(
                            &options.podman,
                            &["start".to_owned(), "-a".to_owned(), id],
                            &env(options),
                        );
                        let ran = clock.now().saturating_sub(started);
                        if !note_run(options, selection.epoch, ran, &mut failures) {
                            back_off(clock, options, &mut failures);
                        }
                    }
                    Err(_) => {
                        block_and_wait(clock, options, selection.epoch)?;
                        failures = 0;
                    }
                }
            }
            Step::Create => match create_and_start(runner, clock, options, &selection) {
                Ok(Some(ran)) => {
                    if !note_run(options, selection.epoch, ran, &mut failures) {
                        back_off(clock, options, &mut failures);
                    }
                }
                // Superseded by a newer selection, or unblocked by one: begin afresh.
                Ok(None) => failures = 0,
                Err(error @ ServiceError::NoSelection { .. }) => return Err(error),
                Err(error) => {
                    log_line(&format!("cannot create the daemon container: {error}"));
                    back_off(clock, options, &mut failures);
                }
            },
            Step::RemoveAndCreate { id } => {
                let removed = runner.run(
                    &options.podman,
                    &["rm".to_owned(), "-f".to_owned(), id],
                    &env(options),
                );
                if !removed.is_ok_and(|output| output.success) {
                    back_off(clock, options, &mut failures);
                }
            }
            Step::Blocked { epoch } => {
                block_and_wait(clock, options, epoch)?;
                failures = 0;
            }
        }
    }
}

/// Creates the container for `selection` and runs it attached. `Some(ran)` is how long it ran;
/// `None` means it was not started: the selection changed during the create, or the budget ran out
/// and a new selection arrived.
fn create_and_start(
    runner: &impl CommandRunner,
    clock: &impl Clock,
    options: &ServiceOptions,
    selection: &PlatformService,
) -> Result<Option<Duration>, ServiceError> {
    match note_service_attempt(&options.host_dir, selection.epoch, options.max_attempts) {
        Ok(_) => {}
        Err(BudgetError::Exhausted(_)) => {
            block_and_wait(clock, options, selection.epoch)?;
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    }
    let args = {
        let mut args = vec!["create".to_owned(), "--replace".to_owned()];
        args.extend(selection.argv.iter().cloned());
        args
    };
    let created = runner
        .run(&options.podman, &args, &env(options))
        .map_err(|source| ServiceError::Io {
            args: args.join(" "),
            source,
        })?;
    if !created.success {
        return Err(ServiceError::Podman {
            args: args.join(" "),
            message: created.stderr,
        });
    }
    let id = created.stdout.lines().last().unwrap_or_default().trim();
    if id.is_empty() {
        return Err(ServiceError::Podman {
            args: args.join(" "),
            message: "podman create printed no container id".into(),
        });
    }
    // Re-read after create under the service-selection lock: a selection change during a slow pull
    // must not start the old digest.
    let after = PlatformService::read_locked(&options.host_dir)?;
    let same = after
        .as_ref()
        .is_some_and(|after| after.epoch == selection.epoch && after.digest == selection.digest);
    if !same {
        let _ = runner.run(
            &options.podman,
            &["rm".to_owned(), "-f".to_owned(), id.to_owned()],
            &env(options),
        );
        return Ok(None);
    }
    let started = clock.now();
    let _ = runner.status(
        &options.podman,
        &["start".to_owned(), "-a".to_owned(), id.to_owned()],
        &env(options),
    );
    Ok(Some(clock.now().saturating_sub(started)))
}

/// Marks `epoch` blocked and waits until the selection changes to another epoch. Fails when the
/// selection disappears meanwhile.
fn block_and_wait(
    clock: &impl Clock,
    options: &ServiceOptions,
    epoch: u64,
) -> Result<(), ServiceError> {
    let _ = block_service_epoch(&options.host_dir, epoch);
    log_line(&format!(
        "attempt budget for epoch {epoch} exhausted; waiting for a new selection"
    ));
    loop {
        match PlatformService::load(&options.host_dir) {
            Ok(Some(selection)) if selection.epoch != epoch => return Ok(()),
            Ok(None) => return Err(no_selection(options)),
            _ => clock.sleep(options.poll),
        }
    }
}

fn no_selection(options: &ServiceOptions) -> ServiceError {
    let error = ServiceError::NoSelection {
        path: PlatformService::path(&options.host_dir),
    };
    log_line(&error.to_string());
    error
}

fn log_line(message: &str) {
    eprintln!("weglarka-launcher: {message}");
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::budget::ServiceAttempts;
    use crate::selection::{LABEL_ACTIVATION_EPOCH, LABEL_DAEMON_DIGEST};
    use weglarka_model::release_set::StrictDigest;

    fn digest(byte: char) -> StrictDigest {
        StrictDigest::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn selection(epoch: u64) -> PlatformService {
        let d = digest('a');
        let image = format!("ghcr.io/example/weglarka@{d}");
        let argv = vec![
            "--name".to_owned(),
            "weglarka".to_owned(),
            "--label".to_owned(),
            format!("{LABEL_ACTIVATION_EPOCH}={epoch}"),
            "--label".to_owned(),
            format!("{LABEL_DAEMON_DIGEST}={d}"),
            image.clone(),
        ];
        PlatformService::build("weglarka", image, d, epoch, argv).unwrap()
    }

    #[test]
    fn the_plan_only_stops_containers_of_the_same_epoch() {
        let selection = selection(4);
        let same = ContainerState {
            id: "abc".into(),
            epoch: Some(4),
            running: true,
        };
        assert_eq!(
            plan_step(&selection, Some(&same), false),
            Step::Wait { id: "abc".into() }
        );
        let stopped = ContainerState {
            running: false,
            ..same.clone()
        };
        assert_eq!(
            plan_step(&selection, Some(&stopped), false),
            Step::Start { id: "abc".into() }
        );
        let old = ContainerState {
            epoch: Some(3),
            ..same
        };
        assert_eq!(
            plan_step(&selection, Some(&old), false),
            Step::RemoveAndCreate { id: "abc".into() }
        );
        assert_eq!(plan_step(&selection, None, false), Step::Create);
        assert_eq!(
            plan_step(&selection, None, true),
            Step::Blocked { epoch: 4 }
        );
    }

    #[test]
    fn the_attempt_budget_is_exhausted_per_epoch() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(note_service_attempt(dir.path(), 1, 2).unwrap().number, 1);
        assert_eq!(note_service_attempt(dir.path(), 1, 2).unwrap().number, 2);
        assert!(note_service_attempt(dir.path(), 1, 2).is_err());
        assert_eq!(note_service_attempt(dir.path(), 2, 2).unwrap().number, 1);
    }

    struct ScriptedRunner {
        host: PathBuf,
        calls: std::sync::Mutex<Vec<String>>,
        change_on_create: bool,
    }

    impl CommandRunner for ScriptedRunner {
        fn run(
            &self,
            _program: &str,
            args: &[String],
            _env: &[(String, String)],
        ) -> io::Result<Output> {
            self.calls.lock().unwrap().push(args.join(" "));
            if args.first().map(String::as_str) == Some("create") && self.change_on_create {
                // Simulate a slow pull during which activation selected a newer epoch.
                selection(2).save(&self.host).unwrap();
            }
            Ok(Output {
                success: true,
                stdout: if args.first().map(String::as_str) == Some("create") {
                    "newid".to_owned()
                } else {
                    String::new()
                },
                stderr: String::new(),
            })
        }

        fn status(
            &self,
            _program: &str,
            args: &[String],
            _env: &[(String, String)],
        ) -> io::Result<std::process::ExitStatus> {
            self.calls.lock().unwrap().push(args.join(" "));
            std::process::Command::new("true").status()
        }
    }

    fn options(host: &Path, change_on_create: bool) -> (ServiceOptions, ScriptedRunner) {
        (
            ServiceOptions {
                host_dir: host.to_owned(),
                runtime_dir: PathBuf::from("/run/user/1001"),
                podman: "podman".to_owned(),
                poll: Duration::from_millis(10),
                max_attempts: 3,
                stable_after: Duration::from_secs(600),
                backoff_base: Duration::from_secs(2),
                backoff_cap: Duration::from_secs(60),
            },
            ScriptedRunner {
                host: host.to_owned(),
                calls: std::sync::Mutex::new(Vec::new()),
                change_on_create,
            },
        )
    }

    #[test]
    fn a_slow_create_never_starts_the_previous_digest() {
        let dir = tempfile::tempdir().unwrap();
        let host = dir.path().join("host");
        std::fs::create_dir_all(&host).unwrap();
        selection(1).save(&host).unwrap();
        let (options, runner) = options(&host, true);
        create_and_start(&runner, &SystemClock::new(), &options, &selection(1)).unwrap();
        let calls = runner.calls.lock().unwrap().clone();
        assert!(calls.iter().any(|c| c.starts_with("create")));
        assert!(calls.iter().any(|c| c == "rm -f newid"), "{calls:?}");
        assert!(
            !calls.iter().any(|c| c.starts_with("start")),
            "the old digest must not start: {calls:?}"
        );
    }

    #[test]
    fn a_stable_selection_starts_the_created_container() {
        let dir = tempfile::tempdir().unwrap();
        let host = dir.path().join("host");
        std::fs::create_dir_all(&host).unwrap();
        selection(1).save(&host).unwrap();
        let (options, runner) = options(&host, false);
        create_and_start(&runner, &SystemClock::new(), &options, &selection(1)).unwrap();
        let calls = runner.calls.lock().unwrap().clone();
        assert!(calls.iter().any(|c| c == "start -a newid"), "{calls:?}");
    }

    #[test]
    fn blocked_exhaustion_returns_when_a_new_selection_arrives() {
        let dir = tempfile::tempdir().unwrap();
        let host = dir.path().join("host");
        std::fs::create_dir_all(&host).unwrap();
        selection(1).save(&host).unwrap();
        let (options, _runner) = options(&host, false);
        let writer = host.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            selection(2).save(&writer).unwrap();
        });
        block_and_wait(&SystemClock::new(), &options, 1).unwrap();
        assert_eq!(PlatformService::load(&host).unwrap().unwrap().epoch, 2);
    }

    #[test]
    fn a_vanished_selection_ends_the_wait_for_a_new_one() {
        let dir = tempfile::tempdir().unwrap();
        let host = dir.path().join("host");
        std::fs::create_dir_all(&host).unwrap();
        selection(1).save(&host).unwrap();
        let (options, _runner) = options(&host, false);
        let clock = FakeClock::default();
        std::fs::remove_file(PlatformService::path(&host)).unwrap();
        let error = block_and_wait(&clock, &options, 1).unwrap_err();
        assert!(matches!(error, ServiceError::NoSelection { .. }), "{error}");
    }

    /// A clock that only moves when told to: `sleep` records the delay and advances it.
    #[derive(Default)]
    struct FakeClock {
        now: std::cell::Cell<Duration>,
        sleeps: std::cell::RefCell<Vec<Duration>>,
    }

    impl FakeClock {
        fn advance(&self, by: Duration) {
            self.now.set(self.now.get() + by);
        }

        fn sleeps(&self) -> Vec<u64> {
            self.sleeps.borrow().iter().map(Duration::as_secs).collect()
        }
    }

    impl Clock for FakeClock {
        fn now(&self) -> Duration {
            self.now.get()
        }

        fn sleep(&self, duration: Duration) {
            assert!(
                self.sleeps.borrow().len() < 100,
                "the loop is not terminating"
            );
            self.sleeps.borrow_mut().push(duration);
            self.advance(duration);
        }
    }

    /// Reports a stopped container of epoch 1 and "runs" it for a scripted time per start (the
    /// last entry repeats). After `starts` runs it deletes the selection, which ends the loop.
    struct CrashingRunner<'a> {
        host: PathBuf,
        clock: &'a FakeClock,
        run_for: Vec<Duration>,
        starts: std::cell::Cell<usize>,
        stop_after: usize,
    }

    impl CommandRunner for CrashingRunner<'_> {
        fn run(&self, _: &str, args: &[String], _: &[(String, String)]) -> io::Result<Output> {
            assert_eq!(
                args.first().map(String::as_str),
                Some("inspect"),
                "{args:?}"
            );
            Ok(Output {
                success: true,
                stdout: "abc|false|img|repo@sha256:aa|1".to_owned(),
                stderr: String::new(),
            })
        }

        fn status(
            &self,
            _: &str,
            args: &[String],
            _: &[(String, String)],
        ) -> io::Result<ExitStatus> {
            assert_eq!(args.join(" "), "start -a abc");
            let n = self.starts.get();
            self.starts.set(n + 1);
            self.clock
                .advance(self.run_for[n.min(self.run_for.len() - 1)]);
            if n + 1 == self.stop_after {
                std::fs::remove_file(PlatformService::path(&self.host)).unwrap();
            }
            std::process::Command::new("true").status()
        }
    }

    /// Runs the loop against `CrashingRunner` until it loses its selection; returns the delays
    /// slept and the final budget.
    fn crash_loop(
        options: ServiceOptions,
        run_for: &[u64],
        stop_after: usize,
    ) -> (Vec<u64>, ServiceAttempts, usize) {
        let host = options.host_dir.clone();
        selection(1).save(&host).unwrap();
        let clock = FakeClock::default();
        let runner = CrashingRunner {
            host: host.clone(),
            clock: &clock,
            run_for: run_for.iter().copied().map(Duration::from_secs).collect(),
            starts: std::cell::Cell::new(0),
            stop_after,
        };
        let error = run_service(&runner, &clock, &options).unwrap_err();
        assert!(matches!(error, ServiceError::NoSelection { .. }), "{error}");
        (
            clock.sleeps(),
            ServiceAttempts::load(&host, 1).unwrap(),
            runner.starts.get(),
        )
    }

    fn host_dir() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let host = dir.path().join("host");
        std::fs::create_dir_all(&host).unwrap();
        (dir, host)
    }

    #[test]
    fn long_runs_never_exhaust_the_budget() {
        // The reboot case: the daemon runs for hours, the host restarts, and the runner starts the
        // stopped container again. Five such runs against a budget of three.
        let (_dir, host) = host_dir();
        let (options, _) = options(&host, false);
        let (sleeps, budget, starts) = crash_loop(options, &[3600], 5);
        assert_eq!(starts, 5);
        assert!(sleeps.is_empty(), "stable runs need no backoff: {sleeps:?}");
        assert!(!budget.blocked);
        assert_eq!(budget.attempts, 0);
    }

    #[test]
    fn short_runs_back_off_exponentially_up_to_the_cap() {
        let (_dir, host) = host_dir();
        let (mut options, _) = options(&host, false);
        options.max_attempts = 5;
        options.backoff_cap = Duration::from_secs(8);
        let (sleeps, budget, starts) = crash_loop(options, &[1], 5);
        assert_eq!(starts, 5);
        assert_eq!(sleeps, [2, 4, 8, 8, 8]);
        assert_eq!(budget.attempts, 5);
    }

    #[test]
    fn a_stable_run_in_the_middle_restarts_the_backoff_and_the_count() {
        let (_dir, host) = host_dir();
        let (mut options, _) = options(&host, false);
        options.max_attempts = 3;
        let (sleeps, budget, starts) = crash_loop(options, &[1, 1, 601, 1], 4);
        assert_eq!(starts, 4);
        assert_eq!(sleeps, [2, 4, 2]);
        assert_eq!(budget.attempts, 1);
    }

    #[test]
    fn a_run_of_exactly_the_threshold_is_still_a_failure() {
        let (_dir, host) = host_dir();
        let (options, _) = options(&host, false);
        let (sleeps, budget, _) = crash_loop(options, &[600], 2);
        assert_eq!(sleeps, [2, 4]);
        assert_eq!(budget.attempts, 2);
    }

    #[test]
    fn no_selection_at_start_fails_instead_of_waiting() {
        let (_dir, host) = host_dir();
        let (options, runner) = options(&host, false);
        let clock = FakeClock::default();
        let error = run_service(&runner, &clock, &options).unwrap_err();
        assert!(matches!(error, ServiceError::NoSelection { .. }), "{error}");
        assert!(clock.sleeps().is_empty());
        assert!(runner.calls.lock().unwrap().is_empty());
    }

    /// Answers every call with one fixed outcome.
    struct FixedRunner(Output);

    impl CommandRunner for FixedRunner {
        fn run(&self, _: &str, _: &[String], _: &[(String, String)]) -> io::Result<Output> {
            Ok(self.0.clone())
        }

        fn status(&self, _: &str, _: &[String], _: &[(String, String)]) -> io::Result<ExitStatus> {
            unreachable!("inspect never runs with inherited stdio")
        }
    }

    fn failed(stderr: &str) -> FixedRunner {
        FixedRunner(Output {
            success: false,
            stdout: String::new(),
            stderr: stderr.to_owned(),
        })
    }

    #[test]
    fn inspect_reads_the_container_state() {
        let (options, _) = options(Path::new("/unused"), false);
        let runner = FixedRunner(Output {
            success: true,
            stdout: "abc|true|img|repo@sha256:aa|4".to_owned(),
            stderr: String::new(),
        });
        assert_eq!(
            inspect(&runner, &options, "weglarka").unwrap(),
            Some(ContainerState {
                id: "abc".into(),
                epoch: Some(4),
                running: true,
            })
        );
    }

    #[test]
    fn inspect_treats_a_missing_container_as_absent() {
        let (options, _) = options(Path::new("/unused"), false);
        let runner = failed("Error: no such container weglarka");
        assert_eq!(inspect(&runner, &options, "weglarka").unwrap(), None);
    }

    #[test]
    fn inspect_ignores_warnings_before_a_missing_container() {
        let (options, _) = options(Path::new("/unused"), false);
        let runner = failed(
            "level=warning msg=\"Failed to add pause process to systemd sandbox cgroup: dial unix \
         /run/user/1001/bus: connect: no such file or directory\"\nError: no such container \
         weglarka",
        );
        assert_eq!(inspect(&runner, &options, "weglarka").unwrap(), None);
    }

    #[test]
    fn inspect_reports_an_unreachable_socket_as_an_error() {
        let (options, _) = options(Path::new("/unused"), false);
        let runner = failed(
            "Cannot connect to Podman. Please verify your connection to the Linux system using \
         `podman system connection list`, or try `podman machine init` and `podman machine \
         start` to manage a new Linux VM\nError: unable to connect to Podman socket: failed to \
         connect: dial unix /run/user/1001/podman/podman.sock: connect: no such file or \
         directory: unix:///run/user/1001/podman/podman.sock",
        );
        let error = inspect(&runner, &options, "weglarka").unwrap_err();
        assert!(matches!(error, ServiceError::Podman { .. }), "{error}");
    }
}
