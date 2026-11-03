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
//! the service permanently inactive.

use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::time::Duration;

use crate::budget::{BudgetError, block_service_epoch, note_service_attempt};
use crate::host::HOST_DAEMON_FILE;
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
    /// How long to wait before retrying a missing socket or an unchanged selection.
    pub poll: Duration,
    pub max_attempts: u32,
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
    let args = vec![
        "inspect".to_owned(),
        "--type".to_owned(),
        "container".to_owned(),
        "--format".to_owned(),
        "{{.Id}}|{{.State.Running}}|{{index .Config.Labels \"io.weglarka.activation-epoch\"}}"
            .to_owned(),
        service.to_owned(),
    ];
    let output = runner
        .run(&options.podman, &args, &env(options))
        .map_err(|source| ServiceError::Io {
            args: args.join(" "),
            source,
        })?;
    if !output.success {
        let stderr = output.stderr.to_ascii_lowercase();
        if stderr.contains("no such") || stderr.contains("not found") {
            return Ok(None);
        }
        return Err(ServiceError::Podman {
            args: args.join(" "),
            message: output.stderr,
        });
    }
    let mut parts = output.stdout.split('|');
    let id = parts.next().unwrap_or_default().trim();
    if id.is_empty() {
        return Ok(None);
    }
    let running = parts.next().unwrap_or_default().trim() == "true";
    let epoch = parts.next().unwrap_or_default().trim().parse::<u64>().ok();
    Ok(Some(ContainerState {
        id: id.to_owned(),
        epoch,
        running,
    }))
}

/// Runs the foreground service loop until the process is stopped by the init system.
pub fn run_service(
    runner: &impl CommandRunner,
    options: &ServiceOptions,
) -> Result<(), ServiceError> {
    loop {
        let selection = match PlatformService::load(&options.host_dir) {
            Ok(Some(selection)) => selection,
            Ok(None) => {
                // No selection yet: the service stays alive for the adapter to fill it in.
                std::thread::sleep(options.poll);
                continue;
            }
            Err(error) => {
                log_line(&format!("cannot read the service selection: {error}"));
                std::thread::sleep(options.poll);
                continue;
            }
        };
        let observed = match inspect(runner, options, &selection.service) {
            Ok(observed) => observed,
            Err(error) => {
                // A missing socket at boot must not kill the supervised service.
                log_line(&format!("cannot observe the daemon container: {error}"));
                std::thread::sleep(options.poll);
                continue;
            }
        };
        let attempts = crate::budget::ServiceAttempts::load(&options.host_dir, selection.epoch)
            .map(|state| state.blocked)
            .unwrap_or(false);
        match plan_step(&selection, observed.as_ref(), attempts) {
            Step::Wait { id } => {
                let _ = runner.status(&options.podman, &["wait".to_owned(), id], &env(options));
            }
            Step::Start { id } => {
                match note_service_attempt(&options.host_dir, selection.epoch, options.max_attempts)
                {
                    Ok(attempt) => {
                        log_line(&format!(
                            "starting the existing daemon container (attempt {})",
                            attempt.number
                        ));
                        let _ = runner.status(
                            &options.podman,
                            &["start".to_owned(), "-a".to_owned(), id],
                            &env(options),
                        );
                    }
                    Err(_) => block_and_wait(options, selection.epoch),
                }
            }
            Step::Create => match create_and_start(runner, options, &selection) {
                Ok(()) => {}
                Err(error) => {
                    log_line(&format!("cannot create the daemon container: {error}"));
                    std::thread::sleep(options.poll);
                }
            },
            Step::RemoveAndCreate { id } => {
                let _ = runner.run(
                    &options.podman,
                    &["rm".to_owned(), "-f".to_owned(), id],
                    &env(options),
                );
            }
            Step::Blocked { epoch } => block_and_wait(options, epoch),
        }
    }
}

fn create_and_start(
    runner: &impl CommandRunner,
    options: &ServiceOptions,
    selection: &PlatformService,
) -> Result<(), ServiceError> {
    match note_service_attempt(&options.host_dir, selection.epoch, options.max_attempts) {
        Ok(_) => {}
        Err(BudgetError::Exhausted(_)) => {
            block_and_wait(options, selection.epoch);
            return Ok(());
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
        return Ok(());
    }
    let _ = runner.status(
        &options.podman,
        &["start".to_owned(), "-a".to_owned(), id.to_owned()],
        &env(options),
    );
    Ok(())
}

fn block_and_wait(options: &ServiceOptions, epoch: u64) {
    let _ = block_service_epoch(&options.host_dir, epoch);
    log_line(&format!(
        "attempt budget for epoch {epoch} exhausted; waiting for a new selection"
    ));
    loop {
        match PlatformService::load(&options.host_dir) {
            Ok(Some(selection)) if selection.epoch != epoch => return,
            _ => std::thread::sleep(options.poll),
        }
    }
}

fn log_line(message: &str) {
    eprintln!("weglarka-launcher: {message}");
}

/// Host tool name used in diagnostics (kept here so the module compiles alone).
pub const DAEMON_TOOL: &str = HOST_DAEMON_FILE;

/// Convenience for the adapter's argv: label pairs are always inserted before the image.
pub fn label_args(labels: &[(String, String)]) -> Vec<String> {
    let mut args = Vec::new();
    for (key, value) in labels {
        args.push("--label".to_owned());
        args.push(format!("{key}={value}"));
    }
    args
}

/// Blocking wait used by tests and by the adapter's bounded observation loop.
pub fn wait_for_path(path: &Path, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
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
        create_and_start(&runner, &options, &selection(1)).unwrap();
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
        create_and_start(&runner, &options, &selection(1)).unwrap();
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
        block_and_wait(&options, 1);
        assert_eq!(PlatformService::load(&host).unwrap().unwrap().epoch, 2);
    }

    #[test]
    fn labels_are_rendered_as_pairs() {
        assert_eq!(
            label_args(&[("a".into(), "b".into())]),
            vec!["--label".to_string(), "a=b".to_string()]
        );
    }
}
