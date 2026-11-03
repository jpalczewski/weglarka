//! Role execution: fixed argument vectors executed directly, never through a shell.
//!
//! The launcher only ever executes a verified host tool from a generation directory. It observes
//! spawn errors and enforces a bounded worker timeout; on timeout it kills the child and reports a
//! failure. Nothing here sources a state file or evaluates configuration as shell text.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::generation::Generation;
use crate::host::{HOST_CLI_FILE, HOST_DAEMON_FILE, HostError, shared_state_dir};

/// The fixed launcher roles from the v1 contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Update,
    Supervise,
    Cli,
    DaemonService,
    Recover,
    Preflight,
}

impl Role {
    pub const fn as_str(self) -> &'static str {
        match self {
            Role::Update => "update",
            Role::Supervise => "supervise",
            Role::Cli => "cli",
            Role::DaemonService => "daemon-service",
            Role::Recover => "recover",
            Role::Preflight => "preflight",
        }
    }
}

/// Which selector field a role or a preflight resolves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenerationChoice {
    Active,
    Previous,
    Candidate,
}

impl GenerationChoice {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Previous => "previous",
            Self::Candidate => "candidate",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "previous" => Some(Self::Previous),
            "candidate" => Some(Self::Candidate),
            _ => None,
        }
    }
}

/// An argument vector to execute directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecPlan {
    pub program: PathBuf,
    pub args: Vec<String>,
}

impl ExecPlan {
    pub fn new(program: impl Into<PathBuf>, args: Vec<String>) -> Self {
        Self {
            program: program.into(),
            args,
        }
    }
}

/// The daemon subcommand the launcher's `update` role runs. The coordinator may replace the body
/// behind this fixed name; the launcher never changes the role's argv shape.
pub const UPDATE_SUBCOMMAND: &str = "self-update";
/// The daemon subcommand for the watchdog.
pub const SUPERVISE_SUBCOMMAND: &str = "supervise";
/// The bounded recovery subcommand (brief D owns its decision machine).
pub const RECOVER_SUBCOMMAND: &str = "recover-v1";
/// The read-only preflight subcommand every generation implements.
pub const PREFLIGHT_SUBCOMMAND: &str = "host-preflight";

pub fn plan_update(generation: &Generation, config: &Path) -> Result<ExecPlan, RunError> {
    plan_daemon(generation, config, UPDATE_SUBCOMMAND)
}

pub fn plan_supervise(generation: &Generation, config: &Path) -> Result<ExecPlan, RunError> {
    plan_daemon(generation, config, SUPERVISE_SUBCOMMAND)
}

pub fn plan_recover(generation: &Generation, config: &Path) -> Result<ExecPlan, RunError> {
    plan_daemon(generation, config, RECOVER_SUBCOMMAND)
}

pub fn plan_preflight(generation: &Generation, config: &Path) -> Result<ExecPlan, RunError> {
    plan_daemon(generation, config, PREFLIGHT_SUBCOMMAND)
}

fn plan_daemon(
    generation: &Generation,
    config: &Path,
    subcommand: &str,
) -> Result<ExecPlan, RunError> {
    let program = generation
        .binary(HOST_DAEMON_FILE)
        .map_err(RunError::Generation)?;
    Ok(ExecPlan::new(
        program,
        vec![
            "--config".to_owned(),
            config.display().to_string(),
            subcommand.to_owned(),
        ],
    ))
}

/// `cli` passes through to the selected CLI directly; no shell and no implicit arguments.
pub fn plan_cli(generation: &Generation, args: Vec<String>) -> Result<ExecPlan, RunError> {
    let program = generation
        .binary(HOST_CLI_FILE)
        .map_err(RunError::Generation)?;
    Ok(ExecPlan::new(program, args))
}

#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error(transparent)]
    Generation(#[from] crate::generation::GenerationError),
    #[error("cannot execute {program}: {source}")]
    Spawn {
        program: PathBuf,
        source: std::io::Error,
    },
    #[error("worker {program} exceeded its {timeout:?} timeout and was killed")]
    Timeout { program: PathBuf, timeout: Duration },
    #[error("worker {program} ended without an exit code (signal)")]
    Signalled { program: PathBuf },
    #[error("worker {program} failed with exit code {code}")]
    Failed { program: PathBuf, code: i32 },
}

/// Runs a plan to completion. `None` means no timeout (the daemon-service role manages its own
/// lifetime); a value is the bounded worker timeout.
pub fn run_plan(plan: &ExecPlan, timeout: Option<Duration>) -> Result<(), RunError> {
    let mut command = Command::new(&plan.program);
    command
        .args(&plan.args)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let mut child = command.spawn().map_err(|source| RunError::Spawn {
        program: plan.program.clone(),
        source,
    })?;

    let deadline = timeout.map(|timeout| (Instant::now() + timeout, timeout));
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return match status.code() {
                    Some(0) => Ok(()),
                    Some(code) => Err(RunError::Failed {
                        program: plan.program.clone(),
                        code,
                    }),
                    None => Err(RunError::Signalled {
                        program: plan.program.clone(),
                    }),
                };
            }
            Ok(None) => {}
            Err(source) => {
                return Err(RunError::Spawn {
                    program: plan.program.clone(),
                    source,
                });
            }
        }
        if let Some((deadline, timeout)) = deadline
            && Instant::now() >= deadline
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err(RunError::Timeout {
                program: plan.program.clone(),
                timeout,
            });
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Runs `weglarka-daemon host-preflight` for one verified generation.
pub fn run_preflight(
    generation: &Generation,
    config: &Path,
    timeout: Duration,
) -> Result<(), RunError> {
    run_plan(&plan_preflight(generation, config)?, Some(timeout))
}

/// Reads the shared state directory from the current host configuration (read-only; the launcher
/// never parses `apps.toml`).
pub fn state_dir_for_config(config: &Path) -> Result<PathBuf, HostError> {
    shared_state_dir(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    use weglarka_model::release_set::StrictDigest;

    fn make_generation(dir: &Path, script: &str) -> Generation {
        use sha2::{Digest as _, Sha256};
        let generation_digest = StrictDigest::new(format!(
            "sha256:{}",
            hex::encode(Sha256::digest(script.as_bytes()))
        ))
        .unwrap();
        let store = crate::generation::GenerationStore::new(dir);
        let staging = store.staging_dir().unwrap();
        for name in [HOST_DAEMON_FILE, HOST_CLI_FILE] {
            let path = staging.join(name);
            std::fs::write(&path, script).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let digest = |bytes: &[u8]| {
            StrictDigest::new(format!("sha256:{}", hex::encode(Sha256::digest(bytes)))).unwrap()
        };
        let expected = [
            crate::generation::ExpectedFile::new(
                HOST_DAEMON_FILE,
                script.len() as u64,
                digest(script.as_bytes()),
            ),
            crate::generation::ExpectedFile::new(
                HOST_CLI_FILE,
                script.len() as u64,
                digest(script.as_bytes()),
            ),
        ];
        store
            .install(&staging, &generation_digest, &expected)
            .unwrap()
    }

    #[test]
    fn a_zero_exit_is_success_and_a_failure_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let generation = make_generation(dir.path(), "#!/bin/sh\nexit 0\n");
        run_plan(
            &plan_daemon(
                &generation,
                Path::new("/etc/weglarka/weglarka.toml"),
                "self-update",
            )
            .unwrap(),
            Some(Duration::from_secs(5)),
        )
        .unwrap();

        let generation = make_generation(dir.path(), "#!/bin/sh\nexit 7\n");
        assert!(matches!(
            run_plan(
                &plan_daemon(
                    &generation,
                    Path::new("/etc/weglarka/weglarka.toml"),
                    "self-update"
                )
                .unwrap(),
                Some(Duration::from_secs(5))
            ),
            Err(RunError::Failed { code: 7, .. })
        ));
    }

    #[test]
    fn the_parent_survives_a_child_that_hangs_by_killing_it_at_the_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let generation = make_generation(dir.path(), "#!/bin/sh\nsleep 30\n");
        let started = Instant::now();
        assert!(matches!(
            run_plan(
                &plan_daemon(
                    &generation,
                    Path::new("/etc/weglarka/weglarka.toml"),
                    "self-update"
                )
                .unwrap(),
                Some(Duration::from_millis(150))
            ),
            Err(RunError::Timeout { .. })
        ));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn an_exec_error_is_reported_not_swallowed() {
        let dir = tempfile::tempdir().unwrap();
        let generation = make_generation(dir.path(), "#!/bin/sh\nexit 0\n");
        let mut plan =
            plan_preflight(&generation, Path::new("/etc/weglarka/weglarka.toml")).unwrap();
        plan.program = dir.path().join("missing");
        assert!(matches!(
            run_plan(&plan, Some(Duration::from_secs(1))),
            Err(RunError::Spawn { .. })
        ));
    }

    #[test]
    fn cli_arguments_are_passed_through_without_a_shell() {
        let dir = tempfile::tempdir().unwrap();
        let generation = make_generation(dir.path(), "#!/bin/sh\nexit 0\n");
        let plan = plan_cli(&generation, vec!["apps".into(), "show;id".into()]).unwrap();
        assert_eq!(plan.args, vec!["apps".to_string(), "show;id".to_string()]);
        assert_eq!(plan.program, generation.binary(HOST_CLI_FILE).unwrap());
    }
}
