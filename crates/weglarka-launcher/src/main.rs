//! `weglarka-launcher` — the fixed-role host launcher (host protocol v1).
//!
//! Roles and argv are fixed: `update`, `supervise`, `cli`, `daemon-service`, `recover`, `preflight`.
//! It accepts only an installation-configured host-only root, validates generation digests and
//! selectors, refuses unsupported protocol versions and executes argument vectors directly. It never
//! sources a state file or evaluates configuration as shell text.
//!
//! This binary is built for the static musl target and installed by `platform bootstrap`.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use weglarka_launcher::budget::note_recovery_attempt;
use weglarka_launcher::generation::{Generation, GenerationStore};
use weglarka_launcher::host::{HOST_PROTOCOL_VERSION, validate_host_dir};
use weglarka_launcher::run::{
    GenerationChoice, Role, exec_plan, plan_cli, plan_recover, plan_supervise, plan_update,
    run_plan,
};
use weglarka_launcher::selection::{Job, RuntimeJobs};
use weglarka_launcher::selector::HostSelector;
use weglarka_launcher::service::{ProcessRunner, ServiceOptions, SystemClock, run_service};

#[derive(Parser)]
#[command(
    name = "weglarka-launcher",
    version,
    about = "Węglarka host launcher (host protocol v1)"
)]
struct Cli {
    /// Installation-configured host-only directory (absolute, outside every daemon bind mount).
    #[arg(long, global = true, default_value = weglarka_launcher::host::DEFAULT_HOST_DIR)]
    host_dir: PathBuf,
    /// Host protocol this binary implements (informational; a mismatch is a version error).
    #[arg(long, global = true, default_value_t = HOST_PROTOCOL_VERSION)]
    host_protocol: u32,
    /// Host configuration file (used by update/supervise/recover/preflight and the state dir).
    #[arg(long, global = true, default_value = "/etc/weglarka/weglarka.toml")]
    config: PathBuf,
    #[command(subcommand)]
    role: RoleArg,
}

#[derive(Subcommand)]
enum RoleArg {
    /// Run the active generation's host updater.
    Update(WorkerArgs),
    /// Run the active generation's watchdog.
    Supervise(WorkerArgs),
    /// Run the active generation's CLI with the given arguments.
    Cli {
        /// Arguments passed to `weglarka` unchanged.
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// Run the daemon container in the foreground (OpenRC supervises this process).
    DaemonService {
        /// Rootless Podman runtime directory (`XDG_RUNTIME_DIR`).
        #[arg(long)]
        runtime_dir: Option<PathBuf>,
        /// Delay before retrying a missing socket or an unchanged selection.
        #[arg(long, default_value_t = 5)]
        poll_secs: u64,
        /// Bounded start attempts per activation epoch.
        #[arg(long, default_value_t = 5)]
        max_attempts: u32,
    },
    /// Run the recorded recovery generation in bounded `recover-v1` mode.
    Recover {
        /// Transaction the budget belongs to; a new transaction starts a fresh budget.
        #[arg(long)]
        transaction: Option<String>,
        /// Maximum recovery attempts for this transaction.
        #[arg(long, default_value_t = 3)]
        max_attempts: u32,
        #[arg(long, default_value_t = 600)]
        worker_timeout_secs: u64,
    },
    /// Run the read-only host preflight for one or all generations.
    Preflight {
        /// Generation to check: active (default), previous or candidate.
        #[arg(long, default_value = "active")]
        selector: String,
        /// Check the active, recovery and candidate generations (when present).
        #[arg(long)]
        all: bool,
        #[arg(long, default_value_t = 60)]
        timeout_secs: u64,
    },
}

#[derive(clap::Args)]
struct WorkerArgs {
    /// Bounded worker timeout enforced by the launcher's parent process.
    #[arg(long, default_value_t = 600)]
    worker_timeout_secs: u64,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.host_protocol != HOST_PROTOCOL_VERSION {
        bail!(
            "unsupported host protocol {}; this launcher implements {}",
            cli.host_protocol,
            HOST_PROTOCOL_VERSION
        );
    }
    let host_dir = validate_host_dir(&cli.host_dir).context("invalid --host-dir")?;
    match cli.role {
        RoleArg::Update(args) => run_worker(&host_dir, &cli.config, Role::Update, &args),
        RoleArg::Supervise(args) => run_worker(&host_dir, &cli.config, Role::Supervise, &args),
        RoleArg::Cli { args } => {
            let generation = resolve(&host_dir, GenerationChoice::Active, true)?;
            // Replace the launcher with the CLI: its exit code, stdin and TTY pass through.
            exec_plan(&plan_cli(&generation, args)?)?;
            Ok(())
        }
        RoleArg::DaemonService {
            runtime_dir,
            poll_secs,
            max_attempts,
        } => {
            let runtime_dir = match runtime_dir {
                Some(dir) => dir,
                None => std::env::var_os("XDG_RUNTIME_DIR")
                    .map(PathBuf::from)
                    .ok_or_else(|| {
                        anyhow::anyhow!("daemon-service needs --runtime-dir or XDG_RUNTIME_DIR")
                    })?,
            };
            if poll_secs == 0 || max_attempts == 0 {
                bail!("--poll-secs and --max-attempts must be positive");
            }
            run_service(
                &ProcessRunner,
                &SystemClock::new(),
                &ServiceOptions {
                    host_dir,
                    runtime_dir,
                    podman: "podman".to_owned(),
                    poll: Duration::from_secs(poll_secs),
                    max_attempts,
                },
            )?;
            Ok(())
        }
        RoleArg::Recover {
            transaction,
            max_attempts,
            worker_timeout_secs,
        } => {
            let generation = recovery_generation(&host_dir)?;
            let attempt = note_recovery_attempt(&host_dir, transaction.as_deref(), max_attempts)
                .map_err(|error| {
                    anyhow::anyhow!(
                        "{error}; BlockedRecovery stays recorded and the supervisor remains \
                             available for a new selection"
                    )
                })?;
            eprintln!(
                "weglarka-launcher: recovery attempt {} of at most {}",
                attempt.number, max_attempts
            );
            run_plan(
                &plan_recover(&generation, &cli.config)?,
                Some(Duration::from_secs(worker_timeout_secs)),
            )?;
            Ok(())
        }
        RoleArg::Preflight {
            selector,
            all,
            timeout_secs,
        } => {
            let timeout = Duration::from_secs(timeout_secs);
            let mut generations = Vec::new();
            if all {
                generations.push((
                    "active".to_owned(),
                    resolve(&host_dir, GenerationChoice::Active, false)?,
                ));
                let recovery = recovery_generation(&host_dir)?;
                if generations
                    .iter()
                    .all(|(_, g)| g.digest() != recovery.digest())
                {
                    generations.push(("recovery".to_owned(), recovery));
                }
                if let Some(candidate) = candidate_generation(&host_dir)? {
                    generations.push(("candidate".to_owned(), candidate));
                }
            } else {
                let choice = GenerationChoice::parse(&selector).ok_or_else(|| {
                    anyhow::anyhow!(
                        "unknown --selector {selector:?}; expected active, previous or candidate"
                    )
                })?;
                let generation = match choice {
                    GenerationChoice::Active => resolve(&host_dir, choice, false)?,
                    GenerationChoice::Previous => recovery_generation(&host_dir)?,
                    GenerationChoice::Candidate => {
                        candidate_generation(&host_dir)?.ok_or_else(|| {
                            anyhow::anyhow!(
                                "no candidate generation is recorded in host-tools.toml"
                            )
                        })?
                    }
                };
                generations.push((choice.as_str().to_owned(), generation));
            }
            let mut failed = Vec::new();
            for (label, generation) in &generations {
                eprintln!(
                    "weglarka-launcher: preflight {label} generation {}",
                    generation.digest()
                );
                if let Err(error) =
                    weglarka_launcher::run::run_preflight(generation, &cli.config, timeout)
                {
                    eprintln!("weglarka-launcher: preflight {label} failed: {error}");
                    failed.push((label.clone(), error.to_string()));
                }
            }
            if !failed.is_empty() {
                bail!("preflight failed for: {failed:?}");
            }
            Ok(())
        }
    }
}

fn run_worker(
    host_dir: &std::path::Path,
    config: &std::path::Path,
    role: Role,
    args: &WorkerArgs,
) -> Result<()> {
    let job = match role {
        Role::Update => Job::Update,
        Role::Supervise => Job::Watchdog,
        _ => unreachable!("only update and supervise are periodic jobs"),
    };
    let state_dir = weglarka_launcher::run::state_dir_for_config(config)
        .context("deriving the shared state directory")?;
    if !RuntimeJobs::load(&state_dir)
        .context("reading runtime-jobs.toml")?
        .enabled(job)
    {
        println!("{} job is disabled in runtime-jobs.toml", job.as_str());
        return Ok(());
    }
    // The update job always hashes the binaries it is about to run (and may replace); the watchdog
    // runs often enough that it trusts the root-owned verified-metadata record.
    let generation = match role {
        Role::Update => resolve(host_dir, GenerationChoice::Active, false)?,
        _ => resolve(host_dir, GenerationChoice::Active, true)?,
    };
    let plan = match role {
        Role::Update => plan_update(&generation, config)?,
        Role::Supervise => plan_supervise(&generation, config)?,
        _ => unreachable!(),
    };
    run_plan(&plan, Some(Duration::from_secs(args.worker_timeout_secs)))?;
    Ok(())
}

/// Opens the selected generation. `cached` skips the hash of binaries whose metadata matches the
/// record of their last full verification; only the hot paths (the CLI and the watchdog) ask for it.
fn resolve(
    host_dir: &std::path::Path,
    choice: GenerationChoice,
    cached: bool,
) -> Result<Generation> {
    let selector = HostSelector::load(host_dir).context("reading host-tools.toml")?;
    let digest = match choice {
        GenerationChoice::Active => selector.active.clone(),
        GenerationChoice::Previous => selector.recovery().clone(),
        GenerationChoice::Candidate => selector
            .candidate
            .clone()
            .ok_or_else(|| anyhow::anyhow!("no candidate generation is recorded"))?,
    };
    let store = GenerationStore::new(host_dir);
    let opened = if cached {
        store.open_cached(&digest)
    } else {
        store.open(&digest)
    };
    opened.with_context(|| format!("opening generation {digest}"))
}

fn recovery_generation(host_dir: &std::path::Path) -> Result<Generation> {
    resolve(host_dir, GenerationChoice::Previous, false)
}

fn candidate_generation(host_dir: &std::path::Path) -> Result<Option<Generation>> {
    let selector = HostSelector::load(host_dir).context("reading host-tools.toml")?;
    match selector.candidate {
        None => Ok(None),
        Some(digest) => Ok(Some(
            GenerationStore::new(host_dir)
                .open(&digest)
                .with_context(|| format!("opening candidate generation {digest}"))?,
        )),
    }
}
