//! Installer side of `platform bootstrap` and the reverse (downgrade).
//!
//! This is the privileged, one-time migration from the legacy host switcher to the generation
//! selector. It installs the stable launcher, stages the current verified tools as generation 0,
//! writes `host-tools.toml` and the shared `host-capabilities.toml`, retires the legacy
//! self-update/watchdog units and `self-update.toml`, and points the periodic jobs at the launcher's
//! fixed roles.
//!
//! The coordinator/journal decision machine, panel enrollment and the *runtime* handoff belong to
//! brief D; this module only supplies the installation mechanism and the completeness gate
//! (`weglarka_launcher::bootstrap::coordinated_updates_ready`).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use weglarka_engine::platform::{ActivationEpoch, JobId, Platform, PlatformError, ScheduledJob};
use weglarka_launcher::bootstrap::{PreflightOutcome, coordinated_updates_ready};
use weglarka_launcher::generation::{Generation, GenerationStore};
use weglarka_launcher::host::{
    BOOTSTRAP_MARKER, GENERATION_MANIFEST, GENERATIONS_DIR, HOST_DAEMON_FILE, LAUNCHER_FILE,
    generation_name, validate_host_dir,
};
use weglarka_launcher::lock;
use weglarka_launcher::selector::{BootstrapMarker, HostSelector, LegacyImport};
use weglarka_model::fsutil::write_atomic;
use weglarka_model::platform_update::{
    CAPABILITIES_FILE_NAME, CapabilityRecord, CoordinationFeature, FORMAT_VERSION as UPDATE_FORMAT,
    HOST_PROTOCOL_VERSION, PlatformUpdate,
};
use weglarka_model::release_set::StrictDigest;

use crate::openrc::PODMAN_SERVICE;
use crate::platform::{
    SELF_UPDATE_SERVICE, SELF_UPDATE_TIMER, WATCHDOG_SERVICE, WATCHDOG_TIMER,
    render_self_update_units, render_watchdog_units,
};
use crate::service::service_spec;
use crate::settings::Settings;

/// The legacy runner's lock file in the state directory.
const LEGACY_LOCK_FILE: &str = "self-update.lock";

/// Inputs of a bootstrap. `--host-dir` is the installation-configured host-only directory; all
/// paths are explicit because bootstrap runs before any selector exists.
#[derive(Debug, Clone)]
pub struct BootstrapOptions {
    pub host_dir: PathBuf,
    pub state_dir: PathBuf,
    pub config_path: PathBuf,
    pub runtime_user: String,
    pub runtime_uid: Option<u32>,
    pub runtime_gid: Option<u32>,
    /// Verified digest the current tools were extracted from (generation key).
    pub generation: StrictDigest,
    pub daemon_binary: PathBuf,
    pub cli_binary: PathBuf,
    pub launcher_binary: PathBuf,
    /// Pinned daemon image used for the legacy-compatible service spec.
    pub image: String,
    /// Optional channel pointer the gate checks. Brief D supplies the configured channel.
    pub channel: Option<weglarka_model::release_set::Channel>,
    /// Enable linger for the runtime user on systemd (root install step).
    pub enable_linger: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapReport {
    pub host_dir: PathBuf,
    pub generation: StrictDigest,
    pub selector_epoch: u64,
    /// False until a channel pointer exists (the contract's enabling predicate).
    pub coordinated_ready: bool,
    pub retired_units: Vec<String>,
    pub linger_enabled: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error(transparent)]
    Host(#[from] weglarka_launcher::host::HostError),
    #[error(transparent)]
    Generation(#[from] weglarka_launcher::generation::GenerationError),
    #[error(transparent)]
    Selector(#[from] weglarka_launcher::selector::SelectorError),
    #[error(transparent)]
    Platform(#[from] PlatformError),
    #[error(transparent)]
    Lock(#[from] weglarka_launcher::lock::LockError),
    #[error(
        "bootstrap cannot use {host} as the host-only directory while the shared state is {state}"
    )]
    Overlapping { host: PathBuf, state: PathBuf },
    #[error("cannot read/write {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid legacy state: {0}")]
    Legacy(String),
    #[error("preflight failed for the {0} generation: {1}")]
    Preflight(&'static str, String),
    #[error(
        "this host is already bootstrapped with generation {0}; use an explicit administrator install to change it"
    )]
    AlreadyBootstrapped(StrictDigest),
    #[error("a legacy runner still holds self-update.lock; stop it before bootstrapping")]
    LegacyRunnerActive,
    #[error("the bootstrap did not complete: {0}")]
    Incomplete(String),
}

/// One state-changing action of a bootstrap, in execution order. A step carries everything it needs,
/// so [`apply`] never has to look at the host to decide *whether* to act.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Create the host-only directory with mode 0700 (the ownership step opens it up later).
    CreateHostDir { path: PathBuf },
    /// Copy the stable launcher into the host-only directory.
    InstallLauncher { source: PathBuf },
    /// Enable lingering for the runtime user (systemd).
    EnableLinger { user: String },
    /// Stage the current tools as a verified generation.
    InstallGeneration {
        digest: StrictDigest,
        daemon: PathBuf,
        cli: PathBuf,
    },
    /// Disable and remove the legacy self-update/watchdog units and the legacy lock file.
    RetireLegacyUnits,
    /// Import `self-update.toml`, if it exists, into the host-only directory and retire the file. The
    /// file is read when this step runs (after the legacy timers are off), never from the plan.
    ImportLegacyState,
    /// Write the initial selector. Not planned when the host already carries one for this
    /// generation (the epoch is kept).
    WriteSelector { selector: HostSelector },
    /// Write the shared `host-capabilities.toml`.
    WriteCapabilities,
    /// Install the fixed launcher jobs.
    InstallJobs { jobs: Vec<ScheduledJob> },
    /// Install the daemon service pinned to the image.
    InstallService { image: String },
    /// OpenRC: write the service selection with the selector epoch.
    ActivateService,
    /// OpenRC: start the runtime user's Podman service and wait for its socket.
    StartRuntimeSocket { user: String },
    /// Hand the code to root and the flat state files to the runtime user.
    ApplyOwnership { uid: u32, gid: u32 },
    /// Run `host-preflight` of the active and recovery generation against the installed host.
    VerifyPreflight,
    /// Write the durable "bootstrap complete" marker.
    WriteMarker,
}

impl std::fmt::Display for Step {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CreateHostDir { path } => write!(f, "create host directory {}", path.display()),
            Self::InstallLauncher { source } => {
                write!(f, "install launcher from {}", source.display())
            }
            Self::EnableLinger { user } => write!(f, "enable linger for {user}"),
            Self::InstallGeneration {
                digest,
                daemon,
                cli,
            } => write!(
                f,
                "install generation {digest} (daemon {}, cli {})",
                daemon.display(),
                cli.display()
            ),
            Self::RetireLegacyUnits => {
                write!(f, "retire legacy self-update/watchdog units and lock")
            }
            Self::ImportLegacyState => {
                write!(
                    f,
                    "import legacy self-update state (if any) and retire the file"
                )
            }
            Self::WriteSelector { selector } => write!(
                f,
                "select generation {} (epoch {})",
                selector.active, selector.epoch
            ),
            Self::WriteCapabilities => write!(f, "write host capabilities"),
            Self::InstallJobs { jobs } => {
                let ids: Vec<&str> = jobs.iter().map(|job| job.id.as_str()).collect();
                write!(f, "install launcher jobs: {}", ids.join(", "))
            }
            Self::InstallService { image } => write!(f, "install service pinned to {image}"),
            Self::ActivateService => write!(f, "write the service selection"),
            Self::StartRuntimeSocket { user } => {
                write!(f, "start the Podman runtime service for {user}")
            }
            Self::ApplyOwnership { uid, gid } => {
                write!(f, "apply host directory ownership (uid {uid}, gid {gid})")
            }
            Self::VerifyPreflight => write!(f, "preflight the active and recovery generation"),
            Self::WriteMarker => write!(f, "write the bootstrap-complete marker"),
        }
    }
}

/// The ordered work of a bootstrap, produced by [`plan`] and executed by [`apply`].
pub struct BootstrapPlan {
    options: BootstrapOptions,
    host_dir: PathBuf,
    now: u64,
    service: weglarka_engine::platform::ServiceSpec,
    /// The selector the host ends up with: the existing one for the same generation, or a fresh one.
    selector: HostSelector,
    steps: Vec<Step>,
}

impl BootstrapPlan {
    pub fn steps(&self) -> &[Step] {
        &self.steps
    }
}

impl std::fmt::Display for BootstrapPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, step) in self.steps.iter().enumerate() {
            if index > 0 {
                writeln!(f)?;
            }
            write!(f, "{:>2}. {step}", index + 1)?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for BootstrapPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapPlan")
            .field("host_dir", &self.host_dir)
            .field("steps", &self.steps)
            .finish()
    }
}

/// Installs the launcher and generation 0, retires the legacy runner and provisions the fixed jobs.
pub async fn bootstrap<P: Platform>(
    platform: &P,
    options: &BootstrapOptions,
) -> Result<BootstrapReport, BootstrapError> {
    let plan = plan(platform, options).await?;
    apply(platform, &plan).await
}

/// Decides what a bootstrap would do: reads the host and runs every precondition and preflight, so
/// that an impossible bootstrap is refused before anything changes. Changes nothing that outlives the
/// call (a scratch directory next to the host directory is removed again).
///
/// The generation preflight runs against a verified scratch copy of the tools on systemd. On OpenRC
/// the preflight also checks the runtime prerequisites (rootless Podman socket, cron) that only the
/// apply step provisions, so there it still runs, unchanged, as the [`Step::VerifyPreflight`] step
/// after provisioning.
pub async fn plan<P: Platform>(
    platform: &P,
    options: &BootstrapOptions,
) -> Result<BootstrapPlan, BootstrapError> {
    let host_dir = validate_host_dir(&options.host_dir)?;
    if host_dir == options.state_dir
        || host_dir.starts_with(&options.state_dir)
        || options.state_dir.starts_with(&host_dir)
    {
        return Err(BootstrapError::Overlapping {
            host: host_dir,
            state: options.state_dir.clone(),
        });
    }
    let systemd = platform.kind() == weglarka_model::config::PlatformKind::Systemd;
    let now = unix_now();

    // Cheap refusals that only read the host come first.
    //
    // A host already bootstrapped with another generation is refused before anything is touched. The
    // same generation keeps its selector (and epoch).
    let existing = HostSelector::load_optional(&host_dir)?;
    let selector = match &existing {
        Some(existing) if existing.active == options.generation => existing.clone(),
        Some(existing) => return Err(BootstrapError::AlreadyBootstrapped(existing.active.clone())),
        None => HostSelector::fresh(options.generation.clone()),
    };

    // A legacy runner still holding the lock must be stopped; refusing is the safe answer.
    let legacy_lock = options.state_dir.join(LEGACY_LOCK_FILE);
    if lock::is_held(&legacy_lock)? {
        return Err(BootstrapError::LegacyRunnerActive);
    }
    // Only a check: the file is read again when it is imported, after the legacy timers are off.
    read_legacy_import(&options.state_dir, now)?;

    check_launcher(&options.launcher_binary)?;
    let scratch_generation = stage_scratch_generation(&host_dir, options)?;
    if systemd {
        run_preflight_on(
            &scratch_generation.generation,
            "active",
            &options.config_path,
        )?;
    }
    check_existing_generation(&host_dir, &scratch_generation.generation)?;

    let ownership = options.runtime_uid.zip(options.runtime_gid);
    let ownership_step = || ownership.map(|(uid, gid)| Step::ApplyOwnership { uid, gid });

    // The legacy-compatible service spec: the pinned image, and on OpenRC the selection file the
    // supervised launcher reads after boot.
    let settings = Settings::load(&options.config_path)
        .map_err(|e| BootstrapError::Incomplete(e.to_string()))?;
    let socket = platform
        .runtime_socket(&options.runtime_user)
        .await
        .unwrap_or_else(|_| {
            PathBuf::from(format!(
                "/run/user/{}/podman/podman.sock",
                options.runtime_user
            ))
        });
    let service = service_spec(&settings, socket, options.image.clone());

    let mut steps = vec![
        Step::CreateHostDir {
            path: host_dir.clone(),
        },
        Step::InstallLauncher {
            source: options.launcher_binary.clone(),
        },
    ];
    if options.enable_linger && systemd {
        steps.push(Step::EnableLinger {
            user: options.runtime_user.clone(),
        });
    }
    steps.extend([
        Step::InstallGeneration {
            digest: options.generation.clone(),
            daemon: options.daemon_binary.clone(),
            cli: options.cli_binary.clone(),
        },
        // Retire the legacy runner before any new timer can start.
        Step::RetireLegacyUnits,
    ]);
    steps.push(Step::ImportLegacyState);
    if existing.is_none() {
        steps.push(Step::WriteSelector {
            selector: selector.clone(),
        });
    }
    steps.extend([
        // Only features this build really implements are claimed; retention therefore stays
        // fail-closed until A/D extend the set.
        Step::WriteCapabilities,
        Step::InstallJobs {
            jobs: launcher_jobs(options),
        },
        Step::InstallService {
            image: options.image.clone(),
        },
    ]);
    if !systemd {
        steps.push(Step::ActivateService);
        steps.push(Step::StartRuntimeSocket {
            user: options.runtime_user.clone(),
        });
    }
    // Root executes the generation binaries below, so the code must already be root-owned and not
    // writable by the runtime user. (Applied again at the end for the state files written after this.)
    steps.extend(ownership_step());
    steps.push(Step::VerifyPreflight);
    steps.push(Step::WriteMarker);
    steps.extend(ownership_step());

    Ok(BootstrapPlan {
        options: options.clone(),
        host_dir,
        now,
        service,
        selector,
        steps,
    })
}

/// Executes a plan's steps in order.
pub async fn apply<P: Platform>(
    platform: &P,
    plan: &BootstrapPlan,
) -> Result<BootstrapReport, BootstrapError> {
    let options = &plan.options;
    let host_dir = &plan.host_dir;
    let store = GenerationStore::new(host_dir);
    let mut linger_enabled = false;
    let mut retired_units = Vec::new();
    let mut installed = None;
    let selector = &plan.selector;
    let mut preflight = PreflightOutcome {
        active: false,
        recovery: false,
    };

    for step in &plan.steps {
        match step {
            Step::CreateHostDir { path } => create_dir(path)?,
            Step::InstallLauncher { source } => install_launcher(host_dir, source)?,
            Step::EnableLinger { user } => linger_enabled = enable_linger(user),
            Step::InstallGeneration {
                digest,
                daemon,
                cli,
            } => {
                // Verify-and-reuse is idempotent.
                installed = Some(store.install_from_files(
                    digest,
                    &[
                        (HOST_DAEMON_FILE, daemon.clone()),
                        (weglarka_launcher::host::HOST_CLI_FILE, cli.clone()),
                    ],
                )?);
            }
            Step::RetireLegacyUnits => {
                retired_units = retire_legacy_units(platform, &options.state_dir).await?;
            }
            Step::ImportLegacyState => {
                import_legacy_state(host_dir, &options.state_dir, plan.now)?;
            }
            Step::WriteSelector { selector } => selector.save(host_dir)?,
            Step::WriteCapabilities => write_capabilities(&options.state_dir, &options.generation)?,
            Step::InstallJobs { jobs } => platform.install_jobs(jobs).await?,
            Step::InstallService { .. } => platform.install_service(&plan.service).await?,
            Step::ActivateService => {
                platform
                    .activate_service(plan.service.clone(), ActivationEpoch(selector.epoch))
                    .await?;
            }
            Step::StartRuntimeSocket { user } => {
                // The rootless API socket must exist for preflight; starting the installed service
                // is the installer's job, not the runtime user's.
                let _ = platform.restart_service(PODMAN_SERVICE).await;
                if let Ok(socket) = platform.runtime_socket(user).await {
                    for _ in 0..100 {
                        if socket.exists() {
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                }
            }
            Step::ApplyOwnership { uid, gid } => apply_ownership(host_dir, *uid, *gid)?,
            Step::VerifyPreflight => {
                // The active and recovery generation against the *current* configuration, now that
                // the OpenRC runtime prerequisites are provisioned.
                for (label, digest) in [
                    ("active", selector.active.clone()),
                    ("recovery", selector.recovery().clone()),
                ] {
                    let generation = store.open(&digest)?;
                    run_preflight_on(&generation, label, &options.config_path)?;
                    if label == "active" {
                        preflight.active = true;
                    } else {
                        preflight.recovery = true;
                    }
                }
            }
            Step::WriteMarker => {
                // The marker is the durable "bootstrap complete" signal. It is written only after
                // every installation step and both preflights passed.
                BootstrapMarker {
                    format_version: 1,
                    generation: selector.active.clone(),
                    selector_epoch: selector.epoch,
                    completed_at: plan.now,
                }
                .save(host_dir)?;
            }
        }
    }

    let generation = installed.ok_or_else(|| {
        BootstrapError::Incomplete("the plan did not install a generation".into())
    })?;
    // Whether coordinated updates may be enabled now. A missing channel pointer is not a bootstrap
    // failure: the installer completes and the coordinator enables updates later.
    let coordinated_ready = coordinated_updates_ready(
        host_dir,
        &options.state_dir,
        options.channel,
        preflight,
        !legacy_units_present(&options.state_dir),
    )
    .is_ok();

    Ok(BootstrapReport {
        host_dir: host_dir.clone(),
        generation: generation.digest().clone(),
        selector_epoch: selector.epoch,
        coordinated_ready,
        retired_units,
        linger_enabled,
    })
}

/// Reverse command: refuses while a transaction is nonterminal, then removes the launcher setup (jobs,
/// the cron block, launcher-owned init scripts) and restores the legacy daemon-only units. OpenRC had
/// no legacy units, so it ends with none. Panel unenrollment and the coordinator's own downgrade
/// predicate are brief D's.
pub async fn downgrade<P: Platform>(
    platform: &P,
    options: &BootstrapOptions,
) -> Result<BootstrapReport, BootstrapError> {
    let host_dir = validate_host_dir(&options.host_dir)?;
    refuse_nonterminal_transaction(&options.state_dir)?;

    // Jobs, the cron block, launcher-owned services and user units and timers.
    platform.remove_launcher_setup().await?;

    // Restore the legacy units (systemd only; on OpenRC there were none).
    if platform.kind() == weglarka_model::config::PlatformKind::Systemd {
        let settings = Settings::load(&options.config_path)
            .map_err(|e| BootstrapError::Incomplete(e.to_string()))?;
        let mut units = render_self_update_units(&options.daemon_binary, &options.config_path)?;
        units.extend(render_watchdog_units(
            &options.daemon_binary,
            &options.config_path,
        )?);
        platform.install_user_units(&units).await?;
        let _ = platform.set_timer(SELF_UPDATE_TIMER, true).await;
        let _ = platform.set_timer(WATCHDOG_TIMER, true).await;
        let _ = settings;
    }

    restore_legacy_state(&options.state_dir)?;
    for file in [
        BOOTSTRAP_MARKER,
        weglarka_launcher::host::HOST_TOOLS_FILE,
        weglarka_launcher::host::SERVICE_SELECTION_FILE,
        weglarka_launcher::host::LEGACY_IMPORT_FILE,
        CAPABILITIES_FILE_NAME,
    ] {
        let path = if file == CAPABILITIES_FILE_NAME {
            options.state_dir.join(file)
        } else {
            host_dir.join(file)
        };
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(BootstrapError::Io {
                    path: path.clone(),
                    source,
                });
            }
        }
    }
    Ok(BootstrapReport {
        host_dir,
        generation: options.generation.clone(),
        selector_epoch: 0,
        coordinated_ready: false,
        retired_units: Vec::new(),
        linger_enabled: false,
    })
}

fn create_dir(path: &Path) -> Result<(), BootstrapError> {
    std::fs::create_dir_all(path).map_err(|source| BootstrapError::Io {
        path: path.to_owned(),
        source,
    })?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(|source| {
        BootstrapError::Io {
            path: path.to_owned(),
            source,
        }
    })
}

/// Validates the launcher source: a regular file (never a symlink) of bounded size.
fn check_launcher(source: &Path) -> Result<std::fs::Metadata, BootstrapError> {
    let metadata = std::fs::symlink_metadata(source).map_err(|source_err| BootstrapError::Io {
        path: source.to_owned(),
        source: source_err,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(BootstrapError::Incomplete(format!(
            "launcher {} is not a regular file",
            source.display()
        )));
    }
    if metadata.len() > 64 * 1024 * 1024 {
        return Err(BootstrapError::Incomplete(format!(
            "launcher {} is larger than 64 MiB",
            source.display()
        )));
    }
    Ok(metadata)
}

/// The plan already validated the source; it is checked again here because root reads it now.
fn install_launcher(host_dir: &Path, source: &Path) -> Result<(), BootstrapError> {
    check_launcher(source)?;
    let bytes = std::fs::read(source).map_err(|source_err| BootstrapError::Io {
        path: source.to_owned(),
        source: source_err,
    })?;
    let target = host_dir.join(LAUNCHER_FILE);
    write_atomic(&target, &bytes, 0o755).map_err(|source| BootstrapError::Io {
        path: target.clone(),
        source,
    })?;
    Ok(())
}

/// A private directory removed again on drop.
struct Scratch(PathBuf);

const SCRATCH_PREFIX: &str = ".weglarka-bootstrap-plan-";

impl Scratch {
    /// Creates `<parent of near>/.weglarka-bootstrap-plan-<pid>-<nanos>` with mode 0700. Next to the
    /// host directory rather than in `/tmp` because the copy is executed and `/tmp` may be mounted
    /// `noexec`; a missing parent is an error, not a reason to fall back to `/tmp`. Scratch
    /// directories that an earlier run left behind (`panic = "abort"`, a signal) are removed first.
    fn create(near: &Path) -> Result<Self, BootstrapError> {
        use std::os::unix::fs::DirBuilderExt;
        let base = near
            .parent()
            .filter(|parent| parent.is_dir())
            .ok_or_else(|| {
                BootstrapError::Incomplete(format!(
                    "the parent directory of {} does not exist; create it first (the preflight \
                     runs from a private copy next to the host directory)",
                    near.display()
                ))
            })?;
        remove_stale_scratch(base);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let path = base.join(format!("{SCRATCH_PREFIX}{}-{nanos}", std::process::id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|source| BootstrapError::Io {
                path: path.clone(),
                source,
            })?;
        Ok(Self(path))
    }
}

/// Removes `.weglarka-bootstrap-plan-<pid>-*` directories of finished processes that the current user
/// owns. Entries are inspected with `symlink_metadata` and a symlink is never followed or removed.
fn remove_stale_scratch(base: &Path) {
    use std::os::unix::fs::MetadataExt;
    let Ok(me) = std::fs::metadata("/proc/self").map(|meta| meta.uid()) else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(base) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(rest) = name.to_str().and_then(|n| n.strip_prefix(SCRATCH_PREFIX)) else {
            continue;
        };
        let Some(pid) = rest.split('-').next().and_then(|p| p.parse::<u32>().ok()) else {
            continue;
        };
        let running = pid != std::process::id() && Path::new(&format!("/proc/{pid}")).exists();
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !running && meta.is_dir() && !meta.file_type().is_symlink() && meta.uid() == me {
            let _ = std::fs::remove_dir_all(&path);
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The tools staged and verified in a scratch store.
struct ScratchGeneration {
    generation: Generation,
    _scratch: Scratch,
}

/// Stages the tools exactly as the apply step will (same source checks, size limit and digest) into
/// a private scratch store, so a bad source is refused before the host is touched and the preflight
/// has a verified copy to run.
fn stage_scratch_generation(
    host_dir: &Path,
    options: &BootstrapOptions,
) -> Result<ScratchGeneration, BootstrapError> {
    let scratch = Scratch::create(host_dir)?;
    let generation = GenerationStore::new(&scratch.0).install_from_files(
        &options.generation,
        &[
            (HOST_DAEMON_FILE, options.daemon_binary.clone()),
            (
                weglarka_launcher::host::HOST_CLI_FILE,
                options.cli_binary.clone(),
            ),
        ],
    )?;
    Ok(ScratchGeneration {
        generation,
        _scratch: scratch,
    })
}

/// A generation directory that already exists on the host is reused only when it verifies and holds
/// exactly the files being installed. This mirrors `GenerationStore::open` (manifest, exactly the
/// manifest's files, regular files of mode 0755, sizes, SHA-256) but never writes the
/// verified-metadata cache record, so a dry run leaves the host untouched. The authoritative check
/// still runs again in `install_from_files` while applying.
fn check_existing_generation(host_dir: &Path, staged: &Generation) -> Result<(), BootstrapError> {
    use weglarka_launcher::generation::{GenerationError, GenerationManifest};
    use weglarka_launcher::host::{HostError, read_bounded};

    let digest = staged.digest();
    let dir = host_dir.join(GENERATIONS_DIR).join(generation_name(digest));
    if std::fs::symlink_metadata(&dir).is_err() {
        return Ok(());
    }
    let manifest_path = dir.join(GENERATION_MANIFEST);
    let mismatch = |path: PathBuf| GenerationError::Mismatch { path };
    let manifest_error = |message: String| GenerationError::Manifest {
        path: manifest_path.clone(),
        message,
    };
    if !std::fs::symlink_metadata(&dir)
        .map(|meta| meta.is_dir())
        .unwrap_or(false)
    {
        return Err(manifest_error("not a plain directory".into()).into());
    }
    let text = read_bounded(&manifest_path, GENERATION_MANIFEST, 8 * 1024)
        .map_err(GenerationError::from)?
        .ok_or_else(|| manifest_error("manifest is missing".into()))?;
    let manifest: GenerationManifest =
        toml::from_str(&text).map_err(|e| manifest_error(e.to_string()))?;
    if manifest.generation != *digest || manifest.files != staged.manifest().files {
        return Err(mismatch(manifest_path).into());
    }
    let mut unexpected: std::collections::BTreeSet<String> = std::fs::read_dir(&dir)
        .map_err(|source| GenerationError::Dir {
            path: dir.clone(),
            source,
        })?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    unexpected.remove(GENERATION_MANIFEST);
    for file in &manifest.files {
        unexpected.remove(&file.name);
        let path = dir.join(&file.name);
        let meta = std::fs::symlink_metadata(&path).map_err(|source| HostError::Read {
            path: path.clone(),
            source,
        })?;
        if meta.file_type().is_symlink() {
            return Err(GenerationError::from(HostError::Symlink { path }).into());
        }
        if !meta.is_file() {
            return Err(GenerationError::from(HostError::NotRegular { path }).into());
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o755 {
            return Err(GenerationError::from(HostError::Mode {
                path,
                mode,
                expected: 0o755,
            })
            .into());
        }
        if meta.len() != file.size {
            return Err(mismatch(path).into());
        }
        let streamed = std::fs::File::open(&path)
            .and_then(weglarka_model::release_set::sha256_reader)
            .map_err(|source| HostError::Read {
                path: path.clone(),
                source,
            })?;
        if StrictDigest::from_sha256(streamed.sha256) != file.digest {
            return Err(mismatch(path).into());
        }
    }
    if let Some(name) = unexpected.into_iter().next() {
        return Err(GenerationError::UnexpectedFile {
            digest: digest.clone(),
            name,
        }
        .into());
    }
    Ok(())
}

fn run_preflight_on(
    generation: &Generation,
    label: &'static str,
    config: &Path,
) -> Result<(), BootstrapError> {
    weglarka_launcher::run::run_preflight(generation, config, std::time::Duration::from_secs(60))
        .map_err(|error| BootstrapError::Preflight(label, error.to_string()))
}

async fn retire_legacy_units<P: Platform>(
    platform: &P,
    state_dir: &Path,
) -> Result<Vec<String>, BootstrapError> {
    let mut retired = Vec::new();
    if platform.kind() == weglarka_model::config::PlatformKind::Systemd {
        for timer in [SELF_UPDATE_TIMER, WATCHDOG_TIMER] {
            let _ = platform.set_timer(timer, false).await;
        }
        platform
            .remove_user_units(&[
                SELF_UPDATE_SERVICE,
                SELF_UPDATE_TIMER,
                WATCHDOG_SERVICE,
                WATCHDOG_TIMER,
            ])
            .await?;
        retired.extend(
            [
                SELF_UPDATE_SERVICE,
                SELF_UPDATE_TIMER,
                WATCHDOG_SERVICE,
                WATCHDOG_TIMER,
            ]
            .into_iter()
            .map(str::to_owned),
        );
    }
    // A legacy runner that started between the plan and now holds the lock again: the timers are
    // off at this point, so a held lock is a real runner and stopping is the safe answer.
    let legacy_lock = state_dir.join(LEGACY_LOCK_FILE);
    if lock::is_held(&legacy_lock)? {
        return Err(BootstrapError::LegacyRunnerActive);
    }
    match std::fs::remove_file(&legacy_lock) {
        Ok(()) => retired.push("self-update.lock".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(BootstrapError::Io {
                path: legacy_lock,
                source,
            });
        }
    }
    Ok(retired)
}

/// What importing `self-update.toml` writes, or `None` when the file does not exist. A file that
/// does not parse is refused.
fn read_legacy_import(state_dir: &Path, now: u64) -> Result<Option<LegacyImport>, BootstrapError> {
    let state = weglarka_model::self_update::load(state_dir)
        .map_err(|e| BootstrapError::Legacy(e.to_string()))?;
    if !weglarka_model::self_update::path(state_dir).exists() {
        return Ok(None);
    }
    Ok(Some(LegacyImport {
        format_version: 1,
        current: state.current.as_ref().map(|d| d.as_str().to_owned()),
        previous: state.previous.as_ref().map(|d| d.as_str().to_owned()),
        pending: state.pending.as_ref().map(|d| d.as_str().to_owned()),
        imported_at: now,
    }))
}

/// Imports and retires `self-update.toml` as it is *now*. Runs after the legacy timers are off, so a
/// legacy runner can no longer rewrite the file between the read and the rename.
fn import_legacy_state(host_dir: &Path, state_dir: &Path, now: u64) -> Result<(), BootstrapError> {
    let Some(import) = read_legacy_import(state_dir, now)? else {
        return Ok(());
    };
    import.save(host_dir)?;
    let path = weglarka_model::self_update::path(state_dir);
    let retired = path.with_extension("toml.retired");
    std::fs::rename(&path, &retired).map_err(|source| BootstrapError::Io {
        path: retired.clone(),
        source,
    })
}

fn restore_legacy_state(state_dir: &Path) -> Result<(), BootstrapError> {
    let path = weglarka_model::self_update::path(state_dir);
    let retired = path.with_extension("toml.retired");
    if retired.exists() && !path.exists() {
        std::fs::rename(&retired, &path).map_err(|source| BootstrapError::Io {
            path: path.clone(),
            source,
        })?;
    }
    Ok(())
}

fn write_capabilities(state_dir: &Path, generation: &StrictDigest) -> Result<(), BootstrapError> {
    std::fs::create_dir_all(state_dir).map_err(|source| BootstrapError::Io {
        path: state_dir.to_owned(),
        source,
    })?;
    let record = CapabilityRecord {
        format_version: UPDATE_FORMAT,
        host_protocol: HOST_PROTOCOL_VERSION,
        // Only what this build actually implements. Image-lock and reservation phases land with
        // A/D; claiming them early would let retention delete platform images unsafely.
        features: [CoordinationFeature::ServiceActivation]
            .into_iter()
            .collect(),
        active_generation: generation.clone(),
        writer_boot_id: boot_id(),
    };
    let text = record
        .to_toml()
        .map_err(|e| BootstrapError::Incomplete(format!("host-capabilities.toml: {e}")))?;
    let path = state_dir.join(CAPABILITIES_FILE_NAME);
    write_atomic(&path, text.as_bytes(), 0o600).map_err(|source| BootstrapError::Io {
        path: path.clone(),
        source,
    })
}

fn launcher_jobs(options: &BootstrapOptions) -> Vec<ScheduledJob> {
    let interval = std::fs::read_to_string(&options.config_path)
        .ok()
        .and_then(|text| weglarka_model::config::HostConfig::from_toml_str(&text).ok())
        .and_then(|host| host.self_update.map(|s| s.interval_secs))
        .unwrap_or(3600);
    let base = |role: &str, timeout: &str| {
        vec![
            "--host-dir".to_owned(),
            options.host_dir.display().to_string(),
            "--config".to_owned(),
            options.config_path.display().to_string(),
            role.to_owned(),
            "--worker-timeout-secs".to_owned(),
            timeout.to_owned(),
        ]
    };
    vec![
        ScheduledJob {
            id: JobId::Update,
            args: base("update", "600"),
            runtime_user: options.runtime_user.clone(),
            cadence_secs: interval,
            skip_if_running: true,
        },
        ScheduledJob {
            id: JobId::Watchdog,
            args: base("supervise", "120"),
            runtime_user: options.runtime_user.clone(),
            cadence_secs: 60,
            skip_if_running: true,
        },
    ]
}

fn refuse_nonterminal_transaction(state_dir: &Path) -> Result<(), BootstrapError> {
    let path = state_dir.join(weglarka_model::platform_update::FILE_NAME);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(BootstrapError::Io { path, source });
        }
    };
    let journal = PlatformUpdate::parse(&text)
        .map_err(|e| BootstrapError::Incomplete(format!("platform-update.toml: {e}")))?;
    if let Some(transaction) = journal.transaction
        && !transaction.is_terminal()
    {
        return Err(BootstrapError::Incomplete(format!(
            "transaction {} is still {}; finish or explicitly abandon it first",
            transaction.transaction_id, "nonterminal"
        )));
    }
    Ok(())
}

fn legacy_units_present(state_dir: &Path) -> bool {
    state_dir.join("self-update.toml").exists()
        || lock::is_held(&state_dir.join("self-update.lock")).unwrap_or(true)
}

fn boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().to_owned())
        .ok()
        .filter(|s| !s.is_empty() && s.len() <= 128)
        .unwrap_or_else(|| "unknown-boot".to_owned())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// Applies the ownership model of [`crate::ownership`]. The plan has no such step when the runtime
/// user is unknown. A non-root bootstrap (tests, an installer
/// context that already owns the directory) cannot chown and nothing is changed; once the host
/// directory itself was taken over, any entry that could not be secured fails the bootstrap.
fn apply_ownership(host_dir: &Path, uid: u32, gid: u32) -> Result<(), BootstrapError> {
    match crate::ownership::apply(host_dir, uid, gid, &mut crate::ownership::lchown) {
        Ok(outcome) if outcome.code > 0 => Err(BootstrapError::Incomplete(format!(
            "{} entries of {} that root executes could not be secured",
            outcome.code,
            host_dir.display()
        ))),
        Ok(outcome) => {
            if outcome.state > 0 {
                // Entries the runtime user controls cannot block a root bootstrap.
                tracing::warn!(
                    host_dir = %host_dir.display(),
                    entries = outcome.state,
                    "some runtime state entries were left alone (extra hard links or changed under the walk)"
                );
            }
            Ok(())
        }
        Err(error) => {
            tracing::debug!(
                host_dir = %host_dir.display(),
                %error,
                "host directory ownership not changed"
            );
            Ok(())
        }
    }
}

/// Enables lingering so the runtime user's timers and Podman socket start after a reboot without a
/// login. Root-only; best effort outside a real logind host.
fn enable_linger(user: &str) -> bool {
    let status = std::process::Command::new("loginctl")
        .args(["show-user", user, "-p", "Linger"])
        .output();
    if let Ok(output) = status
        && output.status.success()
        && String::from_utf8_lossy(&output.stdout).contains("Linger=yes")
    {
        return true;
    }
    std::process::Command::new("loginctl")
        .args(["enable-linger", user])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Looks up a runtime user in `/etc/passwd` (bootstrap runs on the host, before any container).
pub fn lookup_user(user: &str) -> Option<(u32, u32)> {
    let text = std::fs::read_to_string("/etc/passwd").ok()?;
    text.lines().find_map(|line| {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 4 && fields[0] == user {
            Some((fields[2].parse().ok()?, fields[3].parse().ok()?))
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use weglarka_engine::platform::{Result as PlatformResult, ServiceStatus, UnitFile};
    use weglarka_model::config::PlatformKind;
    use weglarka_model::platform_update::Stage;

    #[derive(Default)]
    struct FakePlatform {
        kind: Option<PlatformKind>,
        jobs: Mutex<Vec<ScheduledJob>>,
        removed_units: Mutex<Vec<String>>,
        timers: Mutex<Vec<(String, bool)>>,
        installed: Mutex<Vec<String>>,
        activated: Mutex<Vec<u64>>,
        teardowns: Mutex<u32>,
    }

    impl FakePlatform {
        fn systemd() -> Self {
            Self {
                kind: Some(PlatformKind::Systemd),
                ..Self::default()
            }
        }
    }

    impl Platform for FakePlatform {
        fn kind(&self) -> PlatformKind {
            self.kind.unwrap_or(PlatformKind::Systemd)
        }
        async fn runtime_socket(&self, _: &str) -> PlatformResult<PathBuf> {
            Ok(PathBuf::from("/run/user/1001/podman/podman.sock"))
        }
        async fn install_service(
            &self,
            spec: &weglarka_engine::platform::ServiceSpec,
        ) -> PlatformResult<()> {
            self.installed.lock().unwrap().push(spec.image.clone());
            Ok(())
        }
        async fn remove_service(&self, _: &str) -> PlatformResult<()> {
            Ok(())
        }
        async fn service_status(&self, _: &str) -> PlatformResult<ServiceStatus> {
            Ok(ServiceStatus::Active)
        }
        async fn install_user_units(&self, _: &[UnitFile]) -> PlatformResult<()> {
            Ok(())
        }
        async fn remove_user_units(&self, names: &[&str]) -> PlatformResult<()> {
            self.removed_units
                .lock()
                .unwrap()
                .extend(names.iter().map(|n| (*n).to_owned()));
            Ok(())
        }
        async fn restart_service(&self, _: &str) -> PlatformResult<()> {
            Ok(())
        }
        async fn reset_failed(&self, _: &str) -> PlatformResult<()> {
            Ok(())
        }
        async fn set_timer(&self, name: &str, enabled: bool) -> PlatformResult<()> {
            self.timers.lock().unwrap().push((name.to_owned(), enabled));
            Ok(())
        }
        async fn remove_launcher_setup(&self) -> PlatformResult<()> {
            *self.teardowns.lock().unwrap() += 1;
            Ok(())
        }
        async fn install_jobs(&self, jobs: &[ScheduledJob]) -> PlatformResult<()> {
            self.jobs.lock().unwrap().extend_from_slice(jobs);
            Ok(())
        }
        async fn activate_service(
            &self,
            _: weglarka_engine::platform::ServiceSpec,
            epoch: ActivationEpoch,
        ) -> PlatformResult<weglarka_engine::platform::ActivationReceipt> {
            self.activated.lock().unwrap().push(epoch.0);
            Ok(weglarka_engine::platform::ActivationReceipt { epoch })
        }
    }

    fn script(path: &Path, body: &str) {
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn options(dir: &Path) -> BootstrapOptions {
        let host = dir.join("host");
        let state = dir.join("state");
        std::fs::create_dir_all(&state).unwrap();
        let daemon = dir.join("src-daemon");
        let cli = dir.join("src-cli");
        script(&daemon, "#!/bin/sh\nexit 0\n");
        script(&cli, "#!/bin/sh\nexit 0\n");
        let config = dir.join("weglarka.toml");
        std::fs::write(
            &config,
            format!(
                r#"
[ingress]
mode = "behind"
bind = "127.0.0.1:8080"
[admin]
socket = "{}/admin.sock"
[webhook]
listen = "127.0.0.1:0"
domain = "hooks.example.org"
[state]
dir = "{}"
[self_update]
image = "ghcr.io/example/weglarka:latest"
"#,
                dir.display(),
                state.display()
            ),
        )
        .unwrap();
        BootstrapOptions {
            host_dir: host,
            state_dir: state,
            config_path: config,
            runtime_user: "weglarka".into(),
            runtime_uid: None,
            runtime_gid: None,
            generation: StrictDigest::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            daemon_binary: daemon,
            cli_binary: cli,
            launcher_binary: {
                let launcher = dir.join("src-launcher");
                script(&launcher, "#!/bin/sh\nexit 0\n");
                launcher
            },
            image: format!("ghcr.io/example/weglarka@sha256:{}", "b".repeat(64)),
            channel: None,
            enable_linger: false,
        }
    }

    #[tokio::test]
    // The fake platform's observation mutexes are asserted between awaits; no production lock is
    // held across one.
    #[allow(clippy::await_holding_lock)]
    async fn bootstrap_is_idempotent_and_records_a_complete_selector() {
        let dir = tempfile::tempdir().unwrap();
        let options = options(dir.path());
        let platform = FakePlatform::systemd();
        let first = bootstrap(&platform, &options).await.unwrap();
        assert_eq!(first.selector_epoch, 1);
        assert!(first.generation.as_str().starts_with("sha256:"));
        assert!(HostSelector::load(&options.host_dir).is_ok());
        assert!(BootstrapMarker::load(&options.host_dir).unwrap().is_some());
        let capabilities =
            std::fs::read_to_string(options.state_dir.join(CAPABILITIES_FILE_NAME)).unwrap();
        let record = CapabilityRecord::parse(&capabilities).unwrap();
        assert_eq!(record.host_protocol, HOST_PROTOCOL_VERSION);
        assert_eq!(record.active_generation, first.generation);
        assert!(
            weglarka_model::platform_update::platform_prune_allowed(Some(&record)).is_err(),
            "this build must not claim image-lock/reservation capabilities it does not implement"
        );
        assert!(options.host_dir.join(LAUNCHER_FILE).is_file());
        let jobs = platform.jobs.lock().unwrap();
        assert_eq!(jobs.len(), 2);
        assert!(
            jobs.iter().any(|job| job.id == JobId::Update
                && job.args.iter().any(|arg| arg == "update")
                && job.args.iter().any(|arg| arg == "--worker-timeout-secs")),
            "{jobs:?}"
        );
        drop(jobs);
        assert!(
            platform
                .removed_units
                .lock()
                .unwrap()
                .contains(&SELF_UPDATE_TIMER.to_owned())
        );
        assert!(
            platform
                .timers
                .lock()
                .unwrap()
                .iter()
                .any(|(t, on)| t == SELF_UPDATE_TIMER && !on)
        );
        let again = bootstrap(&platform, &options).await.unwrap();
        assert_eq!(again.selector_epoch, 1);
        assert_eq!(again.generation, first.generation);
    }

    #[tokio::test]
    async fn bootstrap_refuses_a_live_legacy_runner_and_overlapping_roots() {
        let dir = tempfile::tempdir().unwrap();
        let mut options = options(dir.path());
        std::fs::create_dir_all(&options.state_dir).unwrap();
        let lock_path = options.state_dir.join("self-update.lock");
        let held = weglarka_launcher::lock::lock(&lock_path).unwrap();
        assert!(matches!(
            bootstrap(&FakePlatform::systemd(), &options).await,
            Err(BootstrapError::LegacyRunnerActive)
        ));
        drop(held);

        options.host_dir = options.state_dir.join("host");
        assert!(matches!(
            bootstrap(&FakePlatform::systemd(), &options).await,
            Err(BootstrapError::Overlapping { .. })
        ));
    }

    /// Every path under `root` with its kind, mode, owner and content hash (symlinks by target), so
    /// "nothing changed" is a plain equality. Timestamps are left out on purpose.
    fn tree(root: &Path) -> Vec<String> {
        use sha2::{Digest as _, Sha256};
        use std::os::unix::fs::MetadataExt;
        fn walk(dir: &Path, out: &mut Vec<String>) {
            let mut entries: Vec<_> = std::fs::read_dir(dir)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect();
            entries.sort();
            for path in entries {
                let meta = std::fs::symlink_metadata(&path).unwrap();
                let detail = if meta.file_type().is_symlink() {
                    format!("-> {}", std::fs::read_link(&path).unwrap().display())
                } else if meta.is_file() && meta.len() > 1 << 20 {
                    // Oversized fixtures are sparse; their size stands in for the hash.
                    format!("{} bytes", meta.len())
                } else if meta.is_file() {
                    hex::encode(Sha256::digest(std::fs::read(&path).unwrap()))
                } else {
                    String::new()
                };
                out.push(format!(
                    "{} {:o} {}:{} {detail}",
                    path.display(),
                    meta.mode(),
                    meta.uid(),
                    meta.gid()
                ));
                if meta.is_dir() {
                    walk(&path, out);
                }
            }
        }
        let mut out = Vec::new();
        walk(root, &mut out);
        out
    }

    #[tokio::test]
    async fn an_already_bootstrapped_host_refuses_another_generation_and_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let options = options(dir.path());
        let platform = FakePlatform::systemd();
        bootstrap(&platform, &options).await.unwrap();
        // A legacy file that a premature import would retire.
        std::fs::write(
            options.state_dir.join("self-update.toml"),
            format!("current = \"sha256:{}\"\n", "c".repeat(64)),
        )
        .unwrap();
        let before = tree(dir.path());
        let jobs = platform.jobs.lock().unwrap().len();

        let mut other = options.clone();
        other.generation = StrictDigest::new(format!("sha256:{}", "f".repeat(64))).unwrap();
        let error = bootstrap(&platform, &other).await.unwrap_err();

        assert!(
            matches!(&error, BootstrapError::AlreadyBootstrapped(active) if *active == options.generation),
            "{error}"
        );
        assert_eq!(tree(dir.path()), before);
        assert_eq!(platform.jobs.lock().unwrap().len(), jobs);
    }

    #[tokio::test]
    async fn a_refused_bootstrap_leaves_a_fresh_host_untouched() {
        // Each precondition is checked while planning, so no refusal leaves a half-installed host.
        let dir = tempfile::tempdir().unwrap();
        let base = options(dir.path());
        let before = tree(dir.path());
        let platform = FakePlatform::systemd();

        let failing_preflight = base.clone();
        script(&failing_preflight.daemon_binary, "#!/bin/sh\nexit 3\n");
        let before_script = tree(dir.path());
        assert!(matches!(
            bootstrap(&platform, &failing_preflight).await,
            Err(BootstrapError::Preflight("active", _))
        ));
        assert_eq!(tree(dir.path()), before_script);
        script(&base.daemon_binary, "#!/bin/sh\nexit 0\n");
        assert_eq!(tree(dir.path()), before);

        let mut symlinked_launcher = base.clone();
        let link = dir.path().join("launcher-link");
        std::os::unix::fs::symlink(&base.launcher_binary, &link).unwrap();
        symlinked_launcher.launcher_binary = link;
        let before_link = tree(dir.path());
        assert!(matches!(
            bootstrap(&platform, &symlinked_launcher).await,
            Err(BootstrapError::Incomplete(_))
        ));
        assert_eq!(tree(dir.path()), before_link);

        std::fs::write(base.state_dir.join("self-update.toml"), "current = [1]\n").unwrap();
        let before_legacy = tree(dir.path());
        assert!(matches!(
            bootstrap(&platform, &base).await,
            Err(BootstrapError::Legacy(_))
        ));
        assert_eq!(tree(dir.path()), before_legacy);
        assert!(!base.host_dir.exists());
        assert!(platform.jobs.lock().unwrap().is_empty());
        assert!(platform.installed.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn oversized_symlinked_and_changed_sources_are_refused_before_any_change() {
        let dir = tempfile::tempdir().unwrap();
        let base = options(dir.path());
        let platform = FakePlatform::systemd();
        let oversized = |path: &Path| {
            std::fs::File::create(path)
                .unwrap()
                .set_len(64 * 1024 * 1024 + 1)
                .unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        };

        let mut cases: Vec<(&str, BootstrapOptions)> = Vec::new();
        for tool in ["daemon", "cli"] {
            let link = dir.path().join(format!("{tool}-link"));
            let big = dir.path().join(format!("{tool}-big"));
            let source = if tool == "daemon" {
                &base.daemon_binary
            } else {
                &base.cli_binary
            };
            std::os::unix::fs::symlink(source, &link).unwrap();
            oversized(&big);
            for (name, path) in [("symlinked", link), ("oversized", big)] {
                let mut options = base.clone();
                if tool == "daemon" {
                    options.daemon_binary = path;
                } else {
                    options.cli_binary = path;
                }
                cases.push((
                    if name == "symlinked" {
                        "symlink"
                    } else {
                        "size"
                    },
                    options,
                ));
            }
        }
        let big_launcher = dir.path().join("launcher-big");
        oversized(&big_launcher);
        let mut options = base.clone();
        options.launcher_binary = big_launcher;
        cases.push(("launcher", options));

        let before = tree(dir.path());
        for (label, options) in &cases {
            let result = bootstrap(&platform, options).await;
            assert!(
                matches!(
                    (&result, *label),
                    (Err(BootstrapError::Generation(_)), "symlink" | "size")
                        | (Err(BootstrapError::Incomplete(_)), "launcher")
                ),
                "{label}: {result:?}"
            );
            assert_eq!(tree(dir.path()), before, "{label}");
        }
        assert!(platform.installed.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_existing_generation_directory_with_other_files_is_refused_before_any_change() {
        let dir = tempfile::tempdir().unwrap();
        let options = options(dir.path());
        let platform = FakePlatform::systemd();
        bootstrap(&platform, &options).await.unwrap();

        // Same generation key, different tool content.
        script(&options.daemon_binary, "#!/bin/sh\n# changed\nexit 0\n");
        let before = tree(dir.path());
        let result = bootstrap(&platform, &options).await;
        assert!(
            matches!(
                &result,
                Err(BootstrapError::Generation(
                    weglarka_launcher::generation::GenerationError::Mismatch { .. }
                ))
            ),
            "{result:?}"
        );
        assert_eq!(tree(dir.path()), before);
        script(&options.daemon_binary, "#!/bin/sh\nexit 0\n");

        // The installed copy was tampered with: same size, other content.
        let installed = options
            .host_dir
            .join(GENERATIONS_DIR)
            .join(generation_name(&options.generation))
            .join(HOST_DAEMON_FILE);
        script(&installed, "#!/bin/sh\nexit 9\n");
        let before = tree(dir.path());
        assert!(bootstrap(&platform, &options).await.is_err());
        assert_eq!(tree(dir.path()), before);
    }

    #[tokio::test]
    async fn the_legacy_state_is_read_when_it_is_imported_not_when_it_is_planned() {
        let legacy = |options: &BootstrapOptions, digit: &str| {
            std::fs::write(
                options.state_dir.join("self-update.toml"),
                format!("current = \"sha256:{}\"\n", digit.repeat(64)),
            )
            .unwrap();
        };

        // Rewritten by a legacy timer after the plan: the new content is imported and retired.
        let dir = tempfile::tempdir().unwrap();
        let opts = options(dir.path());
        legacy(&opts, "c");
        let platform = FakePlatform::systemd();
        let planned = plan(&platform, &opts).await.unwrap();
        legacy(&opts, "d");
        apply(&platform, &planned).await.unwrap();
        let import = LegacyImport::load(&opts.host_dir).unwrap().unwrap();
        assert_eq!(import.current, Some(format!("sha256:{}", "d".repeat(64))));
        assert!(!opts.state_dir.join("self-update.toml").exists());

        // Created after the plan: imported all the same.
        let dir = tempfile::tempdir().unwrap();
        let opts = options(dir.path());
        let planned = plan(&platform, &opts).await.unwrap();
        legacy(&opts, "e");
        apply(&platform, &planned).await.unwrap();
        let import = LegacyImport::load(&opts.host_dir).unwrap().unwrap();
        assert_eq!(import.current, Some(format!("sha256:{}", "e".repeat(64))));
        assert!(opts.state_dir.join("self-update.toml.retired").exists());

        // Gone after the plan: nothing half-applied, nothing imported.
        let dir = tempfile::tempdir().unwrap();
        let opts = options(dir.path());
        legacy(&opts, "c");
        let planned = plan(&platform, &opts).await.unwrap();
        std::fs::remove_file(opts.state_dir.join("self-update.toml")).unwrap();
        apply(&platform, &planned).await.unwrap();
        assert!(LegacyImport::load(&opts.host_dir).unwrap().is_none());
        assert!(!opts.state_dir.join("self-update.toml.retired").exists());
    }

    #[tokio::test]
    async fn stale_scratch_directories_are_removed_and_a_missing_parent_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let mut options = options(dir.path());
        let platform = FakePlatform::systemd();

        // Left by a killed run (its pid cannot exist) and a symlink that must not be followed.
        let stale = dir.path().join(format!("{SCRATCH_PREFIX}4294967295-1"));
        std::fs::create_dir(&stale).unwrap();
        std::fs::write(stale.join("leftover"), "x").unwrap();
        let victim = dir.path().join("victim");
        std::fs::create_dir(&victim).unwrap();
        std::fs::write(victim.join("keep"), "x").unwrap();
        let link = dir.path().join(format!("{SCRATCH_PREFIX}4294967294-1"));
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        plan(&platform, &options).await.unwrap();
        assert!(!stale.exists());
        assert!(std::fs::symlink_metadata(&link).is_ok());
        assert!(victim.join("keep").exists());

        options.host_dir = dir.path().join("missing").join("host");
        let result = plan(&platform, &options).await;
        assert!(
            matches!(&result, Err(BootstrapError::Incomplete(m)) if m.contains("parent directory")),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn a_live_legacy_runner_is_refused_before_any_change() {
        let dir = tempfile::tempdir().unwrap();
        let options = options(dir.path());
        let held =
            weglarka_launcher::lock::lock(&options.state_dir.join(LEGACY_LOCK_FILE)).unwrap();
        let before = tree(dir.path());
        let platform = FakePlatform::systemd();
        assert!(matches!(
            plan(&platform, &options).await,
            Err(BootstrapError::LegacyRunnerActive)
        ));
        assert_eq!(tree(dir.path()), before);
        assert!(platform.removed_units.lock().unwrap().is_empty());
        drop(held);
    }

    #[tokio::test]
    async fn dry_run_lists_the_steps_of_a_fresh_host_and_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut options = options(dir.path());
        options.enable_linger = true;
        options.runtime_uid = Some(1001);
        options.runtime_gid = Some(1001);
        std::fs::write(
            options.state_dir.join("self-update.toml"),
            format!("current = \"sha256:{}\"\n", "c".repeat(64)),
        )
        .unwrap();
        let before = tree(dir.path());
        let platform = FakePlatform::systemd();

        let plan = plan(&platform, &options).await.unwrap();

        insta::assert_snapshot!(
            "dry_run_systemd_fresh_host",
            plan.to_string()
                .replace(dir.path().to_str().unwrap(), "[root]")
        );
        assert_eq!(tree(dir.path()), before);
        assert!(platform.jobs.lock().unwrap().is_empty());
        assert!(platform.installed.lock().unwrap().is_empty());
        assert!(platform.removed_units.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn planning_again_on_a_bootstrapped_host_writes_nothing() {
        // Including the verified-metadata record of the existing generation.
        let dir = tempfile::tempdir().unwrap();
        let options = options(dir.path());
        let platform = FakePlatform::systemd();
        bootstrap(&platform, &options).await.unwrap();
        let before = tree(dir.path());
        let planned = plan(&platform, &options).await.unwrap();
        assert!(!planned.steps().is_empty());
        assert_eq!(tree(dir.path()), before);
    }

    #[tokio::test]
    async fn the_openrc_plan_keeps_the_preflight_for_after_provisioning() {
        // On OpenRC the preflight needs the Podman socket and cron that only the apply step
        // provisions, so a failing tool does not fail the plan; the step stays in the plan.
        let dir = tempfile::tempdir().unwrap();
        let options = options(dir.path());
        script(&options.daemon_binary, "#!/bin/sh\nexit 3\n");
        let platform = FakePlatform {
            kind: Some(PlatformKind::Openrc),
            ..FakePlatform::default()
        };
        let plan = plan(&platform, &options).await.unwrap();
        assert!(plan.steps().contains(&Step::VerifyPreflight));
        assert!(plan.steps().contains(&Step::ActivateService));
        assert!(!options.host_dir.exists());
    }

    #[tokio::test]
    async fn bootstrap_imports_and_retires_self_update_toml() {
        let dir = tempfile::tempdir().unwrap();
        let options = options(dir.path());
        std::fs::write(
            options.state_dir.join("self-update.toml"),
            format!(
                "current = \"sha256:{}\"\nprevious = \"sha256:{}\"\n",
                "c".repeat(64),
                "d".repeat(64)
            ),
        )
        .unwrap();
        bootstrap(&FakePlatform::systemd(), &options).await.unwrap();
        assert!(!options.state_dir.join("self-update.toml").exists());
        assert!(options.state_dir.join("self-update.toml.retired").exists());
        let import = LegacyImport::load(&options.host_dir).unwrap().unwrap();
        assert_eq!(import.current, Some(format!("sha256:{}", "c".repeat(64))));
        assert_eq!(import.previous, Some(format!("sha256:{}", "d".repeat(64))));
    }

    #[tokio::test]
    async fn downgrade_refuses_a_nonterminal_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let options = options(dir.path());
        let journal = PlatformUpdate {
            transaction: Some(weglarka_model::platform_update::TransactionJournal {
                transaction_id: weglarka_model::platform_update::TransactionId::new("tx-1")
                    .unwrap(),
                stage: Stage::Prepared,
                owner: weglarka_model::platform_update::OwnerIdentity {
                    pid: 1,
                    boot_id: "b".into(),
                    started_at: 1,
                    handoff_deadline: None,
                },
                old: endpoint(),
                target: endpoint(),
                release_set_digest: StrictDigest::new(format!("sha256:{}", "e".repeat(64)))
                    .unwrap(),
                reservations: vec![],
                candidate: None,
                ack: None,
                selected_generation: None,
                reason: None,
                updated_at: 1,
            }),
            ..PlatformUpdate::default()
        };
        std::fs::write(
            options
                .state_dir
                .join(weglarka_model::platform_update::FILE_NAME),
            journal.to_toml().unwrap(),
        )
        .unwrap();
        let platform = FakePlatform::systemd();
        assert!(matches!(
            downgrade(&platform, &options).await,
            Err(BootstrapError::Incomplete(_))
        ));
        assert_eq!(*platform.teardowns.lock().unwrap(), 0);
    }

    /// Runs nothing and succeeds: the OpenRC adapter's `rc-service`/`rc-update` calls.
    struct QuietRunner;

    impl crate::platform::CommandRunner for QuietRunner {
        async fn run(
            &self,
            _: &str,
            _: &[String],
            _: &[(String, String)],
        ) -> std::io::Result<crate::platform::CommandOutput> {
            Ok(crate::platform::CommandOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }

    #[tokio::test]
    async fn downgrade_on_a_real_openrc_adapter_leaves_no_launcher_init_script_or_cron_line() {
        use crate::openrc::OpenRcPlatform;
        use weglarka_engine::platform::{Hardening, JobId};

        let dir = tempfile::tempdir().unwrap();
        let options = options(dir.path());
        let init = dir.path().join("init.d");
        let crontabs = dir.path().join("crontabs");
        let platform = OpenRcPlatform::with_runner("weglarka", 1001, QuietRunner)
            .with_host_dir(&options.host_dir)
            .with_init_dir(&init)
            .with_crontab_dir(&crontabs);
        let digest = format!("sha256:{}", "b".repeat(64));
        platform
            .install_service(&weglarka_engine::platform::ServiceSpec {
                name: "weglarka".into(),
                image: format!("ghcr.io/example/weglarka@{digest}"),
                run_as_user: "weglarka".into(),
                env: vec![],
                mounts: vec![],
                networks: vec![],
                args: vec!["run".into()],
                hardening: Hardening::default(),
            })
            .await
            .unwrap();
        platform
            .install_jobs(&[ScheduledJob {
                id: JobId::Update,
                args: vec!["update".into()],
                runtime_user: "weglarka".into(),
                cadence_secs: 3600,
                skip_if_running: true,
            }])
            .await
            .unwrap();
        let crontab = crontabs.join("weglarka");
        let managed = std::fs::read_to_string(&crontab).unwrap();
        assert!(managed.contains("weglarka-launcher"), "{managed}");
        std::fs::write(&crontab, format!("0 3 * * * /usr/bin/backup\n{managed}")).unwrap();
        assert_eq!(std::fs::read_dir(&init).unwrap().count(), 2);

        downgrade(&platform, &options).await.unwrap();

        assert_eq!(std::fs::read_dir(&init).unwrap().count(), 0);
        let left = std::fs::read_to_string(&crontab).unwrap();
        assert_eq!(left, "0 3 * * * /usr/bin/backup\n");
        assert!(!left.contains("launcher"), "{left}");
    }

    #[tokio::test]
    async fn downgrade_removes_the_launcher_setup_once_on_either_platform() {
        for kind in [PlatformKind::Systemd, PlatformKind::Openrc] {
            let dir = tempfile::tempdir().unwrap();
            let options = options(dir.path());
            let platform = FakePlatform {
                kind: Some(kind),
                ..FakePlatform::default()
            };
            downgrade(&platform, &options).await.unwrap();
            assert_eq!(*platform.teardowns.lock().unwrap(), 1, "{kind:?}");
        }
    }

    fn endpoint() -> weglarka_model::platform_update::JournalEndpoint {
        weglarka_model::platform_update::JournalEndpoint {
            daemon_repository: weglarka_model::release_set::Repository::new(
                "ghcr.io/example/weglarka",
            )
            .unwrap(),
            daemon_digest: StrictDigest::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            tools_digest: StrictDigest::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            state_read: vec![17],
            state_write: 17,
            host_protocol: 1,
        }
    }
}
