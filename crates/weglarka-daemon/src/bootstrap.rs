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
use weglarka_launcher::generation::GenerationStore;
use weglarka_launcher::host::{
    BOOTSTRAP_MARKER, HOST_DAEMON_FILE, LAUNCHER_FILE, validate_host_dir,
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

/// Installs the launcher and generation 0, retires the legacy runner and provisions the fixed jobs.
pub async fn bootstrap<P: Platform>(
    platform: &P,
    options: &BootstrapOptions,
) -> Result<BootstrapReport, BootstrapError> {
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
    let now = unix_now();

    // 1. Host-only directory and the stable launcher.
    create_dir(&host_dir)?;
    install_launcher(&host_dir, &options.launcher_binary)?;
    let linger_enabled = if options.enable_linger
        && platform.kind() == weglarka_model::config::PlatformKind::Systemd
    {
        enable_linger(&options.runtime_user)
    } else {
        false
    };

    // 2. Stage the current tools as generation 0 (verify-and-reuse is idempotent).
    let store = GenerationStore::new(&host_dir);
    let generation = store.install_from_files(
        &options.generation,
        &[
            (HOST_DAEMON_FILE, options.daemon_binary.clone()),
            (
                weglarka_launcher::host::HOST_CLI_FILE,
                options.cli_binary.clone(),
            ),
        ],
    )?;

    // 3. Retire the legacy runner before any new timer can start.
    let retired_units = retire_legacy_units(platform, &options.state_dir).await?;
    import_legacy_state(&host_dir, &options.state_dir, now)?;

    // 4. Selector (re-running with the same generation keeps the epoch).
    let selector = match HostSelector::load_optional(&host_dir)? {
        Some(existing) if existing.active == options.generation => existing,
        Some(existing) => {
            return Err(BootstrapError::AlreadyBootstrapped(existing.active));
        }
        None => {
            let selector = HostSelector::fresh(options.generation.clone());
            selector.save(&host_dir)?;
            selector
        }
    };

    // 5. Shared capability record. Only features this build really implements are claimed; retention
    //    therefore stays fail-closed until A/D extend the set.
    write_capabilities(&options.state_dir, &options.generation)?;

    // 6. Fixed launcher jobs (systemd user timers or the BusyBox crontab managed block).
    let jobs = launcher_jobs(options);
    platform.install_jobs(&jobs).await?;

    // 7. Point the legacy-compatible service at the pinned image. On OpenRC the selection file is
    //    what the supervised launcher reads after boot; activation writes it without stopping a
    //    container that carries no matching epoch.
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
    let spec = service_spec(&settings, socket, options.image.clone());
    platform.install_service(&spec).await?;
    if platform.kind() == weglarka_model::config::PlatformKind::Openrc {
        platform
            .activate_service(spec, ActivationEpoch(selector.epoch))
            .await?;
        // The rootless API socket must exist for preflight; starting the installed service is the
        // installer's job, not the runtime user's.
        let _ = platform.restart_service(PODMAN_SERVICE).await;
        if let Ok(socket) = platform.runtime_socket(&options.runtime_user).await {
            for _ in 0..100 {
                if socket.exists() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }

    // Root executes the generation binaries below, so the code must already be root-owned and not
    // writable by the runtime user. (Applied again at the end for the state files written after this.)
    apply_ownership(&host_dir, options.runtime_uid, options.runtime_gid)?;

    // 8. Preflight the active and recovery generation against the *current* configuration, now that
    //    the OpenRC runtime prerequisites are provisioned.
    let mut preflight = PreflightOutcome {
        active: false,
        recovery: false,
    };
    for (label, digest) in [
        ("active", selector.active.clone()),
        ("recovery", selector.recovery().clone()),
    ] {
        let generation = store.open(&digest)?;
        match weglarka_launcher::run::run_preflight(
            &generation,
            &options.config_path,
            std::time::Duration::from_secs(60),
        ) {
            Ok(()) => {
                if label == "active" {
                    preflight.active = true;
                } else {
                    preflight.recovery = true;
                }
            }
            Err(error) => return Err(BootstrapError::Preflight(label, error.to_string())),
        }
    }

    // 9. The marker is the durable "bootstrap complete" signal. It is written only after every
    //    installation step and both preflights passed.
    BootstrapMarker {
        format_version: 1,
        generation: selector.active.clone(),
        selector_epoch: selector.epoch,
        completed_at: now,
    }
    .save(&host_dir)?;

    // 10. Report whether coordinated updates may be enabled now. A missing channel pointer is not a
    //     bootstrap failure: the installer completes and the coordinator enables updates later.
    let coordinated_ready = coordinated_updates_ready(
        &host_dir,
        &options.state_dir,
        options.channel,
        preflight,
        !legacy_units_present(&options.state_dir),
    )
    .is_ok();

    apply_ownership(&host_dir, options.runtime_uid, options.runtime_gid)?;

    Ok(BootstrapReport {
        host_dir,
        generation: generation.digest().clone(),
        selector_epoch: selector.epoch,
        coordinated_ready,
        retired_units,
        linger_enabled,
    })
}

/// Reverse command: refuses while a transaction is nonterminal, then removes the launcher jobs and
/// restores the legacy daemon-only units. Panel unenrollment and the coordinator's own downgrade
/// predicate are brief D's.
pub async fn downgrade<P: Platform>(
    platform: &P,
    options: &BootstrapOptions,
) -> Result<BootstrapReport, BootstrapError> {
    let host_dir = validate_host_dir(&options.host_dir)?;
    refuse_nonterminal_transaction(&options.state_dir)?;

    for timer in [
        "weglarka-platform-update.timer",
        "weglarka-platform-watchdog.timer",
    ] {
        let _ = platform.set_timer(timer, false).await;
    }
    let _ = platform
        .remove_user_units(&[
            "weglarka-platform-update.service",
            "weglarka-platform-update.timer",
            "weglarka-platform-watchdog.service",
            "weglarka-platform-watchdog.timer",
        ])
        .await;
    // OpenRC: empty the managed block, keep the daemon-only init scripts.
    if platform.kind() == weglarka_model::config::PlatformKind::Openrc {
        let _ = platform.install_jobs(&[]).await;
    }

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

fn install_launcher(host_dir: &Path, source: &Path) -> Result<(), BootstrapError> {
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
    // A legacy runner still holding the lock must be stopped; refusing is the safe answer.
    let legacy_lock = state_dir.join("self-update.lock");
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

fn import_legacy_state(host_dir: &Path, state_dir: &Path, now: u64) -> Result<(), BootstrapError> {
    let path = weglarka_model::self_update::path(state_dir);
    let state = weglarka_model::self_update::load(state_dir)
        .map_err(|e| BootstrapError::Legacy(e.to_string()))?;
    if path.exists() {
        LegacyImport {
            format_version: 1,
            current: state.current.as_ref().map(|d| d.as_str().to_owned()),
            previous: state.previous.as_ref().map(|d| d.as_str().to_owned()),
            pending: state.pending.as_ref().map(|d| d.as_str().to_owned()),
            imported_at: now,
        }
        .save(host_dir)?;
        let retired = path.with_extension("toml.retired");
        std::fs::rename(&path, &retired).map_err(|source| BootstrapError::Io {
            path: retired.clone(),
            source,
        })?;
    }
    Ok(())
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

/// Applies the ownership model of [`crate::ownership`]. A non-root bootstrap (tests, an installer
/// context that already owns the directory) cannot chown and nothing is changed; once the host
/// directory itself was taken over, any entry that could not be secured fails the bootstrap.
fn apply_ownership(
    host_dir: &Path,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<(), BootstrapError> {
    let (Some(uid), Some(gid)) = (uid, gid) else {
        return Ok(());
    };
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
        assert!(matches!(
            downgrade(&FakePlatform::systemd(), &options).await,
            Err(BootstrapError::Incomplete(_))
        ));
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
