//! Trait `Platform` — differences between init systems (MVP: systemd; later OpenRC/Alpine).
//! Podman events and healthchecks are shared by both; this covers only the Węglarka service and the socket.

use std::future::Future;
use std::path::PathBuf;

use weglarka_model::app::Digest;
use weglarka_model::config::PlatformKind;

#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    #[error("platform {0:?} is not supported")]
    Unsupported(PlatformKind),
    #[error("platform command failed: {0}")]
    Command(String),
    #[error("platform i/o error: {0}")]
    Io(String),
    /// The installed adapter does not implement this v1 interface yet. Callers must treat it as an
    /// explicit unsupported capability, never as success.
    #[error("platform capability {0} is not implemented by this adapter")]
    NotImplemented(&'static str),
}

pub type Result<T, E = PlatformError> = std::result::Result<T, E>;

/// Description of the service that runs the Węglarka container (user quadlet / OpenRC script).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSpec {
    pub name: String,
    pub image: String,
    pub run_as_user: String,
    /// Environment variables and mounts are supplied by the daemon; Platform only serializes them.
    pub env: Vec<(String, String)>,
    /// `(host source, path in the container)`; options (e.g. `:ro`) are appended to the container path.
    pub mounts: Vec<(String, String)>,
    /// Podman networks the container joins (e.g. `net-weglarka`).
    pub networks: Vec<String>,
    /// Arguments of the container command (after the image entrypoint).
    pub args: Vec<String>,
    pub hardening: Hardening,
}

/// Hardening of the Węglarka container; Platform translates it into quadlet / `podman run` options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hardening {
    /// Read-only root filesystem (writes only to mounts and `tmpfs`).
    pub read_only: bool,
    pub drop_all_capabilities: bool,
    pub no_new_privileges: bool,
    pub tmpfs: Vec<String>,
    /// Memory limit (e.g. `128M`), also applies to swap.
    pub memory: Option<String>,
    pub pids_limit: Option<u32>,
}

impl Default for Hardening {
    fn default() -> Self {
        Self {
            read_only: true,
            drop_all_capabilities: true,
            no_new_privileges: true,
            tmpfs: vec!["/tmp".to_owned()],
            memory: None,
            pids_limit: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStatus {
    Active,
    Inactive,
    Failed,
    NotInstalled,
}

/// Typed scheduled job. Arbitrary remote shell commands are deliberately not part of this API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JobId {
    Update,
    Watchdog,
}

impl JobId {
    pub const fn as_str(self) -> &'static str {
        match self {
            JobId::Update => "update",
            JobId::Watchdog => "watchdog",
        }
    }
}

/// A periodic job the installer can provision. The runtime enable flag lives in
/// `runtime-jobs.toml`; cron/systemd entries themselves are installer-owned and never rewritten at
/// runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledJob {
    pub id: JobId,
    /// Fixed argument vector passed to the launcher; never a shell command.
    pub args: Vec<String>,
    /// Runtime user the job runs as.
    pub runtime_user: String,
    /// Minimal spacing between runs, in seconds.
    pub cadence_secs: u64,
    /// Skip this tick when the previous run is still alive.
    pub skip_if_running: bool,
}

/// Monotonic activation epoch. The service selection persists it, and observation reports the epoch
/// the running container actually carries, so an obsolete request cannot stop a newer container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ActivationEpoch(pub u64);

/// Acknowledgment of an activation **request**, not proof of readiness. Read
/// [`Platform::observe_service`] for the actual container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivationReceipt {
    pub epoch: ActivationEpoch,
}

/// Name of the daemon service the platform adapter manages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceName(String);

impl ServiceName {
    pub fn new(name: impl Into<String>) -> Result<Self, PlatformError> {
        let name = name.into();
        if name.is_empty() || name.len() > 255 {
            return Err(PlatformError::Command(
                "service name must be 1-255 characters".into(),
            ));
        }
        Ok(Self(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ServiceName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What is actually running, as observed — not what was requested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedService {
    pub name: ServiceName,
    pub container_id: Option<String>,
    pub image_id: Option<String>,
    pub digest: Option<Digest>,
    pub activation_epoch: Option<ActivationEpoch>,
    /// `None` when readiness is not available from this adapter.
    pub ready: Option<bool>,
}

/// A unit file to install verbatim: name and contents. The service itself is described by
/// [`ServiceSpec`]; this carries the extra units Węglarka needs (the self-update timer and its
/// oneshot service, issue #99) and the quadlet fragments the platform renders from a spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitFile {
    pub file_name: String,
    pub content: String,
}

pub trait Platform: Send + Sync {
    fn kind(&self) -> PlatformKind;

    /// libpod socket for the runtime user (e.g. `/run/user/<uid>/podman/podman.sock`).
    fn runtime_socket(&self, runtime_user: &str) -> impl Future<Output = Result<PathBuf>> + Send;

    fn install_service(&self, spec: &ServiceSpec) -> impl Future<Output = Result<()>> + Send;
    fn remove_service(&self, name: &str) -> impl Future<Output = Result<()>> + Send;
    fn service_status(&self, name: &str) -> impl Future<Output = Result<ServiceStatus>> + Send;

    /// Writes plain user units into the service manager's directory (not the quadlet directory) and
    /// reloads it. Used for the self-update timer and its service (issue #99); an existing file with
    /// the same name is replaced.
    fn install_user_units(&self, files: &[UnitFile]) -> impl Future<Output = Result<()>> + Send;

    /// Removes user units by file name; missing files are not an error.
    fn remove_user_units(&self, names: &[&str]) -> impl Future<Output = Result<()>> + Send;

    /// Restarts the service — the host-side switcher applies a new image this way, so a failed
    /// restart is the switcher's, not the container's, error to report.
    fn restart_service(&self, name: &str) -> impl Future<Output = Result<()>> + Send;

    /// Clears the service manager's failure state before a restart (systemd: `reset-failed`).
    ///
    /// A crash-looping service has exhausted its start limit, and a plain restart then fails with
    /// "start request repeated too quickly". The automatic fallback of the self-update watchdog has
    /// to restart exactly such a service (issue #100, `docs/decisions/0034`), so it clears the state
    /// first. A missing unit is not an error.
    fn reset_failed(&self, name: &str) -> impl Future<Output = Result<()>> + Send;

    /// Enables (or disables) a user timer and starts (stops) it now.
    fn set_timer(&self, name: &str, enabled: bool) -> impl Future<Output = Result<()>> + Send;

    /// Removes everything the launcher-based setup installed: the periodic jobs (and the cron
    /// block), the launcher-owned services and init scripts, and the user units and timers. The
    /// container service definition of `install_service` stays on systemd; `remove_service` owns it.
    ///
    /// Idempotent: missing pieces are not an error, so `remove` and `downgrade` can call it on a
    /// host in any state. Unrelated entries (other crontab lines) are preserved.
    fn remove_launcher_setup(&self) -> impl Future<Output = Result<()>> + Send;

    // Platform update v1 interfaces. Defaults fail explicitly so an adapter that has not grown the
    // capability yet cannot be mistaken for a working one.

    /// Installs the fixed periodic jobs. Idempotent; the argument vector is validated by the
    /// adapter, never evaluated as a shell command.
    fn install_jobs(&self, _jobs: &[ScheduledJob]) -> impl Future<Output = Result<()>> + Send {
        std::future::ready(Err(PlatformError::NotImplemented("install_jobs")))
    }

    /// Writes `runtime-jobs.toml`; never rewrites cron/init entries at runtime.
    fn set_job_enabled(
        &self,
        _id: JobId,
        _enabled: bool,
    ) -> impl Future<Output = Result<()>> + Send {
        std::future::ready(Err(PlatformError::NotImplemented("set_job_enabled")))
    }

    /// Persists the desired service selection (digest + epoch) and requests a restart. The receipt
    /// acknowledges the request, not readiness.
    fn activate_service(
        &self,
        _spec: ServiceSpec,
        _epoch: ActivationEpoch,
    ) -> impl Future<Output = Result<ActivationReceipt>> + Send {
        std::future::ready(Err(PlatformError::NotImplemented("activate_service")))
    }

    /// Observes the actual container: ID, image ID, digest, activation epoch and readiness when
    /// available. A healthy old container is not success.
    fn observe_service(
        &self,
        _name: ServiceName,
    ) -> impl Future<Output = Result<ObservedService>> + Send {
        std::future::ready(Err(PlatformError::NotImplemented("observe_service")))
    }
}
