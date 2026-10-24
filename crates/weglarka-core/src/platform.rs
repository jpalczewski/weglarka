//! Trait `Platform` — differences between init systems (MVP: systemd; later OpenRC/Alpine).
//! Podman events and healthchecks are shared by both; this covers only the Węglarka service and the socket.

use std::future::Future;
use std::path::PathBuf;

use crate::config::PlatformKind;

#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    #[error("platform {0:?} is not supported")]
    Unsupported(PlatformKind),
    #[error("platform command failed: {0}")]
    Command(String),
    #[error("platform i/o error: {0}")]
    Io(String),
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

    /// Enables (or disables) a user timer and starts (stops) it now.
    fn set_timer(&self, name: &str, enabled: bool) -> impl Future<Output = Result<()>> + Send;
}
