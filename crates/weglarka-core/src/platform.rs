//! Trait `Platform` — różnice między systemami init (MVP: systemd; później OpenRC/Alpine).
//! Zdarzenia Podmana i healthchecki są wspólne dla obu; tu tylko serwis Węglarki i socket.

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

/// Opis serwisu uruchamiającego kontener Węglarki (quadlet usera / skrypt OpenRC).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSpec {
    pub name: String,
    pub image: String,
    pub run_as_user: String,
    /// Zmienne środowiskowe i montowania podaje demon; Platform tylko je serializuje.
    pub env: Vec<(String, String)>,
    /// `(źródło na hoście, ścieżka w kontenerze)`; opcje (np. `:ro`) dopisuje się do ścieżki kontenera.
    pub mounts: Vec<(String, String)>,
    /// Sieci Podmana, do których dołącza kontener (np. `net-weglarka`).
    pub networks: Vec<String>,
    /// Argumenty polecenia kontenera (po entrypoincie obrazu).
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

pub trait Platform: Send + Sync {
    fn kind(&self) -> PlatformKind;

    /// Socket libpod dla usera runtime'u (np. `/run/user/<uid>/podman/podman.sock`).
    fn runtime_socket(&self, runtime_user: &str) -> impl Future<Output = Result<PathBuf>> + Send;

    fn install_service(&self, spec: &ServiceSpec) -> impl Future<Output = Result<()>> + Send;
    fn remove_service(&self, name: &str) -> impl Future<Output = Result<()>> + Send;
    fn service_status(&self, name: &str) -> impl Future<Output = Result<ServiceStatus>> + Send;
}
