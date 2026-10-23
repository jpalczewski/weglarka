//! Ustalanie ścieżek: `weglarka.toml` i socketu admin API (flaga > env > plik konfiguracji).

use std::path::{Path, PathBuf};

use weglarka_core::config::HostConfig;

use crate::error::{CliError, Kind};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/weglarka/weglarka.toml";

#[derive(Debug, Clone, Default)]
pub struct Overrides {
    pub config: Option<PathBuf>,
    pub socket: Option<PathBuf>,
}

/// Wczytuje i parsuje `weglarka.toml`.
pub fn load_config(path: &Path) -> Result<HostConfig, CliError> {
    let src = std::fs::read_to_string(path).map_err(|e| {
        CliError::new(
            Kind::Config,
            format!("cannot read config {}: {e}", path.display()),
        )
        .with_hint("podaj plik przez --config / WEGLARKA_CONFIG albo wskaż socket przez --socket / WEGLARKA_SOCKET")
    })?;
    HostConfig::from_toml_str(&src).map_err(|e| {
        CliError::new(
            Kind::Config,
            format!("invalid config {}: {e}", path.display()),
        )
        .with_hint(
            "wymagane sekcje: [ingress], [admin], [webhook]; przykład: notatka MVP (pF8HCwa)",
        )
    })
}

impl Overrides {
    pub fn config_path(&self) -> PathBuf {
        self.config
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH))
    }

    /// Socket admin API: `--socket` > `admin.socket` z konfiguracji.
    pub fn admin_socket(&self) -> Result<PathBuf, CliError> {
        if let Some(s) = &self.socket {
            return Ok(s.clone());
        }
        Ok(load_config(&self.config_path())?.admin.socket)
    }
}
