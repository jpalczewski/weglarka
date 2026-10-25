//! Path resolution: `weglarka.toml` and the admin API socket (flag > env > config file).

use std::path::{Path, PathBuf};

use weglarka_core::config::HostConfig;

use crate::error::{CliError, Kind};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/weglarka/weglarka.toml";

#[derive(Debug, Clone, Default)]
pub struct Overrides {
    pub config: Option<PathBuf>,
    pub socket: Option<PathBuf>,
}

/// Loads and parses `weglarka.toml`.
pub fn load_config(path: &Path) -> Result<HostConfig, CliError> {
    let src = std::fs::read_to_string(path).map_err(|e| {
        CliError::new(
            Kind::Config,
            format!("cannot read config {}: {e}", path.display()),
        )
        .with_hint("pass the file with --config / WEGLARKA_CONFIG or point to the socket with --socket / WEGLARKA_SOCKET")
    })?;
    HostConfig::from_toml_str(&src).map_err(|e| {
        CliError::new(
            Kind::Config,
            format!("invalid config {}: {e}", path.display()),
        )
        .with_hint(
            "required sections: [ingress], [admin], [webhook]; example: docs/install.md (Host configuration)",
        )
    })
}

impl Overrides {
    pub fn config_path(&self) -> PathBuf {
        self.config
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH))
    }

    /// Admin API socket: `--socket` > `admin.socket` from the config.
    pub fn admin_socket(&self) -> Result<PathBuf, CliError> {
        if let Some(s) = &self.socket {
            return Ok(s.clone());
        }
        Ok(load_config(&self.config_path())?.admin.socket)
    }
}
