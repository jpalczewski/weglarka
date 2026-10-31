//! Path resolution: `weglarka.toml`, and where the admin API is: the local socket or a remote host.

use std::path::{Path, PathBuf};

use weglarka_model::config::HostConfig;

use crate::error::{CliError, Kind};
use crate::user_config::UserConfig;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/weglarka/weglarka.toml";

#[derive(Debug, Clone, Default)]
pub struct Overrides {
    pub config: Option<PathBuf>,
    pub socket: Option<PathBuf>,
    /// `--host` / `WEGLARKA_HOST`: a remote host's admin panel.
    pub host: Option<String>,
}

/// Where the admin API is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Socket(PathBuf),
    /// A remote host reached through its panel (docs/decisions/0060).
    Host(String),
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

    /// The remote host, if one is named: `--host` / `WEGLARKA_HOST`, else `host` in `cli.toml`.
    pub fn host_name(&self) -> Result<Option<String>, CliError> {
        if let Some(host) = &self.host {
            return Ok(Some(host.clone()));
        }
        Ok(UserConfig::load_default()?.host)
    }

    /// `--socket` (or `WEGLARKA_SOCKET`; an explicit `--host` has already dropped the variable) > `--host` (or `WEGLARKA_HOST`) > `host` in `cli.toml` >
    /// `admin.socket` from the host config. A socket named on the command line is never
    /// overridden by a `cli.toml` default.
    pub fn target(&self) -> Result<Target, CliError> {
        if let Some(socket) = &self.socket {
            return Ok(Target::Socket(socket.clone()));
        }
        match self.host_name()? {
            Some(host) => Ok(Target::Host(host)),
            None => Ok(Target::Socket(self.admin_socket()?)),
        }
    }

    /// Admin API socket: `--socket` > `admin.socket` from the config.
    pub fn admin_socket(&self) -> Result<PathBuf, CliError> {
        if let Some(s) = &self.socket {
            return Ok(s.clone());
        }
        Ok(load_config(&self.config_path())?.admin.socket)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_named_host_or_socket_decides_without_reading_any_file() {
        let host = Overrides {
            host: Some("https://panel.example.com".into()),
            ..Overrides::default()
        };
        assert_eq!(
            host.target().unwrap(),
            Target::Host("https://panel.example.com".into())
        );
        let socket = Overrides {
            socket: Some("/run/w.sock".into()),
            ..Overrides::default()
        };
        assert_eq!(
            socket.target().unwrap(),
            Target::Socket("/run/w.sock".into())
        );
    }
}
