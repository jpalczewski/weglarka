//! Loading `weglarka.toml` and deriving paths (state, secrets, nginx directory, config root).

use std::path::{Path, PathBuf};

use weglarka_core::config::HostConfig;
use weglarka_core::state::StatePaths;

#[derive(Debug, thiserror::Error)]
pub enum SettingsError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid {path}: {message}")]
    Parse { path: PathBuf, message: String },
}

/// Paths of the files the daemon reads and writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    pub state_dir: PathBuf,
    pub state: StatePaths,
    pub secrets: PathBuf,
    /// Host directory with `nginx.conf` (mounted into the nginx container).
    pub nginx_conf_dir: PathBuf,
    /// Durable queue of notifications that have not been delivered yet (issue #38).
    pub notifications: PathBuf,
    /// ACME account credentials (`[acme]`, issue #96): `0600`, outside the webroot and `tls/`.
    pub acme_account_key: PathBuf,
    /// Host directory with the apps' config files/directories (issue #118), resolved from
    /// `weglarka.toml`'s `config_root`. `None` = config mounts are off.
    pub config_root: Option<PathBuf>,
}

impl Paths {
    pub fn resolve(host: &HostConfig, config_path: &Path) -> Self {
        let config_dir = config_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let state_dir = host.state.dir_or(config_dir);
        // `config_root` may be relative to the `weglarka.toml` directory (ADR 0022): the daemon
        // usually runs in another container, so its cwd says nothing about the host layout.
        let config_root = host.config_root.as_ref().map(|root| {
            if root.is_absolute() {
                root.clone()
            } else {
                config_dir.join(root)
            }
        });
        Self {
            state: StatePaths::in_dir(&state_dir),
            secrets: state_dir.join("secrets.toml"),
            nginx_conf_dir: host
                .ingress
                .nginx_conf_dir
                .clone()
                .unwrap_or_else(|| state_dir.join("nginx")),
            notifications: state_dir.join("notifications.toml"),
            acme_account_key: state_dir.join("acme").join("account.key"),
            config_root,
            state_dir,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub host: HostConfig,
    pub config_path: PathBuf,
    pub paths: Paths,
}

impl Settings {
    pub fn load(config_path: impl Into<PathBuf>) -> Result<Self, SettingsError> {
        let config_path = config_path.into();
        let src = std::fs::read_to_string(&config_path).map_err(|source| SettingsError::Read {
            path: config_path.clone(),
            source,
        })?;
        let host = HostConfig::from_toml_str(&src).map_err(|e| SettingsError::Parse {
            path: config_path.clone(),
            message: e.to_string(),
        })?;
        Ok(Self::from_host(host, config_path))
    }

    pub fn from_host(host: HostConfig, config_path: PathBuf) -> Self {
        let paths = Paths::resolve(&host, &config_path);
        Self {
            host,
            config_path,
            paths,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = r#"
[ingress]
mode = "behind"
bind = "172.17.0.1:8080"
[admin]
socket = "/run/x/admin.sock"
[webhook]
listen = "0.0.0.0:9180"
domain = "w.example.eu"
"#;

    #[test]
    fn paths_default_next_to_config() {
        let host = HostConfig::from_toml_str(HOST).unwrap();
        let p = Paths::resolve(&host, Path::new("/etc/weglarka/weglarka.toml"));
        assert_eq!(p.state.apps, Path::new("/etc/weglarka/apps.toml"));
        assert_eq!(p.secrets, Path::new("/etc/weglarka/secrets.toml"));
        assert_eq!(p.nginx_conf_dir, Path::new("/etc/weglarka/nginx"));
    }

    #[test]
    fn state_dir_overrides_default() {
        let host =
            HostConfig::from_toml_str(&format!("{HOST}\n[state]\ndir = \"/var/lib/weglarka\"\n"))
                .unwrap();
        let p = Paths::resolve(&host, Path::new("/etc/weglarka/weglarka.toml"));
        assert_eq!(p.state.state, Path::new("/var/lib/weglarka/state.toml"));
        assert_eq!(p.secrets, Path::new("/var/lib/weglarka/secrets.toml"));
    }

    #[test]
    fn config_root_is_optional() {
        let host = HostConfig::from_toml_str(HOST).unwrap();
        let p = Paths::resolve(&host, Path::new("/etc/weglarka/weglarka.toml"));
        assert_eq!(p.config_root, None);
    }

    #[test]
    fn config_root_absolute_stays_absolute() {
        let host =
            HostConfig::from_toml_str(&format!("config_root = \"/srv/weglarka/config\"\n{HOST}"))
                .unwrap();
        let p = Paths::resolve(&host, Path::new("/etc/weglarka/weglarka.toml"));
        assert_eq!(
            p.config_root.as_deref(),
            Some(Path::new("/srv/weglarka/config"))
        );
    }

    #[test]
    fn config_root_relative_is_resolved_against_the_config_directory() {
        let host =
            HostConfig::from_toml_str(&format!("config_root = \"configs\"\n{HOST}")).unwrap();
        let p = Paths::resolve(&host, Path::new("/etc/weglarka/weglarka.toml"));
        assert_eq!(
            p.config_root.as_deref(),
            Some(Path::new("/etc/weglarka/configs"))
        );
        // A `weglarka.toml` given without a directory: relative to the current directory.
        let p = Paths::resolve(&host, Path::new("weglarka.toml"));
        assert_eq!(p.config_root.as_deref(), Some(Path::new("./configs")));
    }
}
