//! `weglarka-daemon host-preflight` — the bounded, read-only report every host tool generation
//! implements.
//!
//! It answers exactly what the contract asks of a candidate/recovery generation: the host protocol,
//! the compiled state-schema support, whether it can read the v1 journal, and whether it parses the
//! **current** `weglarka.toml` (including `[self_update]`). It never writes a file, never contacts
//! the registry and never starts a container.
//!
//! The launcher runs it inside the selected generation directory; the JSON output is diagnostic,
//! the exit code is the verdict.

use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use serde::Serialize;
use weglarka_model::config::HostConfig;
use weglarka_model::platform_update::{HOST_PROTOCOL_VERSION, PlatformUpdate};

use crate::settings::Settings;

/// Format of the preflight JSON.
pub const FORMAT_VERSION: u32 = 1;

/// Journal readability, as reported by preflight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalStatus {
    /// No journal yet (a fresh/legacy install).
    Absent,
    /// A v1 journal parses.
    Readable,
    /// The file is present but cannot be read as v1.
    Unreadable { message: String },
}

/// OpenRC runtime prerequisites: the contract's preflight checks `XDG_RUNTIME_DIR`, its ownership
/// and the rootless Podman socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeCheck {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xdg_runtime_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owned_by_user: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub podman_socket: Option<bool>,
}

/// The preflight report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostPreflight {
    pub format_version: u32,
    pub host_protocol: u32,
    pub platform: &'static str,
    /// State schemas this binary can read (migrate forward from).
    pub state_read: Vec<u32>,
    /// State schema this binary writes.
    pub state_write: u32,
    pub journal: JournalStatus,
    pub config: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<RuntimeCheck>,
    /// The selected cron facility answers (OpenRC only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheduler: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl HostPreflight {
    /// Eligible for selection: v1 protocol, current configuration parses and the journal is
    /// readable.
    pub fn is_eligible(&self) -> bool {
        let base = self.host_protocol == HOST_PROTOCOL_VERSION
            && self.config == "readable"
            && matches!(
                self.journal,
                JournalStatus::Absent | JournalStatus::Readable
            );
        if self.platform == "openrc" {
            base && self
                .runtime
                .as_ref()
                .is_some_and(|r| r.owned_by_user == Some(true) && r.podman_socket == Some(true))
                && self.scheduler == Some(true)
        } else {
            base
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            "{\"format_version\":1,\"host_protocol\":1,\"state_read\":[],\"state_write\":0,\
             \"journal\":\"unreadable\",\"config\":\"readable\",\"error\":\"cannot encode report\"}"
                .to_owned()
        })
    }
}

/// Runs the read-only preflight for `config`, using the caller's runtime environment.
pub fn run(config: &Path) -> HostPreflight {
    run_with(
        config,
        std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .as_deref(),
        None,
    )
}

/// Testable core. `runtime_dir` is the rootless Podman runtime directory to verify; `scheduler` is
/// the already-probed cron facility for OpenRC (`None` for systemd). The production [`run`] probes
/// `rc-service crond status` / reads `XDG_RUNTIME_DIR`; tests inject the observation so they do not
/// depend on the host.
pub fn run_with(
    config: &Path,
    runtime_dir: Option<&Path>,
    scheduler: Option<bool>,
) -> HostPreflight {
    let state_read: Vec<u32> = (1..=weglarka_model::state::SCHEMA_VERSION).collect();
    let state_write = weglarka_model::state::SCHEMA_VERSION;
    let text = match std::fs::read_to_string(config) {
        Ok(text) => text,
        Err(e) => {
            return HostPreflight {
                format_version: FORMAT_VERSION,
                host_protocol: HOST_PROTOCOL_VERSION,
                platform: "unknown",
                state_read,
                state_write,
                journal: JournalStatus::Unreadable {
                    message: "configuration is unreadable, so the journal location is unknown"
                        .into(),
                },
                config: "unreadable",
                runtime: None,
                scheduler: None,
                error: Some(format!("cannot read {}: {e}", config.display())),
            };
        }
    };
    let host = match HostConfig::from_toml_str(&text) {
        Ok(host) => host,
        Err(e) => {
            return HostPreflight {
                format_version: FORMAT_VERSION,
                host_protocol: HOST_PROTOCOL_VERSION,
                platform: "unknown",
                state_read,
                state_write,
                journal: JournalStatus::Unreadable {
                    message: "configuration does not parse, so the journal location is unknown"
                        .into(),
                },
                config: "unparseable",
                runtime: None,
                scheduler: None,
                error: Some(format!("invalid {}: {e}", config.display())),
            };
        }
    };
    let platform = match host.platform.kind {
        weglarka_model::config::PlatformKind::Systemd => "systemd",
        weglarka_model::config::PlatformKind::Openrc => "openrc",
    };
    let scheduler = if platform == "openrc" {
        scheduler.or_else(probe_cron)
    } else {
        None
    };
    let runtime = if platform == "openrc" {
        // Bootstrap may run as root with no XDG_RUNTIME_DIR; fall back to the configured runtime
        // user's standard path so the installed prerequisites are what gets checked.
        let runtime_user = host.runtime.user.clone();
        let xdg = runtime_dir.map(Path::to_owned).or_else(|| {
            crate::bootstrap::lookup_user(&runtime_user)
                .map(|(uid, _)| PathBuf::from(format!("/run/user/{uid}")))
        });
        let xdg = xdg.as_deref();
        let expected_uid = crate::bootstrap::lookup_user(&runtime_user)
            .map(|(uid, _)| uid)
            .or_else(effective_uid);
        let runtime_user = expected_uid;
        let owned_by_user = xdg.map(|dir| {
            runtime_user.is_some_and(|uid| {
                std::fs::metadata(dir)
                    .map(|meta| meta.uid() == uid)
                    .unwrap_or(false)
            })
        });
        let podman_socket = xdg.map(|dir| {
            std::fs::metadata(dir.join("podman/podman.sock"))
                .map(|meta| meta.file_type().is_socket())
                .unwrap_or(false)
        });
        Some(RuntimeCheck {
            xdg_runtime_dir: xdg.map(|dir| dir.display().to_string()),
            owned_by_user,
            podman_socket,
        })
    } else {
        None
    };
    let settings = Settings::from_host(host, config.to_owned());
    let journal_path: PathBuf = settings
        .paths
        .state_dir
        .join(weglarka_model::platform_update::FILE_NAME);
    let journal = match std::fs::read_to_string(&journal_path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => JournalStatus::Absent,
        Err(e) => JournalStatus::Unreadable {
            message: format!("cannot read {}: {e}", journal_path.display()),
        },
        Ok(text) => match PlatformUpdate::parse(&text) {
            Ok(_) => JournalStatus::Readable,
            Err(e) => JournalStatus::Unreadable {
                message: e.to_string(),
            },
        },
    };
    HostPreflight {
        format_version: FORMAT_VERSION,
        host_protocol: HOST_PROTOCOL_VERSION,
        platform,
        state_read,
        state_write,
        journal,
        config: "readable",
        runtime,
        scheduler,
        error: None,
    }
}

/// Effective uid, read from `/proc` so no unsafe libc call is needed. On a host without `/proc`
/// the executable's owner is a safe approximation; `None` means ownership cannot be verified.
fn effective_uid() -> Option<u32> {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                line.strip_prefix("Uid:")
                    .and_then(|rest| rest.split_whitespace().next())
                    .and_then(|uid| uid.parse().ok())
            })
        })
        .or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|exe| std::fs::metadata(exe).ok())
                .map(|meta| meta.uid())
        })
}

/// Read-only probe of the selected cron facility (BusyBox `crond`).
fn probe_cron() -> Option<bool> {
    std::process::Command::new("rc-service")
        .args(["crond", "status"])
        .output()
        .ok()
        .map(|output| output.status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(dir: &Path) -> PathBuf {
        let path = dir.join("weglarka.toml");
        std::fs::write(
            &path,
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
                dir.join("state").display()
            ),
        )
        .unwrap();
        path
    }

    #[test]
    fn a_current_config_and_absent_journal_are_eligible() {
        let dir = tempfile::tempdir().unwrap();
        let report = run(&config(dir.path()));
        assert_eq!(report.config, "readable");
        assert_eq!(report.journal, JournalStatus::Absent);
        assert_eq!(report.host_protocol, 1);
        assert_eq!(report.state_write, weglarka_model::state::SCHEMA_VERSION);
        assert!(report.is_eligible());
    }

    #[test]
    fn a_newer_journal_and_an_unparseable_config_are_not_eligible() {
        let dir = tempfile::tempdir().unwrap();
        let path = config(dir.path());
        let state = dir.path().join("state");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(
            state.join(weglarka_model::platform_update::FILE_NAME),
            "format_version = 2\n",
        )
        .unwrap();
        let report = run(&path);
        assert!(matches!(report.journal, JournalStatus::Unreadable { .. }));
        assert!(!report.is_eligible());

        std::fs::write(&path, "[ingress]\nmode = \"edge\"\n").unwrap();
        let report = run(&path);
        assert_eq!(report.config, "unparseable");
        assert!(!report.is_eligible());
    }

    #[test]
    fn openrc_requires_the_runtime_directory_socket_and_scheduler() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("weglarka.toml");
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
[platform]
kind = "openrc"
"#,
                dir.path().display(),
                dir.path().join("state").display()
            ),
        )
        .unwrap();
        let runtime = dir.path().join("runtime");
        std::fs::create_dir_all(runtime.join("podman")).unwrap();
        let _socket =
            std::os::unix::net::UnixListener::bind(runtime.join("podman/podman.sock")).unwrap();
        // The socket path exists but is not a socket in this fixture: create one instead.
        drop(_socket);
        let _ = std::fs::remove_file(runtime.join("podman/podman.sock"));
        let _socket =
            std::os::unix::net::UnixListener::bind(runtime.join("podman/podman.sock")).unwrap();
        let report = run_with(&config, Some(&runtime), Some(true));
        assert_eq!(report.platform, "openrc");
        assert_eq!(report.scheduler, Some(true));
        assert_eq!(report.runtime.as_ref().unwrap().podman_socket, Some(true));
        assert!(report.is_eligible(), "{report:?}");

        let report = run_with(&config, Some(&runtime), Some(false));
        assert!(!report.is_eligible());
        let report = run_with(&config, None, Some(true));
        assert!(!report.is_eligible());
    }

    #[test]
    fn preflight_never_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = config(dir.path());
        let before = std::fs::read_to_string(&path).unwrap();
        let _ = run(&path);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
        assert!(!dir.path().join("state").exists());
    }
}
