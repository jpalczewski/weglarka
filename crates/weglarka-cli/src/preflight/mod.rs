//! `weglarka doctor --preflight` — host checks without the daemon.
//!
//! Each check is a separate type behind the [`Check`] trait (dyn-compatible, synchronous);
//! host access (files, commands, the Podman socket, env) goes exclusively through [`Host`],
//! so tests substitute [`testing::FakeHost`]. A new init system (OpenRC) = new checks +
//! a branch in [`all_checks`].

mod checks;
pub(crate) mod host;
mod parse;
#[cfg(test)]
pub mod testing;

use std::path::PathBuf;

use weglarka_api::{CheckStatus, DoctorCheck, DoctorReport};
use weglarka_model::config::{HostConfig, PlatformKind, RuntimeConfig};

pub use host::{Host, RealHost};

use crate::settings::{Overrides, load_config};

/// Result of determining who the runtime user is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeUser {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
}

/// Shared context for the checks.
pub struct Context<'a> {
    pub host: &'a dyn Host,
    pub config_path: PathBuf,
    pub config: Option<HostConfig>,
    pub config_error: Option<String>,
    pub runtime: RuntimeConfig,
    pub platform: PlatformKind,
    pub user: Option<RuntimeUser>,
    pub secrets_path: PathBuf,
    pub apps_path: PathBuf,
    /// `[state] dir` or the directory of `weglarka.toml` (the same rule the daemon applies).
    pub state_dir: PathBuf,
}

impl<'a> Context<'a> {
    pub fn build(
        host: &'a dyn Host,
        config_path: PathBuf,
        config: Result<HostConfig, String>,
        secrets_file: Option<PathBuf>,
    ) -> Self {
        let (config, config_error) = match config {
            Ok(c) => (Some(c), None),
            Err(e) => (None, Some(e)),
        };
        let runtime = config
            .as_ref()
            .map(|c| c.runtime.clone())
            .unwrap_or_default();
        let platform = config
            .as_ref()
            .map_or(PlatformKind::Systemd, |c| c.platform.kind);
        let user = parse::lookup_user(host, &runtime.user);
        let config_dir = config_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        let state_dir = config
            .as_ref()
            .map_or_else(|| config_dir.to_owned(), |c| c.state.dir_or(config_dir));
        let secrets_path = secrets_file.unwrap_or_else(|| state_dir.join("secrets.toml"));
        let apps_path = state_dir.join("apps.toml");
        Self {
            host,
            config_path,
            config,
            config_error,
            runtime,
            platform,
            user,
            secrets_path,
            apps_path,
            state_dir,
        }
    }

    /// Host directory with `nginx.conf` and, in `edge`, its `tls/` and `acme/` subdirectories:
    /// `[ingress] nginx_conf_dir` verbatim or `<state dir>/nginx` — the same rule as the daemon
    /// (`daemon/src/settings.rs`). A relative value is used verbatim; `nginx_conf_dir` is documented
    /// as absolute.
    pub fn nginx_conf_dir(&self) -> PathBuf {
        self.config
            .as_ref()
            .and_then(|c| c.ingress.nginx_conf_dir.clone())
            .unwrap_or_else(|| self.state_dir.join("nginx"))
    }

    /// libpod socket: `runtime.socket` or the systemd default
    /// (`/run/user/<uid>/podman/podman.sock`).
    pub fn podman_socket(&self) -> Option<PathBuf> {
        if let Some(s) = &self.runtime.socket {
            return Some(s.clone());
        }
        self.user
            .as_ref()
            .map(|u| PathBuf::from(format!("/run/user/{}/podman/podman.sock", u.uid)))
    }
}

/// A single check. Adding a new one = a new type + an entry in [`all_checks`].
pub trait Check {
    /// Stable identifier (`runtime.subuid`) — goes into `DoctorCheck::id`.
    fn id(&self) -> &'static str;
    /// Whether the check makes sense in this configuration (e.g. linger only for systemd).
    fn applies(&self, _cx: &Context<'_>) -> bool {
        true
    }
    fn run(&self, cx: &Context<'_>) -> DoctorCheck;
}

pub fn all_checks() -> Vec<Box<dyn Check>> {
    use checks::*;
    vec![
        Box::new(ConfigFile),
        Box::new(RuntimeUserExists),
        Box::new(SubIds::uid()),
        Box::new(SubIds::gid()),
        Box::new(CgroupsV2),
        Box::new(Linger),
        Box::new(PodmanSocket),
        Box::new(PodmanApiVersion),
        Box::new(PodmanSource),
        Box::new(Netavark),
        Box::new(Pasta),
        Box::new(AppArmorUserns),
        Box::new(TraefikFile),
        Box::new(IngressConfigCheck),
        Box::new(IngressTls),
        Box::new(IngressPrivilegedPorts),
        Box::new(BindAddress),
        Box::new(BindFree),
        Box::new(TraefikSync),
        Box::new(HostPortsFree),
        Box::new(SecretsFile),
    ]
}

pub fn run_checks(cx: &Context<'_>, checks: &[Box<dyn Check>]) -> DoctorReport {
    DoctorReport {
        checks: checks
            .iter()
            .filter(|c| c.applies(cx))
            .map(|c| c.run(cx))
            .collect(),
    }
}

/// Entry point of `doctor --preflight` on the real host.
pub fn run_local(overrides: &Overrides, secrets_file: Option<PathBuf>) -> DoctorReport {
    let path = overrides.config_path();
    let config = load_config(&path).map_err(|e| e.message);
    let host = RealHost;
    let cx = Context::build(&host, path, config, secrets_file);
    run_checks(&cx, &all_checks())
}

// ---- building results ----

pub fn ok(id: &str, message: impl Into<String>) -> DoctorCheck {
    DoctorCheck::ok(id, message)
}

pub fn info(id: &str, message: impl Into<String>) -> DoctorCheck {
    DoctorCheck::info(id, message)
}

pub fn warn(id: &str, message: impl Into<String>, hint: impl Into<String>) -> DoctorCheck {
    DoctorCheck::warn(id, message).with_hint(hint)
}

pub fn fail(id: &str, message: impl Into<String>, hint: impl Into<String>) -> DoctorCheck {
    DoctorCheck::fail(id, message).with_hint(hint)
}

/// Text rendering of the report (shared by `doctor` and `doctor --preflight`).
pub fn render(report: &DoctorReport) -> String {
    let width = report.checks.iter().map(|c| c.id.len()).max().unwrap_or(0);
    let mut out = String::new();
    for c in &report.checks {
        let tag = match c.status {
            CheckStatus::Ok => " OK ",
            CheckStatus::Info => "INFO",
            CheckStatus::Warn => "WARN",
            CheckStatus::Fail => "FAIL",
        };
        out.push_str(&format!("[{tag}] {:<width$}  {}\n", c.id, c.message));
        if let Some(h) = &c.hint {
            out.push_str(&format!("       {:<width$}  hint: {h}\n", ""));
        }
    }
    let (mut ok_n, mut info_n, mut warn_n, mut fail_n) = (0, 0, 0, 0);
    for c in &report.checks {
        match c.status {
            CheckStatus::Ok => ok_n += 1,
            CheckStatus::Info => info_n += 1,
            CheckStatus::Warn => warn_n += 1,
            CheckStatus::Fail => fail_n += 1,
        }
    }
    out.push_str(&format!(
        "\n{ok_n} ok, {info_n} info, {warn_n} warn, {fail_n} fail\n"
    ));
    out
}
