//! `weglarka.toml` — host configuration. Written by a human/Ansible; the daemon only reads it.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::events::Severity;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostConfig {
    #[serde(default)]
    pub runtime: RuntimeConfig,
    pub ingress: IngressConfig,
    pub admin: AdminConfig,
    pub webhook: WebhookConfig,
    #[serde(default)]
    pub platform: PlatformConfig,
    #[serde(default)]
    pub state: StateConfig,
    /// Notifications; absent = off (the events only reach the daemon log).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify: Option<NotifyConfig>,
    /// Failure detection (crash loops, failing healthchecks); defaults apply when absent.
    #[serde(default)]
    pub monitor: MonitorConfig,
    /// Automatic update of Węglarka's own image; absent = off (issue #99, `docs/decisions/0027`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_update: Option<SelfUpdateConfig>,
}

impl HostConfig {
    pub fn from_toml_str(src: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(src)
    }
}

/// Location of the state files: `apps.toml`, `state.toml`, `secrets.toml` (and the nginx directory).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateConfig {
    /// Data directory; defaults to the directory containing `weglarka.toml` (set by the caller,
    /// since `HostConfig` does not know the path of its own file).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir: Option<PathBuf>,
}

impl StateConfig {
    /// State directory: `[state] dir` or `fallback` (usually the config directory).
    pub fn dir_or(&self, fallback: &Path) -> PathBuf {
        self.dir.clone().unwrap_or_else(|| fallback.to_owned())
    }
}

/// Rootless Podman under a configurable user (the name is not hard-coded anywhere).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    #[serde(default = "RuntimeConfig::default_user")]
    pub user: String,
    /// libpod socket; by default determined by `Platform::runtime_socket`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket: Option<PathBuf>,
    /// Reconcile loop period (seconds); reconcile is additionally triggered by desired-state changes.
    #[serde(default = "RuntimeConfig::default_reconcile_interval_secs")]
    pub reconcile_interval_secs: u64,
    /// Allow apps to publish host ports below 1024 (`host_ports`). Rootless Podman can only bind
    /// them on a host with `net.ipv4.ip_unprivileged_port_start=0`; unset/false rejects such ports
    /// in validation instead of failing at container start
    /// (`docs/decisions/0013-host-ports.md`).
    #[serde(default)]
    pub allow_privileged_host_ports: bool,
}

impl RuntimeConfig {
    fn default_reconcile_interval_secs() -> u64 {
        60
    }

    fn default_user() -> String {
        "weglarka".to_owned()
    }
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            user: Self::default_user(),
            socket: None,
            reconcile_interval_secs: Self::default_reconcile_interval_secs(),
            allow_privileged_host_ports: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngressMode {
    /// Węglarka's nginx holds 80/443 (ACME is out of the MVP).
    Edge,
    /// nginx na wysokim porcie za Traefikiem z Coolify.
    Behind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngressConfig {
    pub mode: IngressMode,
    /// nginx publish address on the host, e.g. `172.17.0.1:8080`.
    pub bind: SocketAddr,
    /// Plik dynamicznej konfiguracji Traefika (tryb `behind`), nadpisywany w miejscu.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traefik_dynamic_file: Option<PathBuf>,
    /// Image of the nginx container managed by the daemon.
    #[serde(default = "IngressConfig::default_nginx_image")]
    pub nginx_image: String,
    /// Host directory with `nginx.conf` (mounted into the nginx container); defaults to `<state dir>/nginx`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nginx_conf_dir: Option<PathBuf>,
    /// Peers (IPs/CIDRs) whose `X-Forwarded-*` nginx trusts. Empty = the generator's default
    /// (rootless Podman's port-forwarder networks, see `docs/decisions/0007`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_proxies: Vec<String>,
}

impl IngressConfig {
    pub fn default_nginx_image() -> String {
        "docker.io/library/nginx:1-alpine".to_owned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    /// Unix socket of the admin API (never exposed through nginx).
    pub socket: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    /// Webhook listener address (inside the Węglarka container).
    pub listen: SocketAddr,
    /// Public domain; only the webhook paths are exposed.
    pub domain: String,
    /// `[webhook.forgejo]`: enables `/webhook/forgejo/{instance}`. Absent = the route answers 404.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forgejo: Option<ForgejoWebhookConfig>,
}

/// Forgejo's `package` payload names the owner and the package but not the registry host, and
/// a host taken from a payload would let a signed event point a pull at another registry — so the
/// host comes from here (docs/decisions/0026).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForgejoWebhookConfig {
    /// Registry host (optionally `host:port`) the images are pulled from, e.g. `git.example.eu`.
    pub registry: String,
}

impl ForgejoWebhookConfig {
    /// The registry as a lower-case `host[:port]`; rejects schemes, paths and other surprises.
    pub fn registry_host(&self) -> Result<String, String> {
        let host = self.registry.trim().to_ascii_lowercase();
        let ok = !host.is_empty()
            && host.len() <= 253
            && !host.starts_with(['.', '-', ':'])
            && !host.ends_with(['.', '-', ':'])
            && host.matches(':').count() <= 1
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'));
        if ok {
            Ok(host)
        } else {
            Err(format!(
                "invalid [webhook.forgejo] registry {:?}: expected a bare host[:port]",
                self.registry
            ))
        }
    }
}

/// `[notify]`: where the daemon sends engine events (deploy ok/fail, rollback, …).
///
/// Delivery is at-least-once: a notification is written to a durable outbox before it is sent and
/// retried until ntfy accepts it or the attempts/time limits run out. Absent section = off.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotifyConfig {
    /// Repeated events of one app/kind are coalesced inside this window (seconds): the first one is
    /// sent immediately, the rest become a single summary when the window closes. `0` disables it.
    #[serde(default = "NotifyConfig::default_dedup_window_secs")]
    pub dedup_window_secs: u64,
    /// ntfy channel; `[notify]` without it is treated as disabled (warned about at startup).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ntfy: Option<NtfyConfig>,
}

impl NotifyConfig {
    fn default_dedup_window_secs() -> u64 {
        300
    }
}

impl Default for NotifyConfig {
    fn default() -> Self {
        Self {
            dedup_window_secs: Self::default_dedup_window_secs(),
            ntfy: None,
        }
    }
}

/// ntfy channel: the daemon publishes a JSON message to `<url>/`.
///
/// The token is **not** part of this file: `token_file` points at a 0600 file that the daemon reads
/// once at startup, so `weglarka.toml` (typically 0644) never holds a secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NtfyConfig {
    /// Base URL: `http://` or `https://`, `scheme://host[:port][/base]` (no userinfo/query/fragment).
    pub url: String,
    /// `Host` header and TLS server name when they differ from the URL's host — e.g. a self-hosted
    /// ntfy reached through the ingress container (`url = "http://weglarka-nginx:8080"`,
    /// `host = "ntfy.example.com"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// ntfy topic (`[A-Za-z0-9_-]{1,64}`).
    pub topic: String,
    /// File with an ntfy access token (mode 0600); read once at startup and never logged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_file: Option<PathBuf>,
    /// Lowest severity published to this channel; lower ones are dropped before dedup.
    #[serde(default)]
    pub min_severity: Severity,
}

/// `[monitor]`: which runtime observations become engine events (crash loops, failing healthchecks).
///
/// Detection is independent of notification delivery: with no `[notify]` channel the events still reach
/// the daemon log, so these thresholds are host policy, not channel policy. `0` disables a detector.
/// See `docs/decisions/0022-crash-loop-detection.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MonitorConfig {
    /// New container restarts inside the window that make it a crash loop.
    #[serde(default = "MonitorConfig::default_crash_loop_restarts")]
    pub crash_loop_restarts: u32,
    /// Window for the restart counter (seconds); also the quiet period that counts as recovery.
    #[serde(default = "MonitorConfig::default_crash_loop_window_secs")]
    pub crash_loop_window_secs: u64,
    /// Consecutive observations with a failing healthcheck before the app is reported unhealthy.
    #[serde(default = "MonitorConfig::default_unhealthy_observations")]
    pub unhealthy_observations: u32,
}

impl MonitorConfig {
    fn default_crash_loop_restarts() -> u32 {
        3
    }

    fn default_crash_loop_window_secs() -> u64 {
        600
    }

    fn default_unhealthy_observations() -> u32 {
        2
    }
}

/// `[self_update]`: Węglarka keeps its own image up to date (issue #99, `docs/decisions/0027`).
///
/// The section is read by the **host-side** switcher (`weglarka-daemon self-update`): the container has
/// no `systemctl` and no write access to its own service definition, so it cannot replace itself. The
/// daemon only reads the section for `doctor` (is the switcher configured, has it run recently).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfUpdateConfig {
    /// Image reference to follow, e.g. `ghcr.io/jpalczewski/weglarka:latest`. Must be a tag — the
    /// switcher resolves the digest and pins it in the service definition, so a digest here would
    /// never move again.
    pub image: String,
    /// `false` pauses the checks without removing the section.
    #[serde(default = "SelfUpdateConfig::default_enabled")]
    pub enabled: bool,
    /// Minimum time between two checks (seconds). The timer wakes the switcher more often; until this
    /// interval has passed it returns without touching the network.
    #[serde(default = "SelfUpdateConfig::default_interval_secs")]
    pub interval_secs: u64,
    /// PEM public key overriding the one embedded in the binary (`cosign.pub`) — for rotating the key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_file: Option<PathBuf>,
}

impl SelfUpdateConfig {
    /// Checks run at most hourly by default.
    pub const DEFAULT_INTERVAL_SECS: u64 = 3600;
    /// A shorter interval would hammer the registry; reject it instead of silently clamping.
    pub const MIN_INTERVAL_SECS: u64 = 300;

    fn default_enabled() -> bool {
        true
    }

    fn default_interval_secs() -> u64 {
        Self::DEFAULT_INTERVAL_SECS
    }

    /// Rejects a configuration that cannot work. Called at startup (inside the container) and by the
    /// switcher (on the host), so a typo stops Węglarka instead of silently never updating it.
    pub fn validate(&self) -> Result<(), String> {
        if self.image.is_empty() {
            return Err("[self_update] image is empty".to_owned());
        }
        if self.image.contains('@') {
            return Err(format!(
                "[self_update] image {:?} is a digest reference: give the tag to follow, the switcher \
                 pins the digest itself",
                self.image
            ));
        }
        // The tag is the part after the last '/' of the last segment (`localhost:5000/app:1`).
        let last_segment = self.image.rsplit('/').next().unwrap_or_default();
        if !last_segment.contains(':') {
            return Err(format!(
                "[self_update] image {:?} has no tag (expected e.g. ghcr.io/owner/weglarka:latest)",
                self.image
            ));
        }
        if self.interval_secs < Self::MIN_INTERVAL_SECS {
            return Err(format!(
                "[self_update] interval_secs must be at least {} (got {})",
                Self::MIN_INTERVAL_SECS,
                self.interval_secs
            ));
        }
        if self
            .public_key_file
            .as_ref()
            .is_some_and(|p| p.as_os_str().is_empty())
        {
            return Err("[self_update] public_key_file is empty".to_owned());
        }
        Ok(())
    }
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            crash_loop_restarts: Self::default_crash_loop_restarts(),
            crash_loop_window_secs: Self::default_crash_loop_window_secs(),
            unhealthy_observations: Self::default_unhealthy_observations(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformKind {
    Systemd,
    /// Zarezerwowane (Alpine); brak implementacji w MVP.
    Openrc,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformConfig {
    #[serde(default = "PlatformConfig::default_kind")]
    pub kind: PlatformKind,
    /// Memory limit of the Węglarka container (`podman run --memory`), e.g. `"128M"`; also applies to swap.
    #[serde(default = "PlatformConfig::default_memory")]
    pub memory: String,
    /// Process/thread limit of the Węglarka container (`--pids-limit`).
    #[serde(default = "PlatformConfig::default_pids_limit")]
    pub pids_limit: u32,
}

impl PlatformConfig {
    fn default_kind() -> PlatformKind {
        PlatformKind::Systemd
    }

    pub fn default_memory() -> String {
        "128M".to_owned()
    }

    fn default_pids_limit() -> u32 {
        256
    }
}

impl Default for PlatformConfig {
    fn default() -> Self {
        Self {
            kind: Self::default_kind(),
            memory: Self::default_memory(),
            pids_limit: Self::default_pids_limit(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[runtime]
user = "weglarka"

[ingress]
mode = "behind"
bind = "172.17.0.1:8080"
traefik_dynamic_file = "/data/coolify/proxy/dynamic/weglarka.yml"

[admin]
socket = "/run/user/1001/weglarka/admin.sock"

[webhook]
listen = "0.0.0.0:9180"
domain = "weglarka.descriptortable.eu"

[platform]
kind = "systemd"
"#;

    #[test]
    fn parses_sample_from_mvp_note() {
        insta::assert_json_snapshot!(HostConfig::from_toml_str(SAMPLE).unwrap());
    }

    #[test]
    fn forgejo_registry_is_optional_and_must_be_a_bare_host() {
        assert!(
            HostConfig::from_toml_str(SAMPLE)
                .unwrap()
                .webhook
                .forgejo
                .is_none()
        );
        let cfg = format!("{SAMPLE}\n[webhook.forgejo]\nregistry = \"Git.Example.eu:3000\"\n");
        let parsed = HostConfig::from_toml_str(&cfg).unwrap();
        let forgejo = parsed.webhook.forgejo.unwrap();
        assert_eq!(forgejo.registry_host().unwrap(), "git.example.eu:3000");
        for bad in [
            "",
            "https://git.example.eu",
            "git.example.eu/org",
            "a b",
            "x:1:2",
            "-x",
        ] {
            let c = ForgejoWebhookConfig {
                registry: bad.into(),
            };
            assert!(c.registry_host().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn trusted_proxies_are_optional_and_listed() {
        let cfg = SAMPLE.replace("[admin]", "trusted_proxies = [\"10.89.0.0/16\"]\n\n[admin]");
        let parsed = HostConfig::from_toml_str(&cfg).unwrap();
        assert_eq!(parsed.ingress.trusted_proxies, ["10.89.0.0/16"]);
        assert!(
            HostConfig::from_toml_str(SAMPLE)
                .unwrap()
                .ingress
                .trusted_proxies
                .is_empty()
        );
    }

    #[test]
    fn privileged_host_ports_are_opt_in() {
        assert!(
            !HostConfig::from_toml_str(SAMPLE)
                .unwrap()
                .runtime
                .allow_privileged_host_ports
        );
        let allowed = SAMPLE.replace(
            "[ingress]",
            "allow_privileged_host_ports = true\n\n[ingress]",
        );
        assert!(
            HostConfig::from_toml_str(&allowed)
                .unwrap()
                .runtime
                .allow_privileged_host_ports
        );
    }

    #[test]
    fn rejects_unknown_fields() {
        let bad = SAMPLE.replace("[platform]", "[platform]\nbogus = true");
        assert!(HostConfig::from_toml_str(&bad).is_err());
    }

    #[test]
    fn notifications_are_off_by_default_and_stay_out_of_the_serialized_config() {
        let cfg = HostConfig::from_toml_str(SAMPLE).unwrap();
        assert!(cfg.notify.is_none());
        assert!(!toml::to_string(&cfg).unwrap().contains("notify"));
    }

    #[test]
    fn the_notification_example_parses() {
        // `docs/examples/notify.toml` is a `weglarka.toml` excerpt: keep it valid.
        let example = include_str!("../../../docs/examples/notify.toml");
        let notify = HostConfig::from_toml_str(&format!("{SAMPLE}\n{example}"))
            .unwrap()
            .notify
            .unwrap();
        let ntfy = notify.ntfy.unwrap();
        assert_eq!(notify.dedup_window_secs, 300);
        assert_eq!(ntfy.topic, "weglarka");
        assert_eq!(ntfy.min_severity, Severity::Info);
        assert_eq!(ntfy.host, None, "the public URL is the documented default");
    }

    #[test]
    fn notify_section_parses_with_defaults() {
        let src = format!(
            "{SAMPLE}\n[notify.ntfy]\nurl = \"https://ntfy.example.com\"\ntopic = \"weglarka\"\n"
        );
        let notify = HostConfig::from_toml_str(&src).unwrap().notify.unwrap();
        assert_eq!(notify.dedup_window_secs, 300);
        let ntfy = notify.ntfy.unwrap();
        assert_eq!(ntfy.min_severity, Severity::Info);
        assert_eq!(ntfy.host, None);
        assert_eq!(ntfy.token_file, None);
    }

    #[test]
    fn notify_section_honours_all_options_and_rejects_unknown_fields() {
        let src = format!(
            "{SAMPLE}\n[notify]\ndedup_window_secs = 0\n\
             [notify.ntfy]\nurl = \"http://weglarka-nginx:8080\"\n\
             host = \"ntfy.example.com\"\ntopic = \"wg\"\n\
             token_file = \"/etc/weglarka/ntfy-token\"\nmin_severity = \"warning\"\n"
        );
        let ntfy = HostConfig::from_toml_str(&src)
            .unwrap()
            .notify
            .unwrap()
            .ntfy
            .unwrap();
        assert_eq!(ntfy.min_severity, Severity::Warning);
        assert_eq!(ntfy.host.as_deref(), Some("ntfy.example.com"));
        assert_eq!(
            ntfy.token_file.as_deref(),
            Some(std::path::Path::new("/etc/weglarka/ntfy-token"))
        );
        let bad = format!("{src}\nbogus = true\n");
        assert!(HostConfig::from_toml_str(&bad).is_err());
    }

    #[test]
    fn monitor_defaults_apply_when_the_section_is_absent() {
        let monitor = HostConfig::from_toml_str(SAMPLE).unwrap().monitor;
        assert_eq!(monitor.crash_loop_restarts, 3);
        assert_eq!(monitor.crash_loop_window_secs, 600);
        assert_eq!(monitor.unhealthy_observations, 2);
        assert_eq!(monitor, MonitorConfig::default());
    }

    #[test]
    fn monitor_section_parses_and_rejects_unknown_fields() {
        let src = format!(
            "{SAMPLE}\n[monitor]\ncrash_loop_restarts = 5\n\
             crash_loop_window_secs = 120\nunhealthy_observations = 0\n"
        );
        let monitor = HostConfig::from_toml_str(&src).unwrap().monitor;
        assert_eq!(monitor.crash_loop_restarts, 5);
        assert_eq!(monitor.crash_loop_window_secs, 120);
        assert_eq!(monitor.unhealthy_observations, 0, "0 disables the check");
        let bad = format!("{src}\nbogus = true\n");
        assert!(HostConfig::from_toml_str(&bad).is_err());
    }

    #[test]
    fn the_monitor_example_parses() {
        // `docs/examples/monitor.toml` is a `weglarka.toml` excerpt: keep it valid.
        let example = include_str!("../../../docs/examples/monitor.toml");
        let monitor = HostConfig::from_toml_str(&format!("{SAMPLE}\n{example}"))
            .unwrap()
            .monitor;
        assert_eq!(monitor.crash_loop_restarts, 3);
        assert_eq!(monitor.crash_loop_window_secs, 600);
        assert_eq!(monitor.unhealthy_observations, 2);
    }

    #[test]
    fn self_update_section_is_off_by_default_and_parses_with_defaults() {
        let cfg = HostConfig::from_toml_str(SAMPLE).unwrap();
        assert!(cfg.self_update.is_none());
        assert!(!toml::to_string(&cfg).unwrap().contains("self_update"));

        let src =
            format!("{SAMPLE}\n[self_update]\nimage = \"ghcr.io/jpalczewski/weglarka:latest\"\n");
        let su = HostConfig::from_toml_str(&src)
            .unwrap()
            .self_update
            .unwrap();
        assert!(
            su.enabled,
            "the section is the opt-in, so it starts enabled"
        );
        assert_eq!(su.interval_secs, SelfUpdateConfig::DEFAULT_INTERVAL_SECS);
        assert_eq!(su.public_key_file, None);
        su.validate().unwrap();
    }

    #[test]
    fn self_update_rejects_unknown_fields_and_unusable_images() {
        let bad =
            format!("{SAMPLE}\n[self_update]\nimage = \"ghcr.io/o/w:latest\"\nbogus = true\n");
        assert!(HostConfig::from_toml_str(&bad).is_err(), "unknown field");

        for (image, why) in [
            ("ghcr.io/o/w", "no tag"),
            ("ghcr.io/o/w@sha256:abc", "digest reference"),
            ("", "empty"),
        ] {
            let src = format!("{SAMPLE}\n[self_update]\nimage = \"{image}\"\n");
            let err = HostConfig::from_toml_str(&src)
                .unwrap()
                .self_update
                .unwrap()
                .validate()
                .unwrap_err();
            assert!(err.contains(why), "{image:?}: {err}");
        }

        let src =
            format!("{SAMPLE}\n[self_update]\nimage = \"ghcr.io/o/w:latest\"\ninterval_secs = 5\n");
        assert!(
            HostConfig::from_toml_str(&src)
                .unwrap()
                .self_update
                .unwrap()
                .validate()
                .is_err()
        );
    }

    #[test]
    fn the_self_update_example_parses() {
        // `docs/examples/self-update.toml` is a `weglarka.toml` excerpt: keep it valid.
        let example = include_str!("../../../docs/examples/self-update.toml");
        let su = HostConfig::from_toml_str(&format!("{SAMPLE}\n{example}"))
            .unwrap()
            .self_update
            .unwrap();
        assert!(su.enabled);
        su.validate().unwrap();
    }
}
