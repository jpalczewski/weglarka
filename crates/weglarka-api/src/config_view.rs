//! `GET /v1/config`: the host configuration as an operator panel may see it.
//!
//! An allow-list (docs/decisions/0057 decision 8). The daemon builds it by destructuring every field
//! of `HostConfig` and of each section, so a new field does not compile until someone decides whether
//! the panel may see it.
//!
//! Left out on purpose: every filesystem path of the host layout, the account, the ntfy
//! URL/topic/token, the ACME contact address, the trusted proxy ranges and the internal identity
//! upstream address. The names of the groups that map to the `read`/`admin` scopes are left out too
//! (only their number is shown). The one path that is shown is the operator-chosen `host_mounts`
//! allowlist. Where a hidden value matters, a flag says whether it is set.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use weglarka_model::app::InstanceName;
use weglarka_model::config::{
    CdnProvider, DnsProviderKind, IdentityProvider, IngressMode, PlatformKind,
};
use weglarka_model::events::Severity;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigView {
    pub runtime: RuntimeView,
    pub ingress: IngressView,
    pub admin: AdminView,
    pub webhook: WebhookView,
    pub platform: PlatformView,
    /// `config_root` is set: apps may mount config files from the host.
    pub host_configs: bool,
    /// `[notify]`; absent = off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notify: Option<NotifyView>,
    pub monitor: MonitorView,
    /// `[self_update]`; absent = off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_update: Option<SelfUpdateView>,
    /// `[acme]`; absent = off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acme: Option<AcmeView>,
    /// `[identity]`; absent = off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeView {
    pub reconcile_interval_secs: u64,
    pub allow_privileged_host_ports: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dependency_wait_secs: Option<u32>,
    /// Host paths an app may mount read-only (`host_mounts`).
    pub host_mounts: Vec<PathBuf>,
    /// Group names an app may request (`group_add`).
    pub group_add: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressView {
    pub mode: IngressMode,
    pub bind: SocketAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub https_bind: Option<SocketAddr>,
    pub nginx_image: String,
    /// `trusted_proxies` overrides the default ranges. The CIDRs are not shown: in `behind` mode
    /// they are the proxy network, and they decide whose `X-Forwarded-*` is trusted (ADR 0007).
    pub custom_trusted_proxies: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cdn: Option<CdnView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CdnView {
    pub provider: CdnProvider,
    /// The edge ranges are pinned in the config (otherwise the bundled list applies).
    pub pinned_ranges: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminView {
    /// `[admin.http]`; absent = only the unix socket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<AdminHttpView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminHttpView {
    /// Instances that get the token socket mounted.
    pub clients: Vec<InstanceName>,
    pub audience: String,
    /// How many groups map to `read` / `admin`; the names are not shown.
    pub read_groups: usize,
    pub admin_groups: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookView {
    pub domain: String,
    /// `[webhook.forgejo]` registry host; absent = the Forgejo route is off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forgejo_registry: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformView {
    pub kind: PlatformKind,
    pub memory: String,
    pub pids_limit: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotifyView {
    pub dedup_window_secs: u64,
    /// ntfy channel; absent = `[notify]` has no channel and is treated as disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ntfy: Option<NtfyView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NtfyView {
    pub min_severity: Severity,
    /// An access token file is configured. URL, host, topic and the file are not shown.
    pub authenticated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorView {
    pub crash_loop_restarts: u32,
    pub crash_loop_window_secs: u64,
    pub unhealthy_observations: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfUpdateView {
    pub image: String,
    pub enabled: bool,
    pub interval_secs: u64,
    pub fallback: bool,
    pub fallback_timeout_secs: u64,
    /// A public key file overrides the embedded cosign key.
    pub custom_public_key: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcmeView {
    pub enabled: bool,
    pub directory_url: String,
    pub renew_before_days: u64,
    pub check_interval_secs: u64,
    /// A contact address is configured; the address is not shown.
    pub has_contact: bool,
    /// `[acme.dns]`; absent = HTTP-01 per domain only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<AcmeDnsView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcmeDnsView {
    pub provider: DnsProviderKind,
    pub wildcards: Vec<String>,
    pub propagation_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityView {
    pub provider: IdentityProvider,
    pub instance: InstanceName,
    pub issuer: String,
    /// `upstream` is set; the internal address itself is not shown.
    pub custom_upstream: bool,
}
