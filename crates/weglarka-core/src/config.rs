//! `weglarka.toml` — konfiguracja hosta. Pisze człowiek/Ansible, demon tylko czyta.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

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
}

impl HostConfig {
    pub fn from_toml_str(src: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(src)
    }
}

/// Lokalizacja plików stanu: `apps.toml`, `state.toml`, `secrets.toml` (i katalog nginxa).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateConfig {
    /// Katalog danych; domyślnie katalog, w którym leży `weglarka.toml` (ustala to wywołujący,
    /// bo `HostConfig` nie zna ścieżki własnego pliku).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir: Option<PathBuf>,
}

impl StateConfig {
    /// Katalog stanu: `[state] dir` albo `fallback` (zwykle katalog configu).
    pub fn dir_or(&self, fallback: &Path) -> PathBuf {
        self.dir.clone().unwrap_or_else(|| fallback.to_owned())
    }
}

/// Rootless Podman pod konfigurowalnym userem (nazwa nie jest nigdzie zaszyta w kodzie).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    #[serde(default = "RuntimeConfig::default_user")]
    pub user: String,
    /// Socket libpod; domyślnie wyznacza go `Platform::runtime_socket`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket: Option<PathBuf>,
    /// Okres pętli reconcile (sekundy); dodatkowo reconcile ruszają zmiany stanu pożądanego.
    #[serde(default = "RuntimeConfig::default_reconcile_interval_secs")]
    pub reconcile_interval_secs: u64,
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
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngressMode {
    /// nginx Węglarki trzyma 80/443 (ACME — poza MVP).
    Edge,
    /// nginx na wysokim porcie za Traefikiem z Coolify.
    Behind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngressConfig {
    pub mode: IngressMode,
    /// Adres publikacji nginx na hoście, np. `172.17.0.1:8080`.
    pub bind: SocketAddr,
    /// Plik dynamicznej konfiguracji Traefika (tryb `behind`), nadpisywany w miejscu.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traefik_dynamic_file: Option<PathBuf>,
    /// Obraz kontenera nginx zarządzanego przez demona.
    #[serde(default = "IngressConfig::default_nginx_image")]
    pub nginx_image: String,
    /// Katalog hosta z `nginx.conf` (montowany do kontenera nginx); domyślnie `<state dir>/nginx`.
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
    /// Socket unix admin API (nigdy wystawiany przez nginx).
    pub socket: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    /// Adres listenera webhooków (wewnątrz kontenera Węglarki).
    pub listen: SocketAddr,
    /// Domena publiczna; wystawiane tylko ścieżki webhooków.
    pub domain: String,
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
    fn rejects_unknown_fields() {
        let bad = SAMPLE.replace("[platform]", "[platform]\nbogus = true");
        assert!(HostConfig::from_toml_str(&bad).is_err());
    }
}
