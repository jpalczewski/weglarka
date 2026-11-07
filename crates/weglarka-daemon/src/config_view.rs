//! `GET /v1/config` (`read` scope): an allow-list view of `weglarka.toml` (docs/decisions/0057
//! decision 8).
//!
//! [`project`] destructures every field of `HostConfig` and of each section with no `..`: a field
//! added to the config does not compile until someone decides here whether the panel may see it.
//! A field the panel must not see is bound to `_` on purpose, with the reason next to it.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use weglarka_api::{
    AcmeDnsView, AcmeView, AdminHttpView, AdminView, CdnView, ConfigView, IdentityView,
    IngressView, MetricsView, MonitorView, NotifyView, NtfyView, PlatformView, RuntimeView,
    SelfUpdateView, WebhookView, endpoints,
};
use weglarka_model::config::{
    AcmeConfig, AcmeDnsConfig, AdminConfig, AdminHttpConfig, CdnConfig, ForgejoWebhookConfig,
    HostConfig, IdentityConfig, IngressConfig, MetricsConfig, MonitorConfig, NotifyConfig,
    NtfyConfig, PlatformConfig, RuntimeConfig, SelfUpdateConfig, StateConfig, WebhookConfig,
};
use weglarka_model::podman::PodmanClient;

use crate::app::Daemon;

pub fn routes<P: PodmanClient + 'static>() -> Router<Arc<Daemon<P>>> {
    Router::new().route(endpoints::CONFIG.path, get(show::<P>))
}

async fn show<P: PodmanClient + 'static>(State(d): State<Arc<Daemon<P>>>) -> Response {
    axum::Json(project(&d.host)).into_response()
}

pub(crate) fn project(host: &HostConfig) -> ConfigView {
    let HostConfig {
        runtime,
        ingress,
        admin,
        webhook,
        platform,
        // Layout of the host.
        state: StateConfig { dir: _ },
        config_root,
        notify,
        monitor,
        self_update,
        acme,
        identity,
        metrics,
        logs,
        // Static-site extraction limits are engine policy; they do not change the app's shape.
        sites: _,
    } = host;
    ConfigView {
        runtime: runtime_view(runtime),
        ingress: ingress_view(ingress),
        admin: admin_view(admin),
        webhook: webhook_view(webhook),
        platform: platform_view(platform),
        // Only whether the feature is on; the path is host layout.
        host_configs: config_root.is_some(),
        notify: notify.as_ref().map(notify_view),
        monitor: monitor_view(monitor),
        self_update: self_update.as_ref().map(self_update_view),
        acme: acme.as_ref().map(acme_view),
        identity: identity.as_ref().map(identity_view),
        metrics: metrics.as_ref().map(metrics_view),
        // Retention and the container log driver are read by `status`/`doctor`; the reader is part of
        // the app-facing contract (which instance may set `ingress_logs`).
        logs_reader: logs.reader.clone(),
    }
}

fn runtime_view(runtime: &RuntimeConfig) -> RuntimeView {
    let RuntimeConfig {
        // The runtime account name and the libpod socket path are host layout.
        user: _,
        socket: _,
        reconcile_interval_secs,
        allow_privileged_host_ports,
        dependency_wait_secs,
        host_mounts,
        group_add,
    } = runtime;
    RuntimeView {
        reconcile_interval_secs: *reconcile_interval_secs,
        allow_privileged_host_ports: *allow_privileged_host_ports,
        dependency_wait_secs: *dependency_wait_secs,
        host_mounts: host_mounts.clone(),
        group_add: group_add.clone(),
    }
}

fn ingress_view(ingress: &IngressConfig) -> IngressView {
    let IngressConfig {
        mode,
        bind,
        https_bind,
        // Paths of the host layout.
        traefik_dynamic_file: _,
        nginx_image,
        nginx_conf_dir: _,
        trusted_proxies,
        cdn,
    } = ingress;
    IngressView {
        mode: *mode,
        bind: *bind,
        https_bind: *https_bind,
        nginx_image: nginx_image.clone(),
        // The ranges are the proxy network topology and decide whose `X-Forwarded-*` is trusted.
        custom_trusted_proxies: !trusted_proxies.is_empty(),
        cdn: cdn.as_ref().map(|cdn| {
            let CdnConfig { provider, ranges } = cdn;
            CdnView {
                provider: *provider,
                pinned_ranges: ranges.len(),
            }
        }),
    }
}

fn admin_view(admin: &AdminConfig) -> AdminView {
    let AdminConfig {
        // Path of the host layout.
        socket: _,
        http,
    } = admin;
    AdminView {
        http: http.as_ref().map(|http| {
            let AdminHttpConfig {
                clients,
                audience,
                read_groups,
                admin_groups,
            } = http;
            AdminHttpView {
                clients: clients.clone(),
                audience: audience.clone(),
                // Which IdP group is `admin` is authorization policy: the count only.
                read_groups: read_groups.len(),
                admin_groups: admin_groups.len(),
            }
        }),
    }
}

fn webhook_view(webhook: &WebhookConfig) -> WebhookView {
    let WebhookConfig {
        // The in-container listen address carries no information for an operator.
        listen: _,
        domain,
        forgejo,
    } = webhook;
    WebhookView {
        domain: domain.clone(),
        forgejo_registry: forgejo
            .as_ref()
            .map(|ForgejoWebhookConfig { registry }| registry.clone()),
    }
}

fn platform_view(platform: &PlatformConfig) -> PlatformView {
    let PlatformConfig {
        kind,
        memory,
        pids_limit,
    } = platform;
    PlatformView {
        kind: *kind,
        memory: memory.clone(),
        pids_limit: *pids_limit,
    }
}

fn notify_view(notify: &NotifyConfig) -> NotifyView {
    let NotifyConfig {
        dedup_window_secs,
        ntfy,
    } = notify;
    NotifyView {
        dedup_window_secs: *dedup_window_secs,
        ntfy: ntfy.as_ref().map(|ntfy| {
            let NtfyConfig {
                // The URL can address an internal service, the topic is the only secret of a public
                // ntfy server, and the token file is a path to a credential.
                url: _,
                host: _,
                topic: _,
                token_file,
                token_secret,
                min_severity,
            } = ntfy;
            NtfyView {
                min_severity: *min_severity,
                // Either credential form counts (ADR 0080); neither is shown.
                authenticated: token_file.is_some() || token_secret.is_some(),
            }
        }),
    }
}

fn monitor_view(monitor: &MonitorConfig) -> MonitorView {
    let MonitorConfig {
        crash_loop_restarts,
        crash_loop_window_secs,
        unhealthy_observations,
    } = monitor;
    MonitorView {
        crash_loop_restarts: *crash_loop_restarts,
        crash_loop_window_secs: *crash_loop_window_secs,
        unhealthy_observations: *unhealthy_observations,
    }
}

fn self_update_view(self_update: &SelfUpdateConfig) -> SelfUpdateView {
    let SelfUpdateConfig {
        image,
        enabled,
        interval_secs,
        fallback,
        fallback_timeout_secs,
        public_key_file,
    } = self_update;
    SelfUpdateView {
        image: image.clone(),
        enabled: *enabled,
        interval_secs: *interval_secs,
        fallback: *fallback,
        fallback_timeout_secs: *fallback_timeout_secs,
        custom_public_key: public_key_file.is_some(),
    }
}

fn acme_view(acme: &AcmeConfig) -> AcmeView {
    let AcmeConfig {
        // Consent flag; the daemon refuses to start without it, so it carries no information.
        accept_terms: _,
        email,
        directory_url,
        enabled,
        renew_before_days,
        check_interval_secs,
        dns,
    } = acme;
    AcmeView {
        enabled: *enabled,
        directory_url: directory_url.clone(),
        renew_before_days: *renew_before_days,
        check_interval_secs: *check_interval_secs,
        // A personal address.
        has_contact: email.is_some(),
        dns: dns.as_ref().map(|dns| {
            let AcmeDnsConfig {
                provider,
                // Path to the DNS API credential.
                token_file: _,
                token_secret: _,
                wildcards,
                propagation_secs,
                prefer_wildcard,
            } = dns;
            AcmeDnsView {
                provider: *provider,
                wildcards: wildcards.clone(),
                propagation_secs: *propagation_secs,
                prefer_wildcard: *prefer_wildcard,
            }
        }),
    }
}

fn metrics_view(metrics: &MetricsConfig) -> MetricsView {
    let MetricsConfig {
        listen,
        network,
        scraper,
    } = metrics;
    MetricsView {
        listen: *listen,
        network: network.clone(),
        // A validated instance name, like `[identity] instance`.
        scraper: scraper.clone(),
    }
}

fn identity_view(identity: &IdentityConfig) -> IdentityView {
    let IdentityConfig {
        provider,
        instance,
        issuer,
        // Internal network topology.
        upstream,
        // #590: gated; the view gains it with the identity PR of #593.
        session_store: _,
    } = identity;
    IdentityView {
        provider: *provider,
        instance: instance.clone(),
        issuer: issuer.clone(),
        custom_upstream: upstream.is_some(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every value that must never reach the panel, recognizable in the output.
    const SECRETS: [&str; 15] = [
        "10.77.0.0/16",
        "/SECRET/traefik.yml",
        "SECRET-upstream",
        "SECRET-ntfy-topic",
        "secret-ntfy.internal",
        "SECRET-ntfy-host",
        "/SECRET/ntfy-token",
        "SECRET-acme-contact@example.org",
        "/SECRET/cloudflare-token",
        "SECRET-runtime-user",
        "/SECRET/libpod.sock",
        "/SECRET/state",
        "/SECRET/admin.sock",
        "SECRET-admin-group",
        "/SECRET/public.pem",
    ];

    const FIXTURE: &str = r#"
config_root = "/SECRET/config"

[runtime]
user = "SECRET-runtime-user"
socket = "/SECRET/libpod.sock"
host_mounts = ["/var/log/journal"]
group_add = ["systemd-journal"]

[ingress]
mode = "edge"
bind = "0.0.0.0:8080"
https_bind = "0.0.0.0:8443"
nginx_conf_dir = "/SECRET/nginx"

[ingress.cdn]
provider = "cloudflare"
ranges = ["173.245.48.0/20"]

[admin]
socket = "/SECRET/admin.sock"

[admin.http]
clients = ["panel"]
audience = "https://admin.example.com/api/"
read_groups = ["SECRET-admin-group"]
admin_groups = ["SECRET-admin-group"]

[webhook]
listen = "127.0.0.1:9000"
domain = "hooks.example.com"

[webhook.forgejo]
registry = "git.example.com"

[state]
dir = "/SECRET/state"

[notify]
dedup_window_secs = 30

[notify.ntfy]
url = "http://secret-ntfy.internal"
host = "SECRET-ntfy-host"
topic = "SECRET-ntfy-topic"
token_file = "/SECRET/ntfy-token"
min_severity = "warning"

[self_update]
image = "ghcr.io/example/weglarka:latest"
public_key_file = "/SECRET/public.pem"

[acme]
accept_terms = true
email = "SECRET-acme-contact@example.org"

[acme.dns]
provider = "cloudflare"
token_file = "/SECRET/cloudflare-token"
wildcards = ["example.com"]
prefer_wildcard = true

[identity]
provider = "authelia"
instance = "authelia"
issuer = "https://auth.example.com"
upstream = "SECRET-upstream:9091"
"#;

    /// `behind` mode, the only one that allows `traefik_dynamic_file` and `trusted_proxies`.
    const BEHIND_FIXTURE: &str = r#"
[ingress]
mode = "behind"
bind = "127.0.0.1:8080"
traefik_dynamic_file = "/SECRET/traefik.yml"
trusted_proxies = ["10.77.0.0/16"]

[admin]
socket = "/SECRET/admin.sock"

[webhook]
listen = "127.0.0.1:9000"
domain = "hooks.example.com"
"#;

    fn project_toml(toml: &str) -> serde_json::Value {
        let host = HostConfig::from_toml_str(toml).unwrap();
        host.validate().unwrap();
        serde_json::to_value(project(&host)).unwrap()
    }

    fn view() -> serde_json::Value {
        project_toml(FIXTURE)
    }

    #[test]
    fn no_secret_and_no_host_path_reaches_the_view() {
        let text = view().to_string();
        for secret in SECRETS {
            assert!(!text.contains(secret), "{secret} leaked: {text}");
        }
        assert!(!text.contains("SECRET"), "{text}");
    }

    #[test]
    fn trusted_proxy_ranges_and_the_traefik_file_stay_hidden() {
        let v = project_toml(BEHIND_FIXTURE);
        let text = v.to_string();
        for secret in ["10.77.0.0", "SECRET", "traefik"] {
            assert!(!text.contains(secret), "{secret} leaked: {text}");
        }
        assert_eq!(v["ingress"]["custom_trusted_proxies"], true);
        assert_eq!(view()["ingress"]["custom_trusted_proxies"], false);
    }

    #[test]
    fn a_token_secret_counts_as_authenticated_and_stays_hidden() {
        // The host secret name is a path to a credential too: shown is only that one is set.
        let toml = FIXTURE.replace(
            "token_file = \"/SECRET/ntfy-token\"",
            "token_secret = \"SECRET-ntfy-secret-name\"",
        );
        let v = project_toml(&toml);
        assert_eq!(
            v["notify"]["ntfy"],
            serde_json::json!({"min_severity": "warning", "authenticated": true})
        );
        assert!(!v.to_string().contains("SECRET"), "{v}");
    }

    #[test]
    fn the_allow_listed_settings_are_shown() {
        let v = view();
        assert_eq!(v["host_configs"], true);
        assert_eq!(
            v["runtime"]["host_mounts"],
            serde_json::json!(["/var/log/journal"])
        );
        assert_eq!(
            v["runtime"]["group_add"],
            serde_json::json!(["systemd-journal"])
        );
        assert_eq!(v["ingress"]["https_bind"], "0.0.0.0:8443");
        assert_eq!(
            v["ingress"]["cdn"],
            serde_json::json!({"provider": "cloudflare", "pinned_ranges": 1})
        );
        assert_eq!(v["admin"]["http"]["read_groups"], 1);
        assert_eq!(v["webhook"]["forgejo_registry"], "git.example.com");
        assert_eq!(
            v["notify"]["ntfy"],
            serde_json::json!({"min_severity": "warning", "authenticated": true})
        );
        assert_eq!(v["self_update"]["custom_public_key"], true);
        assert_eq!(v["acme"]["has_contact"], true);
        assert_eq!(
            v["acme"]["dns"]["wildcards"],
            serde_json::json!(["example.com"])
        );
        // The precedence knob is public configuration (issue #210, docs/decisions/0077).
        assert_eq!(v["acme"]["dns"]["prefer_wildcard"], true);
        assert_eq!(v["identity"]["instance"], "authelia");
    }
}
