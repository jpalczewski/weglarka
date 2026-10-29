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
    IngressView, MonitorView, NotifyView, NtfyView, PlatformView, RuntimeView, SelfUpdateView,
    WebhookView, endpoints,
};
use weglarka_model::config::{
    AcmeConfig, AcmeDnsConfig, AdminConfig, AdminHttpConfig, CdnConfig, ForgejoWebhookConfig,
    HostConfig, IdentityConfig, IngressConfig, MonitorConfig, NotifyConfig, NtfyConfig,
    PlatformConfig, RuntimeConfig, SelfUpdateConfig, StateConfig, WebhookConfig,
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
        trusted_proxies: trusted_proxies.clone(),
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
                min_severity,
            } = ntfy;
            NtfyView {
                min_severity: *min_severity,
                authenticated: token_file.is_some(),
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
                wildcards,
                propagation_secs,
            } = dns;
            AcmeDnsView {
                provider: *provider,
                wildcards: wildcards.clone(),
                propagation_secs: *propagation_secs,
            }
        }),
    }
}

fn identity_view(identity: &IdentityConfig) -> IdentityView {
    let IdentityConfig {
        provider,
        instance,
        issuer,
        upstream,
    } = identity;
    IdentityView {
        provider: *provider,
        instance: instance.clone(),
        issuer: issuer.clone(),
        upstream: upstream.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every value that must never reach the panel, recognizable in the output.
    const SECRETS: [&str; 12] = [
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

[identity]
provider = "authelia"
instance = "authelia"
issuer = "https://auth.example.com"
"#;

    fn view() -> serde_json::Value {
        let host = HostConfig::from_toml_str(FIXTURE).unwrap();
        host.validate().unwrap();
        serde_json::to_value(project(&host)).unwrap()
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
        assert_eq!(v["identity"]["instance"], "authelia");
    }
}
