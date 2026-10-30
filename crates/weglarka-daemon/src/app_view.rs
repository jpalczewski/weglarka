//! The one place that turns an app into a [`ShowAppResponse`], and the one place that decides what a
//! caller may see of it (docs/decisions/0056 decision 7, docs/decisions/0057 decision 8).
//!
//! The unix socket is full trust and carries no principal. On the token listener `authenticate`
//! stores the verified [`Principal`] in the request extensions; a caller without `admin` gets an
//! allowlist projection of the app (issue #265): `read_spec` and `read_state` destructure every
//! field of the stored types without `..`, so a new field fails to compile until its read-scope
//! treatment is decided. The policy: `env` values blank (keys kept), every argument of `command` and
//! `health.command` replaced element by element (arity kept), `health.http.path` cut to its first
//! segment, the engine's failure text in `state.failed.reason` replaced by a marker (`events.rs` keeps
//! it from `read` too), and `ShowAppResponse::redacted` set so no client mistakes the view for the
//! stored spec. Every handler that answers with a spec takes an [`Access`] and builds the answer
//! with [`show_response`], so a new path cannot forget to redact.

use std::convert::Infallible;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use weglarka_api::{ContainerHealth, ShowAppResponse};
use weglarka_model::admin_auth::{Principal, Scope};
use weglarka_model::app::{
    AppIngress, AppSpec, ConfigMount, HealthGate, HostMount, HostPort, HttpProbe, InstanceName,
    Resources, SecretBinding, SecretTarget, Security, SharedNetworkRef, SharedVolumeRef,
    VolumeMount,
};
use weglarka_model::identity::OidcClientSpec;
use weglarka_model::podman::{ContainerInfo, HealthStatus};
use weglarka_model::state::{AppState, FailedDeploy};

use crate::admin::runtime_state_for;
use crate::update::with_waiting;

/// What the caller of an admin API request may see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Access {
    /// Unix socket (no token) or a token with `admin`.
    Full,
    /// A token without `admin`: app data is redacted.
    Redacted,
}

impl Access {
    /// `None` is the socket, which never carries a principal. A principal without `admin` is
    /// redacted whatever else it holds, so an unforeseen scope fails closed.
    pub(crate) fn of(principal: Option<&Principal>) -> Self {
        match principal {
            None => Self::Full,
            Some(p) if p.has(Scope::Admin) => Self::Full,
            Some(_) => Self::Redacted,
        }
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Access {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Infallible> {
        Ok(Self::of(parts.extensions.get::<Principal>()))
    }
}

/// Stands in for every element of a redacted command line, and for every path segment of a
/// redacted probe path after the first.
pub(crate) const REDACTED_ARG: &str = "<redacted>";

/// Stands in for the engine's failure text of a redacted deploy failure.
pub(crate) const REDACTED_REASON: &str = "deploy failed (details withheld)";

/// Replaces every element with [`REDACTED_ARG`] and keeps only the number of arguments. `command`
/// replaces the image's `CMD`, so even `argv[0]` is not necessarily a program name: it can be a
/// positional secret or a connection URL with credentials, and no heuristic tells those apart
/// (issue #273).
fn redact_argv(argv: Vec<String>) -> Vec<String> {
    vec![REDACTED_ARG.to_owned(); argv.len()]
}

/// The first path segment, then [`REDACTED_ARG`] for whatever follows it; the query and the fragment
/// are always dropped. The daemon cannot tell a token segment (`/hooks/<token>/ready`) from a normal
/// one, so it shows the least that still says which endpoint is probed (issue #266).
fn redact_probe_path(path: &str) -> String {
    let path = path.split(['?', '#']).next().unwrap_or_default();
    match path.strip_prefix('/').unwrap_or(path).split_once('/') {
        Some((first, rest)) if !rest.is_empty() => format!("/{first}/{REDACTED_ARG}"),
        _ => path.to_owned(),
    }
}

// The read view is an allowlist projection: every function below destructures its input with no
// `..` and rebuilds it field by field, so a field added to one of these types does not compile until
// someone decides what a `read` caller sees of it (issue #265, docs/decisions/0057 decision 8).
// A field is passed through only when it holds a name, a number, a flag or a path, never a value
// an operator may have typed a credential into.

fn read_probe(probe: HttpProbe) -> HttpProbe {
    let HttpProbe {
        path,
        expect_status,
        timeout_secs,
    } = probe;
    HttpProbe {
        path: redact_probe_path(&path),
        expect_status,
        timeout_secs,
    }
}

fn read_health(health: HealthGate) -> HealthGate {
    let HealthGate {
        attempts,
        window_secs,
        command,
        http,
    } = health;
    HealthGate {
        attempts,
        window_secs,
        command: command.map(redact_argv),
        http: http.map(read_probe),
    }
}

/// Only the reference to a secret (its name and where it lands), never a value.
fn read_secret_binding(binding: SecretBinding) -> SecretBinding {
    let SecretBinding { secret, target } = binding;
    SecretBinding {
        secret,
        target: read_secret_target(target),
    }
}

fn read_secret_target(target: SecretTarget) -> SecretTarget {
    match target {
        SecretTarget::Env { var } => SecretTarget::Env { var },
        SecretTarget::Mount {
            path,
            mode,
            uid,
            gid,
        } => SecretTarget::Mount {
            path,
            mode,
            uid,
            gid,
        },
    }
}

fn read_volume(volume: VolumeMount) -> VolumeMount {
    let VolumeMount {
        name,
        target,
        read_only,
    } = volume;
    VolumeMount {
        name,
        target,
        read_only,
    }
}

fn read_shared_volume(volume: SharedVolumeRef) -> SharedVolumeRef {
    let SharedVolumeRef {
        name,
        target,
        read_only,
    } = volume;
    SharedVolumeRef {
        name,
        target,
        read_only,
    }
}

fn read_shared_network(network: SharedNetworkRef) -> SharedNetworkRef {
    let SharedNetworkRef { name, aliases } = network;
    SharedNetworkRef { name, aliases }
}

fn read_host_port(port: HostPort) -> HostPort {
    let HostPort {
        host,
        container,
        ip,
    } = port;
    HostPort {
        host,
        container,
        ip,
    }
}

fn read_resources(resources: Resources) -> Resources {
    let Resources {
        memory,
        pids_limit,
        cpus,
    } = resources;
    Resources {
        memory,
        pids_limit,
        cpus,
    }
}

fn read_security(security: Security) -> Security {
    let Security {
        read_only,
        tmpfs,
        cap_drop,
        cap_add,
        no_new_privileges,
    } = security;
    Security {
        read_only,
        tmpfs,
        cap_drop,
        cap_add,
        no_new_privileges,
    }
}

fn read_ingress(ingress: AppIngress) -> AppIngress {
    let AppIngress {
        streaming,
        stream_timeout_secs,
        strip_prefix,
        max_body_size,
        access_log_skip_paths,
        streaming_paths,
        auth,
        auth_policy,
        auth_groups,
        auth_exempt_paths,
    } = ingress;
    AppIngress {
        streaming,
        stream_timeout_secs,
        strip_prefix,
        max_body_size,
        access_log_skip_paths,
        streaming_paths,
        auth,
        auth_policy,
        auth_groups,
        auth_exempt_paths,
    }
}

fn read_config_mount(mount: ConfigMount) -> ConfigMount {
    let ConfigMount { source, target } = mount;
    ConfigMount { source, target }
}

fn read_host_mount(mount: HostMount) -> HostMount {
    let HostMount { source, target } = mount;
    HostMount { source, target }
}

/// Redirect URIs, scopes and the names of the injected variables are public configuration of the
/// client; the secret itself only appears as a reference (`client_secret` is a target).
fn read_oidc(oidc: OidcClientSpec) -> OidcClientSpec {
    let OidcClientSpec {
        redirect_uris,
        scopes,
        authorization_policy,
        token_endpoint_auth_method,
        audience,
        groups_in_id_token,
        groups_in_access_token,
        access_token,
        pkce,
        public,
        client_id_env,
        issuer_env,
        client_secret,
    } = oidc;
    OidcClientSpec {
        redirect_uris,
        scopes,
        authorization_policy,
        token_endpoint_auth_method,
        audience,
        groups_in_id_token,
        groups_in_access_token,
        access_token,
        pkce,
        public,
        client_id_env,
        issuer_env,
        client_secret: client_secret.map(read_secret_target),
    }
}

/// The spec a caller without `admin` may see: `env` values blank (keys kept), `command` and
/// `health.command` keep only their length (every element a placeholder), `health.http.path` keeps
/// its first segment.
fn read_spec(spec: AppSpec) -> AppSpec {
    let AppSpec {
        kind,
        image,
        command,
        domains,
        paths,
        port,
        ingress,
        env,
        secrets,
        health,
        volumes,
        shared_volumes,
        shared_networks,
        host_ports,
        depends_on,
        resources,
        security,
        auto_update,
        start,
        configs,
        reload_signal,
        host_mounts,
        group_add,
        strategy,
        oidc,
    } = spec;
    AppSpec {
        kind,
        image,
        command: redact_argv(command),
        domains,
        paths,
        port,
        ingress: read_ingress(ingress),
        env: env.into_keys().map(|key| (key, String::new())).collect(),
        secrets: secrets.into_iter().map(read_secret_binding).collect(),
        health: read_health(health),
        volumes: volumes.into_iter().map(read_volume).collect(),
        shared_volumes: shared_volumes.into_iter().map(read_shared_volume).collect(),
        shared_networks: shared_networks
            .into_iter()
            .map(read_shared_network)
            .collect(),
        host_ports: host_ports.into_iter().map(read_host_port).collect(),
        depends_on,
        resources: read_resources(resources),
        security: read_security(security),
        auto_update,
        start,
        configs: configs.into_iter().map(read_config_mount).collect(),
        reload_signal,
        host_mounts: host_mounts.into_iter().map(read_host_mount).collect(),
        group_add,
        strategy,
        oidc: oidc.map(read_oidc),
    }
}

fn read_failed(failed: FailedDeploy) -> FailedDeploy {
    let FailedDeploy { digest, reason: _ } = failed;
    FailedDeploy {
        digest,
        reason: REDACTED_REASON.to_owned(),
    }
}

/// The state a caller without `admin` may see: a failed deploy keeps its digest but not the
/// engine's free-form `reason` (podman and validator output).
fn read_state(state: AppState) -> AppState {
    let AppState {
        generation,
        current,
        previous,
        spec_hash: _spec_hash,
        failed,
        waiting_for_secrets,
        uid_range,
        effective_uid_range,
    } = state;
    AppState {
        generation,
        current,
        previous,
        // A sha256 of the whole spec, `env` values included: with the other fields known it lets a
        // reader test guesses of a blanked value offline, so `read` does not get it.
        spec_hash: None,
        failed: failed.map(read_failed),
        waiting_for_secrets,
        uid_range,
        effective_uid_range,
    }
}

/// `spec` as `access` may see it: `Full` is the stored spec untouched, `Redacted` the projection.
pub(crate) fn redact_spec(access: Access, spec: AppSpec) -> AppSpec {
    match access {
        Access::Full => spec,
        Access::Redacted => read_spec(spec),
    }
}

/// `state` as `access` may see it.
pub(crate) fn redact_state(access: Access, state: AppState) -> AppState {
    match access {
        Access::Full => state,
        Access::Redacted => read_state(state),
    }
}

fn container_health(health: HealthStatus) -> ContainerHealth {
    match health {
        HealthStatus::Starting => ContainerHealth::Starting,
        HealthStatus::Healthy => ContainerHealth::Healthy,
        HealthStatus::Unhealthy => ContainerHealth::Unhealthy,
    }
}

/// The show response of one app. `configs` and `host_mounts` stay `None`: only
/// `GET /v1/apps/{name}` resolves them and sets them on the result.
pub(crate) fn show_response(
    access: Access,
    name: InstanceName,
    spec: AppSpec,
    app_state: Option<&AppState>,
    container: Option<&ContainerInfo>,
) -> ShowAppResponse {
    ShowAppResponse {
        runtime: with_waiting(runtime_state_for(&spec, app_state, container), app_state),
        state: redact_state(access, app_state.cloned().unwrap_or_default()),
        configs: None,
        host_mounts: None,
        restarts: container.map(|c| c.restarts),
        health: container.and_then(|c| c.health).map(container_health),
        started_at: container.and_then(|c| c.started_at.clone()),
        name,
        spec: redact_spec(access, spec),
        redacted: access == Access::Redacted,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn principal(scopes: &[Scope]) -> Principal {
        Principal {
            sub: "u".into(),
            exp: std::time::SystemTime::UNIX_EPOCH,
            scopes: scopes.iter().copied().collect::<BTreeSet<_>>(),
        }
    }

    fn spec() -> AppSpec {
        let mut spec: AppSpec =
            toml::from_str("image = \"ghcr.io/example/app:1\"\nport = 8080\n").expect("spec");
        spec.env
            .insert("DATABASE_URL".into(), "postgres://u:p@h/db".into());
        spec.env.insert("MODE".into(), "prod".into());
        spec
    }

    fn name() -> InstanceName {
        InstanceName::new("app").unwrap()
    }

    #[test]
    fn socket_and_admin_see_everything_read_and_unknown_do_not() {
        assert_eq!(Access::of(None), Access::Full);
        assert_eq!(
            Access::of(Some(&principal(&[Scope::Read, Scope::Admin]))),
            Access::Full
        );
        assert_eq!(
            Access::of(Some(&principal(&[Scope::Read]))),
            Access::Redacted
        );
        assert_eq!(Access::of(Some(&principal(&[]))), Access::Redacted);
    }

    #[test]
    fn redaction_blanks_values_and_keeps_keys() {
        let full = show_response(Access::Full, name(), spec(), None, None);
        assert_eq!(full.spec.env["DATABASE_URL"], "postgres://u:p@h/db");
        let redacted = show_response(Access::Redacted, name(), spec(), None, None);
        let keys: Vec<_> = redacted.spec.env.keys().map(String::as_str).collect();
        assert_eq!(keys, ["DATABASE_URL", "MODE"]);
        assert!(redacted.spec.env.values().all(String::is_empty));
        assert_eq!(redacted.spec.image, full.spec.image);
    }

    fn leaky_spec() -> AppSpec {
        let mut spec = spec();
        spec.command = vec![
            "serve".into(),
            "--password=hunter2".into(),
            "--port".into(),
            "80".into(),
        ];
        spec.health.command = Some(vec!["check".into(), "--token=t0k3n".into()]);
        spec.health.http = Some(weglarka_model::app::HttpProbe {
            path: "/ready?key=s3cret".into(),
            ..Default::default()
        });
        spec
    }

    #[test]
    fn redaction_keeps_only_the_argument_count() {
        let full = show_response(Access::Full, name(), leaky_spec(), None, None);
        assert_eq!(full.spec.command[1], "--password=hunter2");
        assert_eq!(
            full.spec.health.command.as_deref().unwrap()[1],
            "--token=t0k3n"
        );

        let shown = show_response(Access::Redacted, name(), leaky_spec(), None, None);
        let r = REDACTED_ARG.to_owned();
        assert_eq!(shown.spec.command, [REDACTED_ARG; 4]);
        assert_eq!(shown.spec.health.command, Some(vec![r.clone(), r]));
        assert!(!format!("{shown:?}").contains("hunter2"));
        assert!(!format!("{shown:?}").contains("t0k3n"));
    }

    #[test]
    fn redaction_hides_a_bare_or_url_shaped_argv0() {
        for secret in [
            "s3cr3tpassword",
            "postgres://user:pass@db/app",
            "--api-key=k",
        ] {
            let mut spec = spec();
            spec.command = vec![secret.into(), "x".into()];
            spec.health.command = Some(vec![secret.into()]);
            let shown = show_response(Access::Redacted, name(), spec, None, None);
            assert_eq!(shown.spec.command, [REDACTED_ARG, REDACTED_ARG]);
            assert_eq!(shown.spec.health.command, Some(vec![REDACTED_ARG.into()]));
            assert!(!format!("{shown:?}").contains(secret), "{secret}");
        }
    }

    #[test]
    fn redaction_strips_the_probe_query_and_keeps_the_path() {
        let full = show_response(Access::Full, name(), leaky_spec(), None, None);
        assert_eq!(full.spec.health.http.unwrap().path, "/ready?key=s3cret");
        let shown = show_response(Access::Redacted, name(), leaky_spec(), None, None);
        let http = shown.spec.health.http.unwrap();
        assert_eq!(http.path, "/ready");
        assert_eq!(http.expect_status, 200);
    }

    #[test]
    fn the_probe_path_keeps_its_first_segment_only() {
        for (path, shown) in [
            ("/", "/"),
            ("/ready", "/ready"),
            ("/ready/", "/ready/"),
            ("/ready?key=s3cret", "/ready"),
            ("/ready#frag", "/ready"),
            ("/hooks/t0k3n/ready", "/hooks/<redacted>"),
            ("/hooks/t0k3n/ready?key=s3cret", "/hooks/<redacted>"),
            ("/?key=s3cret", "/"),
        ] {
            assert_eq!(redact_probe_path(path), shown, "{path}");
        }
        let mut spec = spec();
        spec.health.http = Some(weglarka_model::app::HttpProbe {
            path: "/hooks/t0k3n/ready".into(),
            expect_status: 204,
            timeout_secs: 3,
        });
        let full = show_response(Access::Full, name(), spec.clone(), None, None);
        assert_eq!(full.spec.health.http.unwrap().path, "/hooks/t0k3n/ready");
        let http = show_response(Access::Redacted, name(), spec, None, None)
            .spec
            .health
            .http
            .unwrap();
        assert_eq!(
            (http.path.as_str(), http.expect_status, http.timeout_secs),
            ("/hooks/<redacted>", 204, 3)
        );
    }

    /// Everything the projection passes through survives it, and only the redacted view says so.
    #[test]
    fn the_projection_keeps_the_structure_and_flags_itself() {
        let spec: AppSpec = toml::from_str(
            r#"
image = "ghcr.io/example/app:1"
port = 8080
domains = ["a.example.com"]
paths = ["/app"]
depends_on = ["db"]
group_add = ["media"]
reload_signal = "SIGHUP"
strategy = "blue_green"
start = false
auto_update = false
secrets = [
  { secret = "db", kind = "env", var = "DB_PASSWORD" },
  { secret = "key", kind = "mount", path = "/run/key", mode = 256, uid = 1, gid = 2 },
]
volumes = [{ name = "data", target = "/data", read_only = true }]
host_ports = [{ host = 9000, container = 80, ip = "127.0.0.1" }]
configs = [{ source = "app/conf", target = "/etc/app" }]
host_mounts = [{ source = "/srv/media", target = "/media" }]
shared_networks = [{ name = "backbone", aliases = ["svc"] }]
[resources]
pids_limit = 100
[security]
read_only = true
tmpfs = ["/tmp"]
cap_drop = ["ALL"]
[ingress]
streaming = true
auth_groups = ["staff"]
[oidc]
redirect_uris = ["https://a.example.com/callback"]
client_id_env = "OIDC_ID"
client_secret = { kind = "env", var = "OIDC_SECRET" }
"#,
        )
        .expect("spec");
        let full = show_response(Access::Full, name(), spec.clone(), None, None);
        assert_eq!(full.spec, spec);
        assert!(!full.redacted);
        let json = serde_json::to_value(&full).unwrap();
        assert!(json.get("redacted").is_none(), "{json}");

        let shown = show_response(Access::Redacted, name(), spec.clone(), None, None);
        assert!(shown.redacted);
        assert_eq!(serde_json::to_value(&shown).unwrap()["redacted"], true);
        // Nothing else to blank here: the view equals the stored spec.
        assert_eq!(shown.spec, spec);
    }

    #[test]
    fn redaction_replaces_the_failure_text_and_keeps_the_digest() {
        let digest =
            weglarka_model::app::Digest::new(format!("sha256:{}", "a".repeat(64))).expect("digest");
        let state = AppState {
            failed: Some(weglarka_model::state::FailedDeploy {
                digest: digest.clone(),
                reason: "pull ghcr.io/x: password=hunter2 rejected".into(),
            }),
            ..Default::default()
        };
        let full = show_response(Access::Full, name(), spec(), Some(&state), None);
        assert!(full.state.failed.unwrap().reason.contains("hunter2"));
        let shown = show_response(Access::Redacted, name(), spec(), Some(&state), None);
        let failed = shown.state.failed.unwrap();
        assert_eq!(failed.digest, digest);
        assert_eq!(failed.reason, REDACTED_REASON);
        let hashed = AppState {
            spec_hash: Some(serde_json::from_str("\"abc123\"").expect("hash")),
            ..Default::default()
        };
        assert!(
            show_response(Access::Full, name(), spec(), Some(&hashed), None)
                .state
                .spec_hash
                .is_some()
        );
        assert!(
            show_response(Access::Redacted, name(), spec(), Some(&hashed), None)
                .state
                .spec_hash
                .is_none()
        );
        // No failure, nothing invented.
        let none = show_response(Access::Redacted, name(), spec(), None, None);
        assert!(none.state.failed.is_none());
    }

    #[test]
    fn runtime_detail_comes_from_the_container() {
        let none = show_response(Access::Full, name(), spec(), None, None);
        assert_eq!(
            (none.restarts, none.health, none.started_at),
            (None, None, None)
        );

        let container = ContainerInfo {
            id: "c".into(),
            name: "app".into(),
            image: "i".into(),
            image_id: "i".into(),
            labels: Default::default(),
            state: weglarka_model::podman::ContainerState::Running,
            exit_code: None,
            health: Some(HealthStatus::Starting),
            restarts: 2,
            started_at: Some("2026-10-29T08:15:30Z".into()),
            networks: vec![],
            addresses: vec![],
            published_ports: vec![],
        };
        let shown = show_response(Access::Full, name(), spec(), None, Some(&container));
        assert_eq!(shown.restarts, Some(2));
        assert_eq!(shown.health, Some(ContainerHealth::Starting));
        assert_eq!(shown.started_at.as_deref(), Some("2026-10-29T08:15:30Z"));
    }
}
