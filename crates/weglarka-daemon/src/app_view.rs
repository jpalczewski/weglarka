//! The one place that turns an app into a [`ShowAppResponse`], and the one place that decides what a
//! caller may see of it (docs/decisions/0056 decision 7, docs/decisions/0057 decision 8).
//!
//! The unix socket is full trust and carries no principal. On the token listener `authenticate`
//! stores the verified [`Principal`] in the request extensions; a caller without `admin` gets the
//! `env` values blanked (keys stay), because `env` is where operators put connection strings. Every
//! handler that answers with a spec takes an [`Access`] and builds the answer with [`show_response`],
//! so a new path cannot forget to redact.

use std::convert::Infallible;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use weglarka_api::{ContainerHealth, ShowAppResponse};
use weglarka_model::admin_auth::{Principal, Scope};
use weglarka_model::app::{AppSpec, InstanceName};
use weglarka_model::podman::{ContainerInfo, HealthStatus};
use weglarka_model::state::AppState;

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

/// `spec` as `access` may see it: with `Redacted`, `env` values are blank and the keys are kept.
pub(crate) fn redact_spec(access: Access, mut spec: AppSpec) -> AppSpec {
    if access == Access::Redacted {
        for value in spec.env.values_mut() {
            value.clear();
        }
    }
    spec
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
        state: app_state.cloned().unwrap_or_default(),
        configs: None,
        host_mounts: None,
        restarts: container.map(|c| c.restarts),
        health: container.and_then(|c| c.health).map(container_health),
        started_at: container.and_then(|c| c.started_at.clone()),
        name,
        spec: redact_spec(access, spec),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn principal(scopes: &[Scope]) -> Principal {
        Principal {
            sub: "u".into(),
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
