//! Endpoint list. Paths contain `{name}` / `{secret}` / `{volume}` parameters.

use weglarka_model::admin_auth::Scope;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
}

impl Method {
    pub const fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    pub method: Method,
    pub path: &'static str,
    /// Scope a bearer token needs on the token listener (docs/decisions/0056). `None` = no
    /// authentication: only `GET /v1/health`. The full-trust unix socket never checks scopes.
    pub scope: Option<Scope>,
}

impl Endpoint {
    /// The endpoint a request for `method` and the router's matched path template (`{name}` style)
    /// belongs to. `None` for anything not in [`ENDPOINTS`]: the token listener refuses it.
    pub fn lookup(method: &str, path: &str) -> Option<&'static Endpoint> {
        ENDPOINTS
            .iter()
            .find(|e| e.method.as_str() == method && e.path == path)
    }
}

/// `GET` → [`StatusResponse`](crate::StatusResponse)
pub const STATUS: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/status",
    scope: Some(Scope::Read),
};
/// `GET` → [`HealthResponse`](crate::HealthResponse). Readiness only: it answers once the admin API
/// is serving and deliberately never calls Podman, so the host-side self-update watchdog can tell a
/// broken daemon from a Podman hiccup (issue #100).
pub const HEALTH: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/health",
    scope: None,
};
/// `GET` → [`ListAppsResponse`](crate::ListAppsResponse)
pub const APPS_LIST: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/apps",
    scope: Some(Scope::Read),
};
/// `POST` [`AddAppRequest`](crate::AddAppRequest) → [`ShowAppResponse`](crate::ShowAppResponse)
pub const APPS_ADD: Endpoint = Endpoint {
    method: Method::Post,
    path: "/v1/apps",
    scope: Some(Scope::Admin),
};
/// `GET` → [`ShowAppResponse`](crate::ShowAppResponse)
pub const APPS_SHOW: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/apps/{name}",
    scope: Some(Scope::Read),
};
/// `PUT` [`UpdateAppRequest`](crate::UpdateAppRequest) → [`UpdateAppResponse`](crate::UpdateAppResponse).
/// Full spec replacement (see the request type). Owner: session 3.
pub const APPS_UPDATE: Endpoint = Endpoint {
    method: Method::Put,
    path: "/v1/apps/{name}",
    scope: Some(Scope::Admin),
};
/// `DELETE` → 204. Query [`RemoveAppQuery`](crate::RemoveAppQuery): `?purge_volumes=true` also removes
/// the instance's volumes (kept by default), `?purge_secrets=true` also removes the instance's secrets
/// (kept by default; independent of the volumes).
pub const APPS_REMOVE: Endpoint = Endpoint {
    method: Method::Delete,
    path: "/v1/apps/{name}",
    scope: Some(Scope::Admin),
};
/// `POST` [`DeployRequest`](crate::DeployRequest) → [`DeployResponse`](crate::DeployResponse)
pub const APPS_DEPLOY: Endpoint = Endpoint {
    method: Method::Post,
    path: "/v1/apps/{name}/deploy",
    scope: Some(Scope::Admin),
};
/// `PUT` a streamed `application/x-tar` image archive (`oci-archive` or `docker-archive`, as written by
/// `podman save`) → [`DeployResponse`](crate::DeployResponse). Loads the image into Podman's store,
/// tags it into the app's image repository and deploys it like any other digest: health gate,
/// rollback, `current`/`previous` in `state.toml`; `apps.toml` is not touched. One upload at a time
/// (409 otherwise); an archive Podman cannot load is a 400 (issue #109, docs/decisions/0042).
pub const APPS_PUSH_IMAGE: Endpoint = Endpoint {
    method: Method::Put,
    path: "/v1/apps/{name}/image",
    scope: Some(Scope::Admin),
};
/// `POST` [`ReloadRequest`](crate::ReloadRequest) → [`ReloadResponse`](crate::ReloadResponse).
/// Sends the app's `reload_signal`, restarts the container when the spec sets none, or recreates it
/// when `recreate = true` (issue #118). Changes no desired state.
pub const APPS_RELOAD: Endpoint = Endpoint {
    method: Method::Post,
    path: "/v1/apps/{name}/reload",
    scope: Some(Scope::Admin),
};
/// `POST` [`RunRequest`](crate::RunRequest) → a stream of [`RunFrame`](crate::RunFrame)s
/// (`application/vnd.weglarka.run-stream`). Runs a command once in a fresh container of the app
/// (its image, env, secrets, volumes, configs and networks; never its `host_ports` or ingress
/// routing) and removes the container afterwards. Closing the connection kills the run (issue #106).
pub const APPS_RUN: Endpoint = Endpoint {
    method: Method::Post,
    path: "/v1/apps/{name}/run",
    scope: Some(Scope::Admin),
};
/// `POST` [`ForwardRequest`](crate::ForwardRequest) → a stream of
/// [`ForwardFrame`](crate::ForwardFrame)s (`application/vnd.weglarka.forward-stream`). Starts a relay
/// container on the app's network, published on a loopback port of the host (the first frame names it),
/// and keeps it for as long as the connection is open; closing the connection removes it (issue #108).
pub const APPS_FORWARD: Endpoint = Endpoint {
    method: Method::Post,
    path: "/v1/apps/{name}/forward",
    scope: Some(Scope::Admin),
};
/// `GET` → [`ListSecretsResponse`](crate::ListSecretsResponse) (without values)
pub const SECRETS_LIST: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/apps/{name}/secrets",
    scope: Some(Scope::Read),
};
/// `PUT` [`SetSecretRequest`](crate::SetSecretRequest) → [`SecretInfo`](crate::SecretInfo).
/// Overwrite only; there is no endpoint for reading the value back.
pub const SECRETS_SET: Endpoint = Endpoint {
    method: Method::Put,
    path: "/v1/apps/{name}/secrets/{secret}",
    scope: Some(Scope::Admin),
};
/// `DELETE` → 204. Query [`RemoveSecretQuery`](crate::RemoveSecretQuery): `?force=true` removes the
/// secret even though the app's spec still binds it (the app then waits for it). Refused with 409
/// while the spec binds it and `force` is not set; 404 when the store has no such secret. The app
/// need not exist in `apps.toml` — that is how the leftovers of a removed app are cleaned up
/// (issue #80).
pub const SECRETS_REMOVE: Endpoint = Endpoint {
    method: Method::Delete,
    path: "/v1/apps/{name}/secrets/{secret}",
    scope: Some(Scope::Admin),
};
/// `GET` → [`ListVolumesResponse`](crate::ListVolumesResponse): volumes declared in the app's spec.
pub const VOLUMES_LIST: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/apps/{name}/volumes",
    scope: Some(Scope::Read),
};
/// `GET` → `application/x-tar`, streamed. `{volume}` is the volume's name within the instance.
pub const VOLUMES_EXPORT: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/apps/{name}/volumes/{volume}/export",
    scope: Some(Scope::Admin),
};
/// `PUT` a streamed `application/x-tar` body → 204. Extracts into the volume (existing files with the
/// same path are overwritten; others are kept). Ownership of the extracted files: docs/decisions/0009.
pub const VOLUMES_IMPORT: Endpoint = Endpoint {
    method: Method::Put,
    path: "/v1/apps/{name}/volumes/{volume}/import",
    scope: Some(Scope::Admin),
};
/// `GET` → [`ListSharedVolumesResponse`](crate::ListSharedVolumesResponse): shared volumes declared in
/// `apps.toml` with their members, uid range and whether Podman knows them (issue #33).
pub const SHARED_VOLUMES_LIST: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/volumes",
    scope: Some(Scope::Read),
};
/// `PUT` with no body → 204. Declares a shared volume (idempotent); apps mount it through
/// `shared_volumes = [...]` (issue #33). Query `group=<name>` puts it in a group that shares one uid
/// range with its other volumes (issue #129); declaring an existing volume with another group is a
/// 409.
pub const SHARED_VOLUMES_DECLARE: Endpoint = Endpoint {
    method: Method::Put,
    path: "/v1/volumes/{volume}",
    scope: Some(Scope::Admin),
};
/// `DELETE` → 204. Query `purge=true` also deletes the Podman volume (its data). Refused while an app
/// mounts it, and without `purge` while it still holds data (issue #33).
pub const SHARED_VOLUMES_REMOVE: Endpoint = Endpoint {
    method: Method::Delete,
    path: "/v1/volumes/{volume}",
    scope: Some(Scope::Admin),
};
/// `GET` → [`ListSharedNetworksResponse`](crate::ListSharedNetworksResponse): shared networks declared
/// in `apps.toml` with their members and whether Podman knows them (issue #128).
pub const SHARED_NETWORKS_LIST: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/networks",
    scope: Some(Scope::Read),
};
/// `PUT` with no body → 204. Declares a shared network (idempotent); apps join it through
/// `shared_networks = [...]` (issue #128).
pub const SHARED_NETWORKS_DECLARE: Endpoint = Endpoint {
    method: Method::Put,
    path: "/v1/networks/{network}",
    scope: Some(Scope::Admin),
};
/// `DELETE` → 204. Refused (409) while an app joins it (issue #128).
pub const SHARED_NETWORKS_REMOVE: Endpoint = Endpoint {
    method: Method::Delete,
    path: "/v1/networks/{network}",
    scope: Some(Scope::Admin),
};
/// `GET` → [`ListSitesResponse`](crate::ListSitesResponse): sites with their environments and the
/// digest each serves (issue #205).
pub const SITES_LIST: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/sites",
    scope: Some(Scope::Read),
};
/// `GET` → [`SiteSummary`](crate::SiteSummary).
pub const SITES_SHOW: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/sites/{site}",
    scope: Some(Scope::Read),
};
/// `PUT` [`DeclareSiteRequest`](crate::DeclareSiteRequest) → 204. Declares or replaces a site; its
/// environments become the instances `<site>-<env>`. An instance name taken by `[apps]` or another
/// site is a 400.
pub const SITES_DECLARE: Endpoint = Endpoint {
    method: Method::Put,
    path: "/v1/sites/{site}",
    scope: Some(Scope::Admin),
};
/// `DELETE` → 204. Query [`RemoveSiteQuery`](crate::RemoveSiteQuery): refused (409) while an
/// environment serves a release unless `?purge=true`.
pub const SITES_REMOVE: Endpoint = Endpoint {
    method: Method::Delete,
    path: "/v1/sites/{site}",
    scope: Some(Scope::Admin),
};
/// `POST` [`PromoteRequest`](crate::PromoteRequest) → [`PromoteResponse`](crate::PromoteResponse).
/// Deploys the digest of the environment's `promote_from` source (or an explicit one, or the
/// previous one) without pulling it again (issue #205, docs/decisions/0050).
pub const SITES_PROMOTE: Endpoint = Endpoint {
    method: Method::Post,
    path: "/v1/sites/{site}/envs/{env}/promote",
    scope: Some(Scope::Admin),
};
/// `GET` → [`EventsResponse`](crate::EventsResponse). Query [`EventsQuery`](crate::EventsQuery):
/// recent domain events from a bounded in-memory history (docs/decisions/0057), newer than `since`.
pub const EVENTS_RECENT: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/events",
    scope: Some(Scope::Read),
};
/// `GET` → [`DoctorReport`](crate::DoctorReport)
pub const DOCTOR: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/doctor",
    scope: Some(Scope::Read),
};
/// `POST` [`PruneImagesRequest`](crate::PruneImagesRequest) → [`PruneImagesResponse`](crate::PruneImagesResponse).
/// Removes images of the repositories named in `apps.toml` that are neither an app's current nor its
/// previous image and that no container uses (issue #40). `dry_run` only reports them.
pub const IMAGES_PRUNE: Endpoint = Endpoint {
    method: Method::Post,
    path: "/v1/images/prune",
    scope: Some(Scope::Admin),
};
/// `POST` with no body → [`OidcRotateResponse`](crate::OidcRotateResponse): replaces the app's OIDC
/// client secret, re-renders the provider's clients, then recreates the app (#213).
pub const OIDC_ROTATE: Endpoint = Endpoint {
    method: Method::Post,
    path: "/v1/apps/{name}/oidc/rotate",
    scope: Some(Scope::Admin),
};
/// `GET` → [`ListOidcClientsResponse`](crate::ListOidcClientsResponse): the external clients.
pub const OIDC_CLIENTS_LIST: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/oidc-clients",
    // The answer carries each client's `secret_digest`: a credential, so `admin` only.
    scope: Some(Scope::Admin),
};
/// `PUT` [`PutOidcClientRequest`](crate::PutOidcClientRequest) → 204; replaces a client of that id.
pub const OIDC_CLIENT_PUT: Endpoint = Endpoint {
    method: Method::Put,
    path: "/v1/oidc-clients/{id}",
    scope: Some(Scope::Admin),
};
/// `DELETE` → 204.
pub const OIDC_CLIENT_REMOVE: Endpoint = Endpoint {
    method: Method::Delete,
    path: "/v1/oidc-clients/{id}",
    scope: Some(Scope::Admin),
};
/// `GET` → [`NotifyStatusResponse`](crate::NotifyStatusResponse): configured channels, the pending
/// outbox and the last delivery error (issue #38).
pub const NOTIFICATIONS_STATUS: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/notifications",
    scope: Some(Scope::Read),
};
/// `POST` with no body → [`NotifyTestResponse`](crate::NotifyTestResponse). Delivers a test
/// notification now, bypassing the outbox (issue #38).
pub const NOTIFICATIONS_TEST: Endpoint = Endpoint {
    method: Method::Post,
    path: "/v1/notifications/test",
    scope: Some(Scope::Admin),
};

pub const ENDPOINTS: &[Endpoint] = &[
    STATUS,
    HEALTH,
    APPS_LIST,
    APPS_ADD,
    APPS_SHOW,
    APPS_UPDATE,
    APPS_REMOVE,
    APPS_DEPLOY,
    APPS_PUSH_IMAGE,
    APPS_RELOAD,
    APPS_RUN,
    APPS_FORWARD,
    SECRETS_LIST,
    SECRETS_SET,
    SECRETS_REMOVE,
    VOLUMES_LIST,
    VOLUMES_EXPORT,
    VOLUMES_IMPORT,
    SHARED_VOLUMES_LIST,
    SHARED_VOLUMES_DECLARE,
    SHARED_VOLUMES_REMOVE,
    SHARED_NETWORKS_LIST,
    SHARED_NETWORKS_DECLARE,
    SHARED_NETWORKS_REMOVE,
    SITES_LIST,
    SITES_SHOW,
    SITES_DECLARE,
    SITES_REMOVE,
    SITES_PROMOTE,
    EVENTS_RECENT,
    DOCTOR,
    IMAGES_PRUNE,
    NOTIFICATIONS_STATUS,
    NOTIFICATIONS_TEST,
    OIDC_ROTATE,
    OIDC_CLIENTS_LIST,
    OIDC_CLIENT_PUT,
    OIDC_CLIENT_REMOVE,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_health_is_unauthenticated() {
        let open: Vec<_> = ENDPOINTS.iter().filter(|e| e.scope.is_none()).collect();
        assert_eq!(open, [&HEALTH]);
    }

    #[test]
    fn mutations_and_data_exports_need_admin() {
        for e in ENDPOINTS {
            let mutating = e.method != Method::Get;
            if mutating || e.path.ends_with("/export") {
                assert_eq!(
                    e.scope,
                    Some(Scope::Admin),
                    "{} {}",
                    e.method.as_str(),
                    e.path
                );
            }
        }
    }

    /// GETs whose answer carries a credential or the data of an app: never `read`. Add an endpoint
    /// here whenever a response type gains such a field.
    #[test]
    fn credential_bearing_reads_need_admin() {
        for e in [VOLUMES_EXPORT, OIDC_CLIENTS_LIST] {
            assert_eq!(e.scope, Some(Scope::Admin), "{}", e.path);
        }
    }

    /// `GET /v1/apps/{name}` is `read` only because the daemon blanks `env` values for a caller
    /// without `admin` (`weglarka-daemon`, `app_view`; test `token_api.rs`). Any other GET that
    /// returns a whole `AppSpec` must either do the same or move to `admin`.
    #[test]
    fn the_read_scope_app_view_is_the_redacted_one() {
        assert_eq!(APPS_SHOW.scope, Some(Scope::Read));
        assert_eq!(APPS_UPDATE.scope, Some(Scope::Admin));
        assert_eq!(APPS_ADD.scope, Some(Scope::Admin));
    }

    #[test]
    fn lookup_finds_by_method_and_template() {
        assert_eq!(Endpoint::lookup("GET", "/v1/apps/{name}"), Some(&APPS_SHOW));
        assert_eq!(
            Endpoint::lookup("DELETE", "/v1/apps/{name}"),
            Some(&APPS_REMOVE)
        );
        assert_eq!(Endpoint::lookup("PATCH", "/v1/apps/{name}"), None);
        assert_eq!(Endpoint::lookup("GET", "/v1/nope"), None);
    }

    #[test]
    fn endpoints_are_unique() {
        for (i, a) in ENDPOINTS.iter().enumerate() {
            for b in &ENDPOINTS[i + 1..] {
                assert!(a.method != b.method || a.path != b.path, "{}", a.path);
            }
        }
    }
}
