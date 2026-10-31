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

/// What a response body carries, declared per endpoint so the scope table can be checked against it.
/// Every endpoint states it; a new one does not compile without a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Body {
    /// No `AppSpec` or `AppState` and no credential: counts, names, digests, statuses, streams.
    NoAppData,
    /// An `AppSpec`/`AppState` (a [`ShowAppResponse`](crate::ShowAppResponse), alone or nested). The
    /// daemon builds it with `show_response`, which gives a caller without `admin` the redacted
    /// projection and sets `redacted` (docs/decisions/0057 decision 8).
    AppView,
    /// A credential or the data of an app: a secret digest, volume contents. `admin` only.
    Credential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    pub method: Method,
    pub path: &'static str,
    /// Scope a bearer token needs on the token listener (docs/decisions/0056). `None` = no
    /// authentication: only `GET /v1/health`. The full-trust unix socket never checks scopes.
    pub scope: Option<Scope>,
    /// What the response carries; see [`Body`].
    pub body: Body,
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
    body: Body::NoAppData,
};
/// `GET` → [`HealthResponse`](crate::HealthResponse). Readiness only: it answers once the admin API
/// is serving and deliberately never calls Podman, so the host-side self-update watchdog can tell a
/// broken daemon from a Podman hiccup (issue #100).
pub const HEALTH: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/health",
    scope: None,
    body: Body::NoAppData,
};
/// `GET` → [`ListAppsResponse`](crate::ListAppsResponse)
pub const APPS_LIST: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/apps",
    scope: Some(Scope::Read),
    body: Body::NoAppData,
};
/// `POST` [`AddAppRequest`](crate::AddAppRequest) → [`ShowAppResponse`](crate::ShowAppResponse)
pub const APPS_ADD: Endpoint = Endpoint {
    method: Method::Post,
    path: "/v1/apps",
    scope: Some(Scope::Admin),
    body: Body::AppView,
};
/// `GET` → [`ShowAppResponse`](crate::ShowAppResponse)
pub const APPS_SHOW: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/apps/{name}",
    scope: Some(Scope::Read),
    body: Body::AppView,
};
/// `PUT` [`UpdateAppRequest`](crate::UpdateAppRequest) → [`UpdateAppResponse`](crate::UpdateAppResponse).
/// Full spec replacement (see the request type). Owner: session 3.
pub const APPS_UPDATE: Endpoint = Endpoint {
    method: Method::Put,
    path: "/v1/apps/{name}",
    scope: Some(Scope::Admin),
    body: Body::AppView,
};
/// `DELETE` → 204. Query [`RemoveAppQuery`](crate::RemoveAppQuery): `?purge_volumes=true` also removes
/// the instance's volumes (kept by default), `?purge_secrets=true` also removes the instance's secrets
/// (kept by default; independent of the volumes).
pub const APPS_REMOVE: Endpoint = Endpoint {
    method: Method::Delete,
    path: "/v1/apps/{name}",
    scope: Some(Scope::Admin),
    body: Body::NoAppData,
};
/// `POST` [`DeployRequest`](crate::DeployRequest) → [`DeployResponse`](crate::DeployResponse)
pub const APPS_DEPLOY: Endpoint = Endpoint {
    method: Method::Post,
    path: "/v1/apps/{name}/deploy",
    scope: Some(Scope::Admin),
    body: Body::NoAppData,
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
    body: Body::NoAppData,
};
/// `POST` [`ReloadRequest`](crate::ReloadRequest) → [`ReloadResponse`](crate::ReloadResponse).
/// Sends the app's `reload_signal`, restarts the container when the spec sets none, or recreates it
/// when `recreate = true` (issue #118). Changes no desired state.
pub const APPS_RELOAD: Endpoint = Endpoint {
    method: Method::Post,
    path: "/v1/apps/{name}/reload",
    scope: Some(Scope::Admin),
    body: Body::NoAppData,
};
/// `POST` [`RunRequest`](crate::RunRequest) → a stream of [`RunFrame`](crate::RunFrame)s
/// (`application/vnd.weglarka.run-stream`). Runs a command once in a fresh container of the app
/// (its image, env, secrets, volumes, configs and networks; never its `host_ports` or ingress
/// routing) and removes the container afterwards. Closing the connection kills the run (issue #106).
pub const APPS_RUN: Endpoint = Endpoint {
    method: Method::Post,
    path: "/v1/apps/{name}/run",
    scope: Some(Scope::Admin),
    body: Body::NoAppData,
};
/// `POST` [`ForwardRequest`](crate::ForwardRequest) → a stream of
/// [`ForwardFrame`](crate::ForwardFrame)s (`application/vnd.weglarka.forward-stream`). Starts a relay
/// container on the app's network, published on a loopback port of the host (the first frame names it),
/// and keeps it for as long as the connection is open; closing the connection removes it (issue #108).
pub const APPS_FORWARD: Endpoint = Endpoint {
    method: Method::Post,
    path: "/v1/apps/{name}/forward",
    scope: Some(Scope::Admin),
    body: Body::NoAppData,
};
/// `GET` → a stream of [`LogFrame`](crate::LogFrame)s (`application/vnd.weglarka.logs-stream`): the
/// output of the app's running container. Query [`LogsQuery`](crate::LogsQuery): `follow`, `tail`,
/// `since`, `timestamps`. 404 before the stream starts when the app or its container does not exist.
/// `admin` only, although it only reads: logs can hold secrets the app printed, and unlike a spec
/// they cannot be redacted ([`Body::Credential`], docs/decisions/0057). Over the token listener the
/// stream ends with a `TokenExpired` frame when the token does; the client reconnects with `since`.
pub const APPS_LOGS: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/apps/{name}/logs",
    scope: Some(Scope::Admin),
    body: Body::Credential,
};
/// `GET` → a stream of [`AccessFrame`](crate::AccessFrame)s: the requests that reached the app through its
/// domains (query: [`AccessQuery`](crate::AccessQuery)). `admin`: addresses and paths can be sensitive and
/// cannot be redacted ([`Body::Credential`], docs/decisions/0063). The daemon filters the shared nginx log.
pub const APPS_ACCESS: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/apps/{name}/access",
    scope: Some(Scope::Admin),
    body: Body::Credential,
};
/// `GET` → [`ListSecretsResponse`](crate::ListSecretsResponse) (without values)
pub const SECRETS_LIST: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/apps/{name}/secrets",
    scope: Some(Scope::Read),
    body: Body::NoAppData,
};
/// `PUT` [`SetSecretRequest`](crate::SetSecretRequest) → [`SecretInfo`](crate::SecretInfo).
/// Overwrite only; there is no endpoint for reading the value back.
pub const SECRETS_SET: Endpoint = Endpoint {
    method: Method::Put,
    path: "/v1/apps/{name}/secrets/{secret}",
    scope: Some(Scope::Admin),
    body: Body::NoAppData,
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
    body: Body::NoAppData,
};
/// `GET` → [`ListVolumesResponse`](crate::ListVolumesResponse): volumes declared in the app's spec.
pub const VOLUMES_LIST: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/apps/{name}/volumes",
    scope: Some(Scope::Read),
    body: Body::NoAppData,
};
/// `GET` → [`ListAppVolumesResponse`](crate::ListAppVolumesResponse): the volumes of every app in one
/// call, each row naming its app (replaces one `VOLUMES_LIST` call per app).
pub const APP_VOLUMES_LIST: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/app-volumes",
    scope: Some(Scope::Read),
    body: Body::NoAppData,
};
/// `GET` → `application/x-tar`, streamed. `{volume}` is the volume's name within the instance.
pub const VOLUMES_EXPORT: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/apps/{name}/volumes/{volume}/export",
    scope: Some(Scope::Admin),
    body: Body::Credential,
};
/// `PUT` a streamed `application/x-tar` body → 204. Extracts into the volume (existing files with the
/// same path are overwritten; others are kept). Ownership of the extracted files: docs/decisions/0009.
pub const VOLUMES_IMPORT: Endpoint = Endpoint {
    method: Method::Put,
    path: "/v1/apps/{name}/volumes/{volume}/import",
    scope: Some(Scope::Admin),
    body: Body::NoAppData,
};
/// `GET` → [`ListSharedVolumesResponse`](crate::ListSharedVolumesResponse): shared volumes declared in
/// `apps.toml` with their members, uid range and whether Podman knows them (issue #33).
pub const SHARED_VOLUMES_LIST: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/volumes",
    scope: Some(Scope::Read),
    body: Body::NoAppData,
};
/// `PUT` with no body → 204. Declares a shared volume (idempotent); apps mount it through
/// `shared_volumes = [...]` (issue #33). Query `group=<name>` puts it in a group that shares one uid
/// range with its other volumes (issue #129); declaring an existing volume with another group is a
/// 409.
pub const SHARED_VOLUMES_DECLARE: Endpoint = Endpoint {
    method: Method::Put,
    path: "/v1/volumes/{volume}",
    scope: Some(Scope::Admin),
    body: Body::NoAppData,
};
/// `DELETE` → 204. Query `purge=true` also deletes the Podman volume (its data). Refused while an app
/// mounts it, and without `purge` while it still holds data (issue #33).
pub const SHARED_VOLUMES_REMOVE: Endpoint = Endpoint {
    method: Method::Delete,
    path: "/v1/volumes/{volume}",
    scope: Some(Scope::Admin),
    body: Body::NoAppData,
};
/// `GET` → [`ListSharedNetworksResponse`](crate::ListSharedNetworksResponse): shared networks declared
/// in `apps.toml` with their members and whether Podman knows them (issue #128).
pub const SHARED_NETWORKS_LIST: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/networks",
    scope: Some(Scope::Read),
    body: Body::NoAppData,
};
/// `PUT` with no body → 204. Declares a shared network (idempotent); apps join it through
/// `shared_networks = [...]` (issue #128).
pub const SHARED_NETWORKS_DECLARE: Endpoint = Endpoint {
    method: Method::Put,
    path: "/v1/networks/{network}",
    scope: Some(Scope::Admin),
    body: Body::NoAppData,
};
/// `DELETE` → 204. Refused (409) while an app joins it (issue #128).
pub const SHARED_NETWORKS_REMOVE: Endpoint = Endpoint {
    method: Method::Delete,
    path: "/v1/networks/{network}",
    scope: Some(Scope::Admin),
    body: Body::NoAppData,
};
/// `GET` → [`ListSitesResponse`](crate::ListSitesResponse): sites with their environments and the
/// digest each serves (issue #205).
pub const SITES_LIST: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/sites",
    scope: Some(Scope::Read),
    body: Body::NoAppData,
};
/// `GET` → [`SiteSummary`](crate::SiteSummary).
pub const SITES_SHOW: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/sites/{site}",
    scope: Some(Scope::Read),
    body: Body::NoAppData,
};
/// `PUT` [`DeclareSiteRequest`](crate::DeclareSiteRequest) → 204. Declares or replaces a site; its
/// environments become the instances `<site>-<env>`. An instance name taken by `[apps]` or another
/// site is a 400.
pub const SITES_DECLARE: Endpoint = Endpoint {
    method: Method::Put,
    path: "/v1/sites/{site}",
    scope: Some(Scope::Admin),
    body: Body::NoAppData,
};
/// `DELETE` → 204. Query [`RemoveSiteQuery`](crate::RemoveSiteQuery): refused (409) while an
/// environment serves a release unless `?purge=true`.
pub const SITES_REMOVE: Endpoint = Endpoint {
    method: Method::Delete,
    path: "/v1/sites/{site}",
    scope: Some(Scope::Admin),
    body: Body::NoAppData,
};
/// `POST` [`PromoteRequest`](crate::PromoteRequest) → [`PromoteResponse`](crate::PromoteResponse).
/// Deploys the digest of the environment's `promote_from` source (or an explicit one, or the
/// previous one) without pulling it again (issue #205, docs/decisions/0050).
pub const SITES_PROMOTE: Endpoint = Endpoint {
    method: Method::Post,
    path: "/v1/sites/{site}/envs/{env}/promote",
    scope: Some(Scope::Admin),
    body: Body::NoAppData,
};
/// `GET` → [`EventsResponse`](crate::EventsResponse). Query [`EventsQuery`](crate::EventsQuery):
/// recent domain events from a bounded in-memory history (docs/decisions/0057), newer than `since`,
/// at most the newest `limit`.
pub const EVENTS_RECENT: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/events",
    scope: Some(Scope::Read),
    body: Body::NoAppData,
};
/// `GET` → [`CertificatesResponse`](crate::CertificatesResponse): expiry of every ACME-managed
/// certificate; never key material or paths.
pub const CERTIFICATES: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/certificates",
    scope: Some(Scope::Read),
    body: Body::NoAppData,
};
/// `GET` → [`ConfigView`](crate::ConfigView): an allow-list projection of `weglarka.toml`.
pub const CONFIG: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/config",
    scope: Some(Scope::Read),
    body: Body::NoAppData,
};
/// `GET` → [`DoctorReport`](crate::DoctorReport)
pub const DOCTOR: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/doctor",
    scope: Some(Scope::Read),
    body: Body::NoAppData,
};
/// `POST` [`PruneImagesRequest`](crate::PruneImagesRequest) → [`PruneImagesResponse`](crate::PruneImagesResponse).
/// Removes images of the repositories named in `apps.toml` that are neither an app's current nor its
/// previous image and that no container uses (issue #40). `dry_run` only reports them.
pub const IMAGES_PRUNE: Endpoint = Endpoint {
    method: Method::Post,
    path: "/v1/images/prune",
    scope: Some(Scope::Admin),
    body: Body::NoAppData,
};
/// `POST` with no body → [`OidcRotateResponse`](crate::OidcRotateResponse): replaces the app's OIDC
/// client secret, re-renders the provider's clients, then recreates the app (#213).
pub const OIDC_ROTATE: Endpoint = Endpoint {
    method: Method::Post,
    path: "/v1/apps/{name}/oidc/rotate",
    scope: Some(Scope::Admin),
    body: Body::NoAppData,
};
/// `GET` → [`ListOidcClientsResponse`](crate::ListOidcClientsResponse): the external clients.
pub const OIDC_CLIENTS_LIST: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/oidc-clients",
    // The answer carries each client's `secret_digest`: a credential, so `admin` only.
    scope: Some(Scope::Admin),
    body: Body::Credential,
};
/// `PUT` [`PutOidcClientRequest`](crate::PutOidcClientRequest) → 204; replaces a client of that id.
pub const OIDC_CLIENT_PUT: Endpoint = Endpoint {
    method: Method::Put,
    path: "/v1/oidc-clients/{id}",
    scope: Some(Scope::Admin),
    body: Body::NoAppData,
};
/// `DELETE` → 204.
pub const OIDC_CLIENT_REMOVE: Endpoint = Endpoint {
    method: Method::Delete,
    path: "/v1/oidc-clients/{id}",
    scope: Some(Scope::Admin),
    body: Body::NoAppData,
};
/// `GET` → [`NotifyStatusResponse`](crate::NotifyStatusResponse): configured channels, the pending
/// outbox and the last delivery error (issue #38).
pub const NOTIFICATIONS_STATUS: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/notifications",
    scope: Some(Scope::Read),
    body: Body::NoAppData,
};
/// `POST` with no body → [`NotifyTestResponse`](crate::NotifyTestResponse). Delivers a test
/// notification now, bypassing the outbox (issue #38).
pub const NOTIFICATIONS_TEST: Endpoint = Endpoint {
    method: Method::Post,
    path: "/v1/notifications/test",
    scope: Some(Scope::Admin),
    body: Body::NoAppData,
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
    APPS_LOGS,
    APPS_ACCESS,
    SECRETS_LIST,
    SECRETS_SET,
    SECRETS_REMOVE,
    VOLUMES_LIST,
    APP_VOLUMES_LIST,
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
    CERTIFICATES,
    CONFIG,
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

    /// A credential or the data of an app is never served at `read`.
    #[test]
    fn credential_bearing_endpoints_need_admin() {
        for e in ENDPOINTS.iter().filter(|e| e.body == Body::Credential) {
            assert_eq!(e.scope, Some(Scope::Admin), "{}", e.path);
        }
        // The two known ones stay classified as such.
        assert_eq!(VOLUMES_EXPORT.body, Body::Credential);
        assert_eq!(OIDC_CLIENTS_LIST.body, Body::Credential);
    }

    /// Only the endpoints that answer with a `ShowAppResponse` are `AppView`; they are `read` only
    /// because the daemon redacts for a caller without `admin` (`weglarka-daemon`, `app_view`; the
    /// integration test `token_api.rs` walks this list). A new endpoint that returns an `AppSpec`
    /// must be added here on purpose.
    #[test]
    fn app_data_is_served_only_through_the_redacted_view() {
        let views: Vec<_> = ENDPOINTS
            .iter()
            .filter(|e| e.body == Body::AppView)
            .map(|e| (e.method.as_str(), e.path))
            .collect();
        assert_eq!(
            views,
            [
                ("POST", "/v1/apps"),
                ("GET", "/v1/apps/{name}"),
                ("PUT", "/v1/apps/{name}"),
            ]
        );
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
