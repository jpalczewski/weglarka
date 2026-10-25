//! Endpoint list. Paths contain `{name}` / `{secret}` / `{volume}` parameters.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    pub method: Method,
    pub path: &'static str,
}

/// `GET` → [`StatusResponse`](crate::StatusResponse)
pub const STATUS: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/status",
};
/// `GET` → [`HealthResponse`](crate::HealthResponse). Readiness only: it answers once the admin API
/// is serving and deliberately never calls Podman, so the host-side self-update watchdog can tell a
/// broken daemon from a Podman hiccup (issue #100).
pub const HEALTH: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/health",
};
/// `GET` → [`ListAppsResponse`](crate::ListAppsResponse)
pub const APPS_LIST: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/apps",
};
/// `POST` [`AddAppRequest`](crate::AddAppRequest) → [`ShowAppResponse`](crate::ShowAppResponse)
pub const APPS_ADD: Endpoint = Endpoint {
    method: Method::Post,
    path: "/v1/apps",
};
/// `GET` → [`ShowAppResponse`](crate::ShowAppResponse)
pub const APPS_SHOW: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/apps/{name}",
};
/// `PUT` [`UpdateAppRequest`](crate::UpdateAppRequest) → [`UpdateAppResponse`](crate::UpdateAppResponse).
/// Full spec replacement (see the request type). Owner: session 3.
pub const APPS_UPDATE: Endpoint = Endpoint {
    method: Method::Put,
    path: "/v1/apps/{name}",
};
/// `DELETE` → 204. Query [`RemoveAppQuery`](crate::RemoveAppQuery): `?purge_volumes=true` also removes
/// the instance's volumes (kept by default), `?purge_secrets=true` also removes the instance's secrets
/// (kept by default; independent of the volumes).
pub const APPS_REMOVE: Endpoint = Endpoint {
    method: Method::Delete,
    path: "/v1/apps/{name}",
};
/// `POST` [`DeployRequest`](crate::DeployRequest) → [`DeployResponse`](crate::DeployResponse)
pub const APPS_DEPLOY: Endpoint = Endpoint {
    method: Method::Post,
    path: "/v1/apps/{name}/deploy",
};
/// `PUT` a streamed `application/x-tar` image archive (`oci-archive` or `docker-archive`, as written by
/// `podman save`) → [`DeployResponse`](crate::DeployResponse). Loads the image into Podman's store,
/// tags it into the app's image repository and deploys it like any other digest: health gate,
/// rollback, `current`/`previous` in `state.toml`; `apps.toml` is not touched. One upload at a time
/// (409 otherwise); an archive Podman cannot load is a 400 (issue #109, docs/decisions/0042).
pub const APPS_PUSH_IMAGE: Endpoint = Endpoint {
    method: Method::Put,
    path: "/v1/apps/{name}/image",
};
/// `POST` [`ReloadRequest`](crate::ReloadRequest) → [`ReloadResponse`](crate::ReloadResponse).
/// Sends the app's `reload_signal`, restarts the container when the spec sets none, or recreates it
/// when `recreate = true` (issue #118). Changes no desired state.
pub const APPS_RELOAD: Endpoint = Endpoint {
    method: Method::Post,
    path: "/v1/apps/{name}/reload",
};
/// `POST` [`RunRequest`](crate::RunRequest) → a stream of [`RunFrame`](crate::RunFrame)s
/// (`application/vnd.weglarka.run-stream`). Runs a command once in a fresh container of the app
/// (its image, env, secrets, volumes, configs and networks; never its `host_ports` or ingress
/// routing) and removes the container afterwards. Closing the connection kills the run (issue #106).
pub const APPS_RUN: Endpoint = Endpoint {
    method: Method::Post,
    path: "/v1/apps/{name}/run",
};
/// `POST` [`ForwardRequest`](crate::ForwardRequest) → a stream of
/// [`ForwardFrame`](crate::ForwardFrame)s (`application/vnd.weglarka.forward-stream`). Starts a relay
/// container on the app's network, published on a loopback port of the host (the first frame names it),
/// and keeps it for as long as the connection is open; closing the connection removes it (issue #108).
pub const APPS_FORWARD: Endpoint = Endpoint {
    method: Method::Post,
    path: "/v1/apps/{name}/forward",
};
/// `GET` → [`ListSecretsResponse`](crate::ListSecretsResponse) (without values)
pub const SECRETS_LIST: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/apps/{name}/secrets",
};
/// `PUT` [`SetSecretRequest`](crate::SetSecretRequest) → [`SecretInfo`](crate::SecretInfo).
/// Overwrite only; there is no endpoint for reading the value back.
pub const SECRETS_SET: Endpoint = Endpoint {
    method: Method::Put,
    path: "/v1/apps/{name}/secrets/{secret}",
};
/// `DELETE` → 204. Query [`RemoveSecretQuery`](crate::RemoveSecretQuery): `?force=true` removes the
/// secret even though the app's spec still binds it (the app then waits for it). Refused with 409
/// while the spec binds it and `force` is not set; 404 when the store has no such secret. The app
/// need not exist in `apps.toml` — that is how the leftovers of a removed app are cleaned up
/// (issue #80).
pub const SECRETS_REMOVE: Endpoint = Endpoint {
    method: Method::Delete,
    path: "/v1/apps/{name}/secrets/{secret}",
};
/// `GET` → [`ListVolumesResponse`](crate::ListVolumesResponse): volumes declared in the app's spec.
pub const VOLUMES_LIST: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/apps/{name}/volumes",
};
/// `GET` → `application/x-tar`, streamed. `{volume}` is the volume's name within the instance.
pub const VOLUMES_EXPORT: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/apps/{name}/volumes/{volume}/export",
};
/// `PUT` a streamed `application/x-tar` body → 204. Extracts into the volume (existing files with the
/// same path are overwritten; others are kept). Ownership of the extracted files: docs/decisions/0009.
pub const VOLUMES_IMPORT: Endpoint = Endpoint {
    method: Method::Put,
    path: "/v1/apps/{name}/volumes/{volume}/import",
};
/// `GET` → [`ListSharedVolumesResponse`](crate::ListSharedVolumesResponse): shared volumes declared in
/// `apps.toml` with their members, uid range and whether Podman knows them (issue #33).
pub const SHARED_VOLUMES_LIST: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/volumes",
};
/// `PUT` with no body → 204. Declares a shared volume (idempotent); apps mount it through
/// `shared_volumes = [...]` (issue #33). Query `group=<name>` puts it in a group that shares one uid
/// range with its other volumes (issue #129); declaring an existing volume with another group is a
/// 409.
pub const SHARED_VOLUMES_DECLARE: Endpoint = Endpoint {
    method: Method::Put,
    path: "/v1/volumes/{volume}",
};
/// `DELETE` → 204. Query `purge=true` also deletes the Podman volume (its data). Refused while an app
/// mounts it, and without `purge` while it still holds data (issue #33).
pub const SHARED_VOLUMES_REMOVE: Endpoint = Endpoint {
    method: Method::Delete,
    path: "/v1/volumes/{volume}",
};
/// `GET` → [`ListSharedNetworksResponse`](crate::ListSharedNetworksResponse): shared networks declared
/// in `apps.toml` with their members and whether Podman knows them (issue #128).
pub const SHARED_NETWORKS_LIST: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/networks",
};
/// `PUT` with no body → 204. Declares a shared network (idempotent); apps join it through
/// `shared_networks = [...]` (issue #128).
pub const SHARED_NETWORKS_DECLARE: Endpoint = Endpoint {
    method: Method::Put,
    path: "/v1/networks/{network}",
};
/// `DELETE` → 204. Refused (409) while an app joins it (issue #128).
pub const SHARED_NETWORKS_REMOVE: Endpoint = Endpoint {
    method: Method::Delete,
    path: "/v1/networks/{network}",
};
/// `GET` → [`ListSitesResponse`](crate::ListSitesResponse): sites with their environments and the
/// digest each serves (issue #205).
pub const SITES_LIST: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/sites",
};
/// `GET` → [`SiteSummary`](crate::SiteSummary).
pub const SITES_SHOW: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/sites/{site}",
};
/// `PUT` [`DeclareSiteRequest`](crate::DeclareSiteRequest) → 204. Declares or replaces a site; its
/// environments become the instances `<site>-<env>`. An instance name taken by `[apps]` or another
/// site is a 400.
pub const SITES_DECLARE: Endpoint = Endpoint {
    method: Method::Put,
    path: "/v1/sites/{site}",
};
/// `DELETE` → 204. Query [`RemoveSiteQuery`](crate::RemoveSiteQuery): refused (409) while an
/// environment serves a release unless `?purge=true`.
pub const SITES_REMOVE: Endpoint = Endpoint {
    method: Method::Delete,
    path: "/v1/sites/{site}",
};
/// `POST` [`PromoteRequest`](crate::PromoteRequest) → [`PromoteResponse`](crate::PromoteResponse).
/// Deploys the digest of the environment's `promote_from` source (or an explicit one, or the
/// previous one) without pulling it again (issue #205, docs/decisions/0050).
pub const SITES_PROMOTE: Endpoint = Endpoint {
    method: Method::Post,
    path: "/v1/sites/{site}/envs/{env}/promote",
};
/// `GET` → [`DoctorReport`](crate::DoctorReport)
pub const DOCTOR: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/doctor",
};
/// `POST` [`PruneImagesRequest`](crate::PruneImagesRequest) → [`PruneImagesResponse`](crate::PruneImagesResponse).
/// Removes images of the repositories named in `apps.toml` that are neither an app's current nor its
/// previous image and that no container uses (issue #40). `dry_run` only reports them.
pub const IMAGES_PRUNE: Endpoint = Endpoint {
    method: Method::Post,
    path: "/v1/images/prune",
};
/// `GET` → [`NotifyStatusResponse`](crate::NotifyStatusResponse): configured channels, the pending
/// outbox and the last delivery error (issue #38).
pub const NOTIFICATIONS_STATUS: Endpoint = Endpoint {
    method: Method::Get,
    path: "/v1/notifications",
};
/// `POST` with no body → [`NotifyTestResponse`](crate::NotifyTestResponse). Delivers a test
/// notification now, bypassing the outbox (issue #38).
pub const NOTIFICATIONS_TEST: Endpoint = Endpoint {
    method: Method::Post,
    path: "/v1/notifications/test",
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
    DOCTOR,
    IMAGES_PRUNE,
    NOTIFICATIONS_STATUS,
    NOTIFICATIONS_TEST,
];
