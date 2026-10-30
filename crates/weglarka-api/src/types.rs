//! Admin API request/response types.

use serde::{Deserialize, Serialize};
use weglarka_model::app::{AppSpec, Digest, InstanceName, SharedNetworkName, SharedVolumeName};
use weglarka_model::environments::{EnvName, SiteName, SiteSpec};
use weglarka_model::events::Severity;
use weglarka_model::state::AppState;
use weglarka_model::uid_range::UidRange;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    NotFound,
    AlreadyExists,
    InvalidRequest,
    Conflict,
    /// The engine is busy with another mutation (e.g. a deploy behind the health gate). Transient:
    /// the CLI retries the same request for a while before giving up.
    Busy,
    /// Token listener only (docs/decisions/0056): no valid bearer token.
    Unauthorized,
    /// Token listener only: a valid token whose scopes do not allow the endpoint.
    Forbidden,
    Internal,
}

impl ErrorCode {
    pub fn http_status(self) -> u16 {
        match self {
            Self::NotFound => 404,
            Self::AlreadyExists | Self::Conflict => 409,
            Self::InvalidRequest => 400,
            Self::Busy => 503,
            Self::Unauthorized => 401,
            Self::Forbidden => 403,
            Self::Internal => 500,
        }
    }
}

/// Error response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeState {
    Running,
    Stopped,
    Missing,
    Unhealthy,
    /// No container yet: the deploy waits for secrets bound in the spec that are not set
    /// (`AppState::waiting_for_secrets` lists them). Setting the last one deploys the app.
    WaitingForSecret,
    /// No container by design: the spec has `start = false`, so the app is provisioned only (image
    /// digest pinned, network, uid range and volumes ready). `apps start` brings it up.
    NotStarted,
}

/// App summary in a list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSummary {
    pub name: InstanceName,
    pub image: String,
    pub domains: Vec<String>,
    pub runtime: RuntimeState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<Digest>,
    /// `<site>/<env>` when the instance is expanded from a site (issue #205).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListAppsResponse {
    pub apps: Vec<AppSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddAppRequest {
    pub name: InstanceName,
    pub spec: AppSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShowAppResponse {
    pub name: InstanceName,
    pub spec: AppSpec,
    pub state: AppState,
    pub runtime: RuntimeState,
    /// Resolved `configs` mounts with a content fingerprint (issue #118); absent when the app
    /// declares no config mounts. Only `GET /v1/apps/{name}` fills it — the daemon reads
    /// `config_root` on demand and the list endpoint does not touch the filesystem.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configs: Option<Vec<ConfigMountView>>,
    /// Declared `host_mounts` with their status against the operator's allowlist (issue #178);
    /// absent when the app declares none. Only `GET /v1/apps/{name}` fills it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_mounts: Option<Vec<HostMountView>>,
    /// Times Podman restarted the container (restart policy); absent when there is no container.
    /// Runtime detail, only `GET /v1/apps/{name}` fills it (add/update answer without a probe).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restarts: Option<u32>,
    /// The container's health as Podman reports it, unlike `runtime` (which folds everything but
    /// `unhealthy` into `running`) it tells `starting` from `healthy`. Absent when there is no
    /// container or the image has no healthcheck.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<ContainerHealth>,
    /// When the container last started, RFC 3339 as Podman reports it; absent when it never ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    /// `true` when the daemon withheld parts of `spec` and `state` from this caller (a token
    /// without `admin`): `env` values are blank, every `command` element and the failure text
    /// are placeholders, the probe path is cut. Such a spec is a view, not the stored spec, so it must
    /// never be sent back in `PUT /v1/apps/{name}` (a full replacement). Absent when nothing was
    /// withheld, so the unredacted answer is unchanged (docs/decisions/0057 decision 8).
    #[serde(default, skip_serializing_if = "is_false")]
    pub redacted: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Raw container health (`GET /v1/apps/{name}`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerHealth {
    /// Inside the healthcheck start period or before the first passing probe.
    Starting,
    Healthy,
    Unhealthy,
}

/// State of one declared host mount as the daemon sees it (issue #178).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostMountStatus {
    /// Allowlisted, exists, resolves to itself.
    Ok,
    /// The source is not in `[runtime] host_mounts` of `weglarka.toml`.
    NotAllowed,
    /// The source does not exist on the host.
    Missing,
    /// The path resolves somewhere else (a symlink in the path).
    Redirected,
    /// The source exists but is neither a regular file nor a directory.
    NotFileOrDir,
    /// The source cannot be statted.
    Unreadable,
}

/// One host mount of an app: always read-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostMountView {
    /// Absolute host path, as declared (and allowlisted).
    pub source: String,
    /// Absolute path in the container.
    pub target: String,
    pub status: HostMountStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// State of one declared config mount as the daemon sees it on disk (issue #118).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigMountStatus {
    /// Resolved inside `config_root`; a regular file or a directory.
    Ok,
    /// The source does not exist under `config_root`.
    Missing,
    /// The app declares `configs`, but `weglarka.toml` has no `config_root`.
    NoRoot,
    /// After resolving symlinks the path escapes `config_root`.
    OutsideRoot,
    /// The source exists but is neither a regular file nor a directory.
    NotFileOrDir,
    /// The path is inside `config_root` but cannot be read/statted.
    Unreadable,
}

/// One config mount of an app: what is declared (`source`, `target`), what the daemon sees now and
/// a fingerprint of the current content (sha256 of the bytes, or of the sorted directory tree;
/// `.git` excluded). `fingerprint` is absent when the source is not readable or is too large.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigMountView {
    /// Path relative to `config_root`, as declared in the app spec.
    pub source: String,
    /// Absolute path in the container.
    pub target: String,
    pub status: ConfigMountStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Human-readable detail for a non-`ok` status (the path, the io error…).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// `PUT /v1/apps/{name}`: **full replacement** of the instance's spec (not a patch). The client reads
/// the spec (`GET`), changes it and sends it back; omitted optional fields are cleared. Chosen over
/// `PATCH` because merge semantics for maps, lists and "set to null" are not worth the ambiguity.
/// The daemon validates, persists to `apps.toml` and reconciles: a changed `spec_hash` recreates the
/// container (rollback via the health gate as for any deploy); a change of only domains or gate
/// settings applies without a recreate. Owner: session 3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateAppRequest {
    pub spec: AppSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateAppResponse {
    pub app: ShowAppResponse,
    /// `Some` when the update caused a (re)deploy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deploy: Option<DeployResponse>,
}

/// Query of `DELETE /v1/apps/{name}`: `?purge_volumes=true` also deletes the instance's named volumes,
/// `?purge_secrets=true` its secrets. Without them volumes and secrets are kept (data survives
/// `remove` + `add`, which also means a new app under the same name inherits the old secrets).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoveAppQuery {
    #[serde(default)]
    pub purge_volumes: bool,
    #[serde(default)]
    pub purge_secrets: bool,
}

/// Query of `DELETE /v1/apps/{name}/secrets/{secret}` (issue #80): `?force=true` removes a secret the
/// app's spec still binds. Without it such a removal is refused with 409.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoveSecretQuery {
    #[serde(default)]
    pub force: bool,
}

/// A volume declared in the app's spec, with what Podman knows about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeSummary {
    /// Name within the instance (`VolumeMount::name`), or the shared volume's name.
    pub name: String,
    /// Mount path in the container.
    pub target: String,
    /// Podman volume name (`<instance>.<name>` or `wg-shared-<name>`).
    pub podman_name: String,
    /// `false` until the first deploy creates it.
    pub exists: bool,
    /// `true` when this is a shared volume the app mounts (issue #33); the field is omitted for
    /// instance volumes, so existing responses keep their shape.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub shared: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListVolumesResponse {
    pub volumes: Vec<VolumeSummary>,
}

/// A shared volume declared once in `apps.toml` and mounted by several instances (issue #33).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedVolumeSummary {
    pub name: SharedVolumeName,
    /// Podman volume name (`wg-shared-<name>`).
    pub podman_name: String,
    /// Group whose uid range the volume lives in (issue #129): the declared `group`, otherwise the
    /// volume's own name. Omitted by daemons that predate groups.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<SharedVolumeName>,
    /// Instances mounting it, sorted by name (empty while it is declared but unused).
    pub members: Vec<InstanceName>,
    /// Allocated on the first member's deploy; `None` before that.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid_range: Option<UidRange>,
    /// `false` until the first member's deploy creates it.
    pub exists: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListSharedVolumesResponse {
    pub volumes: Vec<SharedVolumeSummary>,
}

/// A shared network declared once in `apps.toml` and joined by several instances (issue #128).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedNetworkSummary {
    pub name: SharedNetworkName,
    /// Podman network name (`net-shared-<name>`).
    pub podman_name: String,
    /// Instances joining it, sorted by name (empty while it is declared but unused).
    pub members: Vec<InstanceName>,
    /// `false` until the first member's deploy creates it.
    pub exists: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListSharedNetworksResponse {
    pub networks: Vec<SharedNetworkSummary>,
}

/// One environment of a site as the daemon sees it (issue #205).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteEnvSummary {
    pub env: EnvName,
    /// The instance the environment expands into (`<site>-<env>`).
    pub instance: InstanceName,
    /// Tag the environment follows (`track` environments).
    pub track: Option<String>,
    /// Environment it receives digests from (promote-only environments).
    pub promote_from: Option<EnvName>,
    pub domains: Vec<String>,
    /// Digest being served; `None` before the first release.
    pub current: Option<Digest>,
    pub previous: Option<Digest>,
}

/// A site with its environments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteSummary {
    pub name: SiteName,
    pub image: String,
    pub envs: Vec<SiteEnvSummary>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListSitesResponse {
    pub sites: Vec<SiteSummary>,
}

/// `PUT /v1/sites/{site}`: the declaration (replaces an existing site of that name).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclareSiteRequest {
    pub spec: SiteSpec,
}

/// Query of `DELETE /v1/sites/{site}`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoveSiteQuery {
    /// Also forget the state of environments that still serve a release.
    #[serde(default)]
    pub purge: bool,
}

/// `POST /v1/sites/{site}/envs/{env}/promote`. With neither field set, the source environment's
/// current digest is promoted.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromoteRequest {
    /// Promote this digest of the site's repository instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<Digest>,
    /// Return to the environment's previous digest.
    #[serde(default)]
    pub rollback: bool,
    /// Report what would happen; change nothing.
    #[serde(default)]
    pub dry_run: bool,
}

/// What a promotion did or, for a dry run, would do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromoteResponse {
    pub instance: InstanceName,
    /// Environment instance the digest comes from; `None` for a rollback.
    pub source: Option<InstanceName>,
    pub source_current: Option<Digest>,
    pub target_current: Option<Digest>,
    pub target_previous: Option<Digest>,
    /// The digest the environment serves after the promotion.
    pub digest: Digest,
    /// `None` for a dry run.
    pub deploy: Option<DeployResponse>,
}

/// `POST /v1/images/prune` (issue #40): remove images older than each app's current and previous one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PruneImagesRequest {
    /// Report the images that would be removed; remove nothing.
    #[serde(default)]
    pub dry_run: bool,
}

/// One image of the local Podman store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrunedImage {
    pub id: String,
    /// `repo:tag` names (`<none>:<none>` is filtered out).
    pub tags: Vec<String>,
    /// `repo@sha256:…` names — an untagged leftover is still identified by these.
    pub digests: Vec<String>,
    /// Reported by libpod; `0` when unknown.
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PruneImagesResponse {
    pub dry_run: bool,
    /// Images removed; on a dry run — the images that *would* be removed.
    pub removed: Vec<PrunedImage>,
    /// An upper bound: sizes of layers shared between images are counted per image.
    pub reclaimed_bytes: u64,
    /// `"<id>: <error>"` for images Podman refused (e.g. still in use); the rest is still removed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeployRequest {
    /// Defaults to `spec.image`. A given reference (a tag or digest of the **same repository**) is
    /// pulled and deployed instead: its digest is pinned in `state.toml` like any deploy's, `apps.toml`
    /// keeps `image`, and the next deploy of the tag replaces it (`weglarka push --image`, issue #109).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_ref: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeployOutcome {
    Deployed,
    /// Digest and spec unchanged — nothing to do.
    Unchanged,
    /// The new version failed the health gate; rolled back to the previous digest.
    RolledBack,
    /// `start = false`: nothing was started. The image is pinned and the network, uid range and
    /// volumes are ready; `apps start` deploys the app later.
    Provisioned,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeployResponse {
    pub outcome: DeployOutcome,
    pub generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<Digest>,
}

/// `POST /v1/apps/{name}/reload` (issue #118). An empty body means `recreate = false`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReloadRequest {
    /// Recreate the container from the pinned digest instead of reloading in place. Needed when a
    /// single-file config mount points at the old inode (editors that save with write-and-rename).
    #[serde(default)]
    pub recreate: bool,
}

/// What `apps reload` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReloadAction {
    /// The spec's `reload_signal` was sent to the running container.
    Signalled,
    /// No `reload_signal`: the container was stopped and started again (same container).
    Restarted,
    /// `recreate = true`: the container was recreated from the pinned digest (forced deploy).
    Recreated,
}

/// `POST /v1/apps/{name}/reload` → what happened and what the app now sees.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReloadResponse {
    pub name: InstanceName,
    pub action: ReloadAction,
    /// Signal actually sent (without the `SIG` prefix), for [`ReloadAction::Signalled`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<String>,
    /// The resolved config mounts and their fingerprints after the reload (issue #118); absent
    /// when the app declares no config mounts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configs: Option<Vec<ConfigMountView>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusResponse {
    pub api_version: String,
    pub daemon_version: String,
    pub podman_version: String,
    pub apps: Vec<AppSummary>,
}

/// `GET /v1/health` — readiness of the admin API, not a health check of the apps (issue #100).
///
/// It exists for the host-side self-update watchdog: the admin socket is bound after every startup
/// precondition, so an answer is the signal that the newly switched daemon really came up. The
/// endpoint never calls Podman, so a Podman hiccup cannot look like a failed update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Always `"ok"`: a response only exists while the API is serving.
    pub status: String,
    pub daemon_version: String,
    /// Seconds since the daemon started, for the journal and the API client.
    pub uptime_secs: u64,
}

/// Secret value; `Debug` does not reveal it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetSecretRequest {
    pub value: String,
}

impl std::fmt::Debug for SetSecretRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SetSecretRequest { value: <redacted> }")
    }
}

/// Secret metadata — never the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretInfo {
    pub name: String,
    /// RFC 3339.
    pub updated_at: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListSecretsResponse {
    pub secrets: Vec<SecretInfo>,
}

/// One configured notification channel (`GET /v1/notifications`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotifyChannelSummary {
    /// Channel name as stored in the outbox (`ntfy`).
    pub name: String,
    /// Lowest severity this channel publishes.
    pub min_severity: Severity,
    /// Notifications queued for this channel.
    pub pending: u32,
}

/// `GET /v1/notifications`: notification status (issue #38). `enabled = false` when `weglarka.toml`
/// has no `[notify]` channel — then every other field is empty.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotifyStatusResponse {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub channels: Vec<NotifyChannelSummary>,
    /// Notifications waiting for delivery (durable outbox).
    pub pending: u32,
    /// Notifications dropped since the outbox was created (queue cap, age, permanent errors).
    pub dropped: u64,
    /// Error of the last failed delivery attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// RFC 3339 of the last successful delivery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_delivered_at: Option<String>,
}

/// `POST /v1/notifications/test`: delivery of a test notification, bypassing the outbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotifyTestResponse {
    /// `true` when the channel accepted the notification right now.
    pub delivered: bool,
    /// The channel's verdict when `delivered` is `false`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_request_debug_is_redacted() {
        let r = SetSecretRequest {
            value: "hunter2".into(),
        };
        assert!(!format!("{r:?}").contains("hunter2"));
    }

    #[test]
    fn events_query_parses_since_and_boot() {
        assert_eq!(EventsQuery::parse(None).unwrap(), EventsQuery::default());
        let q = EventsQuery::parse(Some("x=1&since=7&boot=1a2b-3c")).unwrap();
        assert_eq!((q.since, q.boot.as_deref()), (Some(7), Some("1a2b-3c")));
        for bad in [
            "since=-1",
            "since=",
            "since=1.5",
            "boot=",
            "boot=a/b",
            "boot=zz",
        ] {
            assert!(EventsQuery::parse(Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn logs_query_defaults_and_roundtrip() {
        assert_eq!(LogsQuery::parse(None).unwrap(), LogsQuery::default());
        assert_eq!(LogsQuery::parse(Some("")).unwrap(), LogsQuery::default());
        let q = LogsQuery::parse(Some(
            "follow=true&tail=100&since=1700000000.25&timestamps=false",
        ))
        .unwrap();
        assert_eq!(
            q,
            LogsQuery {
                follow: true,
                tail: Some(100),
                since: Some(std::time::Duration::new(1_700_000_000, 250_000_000)),
                timestamps: false,
            }
        );
        assert_eq!(LogsQuery::parse(Some(&q.to_query_string())).unwrap(), q);
        assert_eq!(LogsQuery::default().to_query_string(), "");
        assert_eq!(
            LogsQuery::parse(Some("tail=10000")).unwrap().tail,
            Some(MAX_LOGS_TAIL)
        );
        assert_eq!(
            LogsQuery::parse(Some("since=5")).unwrap().since_time(),
            Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(5))
        );
    }

    #[test]
    fn logs_query_refuses_anything_that_could_reach_libpod_as_a_parameter() {
        for bad in [
            "x=1",
            "stdout=false",
            "follow",
            "follow=",
            "follow=1",
            "follow=TRUE",
            "follow=true&follow=false",
            "tail=",
            "tail=-1",
            "tail=+5",
            "tail=1.5",
            "tail=10001",
            "tail=99999999999",
            "tail=5&until=1",
            "tail=5%26until%3D1",
            "tail=5=6",
            "tail=5 ",
            "tail=5\n",
            "since=",
            "since=.5",
            "since=1.",
            "since=1.2.3",
            "since=-1",
            "since=1e9",
            "since=1%2e5",
            "since=1&until=2",
            "since=123456789012",
            "since=1\n&follow=true",
            "since=1 follow=true",
            "timestamps=true%26tail%3D1",
            "timestamps=yes",
        ] {
            assert!(LogsQuery::parse(Some(bad)).is_err(), "{bad:?}");
        }
        // The message does not echo control characters.
        let err = LogsQuery::parse(Some("bad\nkey=1")).unwrap_err();
        assert!(!err.contains('\n'), "{err:?}");
    }

    #[test]
    fn endpoints_snapshot() {
        let list: Vec<String> = crate::ENDPOINTS
            .iter()
            .map(|e| format!("{:?} {}", e.method, e.path))
            .collect();
        insta::assert_json_snapshot!(list);
    }
}

/// `POST /v1/apps/{name}/oidc/rotate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcRotateResponse {
    pub name: InstanceName,
    /// The app was recreated to pick up the new secret; `false` when it is not running (it reads the
    /// new secret at its next start).
    pub recreated: bool,
}

/// `GET /v1/oidc-clients`: clients of apps Węglarka does not run (`[oidc_clients.<id>]`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListOidcClientsResponse {
    pub clients: std::collections::BTreeMap<
        weglarka_model::identity::ClientId,
        weglarka_model::identity::ExternalClientSpec,
    >,
}

/// `PUT /v1/oidc-clients/{id}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PutOidcClientRequest {
    pub spec: weglarka_model::identity::ExternalClientSpec,
}

/// Query of `GET /v1/events`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventsQuery {
    /// Return only events with a `seq` greater than this (the `next_seq` of the previous answer).
    /// Absent = everything retained.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    /// The `boot_id` of the answer `since` came from. When it no longer matches (the daemon restarted,
    /// so `seq` started over) the cursor is ignored and the answer has `reset` set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot: Option<String>,
}

impl EventsQuery {
    /// Parses a raw query string (`since=12&boot=abc`); unknown keys are ignored.
    pub fn parse(raw: Option<&str>) -> Result<Self, String> {
        let mut query = Self::default();
        for kv in raw
            .unwrap_or_default()
            .split('&')
            .filter(|kv| !kv.is_empty())
        {
            let (key, value) = kv.split_once('=').unwrap_or((kv, ""));
            match key {
                "since" => {
                    query.since = Some(
                        value
                            .parse()
                            .map_err(|_| "`since` must be a non-negative integer".to_owned())?,
                    );
                }
                "boot" => {
                    let ok = !value.is_empty()
                        && value.len() <= 64
                        && value.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-');
                    if !ok {
                        return Err("`boot` must be the `boot_id` of an earlier answer".to_owned());
                    }
                    query.boot = Some(value.to_owned());
                }
                _ => {}
            }
        }
        Ok(query)
    }
}

/// Highest `tail` of [`LogsQuery`].
pub const MAX_LOGS_TAIL: u32 = 10_000;

/// Query of `GET /v1/apps/{name}/logs`.
///
/// The values go into the query string of the libpod request, so [`LogsQuery::parse`] is the guard
/// against injecting parameters there: it accepts nothing but the four known keys, once each, with
/// values that are plain digits or `true`/`false` (no `&`, `=`, `%`, whitespace or sign survives).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LogsQuery {
    /// Keep the stream open for new output (default: end at the end of the log).
    pub follow: bool,
    /// Only the last this many lines, at most [`MAX_LOGS_TAIL`] (default: the whole log).
    pub tail: Option<u32>,
    /// Only output from this instant on, as a duration since the unix epoch.
    pub since: Option<std::time::Duration>,
    /// Prefix every line with its RFC 3339 timestamp.
    pub timestamps: bool,
}

impl LogsQuery {
    /// Parses a raw query string (`follow=true&tail=100&since=1700000000.25`). Unknown or repeated
    /// keys and malformed values are errors (the message is safe to show to the client).
    pub fn parse(raw: Option<&str>) -> Result<Self, String> {
        let mut query = Self::default();
        let mut seen = Vec::new();
        for kv in raw
            .unwrap_or_default()
            .split('&')
            .filter(|kv| !kv.is_empty())
        {
            let (key, value) = kv.split_once('=').unwrap_or((kv, ""));
            if seen.contains(&key) {
                return Err(format!("`{}` is given twice", printable(key)));
            }
            seen.push(key);
            match key {
                "follow" => query.follow = parse_bool("follow", value)?,
                "timestamps" => query.timestamps = parse_bool("timestamps", value)?,
                "tail" => {
                    let ok = !value.is_empty()
                        && value.len() <= 5
                        && value.bytes().all(|b| b.is_ascii_digit());
                    let tail = value
                        .parse::<u32>()
                        .ok()
                        .filter(|t| ok && *t <= MAX_LOGS_TAIL);
                    query.tail = Some(tail.ok_or_else(|| {
                        format!("`tail` must be a number from 0 to {MAX_LOGS_TAIL}")
                    })?);
                }
                "since" => query.since = Some(parse_since(value)?),
                other => return Err(format!("unknown query parameter `{}`", printable(other))),
            }
        }
        Ok(query)
    }

    /// The query string a client sends for this query (parses back to `self`); empty when all default.
    pub fn to_query_string(&self) -> String {
        let mut parts = Vec::new();
        if self.follow {
            parts.push("follow=true".to_owned());
        }
        if let Some(tail) = self.tail {
            parts.push(format!("tail={tail}"));
        }
        if let Some(since) = self.since {
            parts.push(format!(
                "since={}.{:09}",
                since.as_secs(),
                since.subsec_nanos()
            ));
        }
        if self.timestamps {
            parts.push("timestamps=true".to_owned());
        }
        parts.join("&")
    }

    /// `since` as an instant; `None` when absent.
    pub fn since_time(&self) -> Option<std::time::SystemTime> {
        self.since
            .and_then(|d| std::time::UNIX_EPOCH.checked_add(d))
    }
}

fn parse_bool(key: &str, value: &str) -> Result<bool, String> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("`{key}` must be `true` or `false`")),
    }
}

/// `1700000000` or `1700000000.25`: seconds since the epoch, at most 11 digits (year 5138), with an
/// optional fraction.
fn parse_since(value: &str) -> Result<std::time::Duration, String> {
    let bad = || "`since` must be unix seconds, like `1700000000` or `1700000000.25`".to_owned();
    let (secs, frac) = value.split_once('.').unwrap_or((value, ""));
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if secs.is_empty() || secs.len() > 11 || !digits(secs) || !digits(frac) {
        return Err(bad());
    }
    if value.contains('.') && frac.is_empty() {
        return Err(bad());
    }
    // Nanosecond resolution: further digits are dropped.
    let mut nanos = frac.chars().take(9).collect::<String>();
    while nanos.len() < 9 {
        nanos.push('0');
    }
    Ok(std::time::Duration::new(
        secs.parse().map_err(|_| bad())?,
        nanos.parse().map_err(|_| bad())?,
    ))
}

/// A client-supplied token for an error message: short and without control characters.
fn printable(text: &str) -> String {
    text.chars()
        .take(32)
        .map(|c| if c.is_ascii_graphic() { c } else { '?' })
        .collect()
}

/// One domain event as `GET /v1/events` shows it. Flat and deliberately independent of the engine's
/// `Event` enum, so that enum can change without breaking clients (docs/decisions/0057).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRecord {
    /// Monotonic within one daemon process, starting at 1; a restart starts over (compare `next_seq`).
    pub seq: u64,
    /// UTC wall-clock time the daemon recorded the event, RFC 3339 (`2026-10-29T12:00:00Z`).
    pub ts: String,
    pub severity: Severity,
    /// Stable snake_case name of the event type, e.g. `deploy_failed`.
    pub kind: String,
    /// The instance the event is about, when it names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<InstanceName>,
    /// One-line summary (capped in length).
    pub message: String,
    /// Further detail (may be empty; capped in length). Built from structured fields only — never
    /// the engine's free-form failure text, which is for the daemon log.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

/// `GET /v1/events`: the retained events newer than the query's `since`, oldest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventsResponse {
    pub events: Vec<EventRecord>,
    /// Identifies the daemon process whose `seq` numbers these are; pass as `boot` next time.
    pub boot_id: String,
    /// The query's `boot` named another process: its `since` was ignored and `events` is everything
    /// retained. The client should discard what it held.
    #[serde(default)]
    pub reset: bool,
    /// Pass as `since` next time. Equals the highest `seq` assigned so far, also when `events` is empty
    /// (0 = nothing emitted yet). Only events of severity `info` and above are recorded.
    pub next_seq: u64,
    /// `seq` of the oldest retained event; absent while the history is empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oldest_seq: Option<u64>,
    /// `since` was given and events after it were evicted before this answer (the history is a bounded
    /// ring). Never set without `since`.
    #[serde(default)]
    pub dropped: bool,
}
