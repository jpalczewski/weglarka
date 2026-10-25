//! Admin API request/response types.

use serde::{Deserialize, Serialize};
use weglarka_core::app::{AppSpec, Digest, InstanceName, SharedNetworkName, SharedVolumeName};
use weglarka_core::environments::{EnvName, SiteName, SiteSpec};
use weglarka_core::events::Severity;
use weglarka_core::state::AppState;
use weglarka_core::uid_range::UidRange;

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
    Internal,
}

impl ErrorCode {
    pub fn http_status(self) -> u16 {
        match self {
            Self::NotFound => 404,
            Self::AlreadyExists | Self::Conflict => 409,
            Self::InvalidRequest => 400,
            Self::Busy => 503,
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
    fn endpoints_snapshot() {
        let list: Vec<String> = crate::ENDPOINTS
            .iter()
            .map(|e| format!("{:?} {}", e.method, e.path))
            .collect();
        insta::assert_json_snapshot!(list);
    }
}
