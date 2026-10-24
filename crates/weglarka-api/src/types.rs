//! Admin API request/response types.

use serde::{Deserialize, Serialize};
use weglarka_core::app::{AppSpec, Digest, InstanceName, SharedVolumeName};
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

/// Query of `DELETE /v1/apps/{name}`: `?purge_volumes=true` also deletes the instance's named volumes.
/// Without it volumes are kept (data survives `remove` + `add`). Owner: session 1.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoveAppQuery {
    #[serde(default)]
    pub purge_volumes: bool,
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
    /// Defaults to `spec.image`; a given reference overrides it for this deploy only.
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusResponse {
    pub api_version: String,
    pub daemon_version: String,
    pub podman_version: String,
    pub apps: Vec<AppSummary>,
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
