//! Admin API request/response types.

use serde::{Deserialize, Serialize};
use weglarka_core::app::{AppSpec, Digest, InstanceName};
use weglarka_core::state::AppState;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    NotFound,
    AlreadyExists,
    InvalidRequest,
    Conflict,
    Internal,
}

impl ErrorCode {
    pub fn http_status(self) -> u16 {
        match self {
            Self::NotFound => 404,
            Self::AlreadyExists | Self::Conflict => 409,
            Self::InvalidRequest => 400,
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
