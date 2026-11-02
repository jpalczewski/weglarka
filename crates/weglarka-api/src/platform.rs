//! Unix-only panel transition API (contract v1, `docs/contracts/platform-update-v1`).
//!
//! These routes are served on the full-trust unix socket only; they are never routed through the
//! token listener or the panel relay. The request carries no arbitrary image reference or host path:
//! the engine loads the prepared journal/reservation and matches these digests against it.
//!
//! Request bodies reject unknown fields instead of silently ignoring them: a misspelled field must
//! not turn into a different transition.

use serde::{Deserialize, Serialize};
use weglarka_model::platform_update::TransactionId;
use weglarka_model::release_set::StrictDigest;

/// `POST /v1/platform/panel-transition`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PanelTransitionRequest {
    pub transaction_id: TransactionId,
    /// Stale revisions are rejected with `409` while the transaction is not already terminal.
    pub expected_pin_revision: u64,
    /// Resolved OCI manifest digest of the prepared release set.
    pub release_set_digest: StrictDigest,
    pub target_digest: StrictDigest,
    /// Retry a `KnownBad` release instead of returning the recorded failure.
    #[serde(default, skip_serializing_if = "is_false")]
    pub retry_failed_release: bool,
}

/// Recorded status of a panel transition. `Pending`/`Running` are nonterminal; the rest are durable
/// terminal answers, including after a restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PanelTransitionStatus {
    Pending,
    Running,
    Succeeded,
    RolledBack,
    Failed,
}

/// Response of both `POST` and `GET`: the same durable record, so a retry after a restart returns
/// the recorded result instead of redeploying.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PanelTransitionResponse {
    pub transaction_id: TransactionId,
    pub status: PanelTransitionStatus,
    pub requested_digest: StrictDigest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual_digest: Option<StrictDigest>,
    pub pin_revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

fn is_false(value: &bool) -> bool {
    !*value
}
