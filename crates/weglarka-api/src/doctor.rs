//! The `weglarka doctor` report. Shared by `doctor` (via the API) and `doctor --preflight` (local).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorCheck {
    /// Stable identifier, e.g. `runtime.subuid`.
    pub id: String,
    pub status: CheckStatus,
    pub message: String,
    /// Remediation hint (for `warn`/`fail`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorReport {
    pub checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    /// Worst status in the report (`Ok` for an empty one).
    pub fn worst(&self) -> CheckStatus {
        self.checks
            .iter()
            .map(|c| c.status)
            .max()
            .unwrap_or(CheckStatus::Ok)
    }

    /// CLI exit code: 0 = ok, 1 = warn, 2 = fail.
    pub fn exit_code(&self) -> i32 {
        match self.worst() {
            CheckStatus::Ok => 0,
            CheckStatus::Warn => 1,
            CheckStatus::Fail => 2,
        }
    }
}
