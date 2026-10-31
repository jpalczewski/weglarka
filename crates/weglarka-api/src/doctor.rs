//! The `weglarka doctor` report. Shared by `doctor` (via the API) and `doctor --preflight` (local).

use serde::{Deserialize, Serialize};

/// Severity of a [`DoctorCheck`]; the `Ord` order is the one used by [`DoctorReport::worst`].
///
/// `Info` does not signal a problem — it reports something that is going on (e.g. a deploy) and
/// leaves the exit code at 0. It must stay between `Ok` and `Warn`: `worst` then still reports a
/// real warning when there is one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Ok,
    /// Informational only: no action needed, nothing is wrong.
    Info,
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

impl DoctorCheck {
    /// A check with the given status and no hint; see [`with_hint`](Self::with_hint).
    pub fn new(id: impl Into<String>, status: CheckStatus, message: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            status,
            message: message.into(),
            hint: None,
        }
    }

    pub fn ok(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(id, CheckStatus::Ok, message)
    }

    pub fn info(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(id, CheckStatus::Info, message)
    }

    pub fn warn(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(id, CheckStatus::Warn, message)
    }

    pub fn fail(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(id, CheckStatus::Fail, message)
    }

    /// Sets the remediation hint.
    #[must_use]
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
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

    /// CLI exit code: 0 = ok/info, 1 = warn, 2 = fail.
    pub fn exit_code(&self) -> i32 {
        match self.worst() {
            CheckStatus::Ok | CheckStatus::Info => 0,
            CheckStatus::Warn => 1,
            CheckStatus::Fail => 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(id: &str, status: CheckStatus) -> DoctorCheck {
        DoctorCheck::new(id, status, "")
    }

    #[test]
    fn constructors_set_status_and_hint() {
        let c = DoctorCheck::warn("a.b", "msg").with_hint("do it");
        assert_eq!(c.status, CheckStatus::Warn);
        assert_eq!(c.hint.as_deref(), Some("do it"));
        assert_eq!(DoctorCheck::ok("a", "m").hint, None);
        assert_eq!(DoctorCheck::info("a", "m").status, CheckStatus::Info);
        assert_eq!(DoctorCheck::fail("a", "m").status, CheckStatus::Fail);
        let json = serde_json::to_value(DoctorCheck::ok("a", "m")).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"id":"a","status":"ok","message":"m"})
        );
    }

    #[test]
    fn info_is_informational_not_a_problem() {
        let report = DoctorReport {
            checks: vec![check("state.deploying", CheckStatus::Info)],
        };
        assert_eq!(report.worst(), CheckStatus::Info);
        assert_eq!(report.exit_code(), 0);
        assert_eq!(serde_json::to_value(CheckStatus::Info).unwrap(), "info");
    }

    #[test]
    fn info_does_not_outrank_warn_or_fail() {
        let mut report = DoctorReport {
            checks: vec![
                check("state.deploying", CheckStatus::Info),
                check("state.drift", CheckStatus::Warn),
            ],
        };
        assert_eq!(report.worst(), CheckStatus::Warn);
        assert_eq!(report.exit_code(), 1);
        report.checks[1].status = CheckStatus::Fail;
        assert_eq!(report.worst(), CheckStatus::Fail);
        assert_eq!(report.exit_code(), 2);
    }
}
