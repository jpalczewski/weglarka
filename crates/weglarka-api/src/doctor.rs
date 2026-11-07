//! The `weglarka doctor` report. Shared by `doctor` (via the API) and `doctor --preflight` (local).

use serde::{Deserialize, Serialize};

/// Severity of a [`DoctorCheck`]; the `Ord` order is the one used by [`DoctorReport::worst`].
///
/// `Info` does not signal a problem — it reports something that is going on (e.g. a deploy) and
/// leaves the exit code at 0. It must stay between `Ok` and `Warn`: `worst` then still reports a
/// real warning when there is one.
///
/// The order is written by hand rather than derived, because `Unknown` must sort between `Warn` and
/// `Fail` (an unknown check is at least a warning, never ok) while serde only accepts
/// `#[serde(other)]` on the **last** variant of the enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Ok,
    /// Informational only: no action needed, nothing is wrong.
    Info,
    Warn,
    Fail,
    /// A status this client does not know, produced by a newer daemon than the one it expects. The
    /// daemon never sends it: it only keeps a client parsing an answer it cannot name instead of
    /// failing the whole response.
    #[serde(other)]
    Unknown,
}

impl CheckStatus {
    /// Position in the severity order: `Ok < Info < Warn < Unknown < Fail`. An unknown status is a
    /// verdict of its own — at least a warning, never ok, but a real failure still outranks it.
    fn rank(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::Info => 1,
            Self::Warn => 2,
            Self::Unknown => 3,
            Self::Fail => 4,
        }
    }
}

impl PartialOrd for CheckStatus {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CheckStatus {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
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

    /// CLI exit code: 0 = ok/info, 1 = warn or a status from a newer daemon, 2 = fail.
    pub fn exit_code(&self) -> i32 {
        match self.worst() {
            CheckStatus::Ok | CheckStatus::Info => 0,
            CheckStatus::Warn | CheckStatus::Unknown => 1,
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

    #[test]
    fn an_unknown_status_is_at_least_a_warning_never_ok() {
        // The daemon never sends `unknown`: it is the fallback for a status a newer daemon invented.
        let parsed: CheckStatus = serde_json::from_str("\"invented_by_a_newer_daemon\"").unwrap();
        assert_eq!(parsed, CheckStatus::Unknown);
        assert_eq!(
            serde_json::to_value(CheckStatus::Unknown).unwrap(),
            "unknown"
        );

        // A lone unknown check is a warning, not a failure, and certainly not ok.
        let unknown = DoctorReport {
            checks: vec![check("runtime.new_thing", CheckStatus::Unknown)],
        };
        assert_eq!(unknown.worst(), CheckStatus::Unknown);
        assert_eq!(unknown.exit_code(), 1);

        // It outranks the statuses that mean "nothing wrong"...
        for ok in [CheckStatus::Ok, CheckStatus::Info, CheckStatus::Warn] {
            let report = DoctorReport {
                checks: vec![check("a", ok), check("b", CheckStatus::Unknown)],
            };
            assert_eq!(report.worst(), CheckStatus::Unknown, "{ok:?}");
            assert_eq!(report.exit_code(), 1, "{ok:?}");
        }

        // ...and a real failure still wins over it.
        let failing = DoctorReport {
            checks: vec![
                check("a", CheckStatus::Unknown),
                check("b", CheckStatus::Fail),
            ],
        };
        assert_eq!(failing.worst(), CheckStatus::Fail);
        assert_eq!(failing.exit_code(), 2);

        // Every known status still round-trips through its exact wire spelling: the fallback must not
        // hide a daemon-side typo.
        for (wire, status) in [
            ("ok", CheckStatus::Ok),
            ("info", CheckStatus::Info),
            ("warn", CheckStatus::Warn),
            ("fail", CheckStatus::Fail),
        ] {
            assert_eq!(serde_json::to_value(status).unwrap(), wire);
            assert_eq!(
                serde_json::from_value::<CheckStatus>(wire.into()).unwrap(),
                status,
                "{wire}"
            );
        }
    }
}
