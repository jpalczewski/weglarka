//! Engine domain events (deploy ok/fail/rollback…) — types for a future event journal.
//! No durable log in the MVP: the default sink only logs via `tracing`.

use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::app::{Digest, InstanceName};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    DeployOk {
        instance: InstanceName,
        digest: Digest,
        generation: u64,
    },
    /// `start = false`: image pinned, network, uid range and volumes ready, no container created
    /// (a container left over from before the flag flip was stopped and removed).
    Provisioned {
        instance: InstanceName,
        digest: Digest,
    },
    DeployFailed {
        instance: InstanceName,
        digest: Option<Digest>,
        reason: String,
    },
    /// New version rejected by the health gate, previous digest restored.
    RolledBack {
        instance: InstanceName,
        failed: Digest,
        restored: Digest,
        reason: String,
    },
    /// Rollback failed too — the instance needs intervention.
    RollbackFailed {
        instance: InstanceName,
        reason: String,
    },
    /// Container recreated from the pinned digest (container missing or `spec-hash` drift).
    Recreated {
        instance: InstanceName,
        reason: String,
    },
    /// Container removed because the instance is not in `apps.toml`.
    Pruned { container: String },
    /// The spec binds secrets that are not set: no deploy is attempted until they are (not a failure).
    WaitingForSecret {
        instance: InstanceName,
        missing: Vec<String>,
    },
    /// The app cannot start yet: an app it lists in `depends_on` is not running (or not healthy).
    /// Not a failure — the deploy/reconcile retries once the dependencies are up (issue #35).
    WaitingForDependency {
        instance: InstanceName,
        dependencies: Vec<InstanceName>,
    },
    /// Webhook rejected as a duplicate (`delivery_id` already seen).
    WebhookDuplicate { delivery_id: String },
    /// The container keeps restarting: libpod's restart counter grew by `restarts` inside the monitor
    /// window (`[monitor] crash_loop_restarts`, `docs/decisions/0022-crash-loop-detection.md`).
    CrashLooping {
        instance: InstanceName,
        restarts: u32,
    },
    /// The container healthcheck has been failing for several consecutive observations
    /// (`[monitor] unhealthy_observations`).
    Unhealthy { instance: InstanceName },
    /// A crashing or unhealthy instance is running normally again: no new restarts for a full window, or
    /// the healthcheck passes again.
    Recovered { instance: InstanceName },
}

/// How serious an event is. Notification channels route on it (`min_severity`) and the daemon uses it
/// for the log level. The order is meaningful: `Debug < Info < Warning < Critical`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Routine bookkeeping (a container pruned, a duplicate webhook): never alerts.
    Debug,
    #[default]
    Info,
    /// A deploy or a rollback that the operator may have to act on.
    Warning,
    /// The app needs intervention now (a failed rollback).
    Critical,
}

impl Severity {
    /// Lowercase name, as used in `weglarka.toml` and `notify status`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Event {
    /// Severity used for notification routing and for the `tracing` level.
    pub fn severity(&self) -> Severity {
        match self {
            Self::RollbackFailed { .. } | Self::CrashLooping { .. } => Severity::Critical,
            Self::DeployFailed { .. } | Self::RolledBack { .. } | Self::Unhealthy { .. } => {
                Severity::Warning
            }
            Self::Pruned { .. }
            | Self::WaitingForDependency { .. }
            | Self::WebhookDuplicate { .. } => Severity::Debug,
            Self::DeployOk { .. }
            | Self::Provisioned { .. }
            | Self::Recreated { .. }
            | Self::WaitingForSecret { .. }
            | Self::Recovered { .. } => Severity::Info,
        }
    }
}

/// Event sink; synchronous and dyn-compatible (a future journal appends to a file).
pub trait EventSink: Send + Sync {
    fn emit(&self, event: Event);
}

/// Default sink: `tracing` (info level, warnings and criticals as warn).
pub struct TracingSink;

impl EventSink for TracingSink {
    fn emit(&self, event: Event) {
        match event.severity() {
            Severity::Warning | Severity::Critical => tracing::warn!(?event, "weglarka event"),
            // `Debug` events stay at info here: the daemon log keeps the volume it always had.
            Severity::Info | Severity::Debug => tracing::info!(?event, "weglarka event"),
        }
    }
}

/// Collects events in memory (tests).
#[derive(Default)]
pub struct VecSink(Mutex<Vec<Event>>);

impl VecSink {
    pub fn events(&self) -> Vec<Event> {
        self.0.lock().expect("sink mutex poisoned").clone()
    }
}

impl EventSink for VecSink {
    fn emit(&self, event: Event) {
        self.0.lock().expect("sink mutex poisoned").push(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> InstanceName {
        InstanceName::new(s).unwrap()
    }

    fn digest() -> Digest {
        Digest::new(format!("sha256:{}", "a".repeat(64))).unwrap()
    }

    #[test]
    fn severity_is_classified_per_event() {
        let cases = [
            (
                Event::DeployOk {
                    instance: name("a"),
                    digest: digest(),
                    generation: 1,
                },
                Severity::Info,
            ),
            (
                Event::Provisioned {
                    instance: name("a"),
                    digest: digest(),
                },
                Severity::Info,
            ),
            (
                Event::DeployFailed {
                    instance: name("a"),
                    digest: None,
                    reason: "x".into(),
                },
                Severity::Warning,
            ),
            (
                Event::RolledBack {
                    instance: name("a"),
                    failed: digest(),
                    restored: digest(),
                    reason: "x".into(),
                },
                Severity::Warning,
            ),
            (
                Event::RollbackFailed {
                    instance: name("a"),
                    reason: "x".into(),
                },
                Severity::Critical,
            ),
            (
                Event::Recreated {
                    instance: name("a"),
                    reason: "x".into(),
                },
                Severity::Info,
            ),
            (
                Event::Pruned {
                    container: "a".into(),
                },
                Severity::Debug,
            ),
            (
                Event::WaitingForSecret {
                    instance: name("a"),
                    missing: vec!["t".into()],
                },
                Severity::Info,
            ),
            (
                Event::WaitingForDependency {
                    instance: name("a"),
                    dependencies: vec![name("b")],
                },
                Severity::Debug,
            ),
            (
                Event::WebhookDuplicate {
                    delivery_id: "d".into(),
                },
                Severity::Debug,
            ),
            (
                Event::CrashLooping {
                    instance: name("a"),
                    restarts: 4,
                },
                Severity::Critical,
            ),
            (
                Event::Unhealthy {
                    instance: name("a"),
                },
                Severity::Warning,
            ),
            (
                Event::Recovered {
                    instance: name("a"),
                },
                Severity::Info,
            ),
        ];
        for (event, expected) in cases {
            assert_eq!(event.severity(), expected, "{event:?}");
        }
    }

    #[test]
    fn severity_orders_and_serializes_lowercase() {
        assert!(Severity::Debug < Severity::Info);
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::Critical);
        assert_eq!(Severity::default(), Severity::Info);
        assert_eq!(Severity::Warning.as_str(), "warning");
        assert_eq!(Severity::Critical.to_string(), "critical");
        assert_eq!(
            serde_json::from_str::<Severity>("\"critical\"").unwrap(),
            Severity::Critical
        );
        assert_eq!(serde_json::to_string(&Severity::Info).unwrap(), "\"info\"");
    }
}
