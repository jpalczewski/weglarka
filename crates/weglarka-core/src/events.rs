//! Engine domain events (deploy ok/fail/rollback…) — types for a future event journal.
//! No durable log in the MVP: the default sink only logs via `tracing`.

use std::sync::Mutex;

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
}

/// Event sink; synchronous and dyn-compatible (a future journal appends to a file).
pub trait EventSink: Send + Sync {
    fn emit(&self, event: Event);
}

/// Default sink: `tracing` (info level, errors as warn).
pub struct TracingSink;

impl EventSink for TracingSink {
    fn emit(&self, event: Event) {
        match &event {
            Event::DeployFailed { .. } | Event::RollbackFailed { .. } => {
                tracing::warn!(?event, "weglarka event")
            }
            _ => tracing::info!(?event, "weglarka event"),
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
