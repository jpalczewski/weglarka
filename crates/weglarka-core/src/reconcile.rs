//! Reconcile loop: desired state (`apps.toml` + `state.toml`) vs actual containers.
//!
//! Two steps: the **plan** — the pure function [`plan`] (easy to test, no I/O) — and the **executor**
//! [`Reconciler`], which gathers observations from Podman, calls `plan` and carries out the actions.
//! Reconcile does *not* pull new versions: it converges to the pinned digest. A new version is
//! introduced only by deploy (webhook / manual) — see [`crate::deploy`]. Exception: an instance
//! without a pinned digest (fresh) gets its first deploy with a pull.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::{MissedTickBehavior, interval_at};

use crate::app::{AppSpec, AppsFile, Digest, InstanceName};
use crate::deploy::{DeliveryDedup, DeployOutcome};
use crate::events::{Event, EventSink, TracingSink};
use crate::hash::SpecHash;
use crate::labels;
use crate::podman::{ContainerFilter, ContainerInfo, ContainerState, PodmanClient, PodmanError};
use crate::secret_store::{SecretError, SecretStore};
use crate::state::{self, StateError, StatePaths};
use crate::waiting::{apply_waiting, missing_secrets};

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    Secret(#[from] SecretError),
    #[error(transparent)]
    Podman(#[from] PodmanError),
    #[error("unknown instance: {0}")]
    UnknownInstance(InstanceName),
    #[error("cannot resolve image digest for {0}")]
    NoDigest(String),
    /// No free uid range of `size` left in the rootless user's subuid pool (docs/decisions/0009).
    #[error(
        "no free uid range of {size} in the subuid pool of {pool}; enlarge the runtime user's subuid range"
    )]
    UidPoolExhausted { pool: u64, size: u32 },
    /// The engine lock was not obtained in time (a deploy is in progress).
    #[error("engine is busy (deploy in progress)")]
    Busy,
    /// A volume operation the request cannot be served for (unknown volume, app not deployed yet…).
    #[error("{0}")]
    Volume(String),
    /// The spec binds secrets that are not set (not a failure: the instance waits for them).
    #[error("waiting for secrets: {}", .0.join(", "))]
    MissingSecrets(Vec<String>),
    /// The apps in `depends_on` are not running/healthy yet. Not a failure: the start is retried
    /// once they are, and reconcile reports it as waiting (`docs/decisions/0016-depends-on.md`).
    #[error("waiting for dependencies of {instance}: {}", format_pending(pending))]
    DependenciesNotReady {
        instance: InstanceName,
        pending: Vec<(InstanceName, String)>,
    },
    /// `apps remove` of an app that another app lists in `depends_on` (issue #35).
    #[error(
        "app {name} is a dependency of: {}; remove those depends_on entries first",
        join_names(dependents)
    )]
    DependencyInUse {
        name: InstanceName,
        dependents: Vec<InstanceName>,
    },
}

/// `a, b` for error messages.
fn join_names(names: &[InstanceName]) -> String {
    names
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// `dep (reason), dep (reason)` for [`EngineError::DependenciesNotReady`].
fn format_pending(pending: &[(InstanceName, String)]) -> String {
    pending
        .iter()
        .map(|(dep, why)| format!("{dep} ({why})"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// What to do on a secret value change (decision: a daemon config option).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecretChangePolicy {
    /// Secret fingerprints go into `spec-hash` → the next reconcile recreates the container.
    #[default]
    Immediate,
    /// Fingerprints stay out of the hash → the new secret takes effect on the next deploy/recreate.
    NextDeploy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconcilerOptions {
    pub secret_change: SecretChangePolicy,
    /// Time allowed for gracefully stopping the old container.
    pub stop_timeout_secs: u32,
    /// How long a start waits for the apps in `depends_on` (issue #35). `0` means a single check
    /// (no waiting); the default stays below the admin API's mutation timeout.
    pub dependency_wait_secs: u32,
}

impl Default for ReconcilerOptions {
    fn default() -> Self {
        Self {
            secret_change: SecretChangePolicy::default(),
            stop_timeout_secs: 10,
            dependency_wait_secs: 10,
        }
    }
}

// ── Plan (pure function) ────────────────────────────────────────────────────

/// Plan input for a single instance from `apps.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub instance: InstanceName,
    /// Pinned digest (`None` — the instance is not deployed yet).
    pub pinned: Option<Digest>,
    /// Expected container `spec-hash` (`Some` iff `pinned`).
    pub expected_hash: Option<SpecHash>,
    /// Leave this instance alone in this pass (e.g. missing secret, failed first deploy
    /// awaiting manual intervention). Its containers are not orphans.
    pub blocked: bool,
    /// Expected `weglarka.uid-range` label (`Some` iff `pinned`, `None` = not checked). A mismatch —
    /// notably a container created before ranges existed — recreates the container once.
    pub uid_range: Option<String>,
    /// `spec.start`: `false` means provision-only — no container may exist (one is removed).
    pub start: bool,
    /// Apps that must be running before this one starts (`spec.depends_on`, issue #35). Used by
    /// [`plan`] for the start order and by the executor's dependency gate.
    pub depends_on: Vec<InstanceName>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecreateReason {
    Missing,
    SpecDrift,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// First deploy: pull → container → health gate.
    Deploy { instance: InstanceName },
    /// Recreate the container from the pinned digest.
    Recreate {
        instance: InstanceName,
        reason: RecreateReason,
    },
    /// The container exists but is not running (e.g. after a host restart without linger).
    Start { instance: InstanceName },
    /// `start = false`: pin the image, create the network, the uid range and the volumes; no
    /// container (one left over from before the flag flip is stopped and removed).
    Provision { instance: InstanceName },
    /// Orphan or duplicate carrying the `weglarka.instance` label.
    Remove { container: String },
}

/// Compares desired state with observed containers. Order: cleanup first, then instances in
/// `depends_on` order (dependencies first, alphabetical among the ready ones — plain alphabetical
/// when no app declares dependencies). Does no I/O.
pub fn plan(targets: &[Target], observed: &[ContainerInfo]) -> Vec<Action> {
    let mut by_instance: BTreeMap<&str, Vec<&ContainerInfo>> = BTreeMap::new();
    for c in observed {
        if let Some(i) = c.labels.get(labels::INSTANCE) {
            by_instance.entry(i.as_str()).or_default().push(c);
        }
    }
    let known: BTreeSet<&str> = targets.iter().map(|t| t.instance.as_str()).collect();
    let mut removals = Vec::new();
    for (inst, cs) in &by_instance {
        if !known.contains(inst) {
            removals.extend(cs.iter().map(|c| Action::Remove {
                container: c.name.clone(),
            }));
        }
    }

    let mut actions = removals;
    let by_name: BTreeMap<&InstanceName, &Target> =
        targets.iter().map(|t| (&t.instance, t)).collect();
    let edges: Vec<(&InstanceName, &[InstanceName])> = targets
        .iter()
        .map(|t| (&t.instance, t.depends_on.as_slice()))
        .collect();
    for name in crate::depends::order(edges) {
        let Some(t) = by_name.get(&name) else {
            continue;
        };
        let t = *t;
        let own = by_instance.get(t.instance.as_str());
        let main_name = labels::container_name(&t.instance);
        let main = own.and_then(|cs| cs.iter().find(|c| c.name == main_name));
        // Duplicates with our label but a different name are removed regardless of `blocked`.
        for c in own.into_iter().flatten().filter(|c| c.name != main_name) {
            actions.push(Action::Remove {
                container: c.name.clone(),
            });
        }
        if t.blocked {
            continue;
        }
        if !t.start {
            // `start = false`: provision once, and remove a container left over from before the flip.
            if main.is_some() || t.pinned.is_none() {
                actions.push(Action::Provision {
                    instance: t.instance.clone(),
                });
            }
            continue;
        }
        let (Some(_), Some(expected)) = (&t.pinned, &t.expected_hash) else {
            actions.push(Action::Deploy {
                instance: t.instance.clone(),
            });
            continue;
        };
        match main {
            None => actions.push(Action::Recreate {
                instance: t.instance.clone(),
                reason: RecreateReason::Missing,
            }),
            Some(c)
                if c.labels.get(labels::SPEC_HASH).map(String::as_str)
                    != Some(expected.as_str())
                    || t.uid_range.as_ref().is_some_and(|r| {
                        c.labels.get(labels::UID_RANGE).map(String::as_str) != Some(r.as_str())
                    }) =>
            {
                actions.push(Action::Recreate {
                    instance: t.instance.clone(),
                    reason: RecreateReason::SpecDrift,
                })
            }
            Some(c)
                if matches!(
                    c.state,
                    ContainerState::Created | ContainerState::Stopped | ContainerState::Exited
                ) =>
            {
                actions.push(Action::Start {
                    instance: t.instance.clone(),
                })
            }
            Some(_) => {}
        }
    }
    actions
}

// ── Executor ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionOutcome {
    Deployed(DeployOutcome),
    Recreated(DeployOutcome),
    Started,
    Provisioned(DeployOutcome),
    Removed,
}

#[derive(Debug)]
pub struct ActionReport {
    pub action: Action,
    pub result: Result<ActionOutcome, EngineError>,
}

#[derive(Debug, Default)]
pub struct ReconcileReport {
    pub actions: Vec<ActionReport>,
    /// Instances skipped in this pass, with the reason (e.g. missing secret).
    pub blocked: Vec<(InstanceName, String)>,
    /// Instances left alone because the spec binds secrets that are not set (not a problem).
    pub waiting: Vec<(InstanceName, Vec<String>)>,
    /// Instances whose start waits for an app in their `depends_on` that is not running/healthy yet
    /// (not a problem: the next pass retries once the dependency is up, issue #35).
    pub waiting_for_dependencies: Vec<(InstanceName, Vec<InstanceName>)>,
}

impl ReconcileReport {
    pub fn is_clean(&self) -> bool {
        self.blocked.is_empty() && self.actions.iter().all(|a| a.result.is_ok())
    }
}

/// Reason to wake the [`Reconciler::run`] loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// Desired state changed (`apps.toml`, secret) — reconcile now.
    Changed,
}

/// What the engine is doing to an instance right now (in-memory only; see [`InFlight`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivityKind {
    /// Pull, create/start and the health gate of a deploy (manual, webhook or the first reconcile).
    Deploy,
    /// Recreate the container from the pinned digest (spec drift, missing container, secret change).
    Recreate,
    /// `start = false`: pin the digest and prepare the network, uid range and volumes; no container.
    Provision,
}

impl ActivityKind {
    /// Short label for user-facing output (`doctor`).
    pub fn label(self) -> &'static str {
        match self {
            Self::Deploy => "deploy",
            Self::Recreate => "recreate",
            Self::Provision => "provision",
        }
    }
}

/// The instance being mutated right now, exposed by [`Reconciler::in_flight`] so that `doctor` can
/// tell a **transient** mismatch between `state.toml` and the container from real drift: a deploy
/// writes `state.toml` only after the new container passes the health gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InFlight {
    pub instance: InstanceName,
    pub kind: ActivityKind,
}

/// Clears [`Reconciler::in_flight`] when the mutating operation ends (RAII: early returns included).
pub(crate) struct ActivityGuard<'a> {
    slot: &'a std::sync::Mutex<Option<InFlight>>,
}

impl Drop for ActivityGuard<'_> {
    fn drop(&mut self) {
        *self.slot.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

/// Engine: reconcile + deploy. One per daemon process; all mutating operations
/// are serialized by `lock` (the sole state writer).
pub struct Reconciler<P: PodmanClient> {
    pub(crate) podman: P,
    pub(crate) secrets: Arc<dyn SecretStore>,
    pub(crate) paths: StatePaths,
    pub(crate) options: ReconcilerOptions,
    pub(crate) events: Arc<dyn EventSink>,
    pub(crate) http_prober: Option<Arc<dyn crate::limits::HttpProber>>,
    pub(crate) lock: tokio::sync::Mutex<()>,
    pub(crate) dedup: std::sync::Mutex<DeliveryDedup>,
    /// The instance being mutated right now (`None` when the engine is idle). See [`InFlight`].
    pub(crate) activity: std::sync::Mutex<Option<InFlight>>,
}

impl<P: PodmanClient> Reconciler<P> {
    pub fn new(
        podman: P,
        secrets: Arc<dyn SecretStore>,
        paths: StatePaths,
        options: ReconcilerOptions,
    ) -> Self {
        Self {
            podman,
            secrets,
            paths,
            options,
            events: Arc::new(TracingSink),
            http_prober: None,
            lock: tokio::sync::Mutex::new(()),
            dedup: std::sync::Mutex::new(DeliveryDedup::new(256)),
            activity: std::sync::Mutex::new(None),
        }
    }

    pub fn with_events(mut self, events: Arc<dyn EventSink>) -> Self {
        self.events = events;
        self
    }

    /// Prober for `health.http` gates; without one, an app that configures it fails the gate.
    pub fn with_http_prober(mut self, prober: Arc<dyn crate::limits::HttpProber>) -> Self {
        self.http_prober = Some(prober);
        self
    }

    pub fn paths(&self) -> &StatePaths {
        &self.paths
    }

    pub fn podman(&self) -> &P {
        &self.podman
    }

    /// The instance the engine is mutating right now (deploy/recreate/provision), if any.
    ///
    /// In-memory only: after a daemon restart the answer is `None` and `doctor` sees the ordinary
    /// state — correct, because the startup reconcile then really converges the instance.
    pub fn in_flight(&self) -> Option<InFlight> {
        self.activity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Marks `instance` as in flight until the returned guard is dropped (also on early `?` returns
    /// and panics). Callers hold `lock`, so at most one instance is in flight at a time.
    pub(crate) fn begin_activity(
        &self,
        instance: &InstanceName,
        kind: ActivityKind,
    ) -> ActivityGuard<'_> {
        *self.activity.lock().unwrap_or_else(|e| e.into_inner()) = Some(InFlight {
            instance: instance.clone(),
            kind,
        });
        ActivityGuard {
            slot: &self.activity,
        }
    }

    // Desired-state changes (API → daemon). Send [`Trigger::Changed`] after them.

    pub async fn upsert_app(&self, name: InstanceName, spec: AppSpec) -> Result<(), EngineError> {
        let _g = self.lock.lock().await;
        let mut apps = state::load_apps(&self.paths.apps)?;
        apps.apps.insert(name, spec);
        Ok(state::save_apps(&self.paths.apps, &apps)?)
    }

    pub async fn remove_app(&self, name: &InstanceName) -> Result<(), EngineError> {
        let _g = self.lock.lock().await;
        let mut apps = state::load_apps(&self.paths.apps)?;
        crate::depends::ensure_not_depended_on(&apps, name)?;
        if apps.apps.remove(name).is_none() {
            return Err(EngineError::UnknownInstance(name.clone()));
        }
        Ok(state::save_apps(&self.paths.apps, &apps)?)
    }

    /// A single reconcile pass.
    pub async fn reconcile(&self) -> Result<ReconcileReport, EngineError> {
        let _g = self.lock.lock().await;
        let apps = state::load_apps(&self.paths.apps)?;
        let unranged = self.adopt_uid_ranges(&apps).await;
        let mut st = state::load_state(&self.paths.state)?;
        let observed: Vec<ContainerInfo> = self
            .podman
            .container_list(&ContainerFilter::default())
            .await?
            .into_iter()
            .filter(|c| c.labels.contains_key(labels::INSTANCE))
            .collect();

        let mut report = ReconcileReport::default();
        let mut targets = Vec::with_capacity(apps.apps.len());
        let mut waiting_changed = false;
        for (name, spec) in &apps.apps {
            // `start = false` needs no secrets: nothing is deployed until `apps start`.
            let missing = if spec.start {
                missing_secrets(&self.secrets, name, spec).await?
            } else {
                Vec::new()
            };
            if apply_waiting(&mut st, name, &missing) {
                waiting_changed = true;
                if !missing.is_empty() {
                    self.events.emit(Event::WaitingForSecret {
                        instance: name.clone(),
                        missing: missing.clone(),
                    });
                }
            }
            let app_state = st.apps.get(name);
            let pinned = app_state.and_then(|s| s.current.clone());
            let mut blocked = false;
            let mut expected_hash = None;
            if !missing.is_empty() {
                blocked = true;
                report.waiting.push((name.clone(), missing));
            } else if let Some(why) = unranged.get(name) {
                blocked = true;
                report.blocked.push((name.clone(), why.clone()));
            } else if let Some(d) = &pinned {
                match self.desired_hash(name, spec, d).await {
                    Ok(h) => expected_hash = Some(h),
                    Err(e) => {
                        blocked = true;
                        report.blocked.push((name.clone(), e.to_string()));
                    }
                }
            } else if app_state.is_some_and(|s| s.failed.is_some()) {
                // First deploy failed: we do not retry in the loop, it waits for `deploy`.
                blocked = true;
                report.blocked.push((
                    name.clone(),
                    "first deploy failed; run deploy manually".into(),
                ));
            }
            let uid_range = pinned
                .as_ref()
                .and_then(|_| app_state.and_then(|s| s.uid_range))
                .map(labels::uid_range_label);
            targets.push(Target {
                instance: name.clone(),
                pinned,
                expected_hash,
                blocked,
                uid_range,
                start: spec.start,
                depends_on: spec.depends_on.clone(),
            });
        }

        if waiting_changed {
            state::save_state(&self.paths.state, &st)?;
        }
        for action in plan(&targets, &observed) {
            match self.execute(&apps, action.clone()).await {
                Ok(outcome) => report.actions.push(ActionReport {
                    action,
                    result: Ok(outcome),
                }),
                Err(EngineError::DependenciesNotReady { instance, pending }) => {
                    tracing::info!(
                        instance = %instance,
                        pending = %format_pending(&pending),
                        "waiting for dependencies"
                    );
                    report
                        .waiting_for_dependencies
                        .push((instance, pending.into_iter().map(|(dep, _)| dep).collect()));
                }
                Err(e) => {
                    tracing::warn!(?action, error = %e, "reconcile action failed");
                    report.actions.push(ActionReport {
                        action,
                        result: Err(e),
                    });
                }
            }
        }

        // We clean up orphan state after their containers are removed.
        // The actions above saved state.toml themselves; settle on a fresh copy, not on `st`.
        let mut st = state::load_state(&self.paths.state)?;
        if self.settle_orphan_state(&mut st, &apps).await {
            state::save_state(&self.paths.state, &st)?;
        }
        self.prune_networks(&apps).await;
        Ok(report)
    }

    /// Removes per-app networks (`net-<instance>`) whose instance is gone from the desired state.
    /// Best effort and idempotent: a network still in use (the container is not pruned yet, or the
    /// ingress nginx has not detached it yet) is left for a later pass. Only networks Węglarka
    /// created (labelled `weglarka.instance` or `weglarka.managed`) are touched, never
    /// [`labels::INGRESS_NETWORK`].
    async fn prune_networks(&self, apps: &AppsFile) {
        let networks = match self.podman.network_list().await {
            Ok(n) => n,
            Err(e) => {
                tracing::debug!(error = %e, "cannot list networks; skipping network cleanup");
                return;
            }
        };
        for net in networks {
            if net.name == labels::INGRESS_NETWORK || !is_weglarka_network(&net.labels) {
                continue;
            }
            let Some(instance) = net
                .name
                .strip_prefix("net-")
                .and_then(|rest| InstanceName::new(rest).ok())
            else {
                continue;
            };
            if apps.apps.contains_key(&instance) {
                continue;
            }
            match self.podman.network_remove(&net.name).await {
                Ok(()) => tracing::info!(network = %net.name, "removed network of a removed app"),
                Err(e) => {
                    tracing::debug!(network = %net.name, error = %e, "network not removed yet")
                }
            }
        }
    }

    async fn execute(&self, apps: &AppsFile, action: Action) -> Result<ActionOutcome, EngineError> {
        match action {
            Action::Deploy { instance } => Ok(ActionOutcome::Deployed(
                self.deploy_locked(&instance, false).await?,
            )),
            Action::Recreate { instance, reason } => {
                let outcome = self.recreate_locked(&instance, reason).await?;
                Ok(ActionOutcome::Recreated(outcome))
            }
            Action::Start { instance } => {
                let spec = apps
                    .apps
                    .get(&instance)
                    .ok_or_else(|| EngineError::UnknownInstance(instance.clone()))?;
                self.dependency_gate(&instance, spec).await?;
                self.podman
                    .container_start(&labels::container_name(&instance))
                    .await?;
                Ok(ActionOutcome::Started)
            }
            Action::Provision { instance } => {
                let spec = apps
                    .apps
                    .get(&instance)
                    .ok_or_else(|| EngineError::UnknownInstance(instance.clone()))?;
                Ok(ActionOutcome::Provisioned(
                    self.provision_locked(&instance, spec).await?,
                ))
            }
            Action::Remove { container } => {
                self.podman.container_remove(&container, true).await?;
                self.events.emit(Event::Pruned { container });
                Ok(ActionOutcome::Removed)
            }
        }
    }

    /// Daemon loop: reconcile at startup, then every `period` and after each [`Trigger`].
    /// Ends when the trigger sender is closed.
    pub async fn run(&self, mut triggers: mpsc::Receiver<Trigger>, period: Duration) {
        let mut ticker = interval_at(tokio::time::Instant::now() + period, period);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            match self.reconcile().await {
                Ok(r) if r.is_clean() => {}
                Ok(r) => tracing::warn!(blocked = ?r.blocked, "reconcile finished with problems"),
                Err(e) => tracing::error!(error = %e, "reconcile failed"),
            }
            tokio::select! {
                _ = ticker.tick() => {}
                msg = triggers.recv() => if msg.is_none() { return },
            }
        }
    }
}

/// Whether a network was created by Węglarka (deploy labels it with the instance, ingress with
/// `weglarka.managed`).
fn is_weglarka_network(network_labels: &BTreeMap<String, String>) -> bool {
    network_labels.contains_key(labels::INSTANCE) || network_labels.contains_key("weglarka.managed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::spec_hash;

    fn digest(c: char) -> Digest {
        Digest::new(format!("sha256:{}", c.to_string().repeat(64))).unwrap()
    }
    fn name(s: &str) -> InstanceName {
        InstanceName::new(s).unwrap()
    }
    fn spec() -> AppSpec {
        toml::from_str("image = \"ghcr.io/x/y:latest\"").unwrap()
    }
    fn container(inst: &str, cname: &str, hash: &SpecHash, state: ContainerState) -> ContainerInfo {
        ContainerInfo {
            id: "1".into(),
            name: cname.into(),
            image: "i".into(),
            image_id: "i".into(),
            labels: labels::container_labels(&name(inst), 1, hash),
            state,
            exit_code: None,
            health: None,
            networks: vec![],
        }
    }
    fn target(inst: &str, pinned: Option<char>) -> (Target, SpecHash) {
        let h = spec_hash(&spec(), &digest(pinned.unwrap_or('a')));
        (
            Target {
                instance: name(inst),
                pinned: pinned.map(digest),
                expected_hash: pinned.map(|_| h.clone()),
                blocked: false,
                uid_range: None,
                start: true,
                depends_on: vec![],
            },
            h,
        )
    }

    #[test]
    fn fresh_instance_gets_deploy() {
        let (t, _) = target("a", None);
        assert_eq!(
            plan(&[t], &[]),
            vec![Action::Deploy {
                instance: name("a")
            }]
        );
    }

    #[test]
    fn converged_instance_needs_nothing() {
        let (t, h) = target("a", Some('a'));
        let c = container("a", "a", &h, ContainerState::Running);
        assert!(plan(&[t], &[c]).is_empty());
    }

    #[test]
    fn missing_drifted_and_stopped() {
        let (t, h) = target("a", Some('a'));
        assert_eq!(
            plan(std::slice::from_ref(&t), &[]),
            vec![Action::Recreate {
                instance: name("a"),
                reason: RecreateReason::Missing
            }]
        );
        let old = spec_hash(&spec(), &digest('b'));
        let drifted = container("a", "a", &old, ContainerState::Running);
        assert_eq!(
            plan(std::slice::from_ref(&t), &[drifted]),
            vec![Action::Recreate {
                instance: name("a"),
                reason: RecreateReason::SpecDrift
            }]
        );
        let stopped = container("a", "a", &h, ContainerState::Exited);
        assert_eq!(
            plan(&[t], &[stopped]),
            vec![Action::Start {
                instance: name("a")
            }]
        );
    }

    #[test]
    fn start_false_plans_provision_or_removal() {
        let (mut fresh, _) = target("a", None);
        fresh.start = false;
        // Never deployed: provision (network, uid range, volumes, pinned digest), no container.
        assert_eq!(
            plan(std::slice::from_ref(&fresh), &[]),
            vec![Action::Provision {
                instance: name("a")
            }]
        );
        // Already provisioned (pinned digest, no container): nothing to do.
        let (mut provisioned, _) = target("b", Some('a'));
        provisioned.start = false;
        assert!(plan(std::slice::from_ref(&provisioned), &[]).is_empty());
        // The flag was flipped while it ran: provision stops and removes the container.
        let (mut running, h) = target("a", Some('a'));
        running.start = false;
        let c = container("a", "a", &h, ContainerState::Running);
        assert_eq!(
            plan(&[running], &[c]),
            vec![Action::Provision {
                instance: name("a")
            }]
        );
    }

    #[test]
    fn orphans_and_duplicates_are_removed_blocked_is_left_alone() {
        let (mut t, h) = target("a", Some('a'));
        let orphan = container("gone", "gone", &h, ContainerState::Running);
        let dup = container("a", "a-old", &h, ContainerState::Running);
        let main = container("a", "a", &h, ContainerState::Running);
        assert_eq!(
            plan(
                std::slice::from_ref(&t),
                &[main.clone(), dup.clone(), orphan]
            ),
            vec![
                Action::Remove {
                    container: "gone".into()
                },
                Action::Remove {
                    container: "a-old".into()
                },
            ]
        );
        t.blocked = true;
        // Blocked instance without a container: we plan nothing, and its container is not an orphan.
        assert!(plan(&[t], &[main]).is_empty());
    }

    #[test]
    fn plan_is_deterministic_and_ordered_by_instance() {
        let (b, _) = target("b", None);
        let (a, _) = target("a", None);
        let acts = plan(&[b, a], &[]);
        assert_eq!(
            acts,
            vec![
                Action::Deploy {
                    instance: name("a")
                },
                Action::Deploy {
                    instance: name("b")
                }
            ]
        );
    }

    #[test]
    fn dependencies_are_planned_first() {
        // `api` sorts before `db`, but `db` must be started first (issue #35).
        let (mut api, _) = target("api", None);
        api.depends_on = vec![name("db")];
        let (db, _) = target("db", None);
        let (cache, _) = target("cache", None);
        let acts = plan(&[api, db, cache], &[]);
        assert_eq!(
            acts,
            vec![
                Action::Deploy {
                    instance: name("cache")
                },
                Action::Deploy {
                    instance: name("db")
                },
                Action::Deploy {
                    instance: name("api")
                },
            ]
        );
    }
}
