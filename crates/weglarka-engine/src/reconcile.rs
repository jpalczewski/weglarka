//! Reconcile loop: desired state (`apps.toml` + `state.toml`) vs actual containers.
//!
//! Two steps: the **plan** — the pure function [`plan`] (easy to test, no I/O) — and the **executor**
//! [`Reconciler`], which gathers observations from Podman, calls `plan` and carries out the actions.
//! Reconcile does *not* pull new versions: it converges to the pinned digest. A new version is
//! introduced only by deploy (webhook / manual) — see [`crate::deploy`]. Exception: an instance
//! without a pinned digest (fresh) gets its first deploy with a pull.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::{Instant, MissedTickBehavior, interval_at};

use crate::crash;
use crate::deploy::DeployOutcome;
use crate::volumes::RemoveAppOptions;
use crate::waiting::{apply_waiting, missing_secrets};
use weglarka_model::app::{AppKind, AppSpec, AppsFile, Digest, InstanceName};
use weglarka_model::delivery::{self, DeliveryDedup};
use weglarka_model::events::{Event, EventSink, TracingSink};
use weglarka_model::hash::SpecHash;
use weglarka_model::labels;
use weglarka_model::podman::{
    ContainerFilter, ContainerInfo, ContainerState, PodmanClient, PodmanError,
};
use weglarka_model::secret_store::{SecretError, SecretStore, scoped_name};
use weglarka_model::state::{self, StateError, StatePaths};

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
    #[error(transparent)]
    Render(#[from] weglarka_model::generated::RenderError),
    /// The generated config pipeline (#212) could not write, swap or apply a version.
    #[error("generated config for {consumer}: {message}")]
    Generated {
        consumer: InstanceName,
        message: String,
    },
    /// The registry refused the pull (401/403): the image may exist, but the podman user has no
    /// (valid) credentials for it. Fix `auth.json`, do not look for a missing image.
    #[error("cannot resolve image digest for {0}")]
    NoDigest(String),
    /// The registry refused the pull (401/403). Names the secret to fix; never the credentials.
    #[error("{}", registry_auth_message(.instance, .reference, *.sent_credentials))]
    RegistryAuth {
        instance: InstanceName,
        reference: String,
        /// Whether `<instance>.registry-auth` was sent (rejected) or absent (required).
        sent_credentials: bool,
    },
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
    /// An app's config mounts cannot be mounted (no `config_root`, a missing source, an escape…;
    /// issue #118, `docs/decisions/0028-config-root-mounts.md`).
    #[error("invalid config mounts: {0}")]
    Configs(String),
    /// A static site cannot be deployed or served (ADR 0049).
    #[error("static site: {0}")]
    Site(String),
    /// `weglarka run` of an app that has never been deployed: there is no pinned image to run.
    #[error("app {0} has no deployed image yet; run `weglarka apps deploy {0}` first")]
    RunNotDeployed(InstanceName),
    /// `weglarka run` while the maximum number of one-off containers is already running.
    #[error("too many one-off containers running (at most {0}); retry when one has finished")]
    RunLimit(usize),
    /// `weglarka run` request that cannot start a process.
    #[error("{0}")]
    RunInvalid(String),
    /// `weglarka forward` of an app that is not running: there is nothing to forward to.
    #[error("app {0} is not running; use `weglarka apps start {0}`")]
    ForwardNotRunning(InstanceName),
    /// `weglarka forward` while the maximum number of relays is already alive.
    #[error("too many forwards running (at most {0}); retry when one has ended")]
    ForwardLimit(usize),
    /// `weglarka forward` request that cannot be served.
    #[error("{0}")]
    ForwardInvalid(String),
    /// `weglarka push` while another image upload is in progress (docs/decisions/0042).
    #[error("another image upload is in progress; retry when it has finished")]
    PushBusy,
    /// `weglarka push` archive that Podman cannot load (corrupt, unsupported, or cut off).
    #[error("cannot load the image archive: {0}")]
    PushLoad(String),
    /// `weglarka push` request that names an image the app may not be deployed from.
    #[error("{0}")]
    PushInvalid(String),
    /// A tag-sourced deploy (`apps deploy`) of a promote-only environment: its release changes only
    /// through `weglarka promote` (issue #205).
    #[error(
        "{0} is a promote-only environment of a site and never resolves a tag; use `weglarka promote`"
    )]
    PromoteOnly(InstanceName),
    /// `weglarka promote`/`sites` named a site or environment that `apps.toml` does not declare.
    #[error("unknown site or environment: {0}")]
    UnknownSite(String),
    /// `weglarka promote` request that cannot be served (nothing was changed): the operator's fix is
    /// in the request.
    #[error("{0}")]
    PromoteInvalid(String),
    /// `weglarka promote` blocked by the state of the site (e.g. a digest marked failed).
    #[error("{0}")]
    PromoteRefused(String),
    /// `apps update`/`apps remove` of an instance that is expanded from a site.
    #[error("{instance} is managed by site {site}; change the site instead (`weglarka sites`)")]
    ManagedBySite {
        instance: InstanceName,
        site: String,
    },
    /// `apps reload` of an app whose container is not running: there is nothing to signal or restart.
    #[error("app {0} has no running container; use `weglarka apps start {0}`")]
    ReloadNotRunning(InstanceName),
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
    /// A request about the identity integration that cannot be honoured (no `[identity]`, an app
    /// without `oidc`, a client the file rules reject).
    #[error("{0}")]
    IdentityInvalid(String),
    #[error("unknown OIDC client: {0}")]
    UnknownOidcClient(String),
    /// `apps remove` of the instance `[identity]` names: every OIDC and forward-auth app would lose
    /// its provider (#88).
    #[error(
        "app {0} is the identity provider named in weglarka.toml `[identity]`; remove that section first"
    )]
    IdentityProviderInUse(InstanceName),
    /// `apps remove` of an app that another app lists in `depends_on` (issue #35).
    #[error(
        "app {name} is a dependency of: {}; remove those depends_on entries first",
        join_names(dependents)
    )]
    DependencyInUse {
        name: InstanceName,
        dependents: Vec<InstanceName>,
    },
    /// A shared volume is still mounted by other instances (issue #33): purging the instance's
    /// volumes would delete data they use.
    #[error("shared volume {volume} is still mounted by: {members}")]
    SharedVolumeInUse {
        volume: weglarka_model::app::SharedVolumeName,
        members: String,
    },
    /// A shared volume still holds data, so its declaration cannot be dropped without purging it.
    #[error("shared volume {volume} still holds data; pass --purge to delete it")]
    SharedVolumeHasData {
        volume: weglarka_model::app::SharedVolumeName,
    },
    /// A shared volume is in use by running instances, so it cannot be imported into (or replaced).
    #[error(
        "shared volume {volume} is used by running instances: {members}; stop them first \
         (`weglarka apps stop <app>`)"
    )]
    SharedVolumeBusy {
        volume: weglarka_model::app::SharedVolumeName,
        members: String,
    },
    /// A shared volume cannot move to another group while it exists: its files belong to the old
    /// group's uid range (docs/decisions/0029).
    #[error(
        "shared volume {volume} belongs to group {from}, not {to}: its data is owned by that group's \
         uid range; remove it with --purge and declare it again, or import the data into a new volume"
    )]
    SharedGroupChange {
        volume: weglarka_model::app::SharedVolumeName,
        from: weglarka_model::app::SharedVolumeName,
        to: weglarka_model::app::SharedVolumeName,
    },
    /// Unknown shared volume declaration.
    #[error("unknown shared volume: {0}")]
    UnknownSharedVolume(weglarka_model::app::SharedVolumeName),
    /// A shared network is still joined by other instances (issue #128): removing the declaration
    /// would cut them off from each other.
    #[error("shared network {network} is still joined by: {members}")]
    SharedNetworkInUse {
        network: weglarka_model::app::SharedNetworkName,
        members: String,
    },
    /// Unknown shared network declaration.
    #[error("unknown shared network: {0}")]
    UnknownSharedNetwork(weglarka_model::app::SharedNetworkName),
    /// Changing the instance's uid range would make its existing files unreadable (docs/decisions/0017).
    #[error(
        "cannot change the uid range of {instance} from {from} to {to}: it already has volume data; \
         export the data and import it in the new range first"
    )]
    RangeChangeWithData {
        instance: InstanceName,
        from: String,
        to: String,
    },
    /// `secrets remove` of a secret the app's spec still binds (issue #80). Not an error in the
    /// engine: the binding has to go first, or the caller passes `force` (the app then waits).
    #[error(
        "secret {secret} is still bound by the spec of {name}; unbind it first or pass --force"
    )]
    SecretInUse { name: InstanceName, secret: String },
}

/// `a, b` for error messages.
fn join_names(names: &[InstanceName]) -> String {
    names
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Operator hint for [`EngineError::RegistryAuth`].
fn registry_auth_message(instance: &InstanceName, reference: &str, sent: bool) -> String {
    let secret = weglarka_model::secret_store::REGISTRY_AUTH_SECRET;
    if sent {
        format!(
            "registry rejected the credentials in secret {instance}.{secret} for {reference}; \
             check them with `weglarka secrets set {instance} {secret}` (value <username>:<password>)"
        )
    } else {
        format!(
            "registry requires credentials to pull {reference}; \
             set them with `weglarka secrets set {instance} {secret}` (value <username>:<password>) \
             or `podman login` as the podman user"
        )
    }
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcilerOptions {
    pub secret_change: SecretChangePolicy,
    /// Time allowed for gracefully stopping the old container.
    pub stop_timeout_secs: u32,
    /// How long a start waits for the apps in `depends_on` (issue #35). `0` means a single check
    /// (no waiting); the default stays below the admin API's mutation timeout.
    pub dependency_wait_secs: u32,
    /// Host directory with app config files/directories (`weglarka.toml`'s `config_root`, issue #118),
    /// already resolved against the config file's directory by the caller. `None` = the feature is
    /// off: an app that declares `configs` then fails validation instead of mounting anything.
    pub config_root: Option<PathBuf>,
    /// Allowlist for apps' `host_mounts` (`[runtime] host_mounts`, issue #178); empty = no app may
    /// mount a host path.
    pub host_mounts: Vec<PathBuf>,
    /// Allowlist for apps' `group_add` (`[runtime] group_add`, issue #178).
    pub group_add: Vec<String>,
    /// How long a blue-green switch keeps the old container serving after the new one joined the app
    /// network: at least the ingress resolver's cache lifetime, so no request still resolves to a
    /// container that is about to stop (ADR 0046).
    pub switch_drain: Duration,
    /// Directory the static sites' releases are unpacked into (`<nginx_conf_dir>/sites`, ADR 0049).
    /// `None` = the daemon serves no static sites: deploying one fails with a clear error.
    pub sites_root: Option<PathBuf>,
    /// The token admin API socket and the instances that get it (`[admin.http]`, ADR 0056).
    pub admin_token: Option<crate::admin_token::AdminTokenMount>,
}

impl Default for ReconcilerOptions {
    fn default() -> Self {
        Self {
            secret_change: SecretChangePolicy::default(),
            stop_timeout_secs: 10,
            dependency_wait_secs: 10,
            config_root: None,
            host_mounts: Vec::new(),
            group_add: Vec::new(),
            switch_drain: Duration::from_secs(3),
            sites_root: None,
            admin_token: None,
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
    /// `kind = "static"` (ADR 0049): the instance has no container, so [`plan`] only deploys it once and
    /// removes any container that carries its label.
    pub is_static: bool,
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
    for name in weglarka_model::depends::order(edges) {
        let Some(t) = by_name.get(&name) else {
            continue;
        };
        let t = *t;
        let own = by_instance.get(t.instance.as_str());
        let main_name = labels::container_name(&t.instance);
        let main = own.and_then(|cs| cs.iter().find(|c| c.name == main_name));
        // Duplicates with our label but a different name are removed regardless of `blocked`.
        // The challenger and the retiring container of a blue-green switch (ADR 0046) carry the
        // instance label on purpose and live only inside a deploy, which holds the engine lock; a
        // leftover of a crashed deploy is swept by the instance's next blue-green deploy.
        let transient = [
            labels::challenger_name(&t.instance),
            labels::retiring_name(&t.instance),
        ];
        for c in own
            .into_iter()
            .flatten()
            .filter(|c| c.name != main_name && !transient.contains(&c.name))
        {
            actions.push(Action::Remove {
                container: c.name.clone(),
            });
        }
        if t.is_static {
            // A kind flip leaves a container behind; a site has none.
            if let Some(c) = main {
                actions.push(Action::Remove {
                    container: c.name.clone(),
                });
            }
            if !t.blocked && t.pinned.is_none() {
                actions.push(Action::Deploy {
                    instance: t.instance.clone(),
                });
            }
            continue;
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

/// Proof that the engine lock is held. The `*_locked` operations take it by reference, so calling
/// one without the lock — or acquiring the (non-reentrant) lock a second time from inside one —
/// is a compile-time error instead of a data race or a deadlock. Get it from [`Reconciler::acquire`].
pub(crate) struct EngineGuard<'a>(#[allow(dead_code)] tokio::sync::MutexGuard<'a, ()>);

/// Engine: reconcile + deploy. One per daemon process; all mutating operations
/// are serialized by `lock` (the sole state writer).
pub struct Reconciler<P: PodmanClient> {
    pub(crate) podman: P,
    pub(crate) secrets: Arc<dyn SecretStore>,
    pub(crate) paths: StatePaths,
    pub(crate) options: ReconcilerOptions,
    pub(crate) events: Arc<dyn EventSink>,
    pub(crate) http_prober: Option<Arc<dyn weglarka_model::limits::HttpProber>>,
    pub(crate) lock: tokio::sync::Mutex<()>,
    /// Generators of config files for consumer apps (#212); `None` = the feature is off.
    pub(crate) generated: Option<crate::generated::GeneratedWiring>,
    /// `[identity]` of the host: what an `oidc` app gets injected (see [`Self::effective`]).
    pub(crate) identity: Option<weglarka_model::config::IdentityConfig>,
    /// Free slots for one-off containers ([`crate::run::MAX_CONCURRENT_RUNS`]).
    pub(crate) runs: Arc<tokio::sync::Semaphore>,
    /// Free slots for forward relays ([`crate::forward::MAX_CONCURRENT_FORWARDS`]).
    pub(crate) forwards: Arc<tokio::sync::Semaphore>,
    /// The single slot of `weglarka push` image uploads: an archive is streamed into the image store
    /// outside the engine lock, so one at a time bounds the disk and I/O a client can take.
    pub(crate) uploads: Arc<tokio::sync::Semaphore>,
    pub(crate) dedup: std::sync::Mutex<DeliveryDedup>,
    /// The instance being mutated right now (`None` when the engine is idle). See [`InFlight`].
    pub(crate) activity: std::sync::Mutex<Option<InFlight>>,
    /// Crash-loop and health policy (`[monitor]`); [`crash::Policy::default`] unless overridden.
    pub(crate) monitor: crash::Policy,
    /// Per-instance observation state for that policy; in memory only, rebuilt after a restart.
    pub(crate) watch: std::sync::Mutex<crash::Watcher>,
}

impl<P: PodmanClient> Reconciler<P> {
    /// Takes the engine lock (the sole state writer's mutex). Hold the guard for the whole operation
    /// and pass it to every `*_locked` call; never call this again while holding it.
    pub(crate) async fn acquire(&self) -> EngineGuard<'_> {
        EngineGuard(self.lock.lock().await)
    }
}

impl<P: PodmanClient> Reconciler<P> {
    pub fn new(
        podman: P,
        secrets: Arc<dyn SecretStore>,
        paths: StatePaths,
        options: ReconcilerOptions,
    ) -> Self {
        // Handled webhook delivery ids survive a restart (issue #41, ADR 0035). A missing file is an
        // empty set; a broken one only costs a warning — bookkeeping never stops the daemon.
        let dedup = DeliveryDedup::load(paths.deliveries.clone(), delivery::DEFAULT_CAP);
        Self {
            podman,
            secrets,
            paths,
            options,
            events: Arc::new(TracingSink),
            http_prober: None,
            lock: tokio::sync::Mutex::new(()),
            generated: None,
            identity: None,
            runs: Arc::new(tokio::sync::Semaphore::new(crate::run::MAX_CONCURRENT_RUNS)),
            forwards: Arc::new(tokio::sync::Semaphore::new(
                crate::forward::MAX_CONCURRENT_FORWARDS,
            )),
            uploads: Arc::new(tokio::sync::Semaphore::new(1)),
            dedup: std::sync::Mutex::new(dedup),
            activity: std::sync::Mutex::new(None),
            monitor: crash::Policy::default(),
            watch: std::sync::Mutex::new(crash::Watcher::default()),
        }
    }

    /// Registers the generators whose files a consumer needs **before its first start** (bootstrap).
    pub fn with_generated(mut self, wiring: crate::generated::GeneratedWiring) -> Self {
        self.generated = Some(wiring);
        self
    }

    /// The host's `[identity]` section; without it no app gets OIDC credentials injected.
    pub fn with_identity(
        mut self,
        identity: Option<weglarka_model::config::IdentityConfig>,
    ) -> Self {
        self.identity = identity;
        self
    }

    /// `spec` as the container sees it: the injected OIDC env and secret included (#91). Every
    /// reader of `spec.env`/`spec.secrets` at launch time goes through this one overlay.
    pub(crate) fn effective<'a>(
        &self,
        instance: &InstanceName,
        spec: &'a AppSpec,
    ) -> std::borrow::Cow<'a, AppSpec> {
        weglarka_model::identity::effective_spec(instance, spec, self.identity.as_ref())
    }

    /// Mints the OIDC client secret of an `oidc` app when it is absent (#213), so the secret exists
    /// before anything reads it: the waiting check, the hash and the container creation. Idempotent;
    /// the caller holds the engine lock because minting is a read-then-write on the store. A public
    /// client has no secret, and without `[identity]` the injection is off.
    pub(crate) async fn ensure_oidc_credential(
        &self,
        instance: &InstanceName,
        spec: &AppSpec,
    ) -> Result<(), EngineError> {
        if self.identity.is_none() || !spec.oidc.as_ref().is_some_and(|o| !o.public) {
            return Ok(());
        }
        let instance = instance.clone();
        crate::secrets::blocking(&self.secrets, move |store| {
            crate::oidc_credentials::ensure(store, &instance).map(drop)
        })
        .await
    }

    pub fn with_events(mut self, events: Arc<dyn EventSink>) -> Self {
        self.events = events;
        self
    }

    /// Crash-loop / unhealthy thresholds (from `[monitor]`); the default is the production policy.
    pub fn with_monitor(mut self, policy: crash::Policy) -> Self {
        self.monitor = policy;
        self
    }

    /// Prober for `health.http` gates; without one, an app that configures it fails the gate.
    pub fn with_http_prober(mut self, prober: Arc<dyn weglarka_model::limits::HttpProber>) -> Self {
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
        let _guard = self.acquire().await;
        let mut apps = state::load_apps(&self.paths.apps)?;
        crate::promote::ensure_unmanaged(&apps, &name)?;
        apps.apps.insert(name, spec);
        Ok(state::save_apps(&self.paths.apps, &apps)?)
    }

    /// `apps remove` without purging: the instance's volumes (and their data) and secrets stay, so a
    /// re-added app finds them again. The lock moves into [`Self::remove_app_with_purges`].
    pub async fn remove_app(&self, name: &InstanceName) -> Result<(), EngineError> {
        self.remove_app_with_purges(name, RemoveAppOptions::default())
            .await
    }

    /// Deletes one of the instance's secrets from the store (`secrets remove`, issue #80).
    ///
    /// Refused with [`EngineError::SecretInUse`] while the app's spec still binds it and `force` is
    /// not set — the running container would keep the old value while the next launch has none. With
    /// `force` the secret goes away and the app waits for it again (`waiting_for_secrets`). The app
    /// need not exist in `apps.toml`: that is how the leftovers of a removed app are cleaned up.
    /// An absent secret is [`EngineError::Secret`] wrapping [`SecretError::NotFound`].
    pub async fn remove_secret(
        &self,
        instance: &InstanceName,
        secret: &str,
        force: bool,
    ) -> Result<(), EngineError> {
        let _guard = self.acquire().await;
        let apps = state::load_apps(&self.paths.apps)?;
        if !force {
            let bound = apps
                .apps
                .get(instance)
                .is_some_and(|spec| spec.secrets.iter().any(|b| b.secret == secret));
            if bound {
                return Err(EngineError::SecretInUse {
                    name: instance.clone(),
                    secret: secret.to_owned(),
                });
            }
        }
        let key = scoped_name(instance, secret);
        crate::secrets::blocking(&self.secrets, move |store| store.remove(&key)).await?;
        tracing::info!(instance = %instance, secret = %secret, "secret removed");
        Ok(())
    }

    /// A single reconcile pass.
    pub async fn reconcile(&self) -> Result<ReconcileReport, EngineError> {
        let guard = self.acquire().await;
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

        // Crash loops and failing healthchecks: observation only — the counter arrives with the list
        // above, nothing is written and no extra libpod call is made (`docs/decisions/0022`). Emitted
        // before the actions so the events describe the state this pass observed.
        let watched = self
            .watch
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .observe(&observed, &apps, &self.monitor, Instant::now());
        for event in watched {
            self.events.emit(event);
        }

        let mut report = ReconcileReport::default();
        let mut targets = Vec::with_capacity(apps.apps.len());
        let mut waiting_changed = false;
        for (name, spec) in &apps.apps {
            if spec.kind == AppKind::Static {
                let app_state = st.apps.get(name);
                let pinned = app_state.and_then(|s| s.current.clone());
                // A failed first deploy waits for `deploy`, as for containers.
                let blocked = pinned.is_none() && app_state.is_some_and(|s| s.failed.is_some());
                // A promote-only environment waits for its first promotion: reconcile never
                // resolves a tag for it (issue #205). Not reported as blocked — that would warn on
                // every pass; `doctor` carries the signal.
                let awaiting = pinned.is_none() && apps.is_promote_only(name);
                if blocked {
                    report.blocked.push((
                        name.clone(),
                        "first deploy failed; run deploy manually".into(),
                    ));
                }
                targets.push(Target {
                    instance: name.clone(),
                    pinned,
                    expected_hash: None,
                    blocked: blocked || awaiting,
                    uid_range: None,
                    start: true,
                    depends_on: Vec::new(),
                    is_static: true,
                });
                continue;
            }
            // `start = false` needs no secrets: nothing is deployed until `apps start`.
            // A store that cannot mint must not abort the pass for every other app: the secret then
            // reads as missing below, so this app waits and the others carry on.
            if spec.start
                && let Err(error) = self.ensure_oidc_credential(name, spec).await
            {
                tracing::warn!(instance = %name, %error, "cannot ensure the OIDC client credential");
            }
            let missing = if spec.start {
                missing_secrets(&self.secrets, name, &self.effective(name, spec)).await?
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
            } else if let Err(e) = self.resolve_mounts(spec) {
                // A config mount that cannot be mounted is not a deploy failure: the running container
                // stays as it is until the operator fixes the root or the file (ADR 0028).
                blocked = true;
                report.blocked.push((name.clone(), e.to_string()));
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
                .and_then(|_| crate::volumes::effective_range_label(&apps, &st, name, spec));
            targets.push(Target {
                instance: name.clone(),
                pinned,
                expected_hash,
                blocked,
                uid_range,
                start: spec.start,
                depends_on: self.effective(name, spec).depends_on.clone(),
                is_static: false,
            });
        }

        if waiting_changed {
            state::save_state(&self.paths.state, &st)?;
        }
        for action in plan(&targets, &observed) {
            match self.execute(&guard, &apps, action.clone()).await {
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
        let mut settled = self.settle_orphan_state(&mut st, &apps).await;
        settled |= self.settle_shared_volumes(&mut st, &apps).await;
        if settled {
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
            // A shared network (issue #128) belongs to its declaration, not to an instance: it
            // lives as long as `[shared_networks.<name>]` does, whoever is a member right now.
            if let Some(group) = net.labels.get(labels::SHARED_NETWORK) {
                let declared = weglarka_model::app::SharedNetworkName::new(group.as_str())
                    .is_ok_and(|g| apps.shared_networks.contains_key(&g));
                if !declared {
                    self.remove_network(&net.name, "shared network that is no longer declared")
                        .await;
                }
                continue;
            }
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
            self.remove_network(&net.name, "network of a removed app")
                .await;
        }
    }

    /// Best-effort removal: a network still in use is left for a later pass.
    async fn remove_network(&self, name: &str, what: &str) {
        match self.podman.network_remove(name).await {
            Ok(()) => tracing::info!(network = %name, "removed {what}"),
            Err(e) => tracing::debug!(network = %name, error = %e, "network not removed yet"),
        }
    }

    async fn execute(
        &self,
        held: &EngineGuard<'_>,
        apps: &AppsFile,
        action: Action,
    ) -> Result<ActionOutcome, EngineError> {
        match action {
            Action::Deploy { instance } => Ok(ActionOutcome::Deployed(
                self.deploy_locked(held, &instance, false).await?,
            )),
            Action::Recreate { instance, reason } => {
                let outcome = self.recreate_locked(held, &instance, reason).await?;
                Ok(ActionOutcome::Recreated(outcome))
            }
            Action::Start { instance } => {
                let spec = apps
                    .apps
                    .get(&instance)
                    .ok_or_else(|| EngineError::UnknownInstance(instance.clone()))?;
                self.dependency_gate(&instance, &self.effective(&instance, spec))
                    .await?;
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
                    self.provision_locked(held, &instance, spec).await?,
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
    use weglarka_model::hash::spec_hash;

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
            restarts: 0,
            started_at: None,
            networks: vec![],
            addresses: vec![],
            published_ports: vec![],
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
                is_static: false,
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
