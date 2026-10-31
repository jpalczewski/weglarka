//! One-off containers (`weglarka run <app> -- <cmd>`, issue #106, ADR 0040): the app's image, env,
//! secrets, volumes, configs and networks, a different command, and a lifetime of one process.
//!
//! The container is never the app's: it carries [`labels::RUN`] and no `weglarka.instance`, joins the
//! app's networks without DNS aliases, publishes nothing and has no restart policy, so reconcile,
//! ingress and the crash watcher never see it. It is always removed — when the process exits, when the
//! timeout hits, when the caller goes away, and (for a daemon that died mid-run) at the next start.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::StreamExt;
use tokio::sync::{OwnedSemaphorePermit, mpsc};

use crate::deploy::{app_container_base, instance_networks};
use crate::reconcile::{EngineError, EngineGuard, Reconciler};
use crate::secrets::materialize;
use weglarka_model::app::{InstanceName, SecretBinding, SecretTarget};
use weglarka_model::labels;
use weglarka_model::podman::{
    ContainerFilter, ContainerSpec, LogChunk, LogOptions, PodmanClient, PodmanError,
};
use weglarka_model::secret_store::{is_daemon_managed, valid_secret_name};
use weglarka_model::state;

/// How many one-off containers may run at once, across all apps.
pub const MAX_CONCURRENT_RUNS: usize = 4;
/// Longest a run may take when the request names no timeout (a day), and the longest it may ask for.
pub const MAX_RUN_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
/// Most secrets one run may bind.
pub const MAX_RUN_SECRETS: usize = 32;
/// How long output still in flight is read after the process has exited.
const DRAIN_GRACE: Duration = Duration::from_secs(5);
/// A run that is cancelled or timed out is killed outright: it is a throwaway process.
const KILL_SIGNAL: &str = "KILL";

/// What to run. `command` are arguments to the image's entrypoint unless `entrypoint` replaces it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunOptions {
    pub command: Vec<String>,
    pub entrypoint: Option<Vec<String>>,
    /// Added to the app's `env`; a key set in both takes this value. Secrets stay bound by the spec.
    pub env: BTreeMap<String, String>,
    /// `variable -> secret name`: stored secrets of the app exposed as env for this run only
    /// (on top of the spec's own bindings; a binding on the same variable is replaced).
    pub secrets: BTreeMap<String, String>,
    /// Kill the process after this long. `None` = [`MAX_RUN_TIMEOUT`].
    pub timeout: Option<Duration>,
}

/// How a run ended. Its output went through the channel the caller passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunOutcome {
    Exited(i32),
    /// Killed after the timeout.
    TimedOut,
    /// The receiving side went away; the container was killed.
    Cancelled,
}

impl RunOptions {
    /// Rejects what cannot start a process, before anything is created.
    pub fn validate(&self) -> Result<(), EngineError> {
        let invalid = |m: String| Err(EngineError::RunInvalid(m));
        if self.command.is_empty() && self.entrypoint.as_ref().is_none_or(Vec::is_empty) {
            return invalid("nothing to run: give a command after `--` or an entrypoint".into());
        }
        if self.entrypoint.as_ref().is_some_and(|e| e.is_empty()) {
            return invalid("entrypoint must not be empty".into());
        }
        for (key, value) in &self.env {
            if key.is_empty() || key.contains(['=', '\0']) || value.contains('\0') {
                return invalid(format!("invalid environment variable {key:?}"));
            }
        }
        if self.secrets.len() > MAX_RUN_SECRETS {
            return invalid(format!("at most {MAX_RUN_SECRETS} secrets per run"));
        }
        for (var, secret) in &self.secrets {
            if var.is_empty() || var.contains(['=', '\0']) {
                return invalid(format!("invalid environment variable {var:?}"));
            }
            if !valid_secret_name(secret) {
                return invalid(format!("invalid secret name {secret:?}"));
            }
            if is_daemon_managed(secret) {
                return invalid(format!(
                    "secret {secret:?} is managed by Węglarka and cannot be given to a run"
                ));
            }
            if self.env.contains_key(var) {
                return invalid(format!(
                    "{var} is given both as a plain value and as a secret"
                ));
            }
        }
        if self
            .timeout
            .is_some_and(|t| t.is_zero() || t > MAX_RUN_TIMEOUT)
        {
            return invalid("timeout must be between 1 second and 24 hours".into());
        }
        Ok(())
    }
}

/// Unique-enough suffix for a container name: the clock plus a process-wide counter (two runs in the
/// same nanosecond differ by the counter, two daemons by the clock).
fn run_token() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    format!(
        "{:x}{:x}",
        nanos & 0xffff_ffff_ffff,
        COUNTER.fetch_add(1, Ordering::Relaxed) & 0xff
    )
}

/// A one-off container that is created but not started: everything that can be refused has been
/// (unknown or undeployed app, a missing secret, a config mount that cannot be resolved, a busy
/// slot), so a caller that streams the output can still answer with an ordinary error up to here.
/// [`Self::drive`] or [`Self::discard`] must follow; a daemon that dies in between leaves a container
/// the next start sweeps ([`Reconciler::remove_stale_runs`]).
pub struct PendingRun<P: PodmanClient> {
    engine: Arc<Reconciler<P>>,
    instance: InstanceName,
    name: String,
    timeout: Duration,
    _slot: OwnedSemaphorePermit,
}

impl<P: PodmanClient> Reconciler<P> {
    /// Validates `options`, takes a run slot and creates the container (not started), under the engine
    /// lock. The lock covers only this preparation (image, secrets, networks, uid range guard,
    /// volumes), never the run, so a long run does not block deploys. Needs a deployed app (a pinned
    /// digest); the app need not be running.
    pub async fn prepare_run(
        self: &Arc<Self>,
        instance: &InstanceName,
        options: &RunOptions,
    ) -> Result<PendingRun<P>, EngineError> {
        let guard = self.acquire().await;
        self.prepare_run_locked(&guard, instance, options).await
    }

    /// The body of [`Self::prepare_run`] for a caller that already holds the engine lock (the generated
    /// config pipeline validates inside its own critical section). The returned [`PendingRun`] does not
    /// hold the lock: drop the guard before driving it if the run is long.
    pub(crate) async fn prepare_run_locked(
        self: &Arc<Self>,
        _held: &EngineGuard<'_>,
        instance: &InstanceName,
        options: &RunOptions,
    ) -> Result<PendingRun<P>, EngineError> {
        options.validate()?;
        let slot = self
            .runs
            .clone()
            .try_acquire_owned()
            .map_err(|_| EngineError::RunLimit(MAX_CONCURRENT_RUNS))?;
        let name = self.create_run_container(instance, options).await?;
        Ok(PendingRun {
            engine: self.clone(),
            instance: instance.clone(),
            name,
            timeout: options.timeout.unwrap_or(MAX_RUN_TIMEOUT),
            _slot: slot,
        })
    }

    /// [`Self::prepare_run`] and [`PendingRun::drive`] in one call.
    pub async fn run_once(
        self: &Arc<Self>,
        instance: &InstanceName,
        options: RunOptions,
        out: mpsc::Sender<LogChunk>,
    ) -> Result<RunOutcome, EngineError> {
        self.prepare_run(instance, &options).await?.drive(out).await
    }

    /// Creates the container (not started) and returns its name; under the engine lock.
    async fn create_run_container(
        &self,
        instance: &InstanceName,
        options: &RunOptions,
    ) -> Result<String, EngineError> {
        let spec = state::load_apps(&self.paths.apps)?
            .apps
            .remove(instance)
            .ok_or_else(|| EngineError::UnknownInstance(instance.clone()))?;
        // A run must see the same injected OIDC env and secret as the serving container.
        self.ensure_oidc_credential(instance, &spec).await?;
        let mut spec = self.effective(instance, &spec).into_owned();
        // Run-only secrets: bindings on the in-memory copy, so they are materialized like the app's
        // own and never reach the stored spec. One on the same variable replaces the app's.
        for (var, secret) in &options.secrets {
            spec.secrets
                .retain(|b| !matches!(&b.target, SecretTarget::Env { var: v } if v == var));
            spec.secrets.push(SecretBinding {
                secret: secret.clone(),
                target: SecretTarget::Env { var: var.clone() },
            });
        }
        let digest = state::load_state(&self.paths.state)?
            .apps
            .get(instance)
            .and_then(|s| s.current.clone())
            .ok_or_else(|| EngineError::RunNotDeployed(instance.clone()))?;
        // The pinned digest only: a one-off container never follows the tag to something newer.
        let local_id = self.running_image_id(instance).await;
        let image = self
            .ensure_image(instance, &spec, &digest, local_id.as_deref())
            .await?;
        let secrets = materialize(&self.podman, &self.secrets, instance, &spec).await?;
        let (prepared, configs) = self.prepare_instance(instance, &spec).await?;
        // The app's networks, but without the DNS aliases: a run must never answer to the app's name.
        let (networks, _) = instance_networks(instance, &spec);
        let name = labels::run_container_name(instance, &run_token());

        let mut container = ContainerSpec {
            command: options.command.clone(),
            entrypoint: options.entrypoint.clone(),
            ..app_container_base(
                name.clone(),
                image,
                BTreeMap::from([
                    (labels::RUN.to_owned(), "true".to_owned()),
                    (labels::RUN_FOR.to_owned(), instance.to_string()),
                ]),
                &spec,
                networks,
                secrets,
                &configs,
            )
        };
        container.env.extend(options.env.clone());
        prepared.apply(&mut container);
        self.podman.container_create(&container).await?;
        Ok(name)
    }

    /// Starts the container and forwards its output until it exits, times out or `out` closes.
    async fn drive_run(
        &self,
        name: &str,
        timeout: Duration,
        out: &mpsc::Sender<LogChunk>,
    ) -> Result<RunOutcome, EngineError> {
        self.podman.container_start(name).await?;
        let mut logs = self
            .podman
            .container_logs(
                name,
                &LogOptions {
                    follow: true,
                    ..LogOptions::default()
                },
            )
            .await?;
        let wait = self.podman.container_wait(name);
        tokio::pin!(wait);
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);

        let mut logs_done = false;
        let code = loop {
            tokio::select! {
                code = &mut wait => break code?,
                chunk = logs.next(), if !logs_done => match chunk {
                    Some(Ok(chunk)) => {
                        if out.send(chunk).await.is_err() {
                            return Ok(RunOutcome::Cancelled);
                        }
                    }
                    Some(Err(e)) => {
                        // The exit code still arrives through `wait`; lost output is only reported.
                        tracing::warn!(container = name, error = %e, "one-off container log stream failed");
                        logs_done = true;
                    }
                    None => logs_done = true,
                },
                () = out.closed() => return Ok(RunOutcome::Cancelled),
                () = &mut deadline => return Ok(RunOutcome::TimedOut),
            }
        };
        // The process is gone; what it printed last may still be on its way.
        while !logs_done {
            match tokio::time::timeout(DRAIN_GRACE, logs.next()).await {
                Ok(Some(Ok(chunk))) => {
                    if out.send(chunk).await.is_err() {
                        return Ok(RunOutcome::Cancelled);
                    }
                }
                Ok(Some(Err(_)) | None) | Err(_) => logs_done = true,
            }
        }
        Ok(RunOutcome::Exited(code))
    }

    /// A kill first (the process may still be alive after a timeout or a cancel), then a forced remove;
    /// both are idempotent.
    async fn remove_run_container(&self, name: &str) {
        let _ = self.podman.container_kill(name, KILL_SIGNAL).await;
        if let Err(e) = self.podman.container_remove(name, true).await
            && !matches!(e, PodmanError::NotFound(_))
        {
            tracing::warn!(container = name, error = %e, "cannot remove a one-off container");
        }
    }

    /// Removes every one-off container. Only for the daemon's start-up: no run of *this* process can
    /// exist yet, so each one found was orphaned by a daemon that died mid-run.
    pub async fn remove_stale_runs(&self) -> Result<usize, EngineError> {
        let filter = ContainerFilter {
            labels: BTreeMap::from([(labels::RUN.to_owned(), "true".to_owned())]),
        };
        let mut removed = 0;
        for c in self.podman.container_list(&filter).await? {
            let _ = self.podman.container_kill(&c.name, KILL_SIGNAL).await;
            match self.podman.container_remove(&c.name, true).await {
                Ok(()) => removed += 1,
                Err(PodmanError::NotFound(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(removed)
    }
}

impl<P: PodmanClient> PendingRun<P> {
    /// Starts the container and streams its output into `out` until it exits, times out or the
    /// receiver is dropped (which kills it). The container is removed on every path.
    pub async fn drive(self, out: mpsc::Sender<LogChunk>) -> Result<RunOutcome, EngineError> {
        let Self {
            engine,
            instance,
            name,
            timeout,
            ..
        } = &self;
        let result = engine.drive_run(name, *timeout, &out).await;
        engine.remove_run_container(name).await;
        let outcome = result?;
        tracing::info!(%instance, container = %name, ?outcome, "one-off container finished");
        Ok(outcome)
    }

    /// Gives up before starting: removes the container.
    pub async fn discard(self) {
        self.engine.remove_run_container(&self.name).await;
    }
}
