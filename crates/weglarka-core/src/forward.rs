//! Temporary port forward (`weglarka forward <app> <port>`, issue #108, ADR 0041): a short-lived relay
//! container on the app's network, published on a loopback port of the host.
//!
//! Like a one-off run (`crate::run`) the relay is never the app: it carries [`labels::FORWARD`] and no
//! `weglarka.instance`, joins only the app's primary network without DNS aliases, has no restart policy
//! and no healthcheck, so reconcile, ingress and the crash watcher never see it. It is removed when the
//! caller goes away, when the timeout hits, when the relay dies, and (for a daemon that died mid-forward)
//! at the next start.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::StreamExt;
use tokio::sync::OwnedSemaphorePermit;

use crate::app::{InstanceName, Security};
use crate::deploy::instance_networks;
use crate::labels;
use crate::podman::{
    ContainerFilter, ContainerSpec, ContainerState, PodmanClient, PodmanError, PortMapping,
    RestartPolicy,
};
use crate::reconcile::{EngineError, Reconciler};

/// How many forwards may be alive at once, across all apps (separate from the run limit).
pub const MAX_CONCURRENT_FORWARDS: usize = 4;
/// Longest a forward may live when the request names no timeout (a day), and the longest it may ask for.
pub const MAX_FORWARD_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
/// Port the relay listens on inside its container; only the host side is random.
const RELAY_PORT: u16 = 8080;
/// A relay is a throwaway process: it is killed outright.
const KILL_SIGNAL: &str = "KILL";
/// Writes the one-server `stream` config from positional arguments (never interpolated into the
/// script) into the read-only root's `/tmp`, then becomes nginx. `-e` keeps the error log off the
/// read-only `/var/log`.
const RELAY_SCRIPT: &str = "printf 'pid /tmp/relay.pid;\\nevents {}\\nstream {\\n  server {\\n    \
    listen %s;\\n    proxy_pass %s:%s;\\n  }\\n}\\n' \"$1\" \"$2\" \"$3\" > /tmp/relay.conf \
    && exec nginx -e /dev/stderr -c /tmp/relay.conf -g 'daemon off;'";

/// What to forward and which relay to use.
#[derive(Debug, Clone)]
pub struct ForwardOptions {
    /// Port inside the app's container.
    pub port: u16,
    /// End the forward after this long. `None` = [`MAX_FORWARD_TIMEOUT`].
    pub timeout: Option<Duration>,
    /// The relay's image: an nginx image with the `stream` module (`ingress.nginx_image`).
    pub image: String,
    /// The relay's hardening profile (the ingress one: ours to choose, always on, ADR 0014).
    pub security: Security,
}

impl ForwardOptions {
    /// Rejects what cannot be forwarded, before anything is created.
    pub fn validate(&self) -> Result<(), EngineError> {
        if self.port == 0 {
            return Err(EngineError::ForwardInvalid(
                "port must be between 1 and 65535".into(),
            ));
        }
        if self
            .timeout
            .is_some_and(|t| t.is_zero() || t > MAX_FORWARD_TIMEOUT)
        {
            return Err(EngineError::ForwardInvalid(
                "timeout must be between 1 second and 24 hours".into(),
            ));
        }
        Ok(())
    }
}

/// How a forward ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardOutcome {
    /// The caller went away; the relay was removed.
    Closed,
    /// Removed after the timeout.
    TimedOut,
    /// The relay container died by itself (exit code).
    RelayExited(i32),
}

fn forward_token() -> String {
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

/// A relay that is up and published. [`Self::hold`] or [`Self::discard`] must follow; a daemon that
/// dies in between leaves a container the next start sweeps ([`Reconciler::remove_stale_forwards`]).
pub struct PendingForward<P: PodmanClient> {
    engine: Arc<Reconciler<P>>,
    instance: InstanceName,
    name: String,
    host_port: u16,
    timeout: Duration,
    _slot: OwnedSemaphorePermit,
}

impl<P: PodmanClient> Reconciler<P> {
    /// Validates `options`, takes a forward slot, and starts the relay under the engine lock. The app
    /// must be running (there is nothing to forward to otherwise). Returns once the relay is up and its
    /// host port is known; the lock is never held for the forward itself.
    pub async fn prepare_forward(
        self: &Arc<Self>,
        instance: &InstanceName,
        options: &ForwardOptions,
    ) -> Result<PendingForward<P>, EngineError> {
        options.validate()?;
        let slot = self
            .forwards
            .clone()
            .try_acquire_owned()
            .map_err(|_| EngineError::ForwardLimit(MAX_CONCURRENT_FORWARDS))?;
        self.ensure_relay_image(&options.image).await?;
        let (name, host_port) = {
            let _g = self.lock.lock().await;
            self.start_relay(instance, options).await?
        };
        Ok(PendingForward {
            engine: self.clone(),
            instance: instance.clone(),
            name,
            host_port,
            timeout: options.timeout.unwrap_or(MAX_FORWARD_TIMEOUT),
            _slot: slot,
        })
    }

    async fn ensure_relay_image(&self, image: &str) -> Result<(), EngineError> {
        match self.podman.image_inspect(image).await {
            Ok(_) => Ok(()),
            Err(PodmanError::NotFound(_)) => {
                let mut stream = std::pin::pin!(self.podman.image_pull(image));
                while let Some(event) = stream.next().await {
                    event?;
                }
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Creates and starts the relay; on any failure after the create it is removed again.
    async fn start_relay(
        &self,
        instance: &InstanceName,
        options: &ForwardOptions,
    ) -> Result<(String, u16), EngineError> {
        let spec = self.load_spec(instance)?;
        let app = labels::container_name(instance);
        let running = match self.podman.container_inspect(&app).await {
            Ok(info) => info.state == ContainerState::Running,
            Err(PodmanError::NotFound(_)) => false,
            Err(e) => return Err(e.into()),
        };
        if !running {
            return Err(EngineError::ForwardNotRunning(instance.clone()));
        }
        // The app's primary network only: the relay must reach the app, nothing else.
        let (networks, _) = instance_networks(instance, &spec);
        let network = networks
            .into_iter()
            .next()
            .ok_or_else(|| EngineError::ForwardNotRunning(instance.clone()))?;
        let name = labels::forward_container_name(instance, &forward_token());
        let container = ContainerSpec {
            name: name.clone(),
            image: options.image.clone(),
            command: vec![],
            entrypoint: Some(vec![
                "/bin/sh".into(),
                "-c".into(),
                RELAY_SCRIPT.into(),
                "relay".into(),
                RELAY_PORT.to_string(),
                app,
                options.port.to_string(),
            ]),
            labels: BTreeMap::from([
                (labels::FORWARD.to_owned(), "true".to_owned()),
                (labels::FORWARD_FOR.to_owned(), instance.to_string()),
            ]),
            env: BTreeMap::new(),
            networks: vec![network],
            network_aliases: BTreeMap::new(),
            secrets: vec![],
            // Loopback only, random host port: read back from inspect once the container runs.
            publish: vec![PortMapping {
                host_ip: Some("127.0.0.1".into()),
                host_port: 0,
                container_port: RELAY_PORT,
            }],
            restart: RestartPolicy::No,
            userns_auto: true,
            mounts: vec![],
            volumes: vec![],
            resources: Default::default(),
            healthcheck: None,
            id_mapping: None,
            security: options.security.clone(),
        };
        self.podman.container_create(&container).await?;
        match self.relay_host_port(&name).await {
            Ok(port) => Ok((name, port)),
            Err(e) => {
                self.remove_relay(&name).await;
                Err(e)
            }
        }
    }

    async fn relay_host_port(&self, name: &str) -> Result<u16, EngineError> {
        self.podman.container_start(name).await?;
        let info = self.podman.container_inspect(name).await?;
        info.published_ports
            .iter()
            .find(|p| p.container_port == RELAY_PORT)
            .map(|p| p.host_port)
            .ok_or_else(|| {
                EngineError::ForwardInvalid("the relay did not publish a host port".into())
            })
    }

    /// A kill first, then a forced remove; both are idempotent.
    async fn remove_relay(&self, name: &str) {
        let _ = self.podman.container_kill(name, KILL_SIGNAL).await;
        if let Err(e) = self.podman.container_remove(name, true).await
            && !matches!(e, PodmanError::NotFound(_))
        {
            tracing::warn!(container = name, error = %e, "cannot remove a forward relay");
        }
    }

    /// Removes every relay. Only for the daemon's start-up: no forward of *this* process can exist yet.
    pub async fn remove_stale_forwards(&self) -> Result<usize, EngineError> {
        let filter = ContainerFilter {
            labels: BTreeMap::from([(labels::FORWARD.to_owned(), "true".to_owned())]),
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

impl<P: PodmanClient> PendingForward<P> {
    /// The loopback port of the host the relay listens on.
    pub fn host_port(&self) -> u16 {
        self.host_port
    }

    /// Keeps the relay until `closed` resolves (the caller went away), the timeout hits or the relay
    /// dies. The container is removed on every path.
    pub async fn hold(self, closed: impl Future<Output = ()>) -> ForwardOutcome {
        let wait = self.engine.podman.container_wait(&self.name);
        tokio::pin!(wait);
        let deadline = tokio::time::sleep(self.timeout);
        tokio::pin!(deadline);
        tokio::pin!(closed);
        let outcome = tokio::select! {
            () = &mut closed => ForwardOutcome::Closed,
            () = &mut deadline => ForwardOutcome::TimedOut,
            code = &mut wait => match code {
                Ok(code) => ForwardOutcome::RelayExited(code),
                // A failed wait says nothing about the relay; treat it as gone and clean up.
                Err(_) => ForwardOutcome::RelayExited(-1),
            },
        };
        self.engine.remove_relay(&self.name).await;
        tracing::info!(instance = %self.instance, container = %self.name, ?outcome, "forward finished");
        outcome
    }

    /// Gives up before the forward is used: removes the relay.
    pub async fn discard(self) {
        self.engine.remove_relay(&self.name).await;
    }
}
