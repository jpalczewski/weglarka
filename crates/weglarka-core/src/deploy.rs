//! `recreate` deploy: pull → stop old → new container → health gate → digest shift
//! or rollback to the previous digest (retention 1). Plus webhook fan-out
//! (image → all instances tracking that image/tag) with dedup by `delivery_id`
//! (persisted across restarts, see [`crate::delivery`] / ADR 0035).

use std::collections::BTreeMap;
use std::time::Duration;

use futures_util::StreamExt;

use crate::app::{AppSpec, AppsFile, Digest, InstanceName, normalize_signal};
use crate::events::Event;
use crate::hash::{SpecHash, spec_hash, spec_hash_with_secrets};
use crate::labels;
use crate::podman::{
    BindMount, ContainerSpec, ContainerState, HealthStatus, NetworkSpec, PodmanClient, PodmanError,
    PortMapping, PullEvent, RestartPolicy, image_repo,
};
use crate::reconcile::{ActivityKind, EngineError, Reconciler, RecreateReason, SecretChangePolicy};
use crate::secrets::{binding_fingerprints, materialize, registry_auth};
use crate::state::{self, AppState, FailedDeploy, StateFile};
use crate::uid_range::UidRange;
use crate::webhook::WebhookEvent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeployOutcome {
    /// New container passed the gate; digests shifted.
    Deployed { digest: Digest, generation: u64 },
    /// Same digest and the container matches the spec — nothing to do.
    Unchanged { digest: Digest },
    /// This digest already failed the gate once; requires `force`.
    KnownBad { digest: Digest },
    /// New version rejected, previous one restored.
    RolledBack {
        failed: Digest,
        restored: Digest,
        reason: String,
    },
    /// Deploy failed and there was nothing to return to (or the rollback failed too).
    Failed { digest: Digest, reason: String },
    /// `start = false`: nothing was started. The image digest is pinned and the network, uid range
    /// and volumes are ready; `apps start` deploys the app later.
    Provisioned { digest: Digest },
}

/// Outcome of `apps reload` (issue #118): the running app picked up its config without being
/// recreated. Desired state is not touched either way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReloadOutcome {
    /// `reload_signal` was sent to the running container (name without the `SIG` prefix, e.g. `HUP`).
    Signalled { signal: String },
    /// No signal is configured: the same container was stopped and started again.
    Restarted,
}

// ── Helpers (pure) ──────────────────────────────────────────────────────

/// The networks an instance's container joins and the extra DNS aliases on them. The instance's own
/// network stays first (the primary one: egress, ingress); the group network is added next to it,
/// with the declared aliases on top of the container name.
pub(crate) fn instance_networks(
    instance: &InstanceName,
    spec: &AppSpec,
) -> (Vec<String>, BTreeMap<String, Vec<String>>) {
    let mut networks = vec![labels::network_name(instance)];
    let mut aliases = BTreeMap::new();
    if let Some(net) = crate::shared_networks::membership(spec) {
        let shared = labels::shared_network_name(&net.name);
        if !net.aliases.is_empty() {
            aliases.insert(shared.clone(), net.aliases.clone());
        }
        networks.push(shared);
    }
    (networks, aliases)
}

/// Host config mounts: always read-only, and the **canonical** path is what mounts, so a symlink
/// swapped between the check and the mount cannot redirect the bind (ADR 0028).
pub(crate) fn config_binds(configs: &[crate::config_mounts::Resolved]) -> Vec<BindMount> {
    configs
        .iter()
        .map(|c| BindMount {
            source: c.source.display().to_string(),
            target: c.target.clone(),
            read_only: true,
        })
        .collect()
}

/// Reference pinning a digest: `repo@sha256:…`.
pub fn pinned_ref(image: &str, digest: &Digest) -> String {
    format!("{}@{digest}", image_repo(image))
}

/// `(repo, tag)` for comparing webhook images with `apps.toml`; no tag = `latest`.
pub(crate) fn normalize_image(image: &str) -> (String, String) {
    let no_digest = image.split('@').next().unwrap_or(image);
    let repo = image_repo(no_digest).to_ascii_lowercase();
    let tag = no_digest[image_repo(no_digest).len()..]
        .strip_prefix(':')
        .filter(|t| !t.is_empty())
        .unwrap_or("latest")
        .to_owned();
    (repo, tag)
}

/// Instances with `auto_update` that are meant to run (`start`) and track the given image/tag
/// (fan-out). Apps with `start = false` are skipped: nothing may be pulled or deployed for an app
/// that is not running; `apps start` deploys the newest image itself.
pub fn instances_tracking(apps: &AppsFile, image_ref: &str) -> Vec<InstanceName> {
    let wanted = normalize_image(image_ref);
    apps.apps
        .iter()
        .filter(|(_, s)| s.auto_update && s.start && normalize_image(&s.image) == wanted)
        .map(|(n, _)| n.clone())
        .collect()
}

/// Where a deploy takes the digest it pins from.
#[derive(Debug, Clone, Copy)]
pub(crate) enum DigestSource<'a> {
    /// The tag in `spec.image`: webhook, `apps deploy`, reconcile.
    Tag,
    /// Another reference of the same repository, pulled now (`weglarka push --image`).
    Reference(&'a str),
    /// A digest already in the local store (`weglarka push ARCHIVE`, docs/decisions/0042).
    Local(&'a Digest),
}

#[derive(Debug)]
pub struct WebhookOutcome {
    pub duplicate: bool,
    pub matched: Vec<InstanceName>,
    pub results: Vec<(InstanceName, Result<DeployOutcome, EngineError>)>,
}

/// The libpod spec of an app container: what `launch` and the blue-green challenger share. The caller
/// decides the name, the networks and the labels; volumes are added by `Prepared::apply`.
#[allow(clippy::too_many_arguments)]
fn container_spec(
    name: String,
    image: String,
    labels: BTreeMap<String, String>,
    spec: &AppSpec,
    networks: Vec<String>,
    network_aliases: BTreeMap<String, Vec<String>>,
    secrets: Vec<crate::podman::SecretAttachment>,
    configs: &[crate::config_mounts::Resolved],
) -> ContainerSpec {
    ContainerSpec {
        name,
        image,
        command: spec.command.clone(),
        entrypoint: None,
        labels,
        env: spec.env.clone(),
        networks,
        network_aliases,
        secrets,
        publish: spec
            .host_ports
            .iter()
            .map(|p| PortMapping {
                // Validated earlier; the loopback default keeps publishing opt-in.
                host_ip: Some(p.bind_ip().to_owned()),
                host_port: p.host,
                container_port: p.container,
            })
            .collect(),
        restart: RestartPolicy::Always,
        userns_auto: true,
        // Host config mounts: always read-only, and the **canonical** path is what mounts, so a
        // symlink swapped between the check and the mount cannot redirect the bind (ADR 0028).
        mounts: config_binds(configs),
        keep_groups: !spec.group_add.is_empty(),
        volumes: vec![],
        resources: spec.resources.clone(),
        healthcheck: crate::limits::container_healthcheck(&spec.health),
        id_mapping: None,
        security: spec.security.clone(),
    }
}

/// Result of starting a container: the hash it was started with, the uid range its volumes were
/// prepared in (recorded in the state as the data owner, issue #75) and the gate verdict.
struct Launched {
    hash: SpecHash,
    range: UidRange,
    health: Result<(), String>,
    /// A blue-green deploy that failed before the switch: the old container was never touched and
    /// still serves, so there is nothing to roll back to (ADR 0046). Always `false` for `launch`.
    old_intact: bool,
}

impl<P: PodmanClient> Reconciler<P> {
    /// Host-side read-only mounts of an app: `configs` under `config_root` plus the allowlisted
    /// `host_mounts` (issue #178). Both are canonical paths, mounted read-only by [`config_binds`].
    pub(crate) fn resolve_mounts(
        &self,
        spec: &AppSpec,
    ) -> Result<Vec<crate::config_mounts::Resolved>, EngineError> {
        let mut mounts =
            crate::config_mounts::resolve_all(self.options.config_root.as_deref(), spec)
                .map_err(|e| EngineError::Configs(e.to_string()))?;
        crate::host_mounts::check_groups(&self.options.group_add, spec)
            .map_err(|e| EngineError::Configs(e.to_string()))?;
        mounts.extend(
            crate::host_mounts::resolve_all(&self.options.host_mounts, spec)
                .map_err(|e| EngineError::Configs(e.to_string()))?,
        );
        Ok(mounts)
    }

    /// Manual/webhook deploy of a single instance. `force` skips `Unchanged` and `KnownBad`.
    pub async fn deploy(
        &self,
        instance: &InstanceName,
        force: bool,
    ) -> Result<DeployOutcome, EngineError> {
        let _g = self.lock.lock().await;
        self.deploy_locked(instance, force).await
    }

    /// `apps reload` (issue #118): make a **running** app re-read its config without recreating the
    /// container. Sends `reload_signal` when the spec sets one, otherwise restarts the same container
    /// (stop + start). Takes the engine lock, writes neither `apps.toml` nor `state.toml` and emits no
    /// event; a container that is not running is refused with [`EngineError::ReloadNotRunning`].
    pub async fn reload(&self, instance: &InstanceName) -> Result<ReloadOutcome, EngineError> {
        let _g = self.lock.lock().await;
        let spec = self.load_spec(instance)?;
        // Same precondition as a deploy: a config that cannot be mounted is not reloadable either.
        self.resolve_mounts(&spec)?;
        let name = labels::container_name(instance);
        let info = match self.podman.container_inspect(&name).await {
            Ok(info) => info,
            Err(PodmanError::NotFound(_)) => {
                return Err(EngineError::ReloadNotRunning(instance.clone()));
            }
            Err(e) => return Err(e.into()),
        };
        if info.state != ContainerState::Running {
            return Err(EngineError::ReloadNotRunning(instance.clone()));
        }
        if let Some(raw) = &spec.reload_signal {
            let signal = normalize_signal(raw)
                .ok_or_else(|| EngineError::Configs(format!("invalid reload_signal {raw:?}")))?;
            self.podman.container_kill(&name, &signal).await?;
            tracing::info!(%instance, %signal, "sent the reload signal to the container");
            return Ok(ReloadOutcome::Signalled { signal });
        }
        self.podman
            .container_stop(&name, self.options.stop_timeout_secs)
            .await?;
        self.podman.container_start(&name).await?;
        tracing::info!(%instance, "restarted the container to reload its config");
        Ok(ReloadOutcome::Restarted)
    }

    /// "New image" webhook: dedup by `delivery_id`, fan-out to instances with `auto_update`.
    pub async fn handle_webhook(
        &self,
        event: &WebhookEvent,
    ) -> Result<WebhookOutcome, EngineError> {
        let apps = state::load_apps(&self.paths.apps)?;
        if let Some(id) = &event.delivery_id {
            let dup = self
                .dedup
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .check_and_insert(id);
            if dup {
                self.events.emit(Event::WebhookDuplicate {
                    delivery_id: id.clone(),
                });
                return Ok(WebhookOutcome {
                    duplicate: true,
                    matched: vec![],
                    results: vec![],
                });
            }
        }
        let matched = instances_tracking(&apps, &event.image_ref);
        let mut results = Vec::with_capacity(matched.len());
        for inst in &matched {
            results.push((inst.clone(), self.deploy(inst, false).await));
        }
        Ok(WebhookOutcome {
            duplicate: false,
            matched,
            results,
        })
    }

    // ── Internals (called under `lock`) ──────────────────────────────────────────

    pub(crate) fn load_spec(&self, instance: &InstanceName) -> Result<AppSpec, EngineError> {
        state::load_apps(&self.paths.apps)?
            .apps
            .remove(instance)
            .ok_or_else(|| EngineError::UnknownInstance(instance.clone()))
    }

    /// Expected `spec-hash` according to the secret-change policy.
    pub(crate) async fn desired_hash(
        &self,
        instance: &InstanceName,
        spec: &AppSpec,
        digest: &Digest,
    ) -> Result<SpecHash, EngineError> {
        match self.options.secret_change {
            SecretChangePolicy::NextDeploy => Ok(spec_hash(spec, digest)),
            SecretChangePolicy::Immediate => {
                let fp = binding_fingerprints(&self.secrets, instance, spec).await?;
                Ok(spec_hash_with_secrets(spec, digest, &fp))
            }
        }
    }

    /// Pulls `reference` for `instance`, with its `registry-auth` credentials when it has any
    /// (docs/decisions/0026). A 401/403 becomes [`EngineError::RegistryAuth`].
    async fn pull(
        &self,
        instance: &InstanceName,
        reference: &str,
    ) -> Result<Option<Digest>, EngineError> {
        let auth = registry_auth(&self.secrets, instance).await?;
        let mut stream = std::pin::pin!(self.podman.image_pull_with(reference, auth.as_ref()));
        let mut digest = None;
        while let Some(ev) = stream.next().await {
            match ev {
                Ok(PullEvent::Complete { digest: d, .. }) => digest = d,
                Ok(_) => {}
                Err(e) if e.is_registry_auth_failure() => {
                    return Err(EngineError::RegistryAuth {
                        instance: instance.clone(),
                        reference: reference.to_owned(),
                        sent_credentials: auth.is_some(),
                    });
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(digest)
    }

    async fn resolve_digest(
        &self,
        instance: &InstanceName,
        reference: &str,
    ) -> Result<Digest, EngineError> {
        match self.pull(instance, reference).await? {
            Some(d) => Ok(d),
            None => self
                .podman
                .image_inspect(reference)
                .await?
                .digest
                .ok_or_else(|| EngineError::NoDigest(reference.to_owned())),
        }
    }

    async fn digest_from(
        &self,
        instance: &InstanceName,
        spec: &AppSpec,
        source: DigestSource<'_>,
    ) -> Result<Digest, EngineError> {
        match source {
            DigestSource::Tag => self.resolve_digest(instance, &spec.image).await,
            DigestSource::Reference(reference) => self.resolve_digest(instance, reference).await,
            DigestSource::Local(digest) => Ok(digest.clone()),
        }
    }

    /// Returns the image reference to create the container from. Order: the pinned `repo@digest`
    /// if present locally, then `local_id` (the image of the previous container, kept locally so
    /// that a rollback does not depend on the registry), and only then a pull.
    pub(crate) async fn ensure_image(
        &self,
        instance: &InstanceName,
        spec: &AppSpec,
        digest: &Digest,
        local_id: Option<&str>,
    ) -> Result<String, EngineError> {
        let reference = pinned_ref(&spec.image, digest);
        match self.podman.image_inspect(&reference).await {
            Ok(_) => Ok(reference),
            Err(PodmanError::NotFound(_)) => {
                if let Some(id) = local_id
                    && self.podman.image_inspect(id).await.is_ok()
                {
                    return Ok(id.to_owned());
                }
                self.pull(instance, &reference).await?;
                Ok(reference)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// ID of the image the app's container currently runs (retention 1: the rollback target).
    pub(crate) async fn running_image_id(&self, instance: &InstanceName) -> Option<String> {
        let name = labels::container_name(instance);
        self.podman
            .container_inspect(&name)
            .await
            .ok()
            .map(|c| c.image_id)
            .filter(|id| !id.is_empty())
    }

    /// The part of a launch that runs before anything is created or removed: the network, the
    /// uid-range guard, the volumes (uid range + attachments) and only then the old container.
    /// `launch` and `provision_locked` share it, so neither of them can skip the guard again
    /// (issue #75). `Err` = the old container is untouched and nothing new exists yet.
    async fn begin_instance(
        &self,
        instance: &InstanceName,
        spec: &AppSpec,
    ) -> Result<
        (
            crate::volumes::Prepared,
            Vec<crate::config_mounts::Resolved>,
        ),
        EngineError,
    > {
        let prepared = self.prepare_instance(instance, spec).await?;
        let name = labels::container_name(instance);
        match self
            .podman
            .container_stop(&name, self.options.stop_timeout_secs)
            .await
        {
            Ok(()) | Err(PodmanError::NotFound(_)) => {}
            Err(e) => return Err(e.into()),
        }
        match self.podman.container_remove(&name, true).await {
            Ok(()) | Err(PodmanError::NotFound(_)) => {}
            Err(e) => return Err(e.into()),
        }
        Ok(prepared)
    }

    /// Everything a container of `instance` needs before it can be created, without touching the
    /// app's own container: resolved config mounts, the networks, the uid-range guard, the volumes.
    /// A one-off `weglarka run` container goes through exactly this, so it cannot skip a guard either.
    pub(crate) async fn prepare_instance(
        &self,
        instance: &InstanceName,
        spec: &AppSpec,
    ) -> Result<
        (
            crate::volumes::Prepared,
            Vec<crate::config_mounts::Resolved>,
        ),
        EngineError,
    > {
        // A config mount that cannot be resolved fails the deploy **before** the old container is
        // touched (no stop/remove, and no rollback that would only restore the same broken spec,
        // ADR 0028). The resolved canonical paths are what `launch` mounts.
        let configs = self.resolve_mounts(spec)?;
        self.podman
            .network_create(&NetworkSpec {
                name: labels::network_name(instance),
                internal: false,
                labels: BTreeMap::from([(labels::INSTANCE.to_owned(), instance.to_string())]),
            })
            .await?;
        if let Some(net) = crate::shared_networks::membership(spec) {
            self.podman
                .network_create(&NetworkSpec {
                    name: labels::shared_network_name(&net.name),
                    // Group traffic stays on the group: no route out, unlike the per-app network
                    // that carries the ingress and the app's own egress.
                    internal: true,
                    labels: BTreeMap::from([(
                        labels::SHARED_NETWORK.to_owned(),
                        net.name.to_string(),
                    )]),
                })
                .await?;
        }
        // A changed uid range would make the instance's existing files unreadable
        // (docs/decisions/0017-shared-volumes.md): refuse before creating volumes or touching the
        // old container. The range was assigned by the caller, so `state.toml` already has it.
        let new_label = crate::volumes::effective_range_label(
            &state::load_apps(&self.paths.apps)?,
            &state::load_state(&self.paths.state)?,
            instance,
            spec,
        );
        self.range_change_guard_locked(instance, new_label.as_deref())
            .await?;
        let prepared = self.prepare_container(instance, spec).await?; // uid range + volumes
        Ok((prepared, configs))
    }

    /// Prepare (image, network, secrets, uid range) → remove the old one → create+start → gate.
    /// `Err` means failure *before* touching the old container; later errors end up
    /// in `Launched::health`.
    async fn launch(
        &self,
        instance: &InstanceName,
        spec: &AppSpec,
        digest: &Digest,
        generation: u64,
        local_id: Option<&str>,
    ) -> Result<Launched, EngineError> {
        let image = self.ensure_image(instance, spec, digest, local_id).await?;
        let hash = self.desired_hash(instance, spec, digest).await?;
        let secrets = materialize(&self.podman, &self.secrets, instance, spec).await?;
        let (prepared, configs) = self.begin_instance(instance, spec).await?;
        let name = labels::container_name(instance);
        let (networks, network_aliases) = instance_networks(instance, spec);
        let mut container = container_spec(
            name.clone(),
            image,
            labels::container_labels(instance, generation, &hash),
            spec,
            networks,
            network_aliases,
            secrets,
            &configs,
        );
        let range = prepared.range;
        prepared.apply(&mut container);
        let started = async {
            self.podman.container_create(&container).await?;
            self.podman.container_start(&name).await
        }
        .await;
        let health = match started {
            Ok(()) => self.health_gate(&name, spec).await,
            Err(e) => Err(format!("cannot start container: {e}")),
        };
        Ok(Launched {
            hash,
            range,
            health,
            old_intact: false,
        })
    }

    /// Whether a deploy of `spec` swaps blue-green: the app opted in **and** a container is serving now
    /// (a first deploy has nothing to run next to, so it takes the plain path).
    async fn blue_green_applies(&self, instance: &InstanceName, spec: &AppSpec) -> bool {
        spec.strategy == crate::app::Strategy::BlueGreen
            && self
                .podman
                .container_inspect(&labels::container_name(instance))
                .await
                .is_ok_and(|c| c.state == ContainerState::Running)
    }

    /// `launch` or, for a blue-green app with a serving container, [`Self::launch_blue_green`].
    async fn launch_with_strategy(
        &self,
        instance: &InstanceName,
        spec: &AppSpec,
        digest: &Digest,
        generation: u64,
    ) -> Result<Launched, EngineError> {
        if self.blue_green_applies(instance, spec).await {
            self.launch_blue_green(instance, spec, digest, generation)
                .await
        } else {
            self.launch(instance, spec, digest, generation, None).await
        }
    }

    /// Blue-green swap (ADR 0046): the new container starts and passes its gate on a staging network
    /// while the old one keeps serving; only then does it join the app network with the instance
    /// alias, the names are swapped and the old container is stopped after a drain.
    ///
    /// `Err` = failure before anything was created (the old container is untouched). A challenger that
    /// fails its gate is removed and reported as `Launched { old_intact: true, health: Err }`.
    async fn launch_blue_green(
        &self,
        instance: &InstanceName,
        spec: &AppSpec,
        digest: &Digest,
        generation: u64,
    ) -> Result<Launched, EngineError> {
        let image = self.ensure_image(instance, spec, digest, None).await?;
        let hash = self.desired_hash(instance, spec, digest).await?;
        let secrets = materialize(&self.podman, &self.secrets, instance, spec).await?;
        // Everything `launch` prepares, **without** touching the serving container.
        let (prepared, configs) = self.prepare_instance(instance, spec).await?;
        let range = prepared.range;

        let serving = labels::container_name(instance);
        let next = labels::challenger_name(instance);
        let retiring = labels::retiring_name(instance);
        let app_net = labels::network_name(instance);
        let staging = labels::staging_network_name(instance);

        // A leftover of a crashed deploy would hold the names.
        self.remove_transient(&next, &retiring).await;
        self.podman
            .network_create(&NetworkSpec {
                name: staging.clone(),
                internal: false,
                labels: BTreeMap::from([(labels::INSTANCE.to_owned(), instance.to_string())]),
            })
            .await?;

        // The app network is the one nginx is on and the one that carries the alias: the challenger
        // joins it only after its gate. Shared networks (and their aliases) are joined up front, since
        // libpod cannot add an alias to a network the container is already on.
        let (mut networks, network_aliases) = instance_networks(instance, spec);
        networks[0] = staging.clone();
        let mut container = container_spec(
            next.clone(),
            image,
            labels::container_labels(instance, generation, &hash),
            spec,
            networks,
            network_aliases,
            secrets,
            &configs,
        );
        prepared.apply(&mut container);

        let failed = |reason: String| Launched {
            hash: hash.clone(),
            range,
            health: Err(reason),
            old_intact: true,
        };
        let started = async {
            self.podman.container_create(&container).await?;
            self.podman.container_start(&next).await
        }
        .await;
        if let Err(e) = started {
            self.abandon_challenger(&next, &staging).await;
            return Ok(failed(format!("cannot start container: {e}")));
        }
        if let Err(reason) = self.challenger_gate(&next, spec).await {
            self.abandon_challenger(&next, &staging).await;
            return Ok(failed(reason));
        }

        // Switch. From here the challenger answers to the instance name next to the old container.
        let alias = [instance.to_string()];
        if let Err(e) = self
            .podman
            .network_connect_aliased(&app_net, &next, &alias)
            .await
        {
            self.abandon_challenger(&next, &staging).await;
            return Ok(failed(format!("cannot join the app network: {e}")));
        }
        // Names are bookkeeping (libpod keeps the old DNS entry of a renamed container): the old one
        // makes room first, so a container called `<instance>` exists throughout.
        if let Err(e) = self.podman.container_rename(&serving, &retiring).await {
            self.back_out_switch(&app_net, &next, &staging).await;
            return Ok(failed(format!("cannot rename the old container: {e}")));
        }
        if let Err(e) = self.podman.container_rename(&next, &serving).await {
            let _ = self.podman.container_rename(&retiring, &serving).await;
            self.back_out_switch(&app_net, &next, &staging).await;
            return Ok(failed(format!("cannot rename the new container: {e}")));
        }

        // The old container keeps serving through DNS caches until it stops: wait out the resolver TTL.
        tokio::time::sleep(self.options.switch_drain).await;
        match self
            .podman
            .container_stop(&retiring, self.options.stop_timeout_secs)
            .await
        {
            Ok(()) | Err(PodmanError::NotFound(_)) => {}
            Err(e) => tracing::warn!(%instance, error = %e, "cannot stop the retired container"),
        }
        match self.podman.container_remove(&retiring, true).await {
            Ok(()) | Err(PodmanError::NotFound(_)) => {}
            Err(e) => tracing::warn!(%instance, error = %e, "cannot remove the retired container"),
        }
        let _ = self.podman.network_disconnect(&staging, &serving).await;
        let _ = self.podman.network_remove(&staging).await;

        // `health.http` goes through nginx by `Host`, so it only means something once traffic moved.
        let health = match &spec.health.http {
            Some(probe) => self.http_probe(spec, probe).await,
            None => Ok(()),
        };
        Ok(Launched {
            hash,
            range,
            health,
            old_intact: false,
        })
    }

    /// The challenger's gate. It runs on the staging network, so only a check **inside** the container
    /// can speak for it (`health.http` would reach the old container): without one the swap is refused.
    async fn challenger_gate(&self, name: &str, spec: &AppSpec) -> Result<(), String> {
        let info = self
            .podman
            .container_inspect(name)
            .await
            .map_err(|e| format!("inspect failed: {e}"))?;
        if spec.health.command.is_none() && info.health.is_none() {
            return Err("strategy \"blue_green\" needs a container healthcheck (health.command or a \
                        HEALTHCHECK in the image): health.http probes through the ingress, which still \
                        reaches the old container"
                .to_owned());
        }
        let mut inside = spec.clone();
        inside.health.http = None;
        self.health_gate(name, &inside).await
    }

    /// Removes a challenger that did not make it, with its staging network. Best effort.
    async fn abandon_challenger(&self, next: &str, staging: &str) {
        let _ = self.podman.container_stop(next, 1).await;
        let _ = self.podman.container_remove(next, true).await;
        let _ = self.podman.network_remove(staging).await;
    }

    /// Takes the challenger back out of the app network after a failed rename, then removes it.
    async fn back_out_switch(&self, app_net: &str, next: &str, staging: &str) {
        let _ = self.podman.network_disconnect(app_net, next).await;
        self.abandon_challenger(next, staging).await;
    }

    async fn remove_transient(&self, next: &str, retiring: &str) {
        for name in [next, retiring] {
            let _ = self.podman.container_stop(name, 1).await;
            let _ = self.podman.container_remove(name, true).await;
        }
    }

    /// Health gate: `attempts` tries within `window_secs`. The container must keep running throughout.
    /// Probes: the container healthcheck (the spec's `health.command` or, absent that, the image's own)
    /// and the daemon-side `health.http`. In one attempt every configured probe must pass; the first
    /// such attempt ends the gate in success and none after all attempts is a failure. With no probe
    /// at all, success = running for the whole window.
    async fn health_gate(&self, name: &str, spec: &AppSpec) -> Result<(), String> {
        let gate = &spec.health;
        let attempts = gate.attempts.max(1);
        let step = Duration::from_millis(gate.window_secs.max(1) * 1000 / u64::from(attempts));
        let mut last = String::from("no attempt made");
        for _ in 0..attempts {
            tokio::time::sleep(step).await;
            let info = self
                .podman
                .container_inspect(name)
                .await
                .map_err(|e| format!("inspect failed: {e}"))?;
            if info.state != ContainerState::Running {
                return Err(match info.exit_code {
                    Some(c) => format!("container not running ({:?}, exit code {c})", info.state),
                    None => format!("container not running ({:?})", info.state),
                });
            }
            let mut results = Vec::new();
            if gate.command.is_some() || info.health.is_some() {
                results.push(match self.podman.healthcheck_run(name).await {
                    Ok(HealthStatus::Healthy) => Ok(()),
                    Ok(s) => Err(format!("healthcheck {s:?}")),
                    Err(e) => Err(format!("healthcheck error: {e}")),
                });
            }
            if let Some(probe) = &gate.http {
                results.push(self.http_probe(spec, probe).await);
            }
            match crate::limits::attempt_verdict(results) {
                None => last = "running".into(),
                Some(Ok(())) => return Ok(()),
                Some(Err(e)) => last = e,
            }
        }
        if last == "running" {
            Ok(())
        } else {
            Err(format!(
                "health gate failed after {attempts} attempts: {last}"
            ))
        }
    }

    pub(crate) async fn http_probe(
        &self,
        spec: &AppSpec,
        probe: &crate::app::HttpProbe,
    ) -> Result<(), String> {
        let (Some(prober), Some(host)) = (&self.http_prober, spec.domains.first()) else {
            return Err("http probe needs an HTTP prober and a domain".into());
        };
        // The probe goes through nginx, which routes by `Host` and path prefix (ADR 0031): without the
        // app's prefix a shared domain would answer from another instance (or the catch-all).
        let mut probe = probe.clone();
        if let Some(prefix) = spec.paths.first().filter(|p| p.as_str() != "/") {
            probe.path = format!("{prefix}{}", probe.path);
        }
        prober
            .probe(host, &probe)
            .await
            .map_err(|e| format!("http probe: {e}"))
    }

    pub(crate) async fn deploy_locked(
        &self,
        instance: &InstanceName,
        force: bool,
    ) -> Result<DeployOutcome, EngineError> {
        self.deploy_locked_from(instance, force, DigestSource::Tag)
            .await
    }

    /// [`Self::deploy_locked`] with the digest taken from `source` instead of the tag.
    pub(crate) async fn deploy_locked_from(
        &self,
        instance: &InstanceName,
        force: bool,
        source: DigestSource<'_>,
    ) -> Result<DeployOutcome, EngineError> {
        let spec = self.load_spec(instance)?;
        // `start = false` — provision only (no container, no secrets, no health gate).
        if !spec.start {
            return self.provision_from(instance, &spec, source).await;
        }
        // A deploy starts a container: every app in `depends_on` has to be running/healthy first
        // (issue #35). Not a failure — the start is retried once the dependency is up.
        self.dependency_gate(instance, &spec).await?;
        // `state.toml` is written only after the health gate, so until then the instance is
        // "in flight": `doctor` must not read the lagging state as drift.
        let _activity = self.begin_activity(instance, ActivityKind::Deploy);
        self.assign_range(instance, &spec).await?; // before `st` is loaded: it writes state.toml
        let mut st: StateFile = state::load_state(&self.paths.state)?;
        self.secrets_gate(instance, &spec, &mut st).await?;
        let cur: AppState = st.apps.get(instance).cloned().unwrap_or_default();

        let digest = match self.digest_from(instance, &spec, source).await {
            Ok(d) => d,
            Err(e) => {
                self.events.emit(Event::DeployFailed {
                    instance: instance.clone(),
                    digest: None,
                    reason: e.to_string(),
                });
                return Err(e);
            }
        };

        if !force {
            if cur.failed.as_ref().is_some_and(|f| f.digest == digest) {
                return Ok(DeployOutcome::KnownBad { digest });
            }
            if cur.current.as_ref() == Some(&digest)
                && self.is_converged(instance, &spec, &digest).await
            {
                return Ok(DeployOutcome::Unchanged { digest });
            }
        }

        let generation = cur.generation + 1;
        let prev_image_id = self.running_image_id(instance).await;
        let launched = self
            .launch_with_strategy(instance, &spec, &digest, generation)
            .await;
        let launched = match launched {
            Ok(l) => l,
            Err(e) => {
                self.events.emit(Event::DeployFailed {
                    instance: instance.clone(),
                    digest: Some(digest),
                    reason: e.to_string(),
                });
                return Err(e);
            }
        };

        let entry = st.apps.entry(instance.clone()).or_default();
        entry.generation = generation;
        // The volumes were just prepared in this range; remember the data owner in the state even
        // if the app never gets a container or the deploy fails below (issue #75).
        entry.effective_uid_range = Some(launched.range);
        let old_intact = launched.old_intact;
        let reason = match launched.health {
            Ok(()) => {
                if cur.current.as_ref() != Some(&digest) {
                    entry.previous = cur.current.clone().or(cur.previous.clone());
                }
                entry.current = Some(digest.clone());
                entry.spec_hash = Some(launched.hash);
                entry.failed = None;
                state::save_state(&self.paths.state, &st)?;
                self.events.emit(Event::DeployOk {
                    instance: instance.clone(),
                    digest: digest.clone(),
                    generation,
                });
                // Retention of 1 (issue #40): with `current` and `previous` saved, the older images
                // of this repository are dead weight. Best effort — never fails the deploy.
                self.retain_images_locked(image_repo(&spec.image)).await;
                return Ok(DeployOutcome::Deployed { digest, generation });
            }
            Err(reason) => reason,
        };

        entry.failed = Some(FailedDeploy {
            digest: digest.clone(),
            reason: reason.clone(),
        });
        // A blue-green challenger that failed its gate: the old container never stopped serving, so
        // there is nothing to roll back (ADR 0046) — only the failure to record.
        if old_intact {
            state::save_state(&self.paths.state, &st)?;
            self.events.emit(Event::DeployFailed {
                instance: instance.clone(),
                digest: Some(digest.clone()),
                reason: reason.clone(),
            });
            return Ok(DeployOutcome::Failed { digest, reason });
        }
        let name = labels::container_name(instance);
        // Nothing to return to when nothing is pinned or it is the same digest (e.g. an env change).
        let rollback_to = cur.current.clone().filter(|c| *c != digest);
        let Some(prev) = rollback_to else {
            if cur.current.is_none() {
                let _ = self.podman.container_remove(&name, true).await;
            }
            state::save_state(&self.paths.state, &st)?;
            self.events.emit(Event::DeployFailed {
                instance: instance.clone(),
                digest: Some(digest.clone()),
                reason: reason.clone(),
            });
            return Ok(DeployOutcome::Failed { digest, reason });
        };

        let restore = self
            .launch(
                instance,
                &spec,
                &prev,
                generation + 1,
                prev_image_id.as_deref(),
            )
            .await;
        let entry = st.apps.entry(instance.clone()).or_default();
        if let Ok(l) = &restore {
            entry.effective_uid_range = Some(l.range);
        }
        match restore {
            Ok(Launched {
                hash,
                health: Ok(()),
                ..
            }) => {
                entry.generation = generation + 1;
                entry.spec_hash = Some(hash);
                state::save_state(&self.paths.state, &st)?;
                self.events.emit(Event::RolledBack {
                    instance: instance.clone(),
                    failed: digest.clone(),
                    restored: prev.clone(),
                    reason: reason.clone(),
                });
                // The failed image is neither `current` nor `previous` now; it goes away unless it
                // still holds the tag named by the spec (issue #40).
                self.retain_images_locked(image_repo(&spec.image)).await;
                Ok(DeployOutcome::RolledBack {
                    failed: digest,
                    restored: prev,
                    reason,
                })
            }
            other => {
                let why = match other {
                    Ok(Launched { health: Err(r), .. }) => r,
                    Err(e) => e.to_string(),
                    Ok(_) => unreachable!("healthy rollback handled above"),
                };
                entry.generation = generation + 1;
                state::save_state(&self.paths.state, &st)?;
                self.events.emit(Event::RollbackFailed {
                    instance: instance.clone(),
                    reason: why.clone(),
                });
                Ok(DeployOutcome::Failed {
                    digest,
                    reason: format!("{reason}; rollback failed: {why}"),
                })
            }
        }
    }

    /// `start = false`: pin the image digest, create the network, the uid range and the declared
    /// volumes, and make sure **no container** exists. No secrets are materialized and no health
    /// gate runs — nothing will run until `apps start` (or `start = true`).
    ///
    /// Idempotent: network/volume creation is idempotent and a leftover container (the flag was
    /// flipped while it ran) is stopped and removed. `start = false` means "no container".
    pub(crate) async fn provision_locked(
        &self,
        instance: &InstanceName,
        spec: &AppSpec,
    ) -> Result<DeployOutcome, EngineError> {
        self.provision_from(instance, spec, DigestSource::Tag).await
    }

    /// [`Self::provision_locked`] with the digest taken from `source` instead of the tag.
    pub(crate) async fn provision_from(
        &self,
        instance: &InstanceName,
        spec: &AppSpec,
        source: DigestSource<'_>,
    ) -> Result<DeployOutcome, EngineError> {
        // Config mounts are validated before anything is pinned or touched, exactly like a deploy.
        self.resolve_mounts(spec)?;
        let _activity = self.begin_activity(instance, ActivityKind::Provision);
        // Same order as a deploy: the uid range is allocated (and persisted) before the pull, so a
        // failed pull does not lose it and the next pass can retry with the same range.
        self.assign_range(instance, spec).await?;
        let digest = match self.digest_from(instance, spec, source).await {
            Ok(d) => d,
            Err(e) => {
                self.events.emit(Event::DeployFailed {
                    instance: instance.clone(),
                    digest: None,
                    reason: e.to_string(),
                });
                return Err(e);
            }
        };
        // Same prologue as `launch`: network, the uid-range guard, the volumes, and only then the
        // old container — provisioning must not bypass the guard either (issue #75).
        let (prepared, _configs) = self.begin_instance(instance, spec).await?;

        let mut st = state::load_state(&self.paths.state)?;
        let entry = st.apps.entry(instance.clone()).or_default();
        entry.current = Some(digest.clone());
        entry.failed = None;
        entry.effective_uid_range = Some(prepared.range);
        state::save_state(&self.paths.state, &st)?;
        self.events.emit(Event::Provisioned {
            instance: instance.clone(),
            digest: digest.clone(),
        });
        self.retain_images_locked(image_repo(&spec.image)).await;
        Ok(DeployOutcome::Provisioned { digest })
    }

    async fn is_converged(&self, instance: &InstanceName, spec: &AppSpec, digest: &Digest) -> bool {
        let Ok(hash) = self.desired_hash(instance, spec, digest).await else {
            return false;
        };
        match self
            .podman
            .container_inspect(&labels::container_name(instance))
            .await
        {
            Ok(c) => {
                c.state == ContainerState::Running
                    && c.labels.get(labels::SPEC_HASH).map(String::as_str) == Some(hash.as_str())
                    && self.uid_range_matches(instance, spec, &c.labels)
            }
            Err(_) => false,
        }
    }

    /// Recreate the container from the pinned digest (container missing / drift). No rollback:
    /// the digest is already considered good, and the old container does not exist or has a bad spec.
    pub(crate) async fn recreate_locked(
        &self,
        instance: &InstanceName,
        reason: RecreateReason,
    ) -> Result<DeployOutcome, EngineError> {
        let spec = self.load_spec(instance)?;
        // Recreating a **missing** container is a start, so the dependencies must be up first.
        // Replacing a container that is already running (`SpecDrift`) is not gated.
        if reason == RecreateReason::Missing {
            self.dependency_gate(instance, &spec).await?;
        }
        let _activity = self.begin_activity(instance, ActivityKind::Recreate);
        self.assign_range(instance, &spec).await?; // before `st` is loaded: it writes state.toml
        let mut st = state::load_state(&self.paths.state)?;
        let cur = st.apps.get(instance).cloned().unwrap_or_default();
        let digest = cur
            .current
            .clone()
            .ok_or_else(|| EngineError::UnknownInstance(instance.clone()))?;
        let generation = cur.generation + 1;
        let launched = self
            .launch_with_strategy(instance, &spec, &digest, generation)
            .await?;

        let entry = st.apps.entry(instance.clone()).or_default();
        entry.generation = generation;
        // A blue-green challenger that failed its gate left the old container serving with its old
        // hash, so the recorded hash must stay (the next pass retries the swap).
        if !launched.old_intact {
            entry.spec_hash = Some(launched.hash);
        }
        entry.effective_uid_range = Some(launched.range);
        state::save_state(&self.paths.state, &st)?;
        match launched.health {
            Ok(()) => {
                self.events.emit(Event::Recreated {
                    instance: instance.clone(),
                    reason: format!("{reason:?}"),
                });
                Ok(DeployOutcome::Deployed { digest, generation })
            }
            Err(why) => {
                self.events.emit(Event::DeployFailed {
                    instance: instance.clone(),
                    digest: Some(digest.clone()),
                    reason: why.clone(),
                });
                Ok(DeployOutcome::Failed {
                    digest,
                    reason: why,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_ref_pins_the_digest() {
        let d = Digest::new(format!("sha256:{}", "a".repeat(64))).unwrap();
        assert_eq!(pinned_ref("ghcr.io/a/b:x", &d), format!("ghcr.io/a/b@{d}"));
        assert_eq!(
            pinned_ref("localhost:5000/a/b:1", &d),
            format!("localhost:5000/a/b@{d}")
        );
    }

    #[test]
    fn normalize_defaults_to_latest_and_ignores_case_and_digest() {
        assert_eq!(
            normalize_image("GHCR.io/A/b"),
            ("ghcr.io/a/b".into(), "latest".into())
        );
        assert_eq!(
            normalize_image("ghcr.io/a/b:v1@sha256:x"),
            ("ghcr.io/a/b".into(), "v1".into())
        );
    }

    /// `start = false` apps never receive webhook-driven deploys: nothing is pulled for an app that
    /// must not run (`apps start` deploys the newest image itself).
    #[test]
    fn stopped_instances_are_not_webhook_targets() {
        let apps: AppsFile = toml::from_str(
            r#"
[apps.running]
image = "ghcr.io/x/y:latest"
[apps.stopped]
image = "ghcr.io/x/y:latest"
start = false
[apps.no-auto-update]
image = "ghcr.io/x/y:latest"
auto_update = false
"#,
        )
        .unwrap();
        assert_eq!(
            instances_tracking(&apps, "ghcr.io/x/y:latest"),
            vec![InstanceName::new("running").unwrap()]
        );
    }
}
