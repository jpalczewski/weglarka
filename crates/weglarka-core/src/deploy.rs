//! `recreate` deploy: pull → stop old → new container → health gate → digest shift
//! or rollback to the previous digest (retention 1). Plus webhook fan-out
//! (image → all instances tracking that image/tag) with dedup by `delivery_id`.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::time::Duration;

use futures_util::StreamExt;

use crate::app::{AppSpec, AppsFile, Digest, InstanceName};
use crate::events::Event;
use crate::hash::{SpecHash, spec_hash, spec_hash_with_secrets};
use crate::labels;
use crate::podman::{
    ContainerSpec, ContainerState, HealthStatus, NetworkSpec, PodmanClient, PodmanError, PullEvent,
    RestartPolicy,
};
use crate::reconcile::{EngineError, Reconciler, RecreateReason, SecretChangePolicy};
use crate::secrets::{binding_fingerprints, materialize};
use crate::state::{self, AppState, FailedDeploy, StateFile};
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

// ── Helpers (pure) ──────────────────────────────────────────────────────

/// Repository from an image reference: without tag and digest (`host:5000/a/b:1@sha256:…` →
/// `host:5000/a/b`).
pub fn image_repo(image: &str) -> &str {
    let image = image.split('@').next().unwrap_or(image);
    let name_start = image.rfind('/').map_or(0, |i| i + 1);
    match image[name_start..].rfind(':') {
        Some(i) => &image[..name_start + i],
        None => image,
    }
}

/// Reference pinning a digest: `repo@sha256:…`.
pub fn pinned_ref(image: &str, digest: &Digest) -> String {
    format!("{}@{digest}", image_repo(image))
}

/// `(repo, tag)` for comparing webhook images with `apps.toml`; no tag = `latest`.
fn normalize_image(image: &str) -> (String, String) {
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

/// Bounded memory of recently seen `delivery_id`s.
pub struct DeliveryDedup {
    cap: usize,
    order: VecDeque<String>,
    seen: HashSet<String>,
}

impl DeliveryDedup {
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            order: VecDeque::new(),
            seen: HashSet::new(),
        }
    }

    /// `true` if the identifier was already seen; otherwise remembers it.
    pub fn check_and_insert(&mut self, id: &str) -> bool {
        if self.seen.contains(id) {
            return true;
        }
        if self.order.len() == self.cap
            && let Some(old) = self.order.pop_front()
        {
            self.seen.remove(&old);
        }
        self.order.push_back(id.to_owned());
        self.seen.insert(id.to_owned());
        false
    }
}

#[derive(Debug)]
pub struct WebhookOutcome {
    pub duplicate: bool,
    pub matched: Vec<InstanceName>,
    pub results: Vec<(InstanceName, Result<DeployOutcome, EngineError>)>,
}

/// Result of starting a container: the hash it was started with, and the gate verdict.
struct Launched {
    hash: SpecHash,
    health: Result<(), String>,
}

impl<P: PodmanClient> Reconciler<P> {
    /// Manual/webhook deploy of a single instance. `force` skips `Unchanged` and `KnownBad`.
    pub async fn deploy(
        &self,
        instance: &InstanceName,
        force: bool,
    ) -> Result<DeployOutcome, EngineError> {
        let _g = self.lock.lock().await;
        self.deploy_locked(instance, force).await
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

    fn load_spec(&self, instance: &InstanceName) -> Result<AppSpec, EngineError> {
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

    async fn pull(&self, reference: &str) -> Result<Option<Digest>, EngineError> {
        let mut stream = std::pin::pin!(self.podman.image_pull(reference));
        let mut digest = None;
        while let Some(ev) = stream.next().await {
            if let PullEvent::Complete { digest: d, .. } = ev? {
                digest = d;
            }
        }
        Ok(digest)
    }

    async fn resolve_digest(&self, reference: &str) -> Result<Digest, EngineError> {
        match self.pull(reference).await? {
            Some(d) => Ok(d),
            None => self
                .podman
                .image_inspect(reference)
                .await?
                .digest
                .ok_or_else(|| EngineError::NoDigest(reference.to_owned())),
        }
    }

    /// Returns the image reference to create the container from. Order: the pinned `repo@digest`
    /// if present locally, then `local_id` (the image of the previous container, kept locally so
    /// that a rollback does not depend on the registry), and only then a pull.
    async fn ensure_image(
        &self,
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
                self.pull(&reference).await?;
                Ok(reference)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// ID of the image the app's container currently runs (retention 1: the rollback target).
    async fn running_image_id(&self, instance: &InstanceName) -> Option<String> {
        let name = labels::container_name(instance);
        self.podman
            .container_inspect(&name)
            .await
            .ok()
            .map(|c| c.image_id)
            .filter(|id| !id.is_empty())
    }

    /// Prepare (image, network, secrets) → remove the old one → create+start → gate.
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
        let image = self.ensure_image(spec, digest, local_id).await?;
        let network = labels::network_name(instance);
        self.podman
            .network_create(&NetworkSpec {
                name: network.clone(),
                internal: false,
                labels: BTreeMap::from([(labels::INSTANCE.to_owned(), instance.to_string())]),
            })
            .await?;
        let hash = self.desired_hash(instance, spec, digest).await?;
        let secrets = materialize(&self.podman, &self.secrets, instance, spec).await?;
        let prepared = self.prepare_container(instance, spec).await?; // uid range + volumes

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

        let mut container = ContainerSpec {
            name: name.clone(),
            image,
            labels: labels::container_labels(instance, generation, &hash),
            env: spec.env.clone(),
            networks: vec![network],
            secrets,
            publish: vec![],
            restart: RestartPolicy::Always,
            userns_auto: true,
            mounts: vec![],
            volumes: vec![],
            resources: spec.resources.clone(),
            healthcheck: crate::limits::container_healthcheck(&spec.health),
            id_mapping: None,
            security: spec.security.clone(),
        };
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
        Ok(Launched { hash, health })
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

    async fn http_probe(
        &self,
        spec: &AppSpec,
        probe: &crate::app::HttpProbe,
    ) -> Result<(), String> {
        let (Some(prober), Some(host)) = (&self.http_prober, spec.domains.first()) else {
            return Err("http probe needs an HTTP prober and a domain".into());
        };
        prober
            .probe(host, probe)
            .await
            .map_err(|e| format!("http probe: {e}"))
    }

    pub(crate) async fn deploy_locked(
        &self,
        instance: &InstanceName,
        force: bool,
    ) -> Result<DeployOutcome, EngineError> {
        let spec = self.load_spec(instance)?;
        // `start = false` — provision only (no container, no secrets, no health gate).
        if !spec.start {
            return self.provision_locked(instance, &spec).await;
        }
        self.assign_uid_range(instance).await?; // before `st` is loaded: it writes state.toml
        let mut st: StateFile = state::load_state(&self.paths.state)?;
        self.secrets_gate(instance, &spec, &mut st).await?;
        let cur: AppState = st.apps.get(instance).cloned().unwrap_or_default();

        let digest = match self.resolve_digest(&spec.image).await {
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
            .launch(instance, &spec, &digest, generation, None)
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
                return Ok(DeployOutcome::Deployed { digest, generation });
            }
            Err(reason) => reason,
        };

        entry.failed = Some(FailedDeploy {
            digest: digest.clone(),
            reason: reason.clone(),
        });
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
        match restore {
            Ok(Launched {
                hash,
                health: Ok(()),
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
        // Same order as a deploy: the uid range is allocated (and persisted) before the pull, so a
        // failed pull does not lose it and the next pass can retry with the same range.
        self.assign_uid_range(instance).await?;
        let digest = match self.resolve_digest(&spec.image).await {
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
        self.podman
            .network_create(&NetworkSpec {
                name: labels::network_name(instance),
                internal: false,
                labels: BTreeMap::from([(labels::INSTANCE.to_owned(), instance.to_string())]),
            })
            .await?;
        let _prepared = self.prepare_container(instance, spec).await?; // uid range + volumes

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

        let mut st = state::load_state(&self.paths.state)?;
        let entry = st.apps.entry(instance.clone()).or_default();
        entry.current = Some(digest.clone());
        entry.failed = None;
        state::save_state(&self.paths.state, &st)?;
        self.events.emit(Event::Provisioned {
            instance: instance.clone(),
            digest: digest.clone(),
        });
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
                    && self.uid_range_matches(instance, &c.labels)
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
        self.assign_uid_range(instance).await?; // before `st` is loaded: it writes state.toml
        let mut st = state::load_state(&self.paths.state)?;
        let cur = st.apps.get(instance).cloned().unwrap_or_default();
        let digest = cur
            .current
            .clone()
            .ok_or_else(|| EngineError::UnknownInstance(instance.clone()))?;
        let generation = cur.generation + 1;
        let launched = self
            .launch(instance, &spec, &digest, generation, None)
            .await?;

        let entry = st.apps.entry(instance.clone()).or_default();
        entry.generation = generation;
        entry.spec_hash = Some(launched.hash);
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
    fn image_repo_and_pinned_ref() {
        assert_eq!(image_repo("ghcr.io/a/b:latest"), "ghcr.io/a/b");
        assert_eq!(image_repo("ghcr.io/a/b"), "ghcr.io/a/b");
        assert_eq!(image_repo("localhost:5000/a/b:1"), "localhost:5000/a/b");
        assert_eq!(image_repo("localhost:5000/a"), "localhost:5000/a");
        assert_eq!(image_repo("ghcr.io/a/b:1@sha256:abc"), "ghcr.io/a/b");
        let d = Digest::new(format!("sha256:{}", "a".repeat(64))).unwrap();
        assert_eq!(pinned_ref("ghcr.io/a/b:x", &d), format!("ghcr.io/a/b@{d}"));
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

    #[test]
    fn dedup_is_bounded() {
        let mut d = DeliveryDedup::new(2);
        assert!(!d.check_and_insert("a"));
        assert!(d.check_and_insert("a"));
        assert!(!d.check_and_insert("b"));
        assert!(!d.check_and_insert("c")); // evicts "a"
        assert!(!d.check_and_insert("a"));
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
