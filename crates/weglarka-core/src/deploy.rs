//! Deploy `recreate`: pull → stop starego → nowy kontener → bramka zdrowia → przesunięcie
//! digestów albo rollback do poprzedniego digestu (retencja 1). Do tego fan-out webhooka
//! (obraz → wszystkie instancje śledzące ten obraz/tag) z deduplikacją po `delivery_id`.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::time::Duration;

use futures_util::StreamExt;

use crate::app::{AppSpec, AppsFile, Digest, HealthGate, InstanceName};
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
    /// Nowy kontener przeszedł bramkę; digesty przesunięte.
    Deployed { digest: Digest, generation: u64 },
    /// Ten sam digest i kontener zgodny ze specyfikacją — nic do roboty.
    Unchanged { digest: Digest },
    /// Ten digest już raz nie przeszedł bramki; wymaga `force`.
    KnownBad { digest: Digest },
    /// Nowa wersja odrzucona, przywrócono poprzednią.
    RolledBack {
        failed: Digest,
        restored: Digest,
        reason: String,
    },
    /// Wdrożenie się nie udało i nie było do czego wrócić (lub rollback też zawiódł).
    Failed { digest: Digest, reason: String },
}

// ── Pomocnicze (czyste) ──────────────────────────────────────────────────────

/// Repozytorium z referencji obrazu: bez tagu i digestu (`host:5000/a/b:1@sha256:…` → `host:5000/a/b`).
pub fn image_repo(image: &str) -> &str {
    let image = image.split('@').next().unwrap_or(image);
    let name_start = image.rfind('/').map_or(0, |i| i + 1);
    match image[name_start..].rfind(':') {
        Some(i) => &image[..name_start + i],
        None => image,
    }
}

/// Referencja przypinająca digest: `repo@sha256:…`.
pub fn pinned_ref(image: &str, digest: &Digest) -> String {
    format!("{}@{digest}", image_repo(image))
}

/// `(repo, tag)` do porównywania obrazów z webhooka z `apps.toml`; brak tagu = `latest`.
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

/// Instancje z `auto_update`, które śledzą dany obraz/tag (fan-out).
pub fn instances_tracking(apps: &AppsFile, image_ref: &str) -> Vec<InstanceName> {
    let wanted = normalize_image(image_ref);
    apps.apps
        .iter()
        .filter(|(_, s)| s.auto_update && normalize_image(&s.image) == wanted)
        .map(|(n, _)| n.clone())
        .collect()
}

/// Ograniczona pamięć ostatnio widzianych `delivery_id`.
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

    /// `true`, jeśli identyfikator był już widziany; w przeciwnym razie zapamiętuje go.
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

/// Wynik startu kontenera: hash, z którym go uruchomiono, i werdykt bramki.
struct Launched {
    hash: SpecHash,
    health: Result<(), String>,
}

impl<P: PodmanClient> Reconciler<P> {
    /// Ręczny/webhookowy deploy jednej instancji. `force` pomija `Unchanged` i `KnownBad`.
    pub async fn deploy(
        &self,
        instance: &InstanceName,
        force: bool,
    ) -> Result<DeployOutcome, EngineError> {
        let _g = self.lock.lock().await;
        self.deploy_locked(instance, force).await
    }

    /// Webhook „nowy obraz”: dedup po `delivery_id`, fan-out do instancji z `auto_update`.
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

    // ── Wnętrze (wołane pod `lock`) ──────────────────────────────────────────

    fn load_spec(&self, instance: &InstanceName) -> Result<AppSpec, EngineError> {
        state::load_apps(&self.paths.apps)?
            .apps
            .remove(instance)
            .ok_or_else(|| EngineError::UnknownInstance(instance.clone()))
    }

    /// Oczekiwany `spec-hash` zgodnie z polityką zmiany sekretów.
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

    async fn ensure_image(&self, spec: &AppSpec, digest: &Digest) -> Result<(), EngineError> {
        let reference = pinned_ref(&spec.image, digest);
        match self.podman.image_inspect(&reference).await {
            Ok(_) => Ok(()),
            Err(PodmanError::NotFound(_)) => self.pull(&reference).await.map(|_| ()),
            Err(e) => Err(e.into()),
        }
    }

    /// Przygotowanie (obraz, sieć, sekrety) → usunięcie starego → create+start → bramka.
    /// `Err` oznacza porażkę *przed* ruszeniem starego kontenera; późniejsze błędy lądują
    /// w `Launched::health`.
    async fn launch(
        &self,
        instance: &InstanceName,
        spec: &AppSpec,
        digest: &Digest,
        generation: u64,
    ) -> Result<Launched, EngineError> {
        self.ensure_image(spec, digest).await?;
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

        let container = ContainerSpec {
            name: name.clone(),
            image: pinned_ref(&spec.image, digest),
            labels: labels::container_labels(instance, generation, &hash),
            env: spec.env.clone(),
            networks: vec![network],
            secrets,
            publish: vec![],
            restart: RestartPolicy::Always,
            userns_auto: true,
            mounts: vec![],
        };
        let started = async {
            self.podman.container_create(&container).await?;
            self.podman.container_start(&name).await
        }
        .await;
        let health = match started {
            Ok(()) => self.health_gate(&name, &spec.health).await,
            Err(e) => Err(format!("cannot start container: {e}")),
        };
        Ok(Launched { hash, health })
    }

    /// Bramka zdrowia: `attempts` prób w oknie `window_secs`. Kontener musi cały czas działać;
    /// jeśli obraz ma healthcheck, pierwszy `Healthy` kończy bramkę sukcesem, a brak `Healthy`
    /// po wszystkich próbach to porażka. Bez healthchecka sukces = running przez całe okno.
    async fn health_gate(&self, name: &str, gate: &HealthGate) -> Result<(), String> {
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
            if info.health.is_none() {
                last = "running".into();
                continue;
            }
            match self.podman.healthcheck_run(name).await {
                Ok(HealthStatus::Healthy) => return Ok(()),
                Ok(s) => last = format!("healthcheck {s:?}"),
                Err(e) => last = format!("healthcheck error: {e}"),
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

    pub(crate) async fn deploy_locked(
        &self,
        instance: &InstanceName,
        force: bool,
    ) -> Result<DeployOutcome, EngineError> {
        let spec = self.load_spec(instance)?;
        let mut st: StateFile = state::load_state(&self.paths.state)?;
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
        let launched = self.launch(instance, &spec, &digest, generation).await;
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
        // Nie ma do czego wrócić, gdy nic nie jest przypięte albo to ten sam digest (np. zmiana env).
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

        let restore = self.launch(instance, &spec, &prev, generation + 1).await;
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
            }
            Err(_) => false,
        }
    }

    /// Odtworzenie kontenera z przypiętego digestu (brak kontenera / drift). Bez rollbacku:
    /// digest jest już uznany za dobry, a stary kontener nie istnieje albo ma zły spec.
    pub(crate) async fn recreate_locked(
        &self,
        instance: &InstanceName,
        reason: RecreateReason,
    ) -> Result<DeployOutcome, EngineError> {
        let spec = self.load_spec(instance)?;
        let mut st = state::load_state(&self.paths.state)?;
        let cur = st.apps.get(instance).cloned().unwrap_or_default();
        let digest = cur
            .current
            .clone()
            .ok_or_else(|| EngineError::UnknownInstance(instance.clone()))?;
        let generation = cur.generation + 1;
        let launched = self.launch(instance, &spec, &digest, generation).await?;

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
        assert!(!d.check_and_insert("c")); // wypycha "a"
        assert!(!d.check_and_insert("a"));
    }
}
