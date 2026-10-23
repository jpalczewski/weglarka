//! Pętla reconcile: stan pożądany (`apps.toml` + `state.toml`) vs faktyczne kontenery.
//!
//! Dwa kroki: **plan** — czysta funkcja [`plan`] (łatwo testowalna, bez I/O) — oraz **wykonawca**
//! [`Reconciler`], który zbiera obserwacje z Podmana, woła `plan` i realizuje akcje.
//! Reconcile *nie* ściąga nowych wersji: zbiega do przypiętego digestu. Nową wersję wprowadza
//! dopiero deploy (webhook / ręcznie) — patrz [`crate::deploy`]. Wyjątek: instancja bez
//! przypiętego digestu (świeża) dostaje pierwszy deploy z pullem.

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
}

/// Co robić ze zmianą wartości sekretu (decyzja: opcja konfiguracyjna demona).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecretChangePolicy {
    /// Odciski sekretów wchodzą do `spec-hash` → najbliższy reconcile odtwarza kontener.
    #[default]
    Immediate,
    /// Odciski nie wchodzą do hasha → nowy sekret zadziała przy następnym deployu/odtworzeniu.
    NextDeploy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconcilerOptions {
    pub secret_change: SecretChangePolicy,
    /// Czas na łagodne zatrzymanie starego kontenera.
    pub stop_timeout_secs: u32,
}

impl Default for ReconcilerOptions {
    fn default() -> Self {
        Self {
            secret_change: SecretChangePolicy::default(),
            stop_timeout_secs: 10,
        }
    }
}

// ── Plan (czysta funkcja) ────────────────────────────────────────────────────

/// Wejście planu dla jednej instancji z `apps.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub instance: InstanceName,
    /// Przypięty digest (`None` — instancja jeszcze nie wdrożona).
    pub pinned: Option<Digest>,
    /// Oczekiwany `spec-hash` kontenera (`Some` iff `pinned`).
    pub expected_hash: Option<SpecHash>,
    /// Nie ruszaj tej instancji w tym przebiegu (np. brak sekretu, nieudany pierwszy deploy
    /// czekający na ręczną interwencję). Jej kontenery nie są sierotami.
    pub blocked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecreateReason {
    Missing,
    SpecDrift,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Pierwszy deploy: pull → kontener → bramka zdrowia.
    Deploy { instance: InstanceName },
    /// Odtworzenie kontenera z przypiętego digestu.
    Recreate {
        instance: InstanceName,
        reason: RecreateReason,
    },
    /// Kontener istnieje, ale nie działa (np. po restarcie hosta bez linger).
    Start { instance: InstanceName },
    /// Sierota lub duplikat z etykietą `weglarka.instance`.
    Remove { container: String },
}

/// Porównuje stan pożądany z obserwowanymi kontenerami. Kolejność: najpierw sprzątanie, potem
/// instancje alfabetycznie. Nie robi I/O.
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
    let mut ordered: Vec<&Target> = targets.iter().collect();
    ordered.sort_by(|a, b| a.instance.cmp(&b.instance));
    for t in ordered {
        let own = by_instance.get(t.instance.as_str());
        let main_name = labels::container_name(&t.instance);
        let main = own.and_then(|cs| cs.iter().find(|c| c.name == main_name));
        // Duplikaty z naszą etykietą, ale inną nazwą, usuwamy niezależnie od `blocked`.
        for c in own.into_iter().flatten().filter(|c| c.name != main_name) {
            actions.push(Action::Remove {
                container: c.name.clone(),
            });
        }
        if t.blocked {
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
                    != Some(expected.as_str()) =>
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

// ── Wykonawca ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionOutcome {
    Deployed(DeployOutcome),
    Recreated(DeployOutcome),
    Started,
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
    /// Instancje pominięte w tym przebiegu wraz z powodem (np. brak sekretu).
    pub blocked: Vec<(InstanceName, String)>,
}

impl ReconcileReport {
    pub fn is_clean(&self) -> bool {
        self.blocked.is_empty() && self.actions.iter().all(|a| a.result.is_ok())
    }
}

/// Powód do przebudzenia pętli [`Reconciler::run`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// Zmienił się stan pożądany (`apps.toml`, sekret) — zrób reconcile teraz.
    Changed,
}

/// Silnik: reconcile + deploy. Jedna instancja na proces demona; wszystkie operacje mutujące
/// są serializowane przez `lock` (jedyny pisarz stanu).
pub struct Reconciler<P: PodmanClient> {
    pub(crate) podman: P,
    pub(crate) secrets: Arc<dyn SecretStore>,
    pub(crate) paths: StatePaths,
    pub(crate) options: ReconcilerOptions,
    pub(crate) events: Arc<dyn EventSink>,
    pub(crate) lock: tokio::sync::Mutex<()>,
    pub(crate) dedup: std::sync::Mutex<DeliveryDedup>,
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
            lock: tokio::sync::Mutex::new(()),
            dedup: std::sync::Mutex::new(DeliveryDedup::new(256)),
        }
    }

    pub fn with_events(mut self, events: Arc<dyn EventSink>) -> Self {
        self.events = events;
        self
    }

    pub fn paths(&self) -> &StatePaths {
        &self.paths
    }

    pub fn podman(&self) -> &P {
        &self.podman
    }

    // Zmiany stanu pożądanego (API → demon). Po nich wyślij [`Trigger::Changed`].

    pub async fn upsert_app(&self, name: InstanceName, spec: AppSpec) -> Result<(), EngineError> {
        let _g = self.lock.lock().await;
        let mut apps = state::load_apps(&self.paths.apps)?;
        apps.apps.insert(name, spec);
        Ok(state::save_apps(&self.paths.apps, &apps)?)
    }

    pub async fn remove_app(&self, name: &InstanceName) -> Result<(), EngineError> {
        let _g = self.lock.lock().await;
        let mut apps = state::load_apps(&self.paths.apps)?;
        if apps.apps.remove(name).is_none() {
            return Err(EngineError::UnknownInstance(name.clone()));
        }
        Ok(state::save_apps(&self.paths.apps, &apps)?)
    }

    /// Jeden przebieg reconcile.
    pub async fn reconcile(&self) -> Result<ReconcileReport, EngineError> {
        let _g = self.lock.lock().await;
        let apps = state::load_apps(&self.paths.apps)?;
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
        for (name, spec) in &apps.apps {
            let app_state = st.apps.get(name);
            let pinned = app_state.and_then(|s| s.current.clone());
            let mut blocked = false;
            let mut expected_hash = None;
            if let Some(d) = &pinned {
                match self.desired_hash(name, spec, d).await {
                    Ok(h) => expected_hash = Some(h),
                    Err(e) => {
                        blocked = true;
                        report.blocked.push((name.clone(), e.to_string()));
                    }
                }
            } else if app_state.is_some_and(|s| s.failed.is_some()) {
                // Pierwszy deploy się nie udał: nie ponawiamy w pętli, czeka na `deploy`.
                blocked = true;
                report.blocked.push((
                    name.clone(),
                    "first deploy failed; run deploy manually".into(),
                ));
            }
            targets.push(Target {
                instance: name.clone(),
                pinned,
                expected_hash,
                blocked,
            });
        }

        for action in plan(&targets, &observed) {
            let result = self.execute(&apps, action.clone()).await;
            if let Err(e) = &result {
                tracing::warn!(?action, error = %e, "reconcile action failed");
            }
            report.actions.push(ActionReport { action, result });
        }

        // Stan sierot sprzątamy po usunięciu ich kontenerów.
        let before = st.apps.len();
        st.apps.retain(|k, _| apps.apps.contains_key(k));
        if st.apps.len() != before {
            state::save_state(&self.paths.state, &st)?;
        }
        Ok(report)
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
                debug_assert!(apps.apps.contains_key(&instance));
                self.podman
                    .container_start(&labels::container_name(&instance))
                    .await?;
                Ok(ActionOutcome::Started)
            }
            Action::Remove { container } => {
                self.podman.container_remove(&container, true).await?;
                self.events.emit(Event::Pruned { container });
                Ok(ActionOutcome::Removed)
            }
        }
    }

    /// Pętla demona: reconcile na starcie, potem co `period` i po każdym [`Trigger`].
    /// Kończy się, gdy nadawca triggerów zostanie zamknięty.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::spec_hash;
    use std::collections::BTreeMap;

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
        // Zablokowana instancja bez kontenera: nic nie planujemy, a jej kontener nie jest sierotą.
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
}
