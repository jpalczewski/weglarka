//! `FakePodman` — `PodmanClient` w pamięci. Deterministyczny, bez I/O i czasu.
//! Skryptowanie: digesty pulla, błędy pulla, kolejka wyników healthchecka, zdarzenia.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

use futures_core::Stream;
use futures_util::stream;
use sha2::{Digest as _, Sha256};

use crate::app::Digest;
use crate::podman::{
    ContainerFilter, ContainerInfo, ContainerSpec, ContainerState, EventFilter, HealthStatus,
    ImageInfo, NetworkSpec, PodmanClient, PodmanError, PodmanEvent, PullEvent, Result, VersionInfo,
};

/// Zapis wywołania — do asercji kolejności operacji w testach reconcile/deploy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    ContainerCreate(String),
    ContainerStart(String),
    ContainerStop(String),
    ContainerRemove(String),
    ImagePull(String),
    ImageTag {
        id: String,
        repo: String,
        tag: String,
    },
    ImageRemove(String),
    NetworkCreate(String),
    NetworkConnect {
        network: String,
        container: String,
    },
    SecretCreate(String),
    SecretRemove(String),
    HealthcheckRun(String),
}

#[derive(Default)]
struct State {
    containers: BTreeMap<String, ContainerInfo>,
    /// referencja → obraz
    images: BTreeMap<String, ImageInfo>,
    pull_digests: BTreeMap<String, Digest>,
    pull_failures: BTreeMap<String, String>,
    networks: BTreeMap<String, (NetworkSpec, Vec<String>)>,
    secrets: BTreeMap<String, Vec<u8>>,
    health_scripts: BTreeMap<String, VecDeque<HealthStatus>>,
    events: Vec<PodmanEvent>,
    calls: Vec<Call>,
    next_id: u64,
}

/// Klonowanie daje uchwyt na ten sam stan (`Arc`).
#[derive(Clone, Default)]
pub struct FakePodman {
    state: Arc<Mutex<State>>,
}

impl FakePodman {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("fake podman mutex poisoned")
    }

    /// Digest zwracany przez kolejne pulle danej referencji (domyślnie: hash referencji).
    pub fn set_pull_digest(&self, reference: &str, digest: Digest) {
        self.lock()
            .pull_digests
            .insert(reference.to_owned(), digest);
    }

    /// Pull tej referencji zakończy się błędem w środku strumienia.
    pub fn fail_pull(&self, reference: &str, message: &str) {
        self.lock()
            .pull_failures
            .insert(reference.to_owned(), message.to_owned());
    }

    pub fn clear_pull_failure(&self, reference: &str) {
        self.lock().pull_failures.remove(reference);
    }

    /// Kolejne `healthcheck_run`/odczyty zdrowia kontenera; ostatni element powtarza się w nieskończoność.
    pub fn script_health(&self, container: &str, results: impl IntoIterator<Item = HealthStatus>) {
        self.lock()
            .health_scripts
            .insert(container.to_owned(), results.into_iter().collect());
    }

    /// Dodaje zdarzenie do odtworzenia przez `events()`.
    pub fn push_event(&self, event: PodmanEvent) {
        self.lock().events.push(event);
    }

    /// Symuluje zakończenie kontenera (crash).
    pub fn crash_container(&self, name: &str, exit_code: i32) {
        if let Some(c) = self.lock().containers.get_mut(name) {
            c.state = ContainerState::Exited;
            c.exit_code = Some(exit_code);
        }
    }

    pub fn calls(&self) -> Vec<Call> {
        self.lock().calls.clone()
    }

    pub fn containers(&self) -> Vec<ContainerInfo> {
        self.lock().containers.values().cloned().collect()
    }

    pub fn has_secret(&self, name: &str) -> bool {
        self.lock().secrets.contains_key(name)
    }

    pub fn networks(&self) -> Vec<String> {
        self.lock().networks.keys().cloned().collect()
    }

    fn default_digest(reference: &str) -> Digest {
        Digest::new(format!(
            "sha256:{}",
            hex::encode(Sha256::digest(reference.as_bytes()))
        ))
        .expect("sha256 hex is a valid digest")
    }
}

impl State {
    fn next_id(&mut self) -> String {
        self.next_id += 1;
        format!("{:064x}", self.next_id)
    }

    fn container_mut(&mut self, name: &str) -> Result<&mut ContainerInfo> {
        self.containers
            .get_mut(name)
            .ok_or_else(|| PodmanError::NotFound(name.to_owned()))
    }

    fn next_health(&mut self, name: &str) -> Option<HealthStatus> {
        let queue = self.health_scripts.get_mut(name)?;
        if queue.len() > 1 {
            queue.pop_front()
        } else {
            queue.front().copied()
        }
    }
}

impl PodmanClient for FakePodman {
    async fn version(&self) -> Result<VersionInfo> {
        Ok(VersionInfo {
            version: "6.1.0-fake".into(),
            api_version: "6.0.0".into(),
        })
    }

    async fn container_create(&self, spec: &ContainerSpec) -> Result<String> {
        let mut s = self.lock();
        s.calls.push(Call::ContainerCreate(spec.name.clone()));
        if s.containers.contains_key(&spec.name) {
            return Err(PodmanError::Conflict(spec.name.clone()));
        }
        // Prawdziwy Podman nie tworzy kontenera z nieznanego obrazu.
        let image = s
            .images
            .iter()
            .find(|(reference, img)| {
                **reference == spec.image
                    || img
                        .digest
                        .as_ref()
                        .is_some_and(|d| spec.image.ends_with(d.as_str()))
            })
            .map(|(_, img)| img.clone())
            .ok_or_else(|| PodmanError::NotFound(format!("image {}", spec.image)))?;
        for net in &spec.networks {
            if !s.networks.contains_key(net) {
                return Err(PodmanError::NotFound(format!("network {net}")));
            }
        }
        for att in &spec.secrets {
            if !s.secrets.contains_key(&att.secret) {
                return Err(PodmanError::NotFound(format!("secret {}", att.secret)));
            }
        }
        let id = s.next_id();
        for net in &spec.networks {
            if let Some((_, members)) = s.networks.get_mut(net) {
                members.push(spec.name.clone());
            }
        }
        let health = s
            .health_scripts
            .contains_key(&spec.name)
            .then_some(HealthStatus::Starting);
        s.containers.insert(
            spec.name.clone(),
            ContainerInfo {
                id: id.clone(),
                name: spec.name.clone(),
                image: spec.image.clone(),
                image_id: image.id,
                labels: spec.labels.clone(),
                state: ContainerState::Created,
                exit_code: None,
                health,
            },
        );
        Ok(id)
    }

    async fn container_start(&self, name: &str) -> Result<()> {
        let mut s = self.lock();
        s.calls.push(Call::ContainerStart(name.to_owned()));
        s.container_mut(name)?.state = ContainerState::Running;
        Ok(())
    }

    async fn container_stop(&self, name: &str, _timeout_secs: u32) -> Result<()> {
        let mut s = self.lock();
        s.calls.push(Call::ContainerStop(name.to_owned()));
        s.container_mut(name)?.state = ContainerState::Stopped;
        Ok(())
    }

    async fn container_remove(&self, name: &str, force: bool) -> Result<()> {
        let mut s = self.lock();
        s.calls.push(Call::ContainerRemove(name.to_owned()));
        let running = s.container_mut(name)?.state == ContainerState::Running;
        if running && !force {
            return Err(PodmanError::Conflict(format!(
                "container {name} is running"
            )));
        }
        s.containers.remove(name);
        for (_, members) in s.networks.values_mut() {
            members.retain(|m| m != name);
        }
        Ok(())
    }

    async fn container_inspect(&self, name: &str) -> Result<ContainerInfo> {
        self.lock()
            .containers
            .get(name)
            .cloned()
            .ok_or_else(|| PodmanError::NotFound(name.to_owned()))
    }

    async fn container_list(&self, filter: &ContainerFilter) -> Result<Vec<ContainerInfo>> {
        Ok(self
            .lock()
            .containers
            .values()
            .filter(|c| {
                filter
                    .labels
                    .iter()
                    .all(|(k, v)| c.labels.get(k) == Some(v))
            })
            .cloned()
            .collect())
    }

    fn image_pull(&self, reference: &str) -> impl Stream<Item = Result<PullEvent>> + Send {
        let mut s = self.lock();
        s.calls.push(Call::ImagePull(reference.to_owned()));
        let mut items = vec![Ok(PullEvent::Progress {
            message: format!("pulling {reference}"),
        })];
        if let Some(msg) = s.pull_failures.get(reference) {
            items.push(Err(PodmanError::Pull(msg.clone())));
        } else {
            let digest = s
                .pull_digests
                .get(reference)
                .cloned()
                .unwrap_or_else(|| Self::default_digest(reference));
            let id = digest.as_str().trim_start_matches("sha256:").to_owned();
            // Ten sam obraz dostępny pod referencją i pod `repo@digest`.
            let repo = reference
                .rsplit_once(':')
                .map_or(reference, |(r, _)| r)
                .to_owned();
            let image = ImageInfo {
                id: id.clone(),
                digest: Some(digest.clone()),
                repo_tags: vec![reference.to_owned()],
            };
            s.images.insert(reference.to_owned(), image.clone());
            s.images.insert(format!("{repo}@{digest}"), image);
            items.push(Ok(PullEvent::Complete {
                image_id: id,
                digest: Some(digest),
            }));
        }
        stream::iter(items)
    }

    async fn image_inspect(&self, reference: &str) -> Result<ImageInfo> {
        self.lock()
            .images
            .get(reference)
            .cloned()
            .ok_or_else(|| PodmanError::NotFound(reference.to_owned()))
    }

    async fn image_tag(&self, id: &str, repo: &str, tag: &str) -> Result<()> {
        let mut s = self.lock();
        s.calls.push(Call::ImageTag {
            id: id.into(),
            repo: repo.into(),
            tag: tag.into(),
        });
        let image = s
            .images
            .values()
            .find(|i| i.id == id)
            .cloned()
            .ok_or_else(|| PodmanError::NotFound(format!("image {id}")))?;
        s.images.insert(format!("{repo}:{tag}"), image);
        Ok(())
    }

    async fn image_remove(&self, reference: &str) -> Result<()> {
        let mut s = self.lock();
        s.calls.push(Call::ImageRemove(reference.to_owned()));
        s.images
            .remove(reference)
            .map(|_| ())
            .ok_or_else(|| PodmanError::NotFound(reference.to_owned()))
    }

    async fn network_create(&self, spec: &NetworkSpec) -> Result<()> {
        let mut s = self.lock();
        s.calls.push(Call::NetworkCreate(spec.name.clone()));
        s.networks
            .entry(spec.name.clone())
            .or_insert_with(|| (spec.clone(), Vec::new()));
        Ok(())
    }

    async fn network_connect(&self, network: &str, container: &str) -> Result<()> {
        let mut s = self.lock();
        s.calls.push(Call::NetworkConnect {
            network: network.into(),
            container: container.into(),
        });
        if !s.containers.contains_key(container) {
            return Err(PodmanError::NotFound(container.to_owned()));
        }
        let (_, members) = s
            .networks
            .get_mut(network)
            .ok_or_else(|| PodmanError::NotFound(network.to_owned()))?;
        if !members.iter().any(|m| m == container) {
            members.push(container.to_owned());
        }
        Ok(())
    }

    async fn secret_create(&self, name: &str, data: &[u8]) -> Result<()> {
        let mut s = self.lock();
        s.calls.push(Call::SecretCreate(name.to_owned()));
        s.secrets.insert(name.to_owned(), data.to_vec());
        Ok(())
    }

    async fn secret_remove(&self, name: &str) -> Result<()> {
        let mut s = self.lock();
        s.calls.push(Call::SecretRemove(name.to_owned()));
        s.secrets
            .remove(name)
            .map(|_| ())
            .ok_or_else(|| PodmanError::NotFound(name.to_owned()))
    }

    async fn healthcheck_run(&self, container: &str) -> Result<HealthStatus> {
        let mut s = self.lock();
        s.calls.push(Call::HealthcheckRun(container.to_owned()));
        let info = s.container_mut(container)?;
        if info.state != ContainerState::Running {
            return Err(PodmanError::Conflict(format!(
                "container {container} is not running"
            )));
        }
        let status = s
            .next_health(container)
            .ok_or_else(|| PodmanError::Conflict(format!("{container} has no healthcheck")))?;
        s.container_mut(container)?.health = Some(status);
        Ok(status)
    }

    fn events(&self, filter: &EventFilter) -> impl Stream<Item = Result<PodmanEvent>> + Send {
        let s = self.lock();
        // Filtr etykiet dopasowuje atrybuty zdarzenia (jak `attributes` w prawdziwym API).
        let items: Vec<_> = s
            .events
            .iter()
            .filter(|e| {
                filter
                    .labels
                    .iter()
                    .all(|(k, v)| e.attributes.get(k) == Some(v))
            })
            .cloned()
            .map(Ok)
            .collect();
        stream::iter(items)
    }
}
