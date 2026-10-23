//! `FakePodman` — in-memory `PodmanClient`. Deterministic, no I/O or time.
//! Scripting: pull digests, pull errors, healthcheck result queue, events.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

use bytes::Bytes;
use futures_core::Stream;
use futures_util::{StreamExt, stream};
use sha2::{Digest as _, Sha256};

use crate::app::Digest;
use crate::podman::{
    ContainerFilter, ContainerInfo, ContainerSpec, ContainerState, EventFilter, HealthStatus,
    ImageInfo, NetworkInfo, NetworkSpec, PodmanClient, PodmanError, PodmanEvent, PullEvent, Result,
    TarStream, VersionInfo, VolumeFilter, VolumeInfo, VolumeSpec,
};

/// Record of a call — for asserting operation order in reconcile/deploy tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    ContainerCreate(String),
    ContainerStart(String),
    ContainerStop(String),
    ContainerRemove(String),
    ContainerKill {
        name: String,
        signal: String,
    },
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
    NetworkDisconnect {
        network: String,
        container: String,
    },
    ContainerExec {
        name: String,
        cmd: Vec<String>,
    },
    SecretCreate(String),
    SecretRemove(String),
    HealthcheckRun(String),
    VolumeCreate(String),
    VolumeImport(String),
    VolumeExport(String),
    VolumeRemove(String),
    ContainerArchivePut {
        name: String,
        path: String,
    },
}

#[derive(Default)]
struct State {
    containers: BTreeMap<String, ContainerInfo>,
    /// reference → image
    images: BTreeMap<String, ImageInfo>,
    pull_digests: BTreeMap<String, Digest>,
    pull_failures: BTreeMap<String, String>,
    networks: BTreeMap<String, (NetworkSpec, Vec<String>)>,
    secrets: BTreeMap<String, Vec<u8>>,
    /// Volumes with the tar bytes last imported (the fake does not model file contents).
    volumes: BTreeMap<String, (VolumeInfo, Vec<u8>)>,
    /// The spec each live container was created from.
    container_specs: BTreeMap<String, ContainerSpec>,
    /// Exit code returned by `container_exec` (default 0).
    exec_exit_codes: BTreeMap<String, i32>,
    health_scripts: BTreeMap<String, VecDeque<HealthStatus>>,
    events: Vec<PodmanEvent>,
    /// Networks whose next `network_disconnect` fails once with this error (race injection).
    disconnect_failures: BTreeMap<String, PodmanError>,
    calls: Vec<Call>,
    next_id: u64,
}

/// Cloning yields a handle to the same state (`Arc`).
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

    /// Digest returned by subsequent pulls of a reference (default: hash of the reference).
    pub fn set_pull_digest(&self, reference: &str, digest: Digest) {
        self.lock()
            .pull_digests
            .insert(reference.to_owned(), digest);
    }

    /// Pulling this reference ends with an error mid-stream.
    pub fn fail_pull(&self, reference: &str, message: &str) {
        self.lock()
            .pull_failures
            .insert(reference.to_owned(), message.to_owned());
    }

    pub fn clear_pull_failure(&self, reference: &str) {
        self.lock().pull_failures.remove(reference);
    }

    /// Successive `healthcheck_run`s / container health reads; the last element repeats forever.
    pub fn script_health(&self, container: &str, results: impl IntoIterator<Item = HealthStatus>) {
        self.lock()
            .health_scripts
            .insert(container.to_owned(), results.into_iter().collect());
    }

    /// The next `network_disconnect` from this network fails once with `error`
    /// (e.g. libpod's "no container with ID …" while another container is being removed).
    pub fn fail_next_disconnect(&self, network: &str, error: PodmanError) {
        self.lock()
            .disconnect_failures
            .insert(network.to_owned(), error);
    }

    /// Adds an event to be replayed by `events()`.
    pub fn push_event(&self, event: PodmanEvent) {
        self.lock().events.push(event);
    }

    /// Simulates the container exiting (crash).
    pub fn crash_container(&self, name: &str, exit_code: i32) {
        if let Some(c) = self.lock().containers.get_mut(name) {
            c.state = ContainerState::Exited;
            c.exit_code = Some(exit_code);
        }
    }

    /// Exit code returned by subsequent `container_exec`s in this container.
    pub fn set_exec_exit_code(&self, container: &str, code: i32) {
        self.lock()
            .exec_exit_codes
            .insert(container.to_owned(), code);
    }

    pub fn calls(&self) -> Vec<Call> {
        self.lock().calls.clone()
    }

    pub fn containers(&self) -> Vec<ContainerInfo> {
        let s = self.lock();
        s.containers.values().map(|c| s.with_networks(c)).collect()
    }

    /// The spec the container was created from (iteration 2: mounts, limits, healthcheck, id map).
    pub fn container_spec(&self, name: &str) -> Option<ContainerSpec> {
        self.lock().container_specs.get(name).cloned()
    }

    pub fn volumes(&self) -> Vec<VolumeInfo> {
        self.lock()
            .volumes
            .values()
            .map(|(v, _)| v.clone())
            .collect()
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

    /// Container snapshot with `networks` filled in from network membership.
    fn with_networks(&self, c: &ContainerInfo) -> ContainerInfo {
        let mut info = c.clone();
        info.networks = self
            .networks
            .iter()
            .filter(|(_, (_, members))| members.contains(&c.name))
            .map(|(n, _)| n.clone())
            .collect();
        info
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
        // Real Podman does not create a container from an unknown image.
        let image = s
            .images
            .iter()
            .find(|(reference, img)| {
                **reference == spec.image
                    || img.id == spec.image
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
        // Like Podman, a named volume that does not exist yet is created implicitly (no labels).
        for att in &spec.volumes {
            s.volumes.entry(att.volume.clone()).or_insert_with(|| {
                (
                    VolumeInfo {
                        name: att.volume.clone(),
                        labels: BTreeMap::new(),
                        mountpoint: Some(format!("/fake/volumes/{}/_data", att.volume)),
                    },
                    Vec::new(),
                )
            });
        }
        s.container_specs.insert(spec.name.clone(), spec.clone());
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
                networks: Vec::new(),
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
        s.container_specs.remove(name);
        for (_, members) in s.networks.values_mut() {
            members.retain(|m| m != name);
        }
        Ok(())
    }

    async fn container_kill(&self, name: &str, signal: &str) -> Result<()> {
        let mut s = self.lock();
        s.calls.push(Call::ContainerKill {
            name: name.to_owned(),
            signal: signal.to_owned(),
        });
        if s.container_mut(name)?.state != ContainerState::Running {
            return Err(PodmanError::Conflict(format!(
                "container {name} is not running"
            )));
        }
        Ok(())
    }

    async fn container_inspect(&self, name: &str) -> Result<ContainerInfo> {
        let s = self.lock();
        s.containers
            .get(name)
            .map(|c| s.with_networks(c))
            .ok_or_else(|| PodmanError::NotFound(name.to_owned()))
    }

    async fn container_exec(&self, name: &str, cmd: &[String]) -> Result<i32> {
        let mut s = self.lock();
        s.calls.push(Call::ContainerExec {
            name: name.to_owned(),
            cmd: cmd.to_vec(),
        });
        if s.container_mut(name)?.state != ContainerState::Running {
            return Err(PodmanError::Conflict(format!(
                "container {name} is not running"
            )));
        }
        Ok(s.exec_exit_codes.get(name).copied().unwrap_or(0))
    }

    async fn container_archive_put(
        &self,
        name: &str,
        path: &str,
        mut tar: TarStream,
    ) -> Result<()> {
        while let Some(chunk) = tar.next().await {
            chunk?;
        }
        let mut s = self.lock();
        s.calls.push(Call::ContainerArchivePut {
            name: name.to_owned(),
            path: path.to_owned(),
        });
        s.container_mut(name)?;
        Ok(())
    }

    async fn container_list(&self, filter: &ContainerFilter) -> Result<Vec<ContainerInfo>> {
        let s = self.lock();
        Ok(s.containers
            .values()
            .filter(|c| {
                filter
                    .labels
                    .iter()
                    .all(|(k, v)| c.labels.get(k) == Some(v))
            })
            .map(|c| s.with_networks(c))
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
            // The same image is available under the reference and under `repo@digest`.
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
            s.images.insert(format!("{repo}@{digest}"), image.clone());
            // Image stays addressable by ID even after its names are gone (as in Podman).
            s.images.insert(id.clone(), image);
            items.push(Ok(PullEvent::Complete {
                image_id: id,
                digest: Some(digest),
            }));
        }
        stream::iter(items)
    }

    async fn image_inspect(&self, reference: &str) -> Result<ImageInfo> {
        let s = self.lock();
        // Like Podman, an image is also addressable by its ID.
        s.images
            .get(reference)
            .or_else(|| s.images.values().find(|i| i.id == reference))
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

    async fn network_disconnect(&self, network: &str, container: &str) -> Result<()> {
        let mut s = self.lock();
        s.calls.push(Call::NetworkDisconnect {
            network: network.into(),
            container: container.into(),
        });
        if let Some(e) = s.disconnect_failures.remove(network) {
            return Err(e);
        }
        if !s.containers.contains_key(container) {
            return Err(PodmanError::NotFound(container.to_owned()));
        }
        let (_, members) = s
            .networks
            .get_mut(network)
            .ok_or_else(|| PodmanError::NotFound(network.to_owned()))?;
        members.retain(|m| m != container);
        Ok(())
    }

    async fn network_inspect(&self, name: &str) -> Result<NetworkInfo> {
        let s = self.lock();
        let index = s
            .networks
            .keys()
            .position(|n| n == name)
            .ok_or_else(|| PodmanError::NotFound(name.to_owned()))?;
        // Deterministic "gateway" derived from the network number (like 10.89.N.1 in netavark).
        let octet = u8::try_from(index % 250).unwrap_or(0);
        Ok(NetworkInfo {
            name: name.to_owned(),
            gateways: vec![std::net::IpAddr::from([10, 89, octet, 1])],
            subnets: vec![format!("10.89.{octet}.0/24")],
        })
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

    async fn volume_create(&self, spec: &VolumeSpec) -> Result<()> {
        let mut s = self.lock();
        s.calls.push(Call::VolumeCreate(spec.name.clone()));
        s.volumes.entry(spec.name.clone()).or_insert_with(|| {
            (
                VolumeInfo {
                    name: spec.name.clone(),
                    labels: spec.labels.clone(),
                    mountpoint: Some(format!("/fake/volumes/{}/_data", spec.name)),
                },
                Vec::new(),
            )
        });
        Ok(())
    }

    async fn volume_inspect(&self, name: &str) -> Result<VolumeInfo> {
        self.lock()
            .volumes
            .get(name)
            .map(|(v, _)| v.clone())
            .ok_or_else(|| PodmanError::NotFound(format!("volume {name}")))
    }

    async fn volume_list(&self, filter: &VolumeFilter) -> Result<Vec<VolumeInfo>> {
        Ok(self
            .lock()
            .volumes
            .values()
            .map(|(v, _)| v)
            .filter(|v| {
                filter
                    .labels
                    .iter()
                    .all(|(k, val)| v.labels.get(k) == Some(val))
            })
            .cloned()
            .collect())
    }

    async fn volume_import(&self, name: &str, mut tar: TarStream) -> Result<()> {
        // The stream is drained outside the lock: a producer may be slow.
        let mut data = Vec::new();
        while let Some(chunk) = tar.next().await {
            data.extend_from_slice(&chunk?);
        }
        let mut s = self.lock();
        s.calls.push(Call::VolumeImport(name.to_owned()));
        let (_, stored) = s
            .volumes
            .get_mut(name)
            .ok_or_else(|| PodmanError::NotFound(format!("volume {name}")))?;
        *stored = data;
        Ok(())
    }

    async fn volume_export(&self, name: &str) -> Result<TarStream> {
        let mut s = self.lock();
        s.calls.push(Call::VolumeExport(name.to_owned()));
        let (_, data) = s
            .volumes
            .get(name)
            .ok_or_else(|| PodmanError::NotFound(format!("volume {name}")))?;
        // Two chunks, so consumers are exercised with a real stream.
        let (head, tail) = data.split_at(data.len() / 2);
        let chunks = vec![
            Ok(Bytes::copy_from_slice(head)),
            Ok(Bytes::copy_from_slice(tail)),
        ];
        Ok(stream::iter(chunks).boxed())
    }

    async fn volume_remove(&self, name: &str, force: bool) -> Result<()> {
        let mut s = self.lock();
        s.calls.push(Call::VolumeRemove(name.to_owned()));
        if !s.volumes.contains_key(name) {
            return Err(PodmanError::NotFound(format!("volume {name}")));
        }
        let in_use = s
            .container_specs
            .values()
            .any(|c| c.volumes.iter().any(|v| v.volume == name));
        if in_use && !force {
            return Err(PodmanError::Conflict(format!("volume {name} is in use")));
        }
        s.volumes.remove(name);
        Ok(())
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
        // The label filter matches the event's attributes (like `attributes` in the real API).
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
