//! `FakePodman` — in-memory `PodmanClient`. Deterministic, no I/O or time.
//! Scripting: pull digests, pull errors, healthcheck result queue, events.

use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use bytes::Bytes;
use futures_core::Stream;
use futures_core::stream::BoxStream;
use futures_util::{StreamExt, stream};
use sha2::{Digest as _, Sha256};

use weglarka_model::app::Digest;
use weglarka_model::podman::{
    ContainerFilter, ContainerInfo, ContainerSpec, ContainerState, ContainerStats, EventFilter,
    HealthStatus, ImageInfo, LoadedImage, LogChunk, LogOptions, LogSource, LogStream, NetworkInfo,
    NetworkSpec, NetworkSummary, PodmanClient, PodmanError, PodmanEvent, PullEvent, RegistryAuth,
    Result, TarStream, VersionInfo, VolumeFilter, VolumeInfo, VolumeSpec, image_repo,
};

/// Record of a call — for asserting operation order in reconcile/deploy tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    ContainerStats,
    ContainerCreate(String),
    ContainerStart(String),
    ContainerStop(String),
    ContainerRemove(String),
    ContainerKill {
        name: String,
        signal: String,
    },
    ImagePull(String),
    /// `image_load`: the number of archive bytes the fake consumed.
    ImageLoad {
        bytes: usize,
    },
    /// `image_save`: the reference that was exported.
    ImageSave(String),
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
    NetworkConnectAliased {
        network: String,
        container: String,
        aliases: Vec<String>,
    },
    ContainerRename {
        from: String,
        to: String,
    },
    NetworkDisconnect {
        network: String,
        container: String,
    },
    NetworkRemove(String),
    ContainerExec {
        name: String,
        cmd: Vec<String>,
    },
    ContainerLogs {
        name: String,
        options: LogOptions,
    },
    ContainerWait(String),
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

/// What a one-off container prints and how it ends; scripted with
/// [`FakePodman::script_next_run`] and picked up by the next `container_start`.
#[derive(Debug, Clone, Default)]
pub struct RunScript {
    pub output: Vec<(LogSource, Vec<u8>)>,
    pub exit_code: i32,
    /// The process never exits: `container_wait` stays pending (timeouts, cancellation, limits).
    pub hang: bool,
}

/// What a running container's log holds, scripted with [`FakePodman::script_logs`]; unlike a
/// [`RunScript`] it is not consumed by `container_start`.
#[derive(Debug, Clone, Default)]
pub struct LogScript {
    pub output: Vec<(LogSource, Vec<u8>)>,
    /// A `follow` stream stays open (and silent) after the output, until the consumer drops it.
    pub hold_open: bool,
}

/// Counts a held-open log stream while it is alive.
struct OpenLogStream(Arc<AtomicUsize>);

impl OpenLogStream {
    fn new(open: Arc<AtomicUsize>) -> Self {
        open.fetch_add(1, Ordering::SeqCst);
        Self(open)
    }
}

impl Drop for OpenLogStream {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// `ContainerInfo::started_at` of every container the fake has started.
pub const FAKE_STARTED_AT: &str = "2026-01-01T00:00:00Z";

#[derive(Default)]
struct State {
    /// Scripts waiting for a container to start.
    run_queue: VecDeque<RunScript>,
    /// Script of each started container.
    run_scripts: BTreeMap<String, RunScript>,
    /// Logs scripted per container name ([`FakePodman::script_logs`]).
    log_scripts: BTreeMap<String, LogScript>,
    /// Scripted `container_stats` ([`FakePodman::script_stats`]).
    stats_script: Option<Vec<ContainerStats>>,
    stats_error: Option<String>,
    /// Held-open follow streams that have not been dropped yet.
    open_log_streams: Arc<AtomicUsize>,
    containers: BTreeMap<String, ContainerInfo>,
    /// reference → image
    images: BTreeMap<String, ImageInfo>,
    /// Names the next `image_load` gives its image (empty = an archive saved by id, no name).
    load_names: VecDeque<Vec<String>>,
    /// The next `image_load` fails with this message (a broken archive).
    load_failures: VecDeque<String>,
    /// Archive that `image_save` returns for an image, keyed by the image's digest.
    image_archives: BTreeMap<Digest, Bytes>,
    pull_digests: BTreeMap<String, Digest>,
    pull_failures: BTreeMap<String, String>,
    /// References that only pull with exactly these credentials (a private registry).
    pull_credentials: BTreeMap<String, RegistryAuth>,
    /// Credentials of every `image_pull_with` call, in order (`None` = anonymous).
    pull_auths: Vec<(String, Option<RegistryAuth>)>,
    /// OCI labels the pulled image reports (`image_inspect`); empty when not scripted.
    pull_labels: BTreeMap<String, BTreeMap<String, String>>,
    networks: BTreeMap<String, (NetworkSpec, Vec<String>)>,
    secrets: BTreeMap<String, Vec<u8>>,
    /// Volumes with the tar bytes last imported (the fake does not model file contents).
    volumes: BTreeMap<String, (VolumeInfo, Vec<u8>)>,
    /// The spec each live container was created from.
    container_specs: BTreeMap<String, ContainerSpec>,
    /// Every spec ever created, including containers removed since (tests that inspect a short-lived
    /// helper container after it was cleaned up).
    create_history: Vec<ContainerSpec>,
    /// Exit code returned by `container_exec` (default 0).
    exec_exit_codes: BTreeMap<String, i32>,
    health_scripts: BTreeMap<String, VecDeque<HealthStatus>>,
    events: Vec<PodmanEvent>,
    /// Networks whose next `network_disconnect` fails once with this error (race injection).
    disconnect_failures: BTreeMap<String, PodmanError>,
    calls: Vec<Call>,
    next_id: u64,
    /// Subuid pool reported by `subuid_pool` (`None` = [`DEFAULT_SUBUID_POOL`]).
    uid_pool: Option<u64>,
}

/// Production-sized subuid pool (production host: `1000000:2000000`).
pub const DEFAULT_SUBUID_POOL: u64 = 2_000_000;

/// Size every pulled image reports (10 MiB), so retention/`doctor` sizes are predictable in tests.
pub const DEFAULT_IMAGE_SIZE_BYTES: u64 = 10 * 1024 * 1024;

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

    /// Subuid pool reported to the allocator (default [`DEFAULT_SUBUID_POOL`]); tests shrink it to
    /// model exhaustion.
    pub fn set_subuid_pool(&self, size: u64) {
        self.lock().uid_pool = Some(size);
    }

    /// Digest returned by subsequent pulls of a reference (default: hash of the reference).
    pub fn set_pull_digest(&self, reference: &str, digest: Digest) {
        self.lock()
            .pull_digests
            .insert(reference.to_owned(), digest);
    }

    /// OCI labels the image pulled from `reference` reports through `image_inspect` (the self-update
    /// reads `io.weglarka.state-schema` there).
    pub fn set_pull_labels(&self, reference: &str, labels: &[(&str, &str)]) {
        self.lock().pull_labels.insert(
            reference.to_owned(),
            labels
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        );
    }

    /// Pulling this reference ends with an error mid-stream.
    pub fn fail_pull(&self, reference: &str, message: &str) {
        self.lock()
            .pull_failures
            .insert(reference.to_owned(), message.to_owned());
    }

    /// Makes `reference` a private image: a pull without exactly `auth` fails the way a registry
    /// answers `401` (`PodmanError::is_registry_auth_failure`).
    pub fn require_pull_auth(&self, reference: &str, auth: RegistryAuth) {
        self.lock()
            .pull_credentials
            .insert(reference.to_owned(), auth);
    }

    /// `(reference, credentials)` of every pull so far, in order.
    pub fn pull_auth_log(&self) -> Vec<(String, Option<RegistryAuth>)> {
        self.lock().pull_auths.clone()
    }

    pub fn clear_pull_failure(&self, reference: &str) {
        self.lock().pull_failures.remove(reference);
    }

    /// Replaces the labels of an existing container (a container Węglarka labelled, added by hand).
    pub fn set_container_labels(&self, name: &str, labels: BTreeMap<String, String>) {
        if let Some(c) = self.lock().containers.get_mut(name) {
            c.labels = labels;
        }
    }

    /// Inserts a running container that Węglarka did not create and therefore does not label — the
    /// daemon's own container, or anything an operator started by hand. Like Podman, the image (a
    /// reference that was pulled first) has to exist.
    pub fn add_foreign_container(&self, name: &str, reference: &str) {
        let mut s = self.lock();
        let Some(image) = s.images.get(reference).cloned() else {
            panic!("pull {reference} before adding a container that runs it");
        };
        let id = s.next_id();
        s.containers.insert(
            name.to_owned(),
            ContainerInfo {
                id,
                name: name.to_owned(),
                image: reference.to_owned(),
                image_id: image.id,
                labels: BTreeMap::new(),
                state: ContainerState::Running,
                exit_code: None,
                health: None,
                networks: Vec::new(),
                addresses: Vec::new(),
                published_ports: Vec::new(),
                restarts: 0,
                started_at: Some(FAKE_STARTED_AT.to_owned()),
                memory_limit: None,
            },
        );
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

    /// libpod's `RestartCount` seen by `container_inspect`/`container_list` (crash-loop detection).
    pub fn set_restarts(&self, name: &str, restarts: u32) {
        if let Some(c) = self.lock().containers.get_mut(name) {
            c.restarts = restarts;
        }
    }

    /// Health status seen by `container_inspect`/`container_list`; `None` = the image has no healthcheck
    /// (unlike `script_health`, which feeds the deploy health gate).
    pub fn set_health(&self, name: &str, health: Option<HealthStatus>) {
        if let Some(c) = self.lock().containers.get_mut(name) {
            c.health = health;
        }
    }

    /// The next container that starts prints `script.output` and exits with `script.exit_code`
    /// (reported by `container_wait`); without a script it exits 0 silently.
    pub fn script_next_run(&self, script: RunScript) {
        self.lock().run_queue.push_back(script);
    }

    /// What the log of the (running) container `name` holds, for `container_logs`; replaces an earlier
    /// script and is not consumed by reading.
    pub fn script_logs(&self, name: &str, script: LogScript) {
        self.lock().log_scripts.insert(name.to_owned(), script);
    }

    /// What `container_stats` reports: replaces an earlier script and is not consumed by reading. Like
    /// libpod, the call lists only running containers, so entries for containers that are not running
    /// are left out. Without a script every running container reports `0` (no data).
    pub fn script_stats(&self, stats: impl IntoIterator<Item = ContainerStats>) {
        self.lock().stats_script = Some(stats.into_iter().collect());
    }

    /// Makes `container_stats` fail (a protocol error with this text) until cleared with `None`.
    pub fn fail_stats(&self, error: Option<&str>) {
        self.lock().stats_error = error.map(str::to_owned);
    }

    /// How many held-open `follow` log streams ([`LogScript::hold_open`]) are alive: a consumer that
    /// went away must bring this back to 0.
    pub fn open_log_streams(&self) -> usize {
        self.lock().open_log_streams.load(Ordering::SeqCst)
    }

    /// The next `image_load` names its image `names` (as the archive would); without a script the
    /// loaded image has no name, like an archive saved by id.
    pub fn script_next_load(&self, names: &[&str]) {
        self.lock()
            .load_names
            .push_back(names.iter().map(|n| (*n).to_owned()).collect());
    }

    /// `image_save` of an image with `digest` returns `archive` (an `oci-archive` tar, see
    /// `crate::sites`); without a script the export fails with `NotFound`.
    pub fn script_image_archive(&self, digest: &Digest, archive: Vec<u8>) {
        self.lock()
            .image_archives
            .insert(digest.clone(), Bytes::from(archive));
    }

    /// The next `image_load` fails with `message` (a corrupt or unsupported archive).
    pub fn script_next_load_failure(&self, message: &str) {
        self.lock().load_failures.push_back(message.to_owned());
    }

    /// Exit code returned by subsequent `container_exec`s in this container.
    pub fn set_exec_exit_code(&self, container: &str, code: i32) {
        self.lock()
            .exec_exit_codes
            .insert(container.to_owned(), code);
    }

    /// Hides one *name* of an image (models an untag, or a repository that no longer resolves this
    /// reference) without removing the image: `image_remove` drops the image with all its names.
    pub fn forget_image_reference(&self, reference: &str) {
        let mut s = self.lock();
        let Some(removed) = s.images.remove(reference) else {
            return;
        };
        for alias in s.images.values_mut().filter(|i| i.id == removed.id) {
            alias.repo_tags.retain(|name| name != reference);
            alias.repo_digests.retain(|name| name != reference);
        }
    }

    /// Images currently in the fake store, one entry per image id (what `image_list` returns).
    pub fn images(&self) -> Vec<ImageInfo> {
        self.lock().unique_images()
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

    /// Every container spec ever created, in creation order (helpers included, even after cleanup).
    pub fn created_specs(&self) -> Vec<ContainerSpec> {
        self.lock().create_history.clone()
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

    /// The spec a network was created with (`None` = no such network).
    pub fn network_spec(&self, name: &str) -> Option<NetworkSpec> {
        self.lock().networks.get(name).map(|(spec, _)| spec.clone())
    }

    /// Containers attached to a network, in attach order.
    pub fn network_members(&self, name: &str) -> Vec<String> {
        self.lock()
            .networks
            .get(name)
            .map(|(_, members)| members.clone())
            .unwrap_or_default()
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

    /// Id of the image behind a reference (one of its names or the id itself).
    fn image_id(&self, reference: &str) -> Option<String> {
        self.images
            .get(reference)
            .or_else(|| self.images.values().find(|i| i.id == reference))
            .map(|i| i.id.clone())
    }

    /// One entry per image, the way `image_list` reports them.
    fn unique_images(&self) -> Vec<ImageInfo> {
        let mut by_id: BTreeMap<String, ImageInfo> = BTreeMap::new();
        for image in self.images.values() {
            by_id
                .entry(image.id.clone())
                .or_insert_with(|| image.clone());
        }
        by_id.into_values().collect()
    }

    /// Container snapshot with `networks` filled in from network membership.
    fn with_networks(&self, c: &ContainerInfo) -> ContainerInfo {
        let mut info = c.clone();
        let joined: Vec<(usize, &String, usize)> = self
            .networks
            .iter()
            .enumerate()
            .filter_map(|(index, (n, (_, members)))| {
                members
                    .iter()
                    .position(|m| *m == c.name)
                    .map(|slot| (index, n, slot))
            })
            .collect();
        info.networks = joined.iter().map(|(_, n, _)| (*n).clone()).collect();
        // Deterministic addresses in the subnet `network_inspect` reports (`10.89.N.0/24`): the gateway
        // is `.1`, members get `.2`, `.3`, … in the order they joined. A stopped container has none.
        info.addresses = if c.state == ContainerState::Running {
            joined
                .iter()
                .map(|(index, _, slot)| {
                    let octet = u8::try_from(index % 250).unwrap_or(0);
                    IpAddr::from([10, 89, octet, u8::try_from(slot + 2).unwrap_or(254)])
                })
                .collect()
        } else {
            Vec::new()
        };
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

    async fn subuid_pool(&self) -> Result<u64> {
        Ok(self.lock().uid_pool.unwrap_or(DEFAULT_SUBUID_POOL))
    }

    async fn container_create(&self, spec: &ContainerSpec) -> Result<String> {
        let mut s = self.lock();
        s.calls.push(Call::ContainerCreate(spec.name.clone()));
        s.create_history.push(spec.clone());
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
                restarts: 0,
                started_at: None,
                networks: Vec::new(),
                addresses: Vec::new(),
                published_ports: spec.publish.clone(),
                memory_limit: spec.resources.memory.map(|m| m.bytes()),
            },
        );
        Ok(id)
    }

    async fn container_start(&self, name: &str) -> Result<()> {
        let mut s = self.lock();
        s.calls.push(Call::ContainerStart(name.to_owned()));
        // Like libpod, a mapping with host port 0 gets a free port once the container starts.
        let base = 40_000 + (s.next_id as u16 % 20_000);
        let container = s.container_mut(name)?;
        container.state = ContainerState::Running;
        // The fake has no clock: a fixed instant is enough to tell "started" from "never started".
        container.started_at = Some(FAKE_STARTED_AT.to_owned());
        for (offset, p) in container.published_ports.iter_mut().enumerate() {
            if p.host_port == 0 {
                p.host_port = base + offset as u16;
            }
        }
        let script = s.run_queue.pop_front().unwrap_or_default();
        s.run_scripts.insert(name.to_owned(), script);
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

    async fn container_stats(&self) -> Result<Vec<ContainerStats>> {
        let mut s = self.lock();
        s.calls.push(Call::ContainerStats);
        if let Some(error) = s.stats_error.clone() {
            return Err(PodmanError::Protocol(error));
        }
        let running = |name: &str| {
            s.containers
                .get(name)
                .is_some_and(|c| c.state == ContainerState::Running)
        };
        Ok(match &s.stats_script {
            Some(script) => script
                .iter()
                .filter(|c| running(&c.name))
                .cloned()
                .collect(),
            None => s
                .containers
                .values()
                .filter(|c| c.state == ContainerState::Running)
                .map(|c| ContainerStats {
                    name: c.name.clone(),
                    memory_usage: 0,
                })
                .collect(),
        })
    }

    async fn container_logs(&self, name: &str, options: &LogOptions) -> Result<LogStream> {
        let mut s = self.lock();
        s.calls.push(Call::ContainerLogs {
            name: name.to_owned(),
            options: *options,
        });
        s.container_mut(name)?;
        // A log scripted for the container wins over what a one-off run printed.
        let output = match s.log_scripts.get(name) {
            Some(script) => Some(&script.output),
            None => s.run_scripts.get(name).map(|script| &script.output),
        };
        let chunks: Vec<Result<LogChunk>> = output
            .map(|output| {
                output
                    .iter()
                    .map(|(source, data)| {
                        Ok(LogChunk {
                            source: *source,
                            data: Bytes::from(data.clone()),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let hold = options.follow
            && s.log_scripts
                .get(name)
                .is_some_and(|script| script.hold_open);
        let open = Arc::clone(&s.open_log_streams);
        drop(s);
        let tail: BoxStream<'static, Result<LogChunk>> = if hold {
            // Like a follow stream of a running container: silent after the scripted output, and
            // alive until the consumer drops it.
            let guard = OpenLogStream::new(open);
            stream::pending()
                .inspect(move |_: &Result<LogChunk>| {
                    let _ = &guard;
                })
                .boxed()
        } else {
            stream::empty().boxed()
        };
        Ok(stream::iter(chunks).chain(tail).boxed())
    }

    async fn container_wait(&self, name: &str) -> Result<i32> {
        let hang = {
            let mut s = self.lock();
            s.calls.push(Call::ContainerWait(name.to_owned()));
            s.run_scripts.get(name).is_some_and(|script| script.hang)
        };
        if hang {
            return std::future::pending().await;
        }
        let mut s = self.lock();
        let code = s.run_scripts.get(name).map_or(0, |script| script.exit_code);
        let container = s.container_mut(name)?;
        container.state = ContainerState::Stopped;
        container.exit_code = Some(code);
        Ok(code)
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

    fn image_pull_with(
        &self,
        reference: &str,
        auth: Option<&RegistryAuth>,
    ) -> impl Stream<Item = Result<PullEvent>> + Send {
        let mut s = self.lock();
        s.calls.push(Call::ImagePull(reference.to_owned()));
        s.pull_auths.push((reference.to_owned(), auth.cloned()));
        let mut items = vec![Ok(PullEvent::Progress {
            message: format!("pulling {reference}"),
        })];
        if let Some(msg) = s.pull_failures.get(reference) {
            items.push(Err(PodmanError::Pull(msg.clone())));
        } else if s
            .pull_credentials
            .get(reference)
            .is_some_and(|required| auth != Some(required))
        {
            items.push(Err(PodmanError::Pull(
                "unauthorized: authentication required".into(),
            )));
        } else {
            let digest = s
                .pull_digests
                .get(reference)
                .cloned()
                .unwrap_or_else(|| Self::default_digest(reference));
            let id = digest.as_str().trim_start_matches("sha256:").to_owned();
            // A tag pull names the image `repo:tag`; a digest pull only gets `repo@digest`.
            let (repo_tags, repo_digests, aliases) = if reference.contains('@') {
                (
                    Vec::new(),
                    vec![reference.to_owned()],
                    vec![reference.to_owned()],
                )
            } else {
                let repo = image_repo(reference);
                let digest_name = format!("{repo}@{digest}");
                (
                    vec![reference.to_owned()],
                    vec![digest_name.clone()],
                    vec![reference.to_owned(), digest_name],
                )
            };
            let image = ImageInfo {
                id: id.clone(),
                digest: Some(digest.clone()),
                repo_tags,
                repo_digests,
                size_bytes: DEFAULT_IMAGE_SIZE_BYTES,
                labels: s.pull_labels.get(reference).cloned().unwrap_or_default(),
            };
            if !reference.contains('@') {
                // A tag moves to the freshly pulled build: the previous holder loses that name and
                // becomes an untagged image that only its repository digest still identifies.
                s.images.remove(reference);
                for existing in s.images.values_mut() {
                    existing.repo_tags.retain(|tag| tag != reference);
                }
            }
            for alias in aliases {
                s.images.insert(alias, image.clone());
            }
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

    async fn image_list(&self) -> Result<Vec<ImageInfo>> {
        Ok(self.lock().unique_images())
    }

    async fn image_tag(&self, id: &str, repo: &str, tag: &str) -> Result<()> {
        let mut s = self.lock();
        s.calls.push(Call::ImageTag {
            id: id.into(),
            repo: repo.into(),
            tag: tag.into(),
        });
        let mut image = s
            .images
            .values()
            .find(|i| i.id == id)
            .cloned()
            .ok_or_else(|| PodmanError::NotFound(format!("image {id}")))?;
        let name = format!("{repo}:{tag}");
        image.repo_tags.push(name.clone());
        // Like libpod, a repository the image is tagged into also resolves `repo@digest` (the pin
        // `weglarka push` relies on, docs/decisions/0042).
        let digest_name = image.digest.as_ref().map(|d| format!("{repo}@{d}"));
        if let Some(digest_name) = &digest_name
            && !image.repo_digests.contains(digest_name)
        {
            image.repo_digests.push(digest_name.clone());
        }
        // Every alias of the image reports the new tag too.
        for existing in s.images.values_mut().filter(|i| i.id == id) {
            *existing = image.clone();
        }
        s.images.insert(name, image.clone());
        if let Some(digest_name) = digest_name {
            s.images.insert(digest_name, image);
        }
        Ok(())
    }

    async fn image_load(&self, tar: TarStream) -> Result<LoadedImage> {
        let mut tar = tar;
        let mut hasher = Sha256::new();
        let mut bytes = 0usize;
        while let Some(chunk) = tar.next().await {
            let chunk = chunk?;
            bytes += chunk.len();
            hasher.update(&chunk);
        }
        let mut s = self.lock();
        s.calls.push(Call::ImageLoad { bytes });
        if let Some(message) = s.load_failures.pop_front() {
            return Err(PodmanError::Api {
                status: 500,
                message,
            });
        }
        // The same archive is the same image: the digest is the hash of the bytes.
        let digest = Digest::new(format!("sha256:{}", hex::encode(hasher.finalize())))
            .expect("sha256 hex is a valid digest");
        let id = digest.as_str().trim_start_matches("sha256:").to_owned();
        let names = s.load_names.pop_front().unwrap_or_default();
        let repo_tags: Vec<String> = names.iter().filter(|n| !n.contains('@')).cloned().collect();
        let repo_digests: Vec<String> = repo_tags
            .iter()
            .map(|n| format!("{}@{digest}", image_repo(n)))
            .collect();
        let image = ImageInfo {
            id: id.clone(),
            digest: Some(digest.clone()),
            repo_tags: repo_tags.clone(),
            repo_digests: repo_digests.clone(),
            size_bytes: DEFAULT_IMAGE_SIZE_BYTES,
            labels: BTreeMap::new(),
        };
        // A repeated load keeps the names the image already had in the store.
        for tag in &repo_tags {
            for existing in s.images.values_mut() {
                existing.repo_tags.retain(|t| t != tag);
            }
            s.images.insert(tag.clone(), image.clone());
        }
        for name in &repo_digests {
            s.images.insert(name.clone(), image.clone());
        }
        s.images.insert(id.clone(), image);
        Ok(LoadedImage {
            names: if names.is_empty() {
                vec![id.clone()]
            } else {
                names
            },
            id,
            digest: Some(digest),
        })
    }

    async fn image_remove(&self, reference: &str) -> Result<()> {
        let mut s = self.lock();
        s.calls.push(Call::ImageRemove(reference.to_owned()));
        let id = s
            .image_id(reference)
            .ok_or_else(|| PodmanError::NotFound(reference.to_owned()))?;
        // Podman refuses an image a container uses — and this client never forces (docs/decisions/0020).
        if let Some(container) = s.containers.values().find(|c| c.image_id == id) {
            return Err(PodmanError::Conflict(format!(
                "image {id} is in use by container {}",
                container.name
            )));
        }
        // Removing an image drops every one of its names, as `podman rmi <id>` does.
        s.images.retain(|_, image| image.id != id);
        Ok(())
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

    async fn network_connect_aliased(
        &self,
        network: &str,
        container: &str,
        aliases: &[String],
    ) -> Result<()> {
        let mut s = self.lock();
        s.calls.push(Call::NetworkConnectAliased {
            network: network.into(),
            container: container.into(),
            aliases: aliases.to_vec(),
        });
        if !s.containers.contains_key(container) {
            return Err(PodmanError::NotFound(container.to_owned()));
        }
        let (_, members) = s
            .networks
            .get_mut(network)
            .ok_or_else(|| PodmanError::NotFound(network.to_owned()))?;
        // Like libpod: a network the container is already on cannot be connected again.
        if members.iter().any(|m| m == container) {
            return Err(PodmanError::Conflict(format!(
                "network is already connected: {container} on {network}"
            )));
        }
        members.push(container.to_owned());
        Ok(())
    }

    async fn container_rename(&self, name: &str, new_name: &str) -> Result<()> {
        let mut s = self.lock();
        s.calls.push(Call::ContainerRename {
            from: name.to_owned(),
            to: new_name.to_owned(),
        });
        if !s.containers.contains_key(name) {
            return Err(PodmanError::NotFound(name.to_owned()));
        }
        if s.containers.contains_key(new_name) {
            return Err(PodmanError::Conflict(new_name.to_owned()));
        }
        if let Some(mut info) = s.containers.remove(name) {
            info.name = new_name.to_owned();
            s.containers.insert(new_name.to_owned(), info);
        }
        if let Some(mut spec) = s.container_specs.remove(name) {
            spec.name = new_name.to_owned();
            s.container_specs.insert(new_name.to_owned(), spec);
        }
        if let Some(script) = s.run_scripts.remove(name) {
            s.run_scripts.insert(new_name.to_owned(), script);
        }
        if let Some(script) = s.health_scripts.remove(name) {
            s.health_scripts.insert(new_name.to_owned(), script);
        }
        for (_, members) in s.networks.values_mut() {
            for m in members.iter_mut().filter(|m| *m == name) {
                *m = new_name.to_owned();
            }
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
        // Detached means detached: the network no longer counts as used by that container.
        if let Some(spec) = s.container_specs.get_mut(container) {
            spec.networks.retain(|n| n != network);
        }
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

    async fn network_list(&self) -> Result<Vec<NetworkSummary>> {
        let s = self.lock();
        Ok(s.networks
            .values()
            .map(|(spec, _)| NetworkSummary {
                name: spec.name.clone(),
                labels: spec.labels.clone(),
            })
            .collect())
    }

    async fn network_remove(&self, name: &str) -> Result<()> {
        let mut s = self.lock();
        s.calls.push(Call::NetworkRemove(name.to_owned()));
        // Like libpod without force: refuses while a container is attached (via connect or create).
        let connected = s.networks.get(name).is_some_and(|(_, m)| !m.is_empty());
        let created_on = s
            .container_specs
            .values()
            .any(|c| c.networks.iter().any(|n| n == name));
        if connected || created_on {
            return Err(PodmanError::Api {
                status: 500,
                message: format!("network {name} is being used"),
            });
        }
        s.networks.remove(name);
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

    async fn image_save(&self, reference: &str) -> Result<TarStream> {
        let mut s = self.lock();
        s.calls.push(Call::ImageSave(reference.to_owned()));
        let archive = reference
            .rsplit_once('@')
            .and_then(|(_, d)| Digest::new(d).ok())
            .and_then(|d| s.image_archives.get(&d).cloned())
            .ok_or_else(|| PodmanError::NotFound(format!("image {reference}")))?;
        // Two chunks, so consumers are exercised with a real stream.
        let (head, tail) = archive.split_at(archive.len() / 2);
        let chunks = vec![
            Ok(Bytes::copy_from_slice(head)),
            Ok(Bytes::copy_from_slice(tail)),
        ];
        Ok(stream::iter(chunks).boxed())
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
