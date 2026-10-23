//! Podman client contract (libpod v6). Implemented by `weglarka-podman` (session a) and by the
//! in-memory `testing::FakePodman` (session b, daemon). The models are *our* domain types —
//! wire models (serde with `#[serde(default)]`, only used fields) live in `weglarka-podman`.
//!
//! Async: native `async fn` in traits + generics (see `docs/decisions/0001-async-traits.md`).
//! Methods are written as `-> impl Future + Send` so implementations can use `async fn`
//! and callers can `tokio::spawn`.

use std::collections::BTreeMap;
use std::future::Future;

use bytes::Bytes;
use futures_core::Stream;
use futures_util::stream::BoxStream;

use crate::app::{Digest, Resources, SecretTarget};

#[derive(Debug, thiserror::Error)]
pub enum PodmanError {
    #[error("podman socket unreachable: {0}")]
    Unreachable(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("already exists: {0}")]
    Conflict(String),
    #[error("podman API error {status}: {message}")]
    Api { status: u16, message: String },
    /// Error reported mid-way through the pull stream (HTTP 200, error in the body).
    #[error("image pull failed: {0}")]
    Pull(String),
    #[error("unexpected podman response: {0}")]
    Protocol(String),
}

pub type Result<T, E = PodmanError> = std::result::Result<T, E>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionInfo {
    pub version: String,
    pub api_version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartPolicy {
    No,
    /// `--restart=always` — conmon does the restart, even when Węglarka is down.
    Always,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortMapping {
    pub host_ip: Option<String>,
    pub host_port: u16,
    pub container_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretAttachment {
    /// Secret name in Podman.
    pub secret: String,
    pub target: SecretTarget,
}

/// Bind mount of a host directory/file (e.g. the ingress `nginx.conf`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindMount {
    pub source: String,
    pub target: String,
    pub read_only: bool,
}

/// Named volume mounted into a container (iteration 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeAttachment {
    /// Podman volume name (`labels::volume_name`).
    pub volume: String,
    pub target: String,
    pub read_only: bool,
    /// Mount option `idmap` (ID-mapped mount; path (b) of docs/decisions/0009).
    pub idmap: bool,
    /// Mount option `U`: chown the volume to the container user on start (docs/decisions/0009).
    pub chown: bool,
}

/// One line of a uid/gid map: container ids `container_id..+size` ↔ ids `host_id..+size` of the
/// namespace the Podman user runs in (rootless: 0 = the user itself, `1..` = its subuids in order).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdRange {
    pub container_id: u32,
    pub host_id: u32,
    pub size: u32,
}

/// Explicit user-namespace mapping; when set it replaces `userns_auto` (path (a) of
/// docs/decisions/0009).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdMapping {
    pub uid_map: Vec<IdRange>,
    pub gid_map: Vec<IdRange>,
}

/// Healthcheck defined by the spec (`health.command`), overriding the image's `HEALTHCHECK`.
/// The deploy gate runs it with `healthcheck_run`; `interval_secs` only matters for the container's
/// own periodic runs. Mapping to libpod: session 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerHealthcheck {
    /// Exec form, no shell.
    pub command: Vec<String>,
    pub interval_secs: u32,
    pub timeout_secs: u32,
    pub retries: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerSpec {
    pub name: String,
    /// Image reference or digest (`repo@sha256:…`) — reconcile pins the digest.
    pub image: String,
    pub labels: BTreeMap<String, String>,
    pub env: BTreeMap<String, String>,
    /// Networks the container joins on creation (first = primary).
    pub networks: Vec<String>,
    pub secrets: Vec<SecretAttachment>,
    pub publish: Vec<PortMapping>,
    pub restart: RestartPolicy,
    /// `--userns=auto` (decision: from the start).
    pub userns_auto: bool,
    /// Host bind mounts (empty list for ordinary apps).
    pub mounts: Vec<BindMount>,
    /// Named volumes (iteration 2).
    pub volumes: Vec<VolumeAttachment>,
    /// Resource limits; unlimited unless set (iteration 2).
    pub resources: Resources,
    /// Healthcheck from the spec; `None` keeps the image's own (iteration 2).
    pub healthcheck: Option<ContainerHealthcheck>,
    /// Explicit uid/gid maps; replaces `userns_auto` when set (iteration 2).
    pub id_mapping: Option<IdMapping>,
}

/// Named volume to create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeSpec {
    pub name: String,
    /// Includes `weglarka.instance` (labels::INSTANCE).
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeInfo {
    pub name: String,
    pub labels: BTreeMap<String, String>,
    /// Host path of the volume data, if reported.
    pub mountpoint: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VolumeFilter {
    pub labels: BTreeMap<String, String>,
}

/// Tar bytes in transit (volume import/export): streamed so a large volume never sits in RAM.
pub type TarStream = BoxStream<'static, Result<Bytes>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerState {
    Created,
    Running,
    Paused,
    Stopped,
    Exited,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    Starting,
    Healthy,
    Unhealthy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    /// Image reference used at creation.
    pub image: String,
    pub image_id: String,
    pub labels: BTreeMap<String, String>,
    pub state: ContainerState,
    pub exit_code: Option<i32>,
    /// `None` — the image has no healthcheck.
    pub health: Option<HealthStatus>,
    /// Names of the networks the container is currently attached to (sorted).
    pub networks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageInfo {
    pub id: String,
    /// Repository digest (from the manifest), if known.
    pub digest: Option<Digest>,
    pub repo_tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PullEvent {
    Progress {
        message: String,
    },
    /// End of the pull; `digest` is the digest that will be pinned in state.
    Complete {
        image_id: String,
        digest: Option<Digest>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkSpec {
    pub name: String,
    pub internal: bool,
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Container,
    Image,
    Network,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodmanEvent {
    pub kind: EventKind,
    /// np. `start`, `die`, `health_status`, `pull`.
    pub action: String,
    pub id: String,
    pub name: String,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventFilter {
    /// Only events from objects with these labels (`k=v`).
    pub labels: BTreeMap<String, String>,
    /// Unix timestamp — replay events from this moment.
    pub since: Option<i64>,
}

/// Network data needed by ingress: gateway addresses where the network DNS (aardvark) listens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkInfo {
    pub name: String,
    pub gateways: Vec<std::net::IpAddr>,
    /// Subnets in CIDR notation (`10.89.1.0/24`).
    pub subnets: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContainerFilter {
    pub labels: BTreeMap<String, String>,
}

/// libpod client. `Send + Sync`, cheaply cloned via `Arc` on the caller's side.
pub trait PodmanClient: Send + Sync {
    fn version(&self) -> impl Future<Output = Result<VersionInfo>> + Send;

    // Containers
    fn container_create(&self, spec: &ContainerSpec)
    -> impl Future<Output = Result<String>> + Send;
    fn container_start(&self, name: &str) -> impl Future<Output = Result<()>> + Send;
    fn container_stop(
        &self,
        name: &str,
        timeout_secs: u32,
    ) -> impl Future<Output = Result<()>> + Send;
    fn container_remove(&self, name: &str, force: bool) -> impl Future<Output = Result<()>> + Send;
    /// Sends a signal (name without `SIG`, e.g. `HUP`) to a running container — reloads nginx.
    fn container_kill(&self, name: &str, signal: &str) -> impl Future<Output = Result<()>> + Send;
    /// `PodmanError::NotFound` if missing.
    /// Runs `cmd` in a running container, waits for it to finish and returns the exit code.
    /// Output is not captured (used for `nginx -t`).
    fn container_exec(
        &self,
        name: &str,
        cmd: &[String],
    ) -> impl Future<Output = Result<i32>> + Send;
    fn container_inspect(&self, name: &str) -> impl Future<Output = Result<ContainerInfo>> + Send;
    fn container_list(
        &self,
        filter: &ContainerFilter,
    ) -> impl Future<Output = Result<Vec<ContainerInfo>>> + Send;

    // Images
    /// Pull as a stream; an error mid-pull appears as an `Err` in the stream.
    fn image_pull(&self, reference: &str) -> impl Stream<Item = Result<PullEvent>> + Send;
    fn image_inspect(&self, reference: &str) -> impl Future<Output = Result<ImageInfo>> + Send;
    /// Gives image `id` an additional tag (manual rollback).
    fn image_tag(&self, id: &str, repo: &str, tag: &str)
    -> impl Future<Output = Result<()>> + Send;
    fn image_remove(&self, reference: &str) -> impl Future<Output = Result<()>> + Send;

    // Networks
    /// Idempotent: an existing network with that name → `Ok`.
    fn network_create(&self, spec: &NetworkSpec) -> impl Future<Output = Result<()>> + Send;
    fn network_connect(
        &self,
        network: &str,
        container: &str,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Detaches a running container from a network. Idempotent: not attached → `Ok`.
    fn network_disconnect(
        &self,
        network: &str,
        container: &str,
    ) -> impl Future<Output = Result<()>> + Send;

    /// `PodmanError::NotFound` if the network is missing.
    fn network_inspect(&self, name: &str) -> impl Future<Output = Result<NetworkInfo>> + Send;

    // Secrets (Podman secrets); `create` overwrites an existing one with that name.
    fn secret_create(&self, name: &str, data: &[u8]) -> impl Future<Output = Result<()>> + Send;
    fn secret_remove(&self, name: &str) -> impl Future<Output = Result<()>> + Send;

    // Volumes (iteration 2). Session 1 owns the callers; the libpod client implements all of these.
    /// Idempotent: an existing volume with that name → `Ok` (labels are not changed).
    fn volume_create(&self, spec: &VolumeSpec) -> impl Future<Output = Result<()>> + Send;
    /// `PodmanError::NotFound` if missing.
    fn volume_inspect(&self, name: &str) -> impl Future<Output = Result<VolumeInfo>> + Send;
    fn volume_list(
        &self,
        filter: &VolumeFilter,
    ) -> impl Future<Output = Result<Vec<VolumeInfo>>> + Send;
    /// Extracts a tar archive into the volume (`POST /libpod/volumes/{name}/import`).
    fn volume_import(&self, name: &str, tar: TarStream) -> impl Future<Output = Result<()>> + Send;
    /// The volume's contents as a tar archive (`GET /libpod/volumes/{name}/export`).
    fn volume_export(&self, name: &str) -> impl Future<Output = Result<TarStream>> + Send;
    /// `PodmanError::NotFound` if missing; `force` also removes it while containers use it.
    fn volume_remove(&self, name: &str, force: bool) -> impl Future<Output = Result<()>> + Send;

    /// One-shot healthcheck invocation (the deploy gate calls it itself — no systemd timers).
    fn healthcheck_run(&self, container: &str)
    -> impl Future<Output = Result<HealthStatus>> + Send;

    /// Event stream (never ends in normal operation).
    fn events(&self, filter: &EventFilter) -> impl Stream<Item = Result<PodmanEvent>> + Send;
}

#[cfg(all(test, feature = "testing"))]
mod fake_tests {
    use futures_util::StreamExt;

    use super::*;
    use crate::testing::FakePodman;

    fn spec(name: &str, image: &str) -> ContainerSpec {
        ContainerSpec {
            name: name.into(),
            image: image.into(),
            labels: BTreeMap::new(),
            env: BTreeMap::new(),
            networks: vec![],
            secrets: vec![],
            publish: vec![],
            restart: RestartPolicy::Always,
            userns_auto: true,
            mounts: vec![],
            volumes: vec![],
            resources: Resources::default(),
            healthcheck: None,
            id_mapping: None,
        }
    }

    #[tokio::test]
    async fn pull_create_start_health() {
        let fake = FakePodman::new();
        let events: Vec<_> = fake.image_pull("ghcr.io/x/y:latest").collect().await;
        assert!(matches!(
            events.last(),
            Some(Ok(PullEvent::Complete {
                digest: Some(_),
                ..
            }))
        ));

        fake.container_create(&spec("app", "ghcr.io/x/y:latest"))
            .await
            .unwrap();
        fake.container_start("app").await.unwrap();
        fake.script_health("app", [HealthStatus::Starting, HealthStatus::Healthy]);
        assert_eq!(
            fake.healthcheck_run("app").await.unwrap(),
            HealthStatus::Starting
        );
        assert_eq!(
            fake.healthcheck_run("app").await.unwrap(),
            HealthStatus::Healthy
        );
        assert_eq!(
            fake.healthcheck_run("app").await.unwrap(),
            HealthStatus::Healthy
        );
    }

    #[tokio::test]
    async fn pull_error_arrives_mid_stream_and_missing_image_is_not_found() {
        let fake = FakePodman::new();
        fake.fail_pull("ghcr.io/x/bad:latest", "manifest unknown");
        let events: Vec<_> = fake.image_pull("ghcr.io/x/bad:latest").collect().await;
        assert!(matches!(events[0], Ok(PullEvent::Progress { .. })));
        assert!(matches!(events[1], Err(PodmanError::Pull(_))));

        let err = fake
            .container_create(&spec("a", "ghcr.io/x/bad:latest"))
            .await
            .unwrap_err();
        assert!(matches!(err, PodmanError::NotFound(_)));
    }
}
