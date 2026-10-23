//! Podman client contract (libpod v6). Implemented by `weglarka-podman` (session a) and by the
//! in-memory `testing::FakePodman` (session b, daemon). The models are *our* domain types —
//! wire models (serde with `#[serde(default)]`, only used fields) live in `weglarka-podman`.
//!
//! Async: native `async fn` in traits + generics (see `docs/decisions/0001-async-traits.md`).
//! Methods are written as `-> impl Future + Send` so implementations can use `async fn`
//! and callers can `tokio::spawn`.

use std::collections::BTreeMap;
use std::future::Future;

use futures_core::Stream;

use crate::app::{Digest, SecretTarget};

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
}

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

    /// `PodmanError::NotFound` if the network is missing.
    fn network_inspect(&self, name: &str) -> impl Future<Output = Result<NetworkInfo>> + Send;

    // Secrets (Podman secrets); `create` overwrites an existing one with that name.
    fn secret_create(&self, name: &str, data: &[u8]) -> impl Future<Output = Result<()>> + Send;
    fn secret_remove(&self, name: &str) -> impl Future<Output = Result<()>> + Send;

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
