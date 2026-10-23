//! Kontrakt klienta Podmana (libpod v6). Implementuje go `weglarka-podman` (sesja a),
//! a `testing::FakePodman` w pamięci (sesja b, demon). Modele są *naszymi* typami domenowymi —
//! modele wire (serde z `#[serde(default)]`, tylko używane pola) żyją w `weglarka-podman`.
//!
//! Async: natywne `async fn` w traitach + generyki (patrz `docs/decisions/0001-async-traits.md`).
//! Metody są zapisane jako `-> impl Future + Send`, żeby implementacje mogły używać `async fn`,
//! a wywołujący mogli `tokio::spawn`.

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
    /// Błąd zgłoszony w środku strumienia pulla (HTTP 200, błąd w ciele).
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
    /// `--restart=always` — restart robi conmon, także gdy Węglarka leży.
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
    /// Nazwa sekretu w Podmanie.
    pub secret: String,
    pub target: SecretTarget,
}

/// Bind mount katalogu/pliku z hosta (np. `nginx.conf` ingressu).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindMount {
    pub source: String,
    pub target: String,
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerSpec {
    pub name: String,
    /// Referencja obrazu lub digest (`repo@sha256:…`) — reconcile przypina digest.
    pub image: String,
    pub labels: BTreeMap<String, String>,
    pub env: BTreeMap<String, String>,
    /// Sieci, do których kontener dołącza przy tworzeniu (pierwsza = główna).
    pub networks: Vec<String>,
    pub secrets: Vec<SecretAttachment>,
    pub publish: Vec<PortMapping>,
    pub restart: RestartPolicy,
    /// `--userns=auto` (decyzja: od początku).
    pub userns_auto: bool,
    /// Bind mounty z hosta (pusta lista dla zwykłych apek).
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
    /// Referencja obrazu użyta przy tworzeniu.
    pub image: String,
    pub image_id: String,
    pub labels: BTreeMap<String, String>,
    pub state: ContainerState,
    pub exit_code: Option<i32>,
    /// `None` — obraz nie ma healthchecka.
    pub health: Option<HealthStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageInfo {
    pub id: String,
    /// Digest repozytoryjny (z manifestu), jeśli znany.
    pub digest: Option<Digest>,
    pub repo_tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PullEvent {
    Progress {
        message: String,
    },
    /// Koniec pulla; `digest` to digest, który zostanie przypięty w stanie.
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
    /// Zdarzenia tylko od obiektów z tymi etykietami (`k=v`).
    pub labels: BTreeMap<String, String>,
    /// Unix timestamp — odtwórz zdarzenia od tej chwili.
    pub since: Option<i64>,
}

/// Dane sieci potrzebne ingressowi: adresy bramek, pod którymi nasłuchuje DNS sieci (aardvark).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkInfo {
    pub name: String,
    pub gateways: Vec<std::net::IpAddr>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContainerFilter {
    pub labels: BTreeMap<String, String>,
}

/// Klient libpod. `Send + Sync`, tanio klonowany przez `Arc` po stronie wywołującego.
pub trait PodmanClient: Send + Sync {
    fn version(&self) -> impl Future<Output = Result<VersionInfo>> + Send;

    // Kontenery
    fn container_create(&self, spec: &ContainerSpec)
    -> impl Future<Output = Result<String>> + Send;
    fn container_start(&self, name: &str) -> impl Future<Output = Result<()>> + Send;
    fn container_stop(
        &self,
        name: &str,
        timeout_secs: u32,
    ) -> impl Future<Output = Result<()>> + Send;
    fn container_remove(&self, name: &str, force: bool) -> impl Future<Output = Result<()>> + Send;
    /// Wysyła sygnał (nazwa bez `SIG`, np. `HUP`) do działającego kontenera — przeładowanie nginxa.
    fn container_kill(&self, name: &str, signal: &str) -> impl Future<Output = Result<()>> + Send;
    /// `PodmanError::NotFound`, gdy brak.
    fn container_inspect(&self, name: &str) -> impl Future<Output = Result<ContainerInfo>> + Send;
    fn container_list(
        &self,
        filter: &ContainerFilter,
    ) -> impl Future<Output = Result<Vec<ContainerInfo>>> + Send;

    // Obrazy
    /// Pull jako strumień; błąd w środku pulla pojawia się jako `Err` w strumieniu.
    fn image_pull(&self, reference: &str) -> impl Stream<Item = Result<PullEvent>> + Send;
    fn image_inspect(&self, reference: &str) -> impl Future<Output = Result<ImageInfo>> + Send;
    /// Nadaje obrazowi `id` dodatkowy tag (ręczny rollback).
    fn image_tag(&self, id: &str, repo: &str, tag: &str)
    -> impl Future<Output = Result<()>> + Send;
    fn image_remove(&self, reference: &str) -> impl Future<Output = Result<()>> + Send;

    // Sieci
    /// Idempotentne: istniejąca sieć o tej nazwie → `Ok`.
    fn network_create(&self, spec: &NetworkSpec) -> impl Future<Output = Result<()>> + Send;
    fn network_connect(
        &self,
        network: &str,
        container: &str,
    ) -> impl Future<Output = Result<()>> + Send;

    /// `PodmanError::NotFound`, gdy brak sieci.
    fn network_inspect(&self, name: &str) -> impl Future<Output = Result<NetworkInfo>> + Send;

    // Sekrety (Podman secrets); `create` nadpisuje istniejący o tej nazwie.
    fn secret_create(&self, name: &str, data: &[u8]) -> impl Future<Output = Result<()>> + Send;
    fn secret_remove(&self, name: &str) -> impl Future<Output = Result<()>> + Send;

    /// Jednorazowe wywołanie healthchecka (bramka deployu woła je sama — bez timerów systemd).
    fn healthcheck_run(&self, container: &str)
    -> impl Future<Output = Result<HealthStatus>> + Send;

    /// Strumień zdarzeń (nigdy się nie kończy w normalnej pracy).
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
