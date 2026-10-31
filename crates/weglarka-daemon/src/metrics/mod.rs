//! The optional `GET /metrics` listener (issue #350, `docs/decisions/0061-metrics-listener.md`).
//!
//! It is built from its own router with exactly one route and shares nothing with the admin route
//! table, so it can never serve an admin endpoint. Values are computed at scrape time by a
//! [`MetricsSource`]; its sources (daemon counters, per-app resources, host numbers) are added there
//! without touching the encoder or the listener.
//!
//! Label contract (ADR 0061, decision 8): `app` is a validated instance name, `role` is one of
//! `active`, `challenger`, `retiring`, one-off containers are skipped, and a label value is never free
//! text (failure reasons, image references, command lines).

pub mod daemon;
pub mod encode;
pub mod host;
pub mod resources;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use tokio::sync::watch;
use weglarka_model::config::MetricsConfig;
use weglarka_model::podman::{NetworkSpec, PodmanClient, PodmanError};

use crate::app::Daemon;
use crate::service::SERVICE_NAME;
use encode::{Family, Kind, Sample};

/// Path of the one route.
pub const PATH: &str = "/metrics";

/// Where metric values come from. Called once per scrape.
pub trait MetricsSource: Send + Sync + 'static {
    fn collect(&self) -> impl Future<Output = Vec<Family>> + Send;
}

/// The sources of this daemon: `weglarka_build_info`, the daemon counters (#352), per-app
/// resources (#351), and the host (#353): `host` for the machine, libpod `/info` for container storage.
pub struct DaemonMetrics<P: PodmanClient + 'static, H: host::HostSource = host::ProcSource> {
    daemon: Arc<Daemon<P>>,
    daemon_source: daemon::DaemonSource,
    resources: resources::Cache,
    host: H,
    storage: resources::Cache,
}

impl<P: PodmanClient + 'static, H: host::HostSource> DaemonMetrics<P, H> {
    /// `counters` must be the sink the daemon's event fan-out feeds.
    pub fn new(daemon: Arc<Daemon<P>>, counters: Arc<daemon::EventCounters>, host: H) -> Self {
        Self {
            daemon,
            daemon_source: daemon::DaemonSource::new(counters),
            resources: resources::Cache::default(),
            host,
            storage: resources::Cache::default(),
        }
    }
}

impl<P: PodmanClient + 'static, H: host::HostSource> MetricsSource for DaemonMetrics<P, H> {
    async fn collect(&self) -> Vec<Family> {
        let mut families = vec![build_info()];
        families.extend(daemon::families(&self.daemon, &self.daemon_source));
        let (resources, host, storage) = tokio::join!(
            resources::collect(&self.daemon, &self.resources),
            self.host.collect(),
            host::storage(self.daemon.engine.podman(), &self.storage),
        );
        families.extend(resources);
        families.extend(host);
        families.extend(storage);
        families
    }
}

fn build_info() -> Family {
    Family {
        name: "weglarka_build_info",
        help: "Version of the running Węglarka daemon; the value is always 1.",
        kind: Kind::Gauge,
        samples: vec![Sample::new(
            vec![("version", env!("CARGO_PKG_VERSION").to_owned())],
            1.0,
        )],
    }
}

/// The metrics router: `GET /metrics` and nothing else (every other path is a `404`, every other
/// method on `/metrics` a `405`).
pub fn router<S: MetricsSource>(source: Arc<S>) -> Router {
    Router::new()
        .route(PATH, get(scrape::<S>))
        .fallback(|| async { StatusCode::NOT_FOUND })
        .with_state(source)
}

async fn scrape<S: MetricsSource>(
    axum::extract::State(source): axum::extract::State<Arc<S>>,
) -> Response {
    let body = encode::encode(source.collect().await);
    ([(header::CONTENT_TYPE, encode::CONTENT_TYPE)], body).into_response()
}

/// What `doctor` reports for the listener (`metrics.listener`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenerStatus {
    /// Bound and serving; the daemon has not (yet) joined the network, `last_error` says why not.
    Joining {
        addr: SocketAddr,
        network: String,
        last_error: Option<String>,
    },
    /// Bound, and the daemon is on the network: scrapers can reach it.
    Listening { addr: SocketAddr, network: String },
    /// Could not bind; permanent until the daemon restarts.
    Failed(String),
}

/// The status `doctor` reads and the join task updates.
#[derive(Debug, Default)]
pub struct StatusCell(Mutex<Option<ListenerStatus>>);

impl StatusCell {
    pub fn set(&self, status: ListenerStatus) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(status);
    }

    pub fn get(&self) -> Option<ListenerStatus> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

/// First and longest wait between attempts to join the network.
const RETRY_FIRST: Duration = Duration::from_secs(5);
const RETRY_MAX: Duration = Duration::from_secs(60);

/// Joins the network in the background until it works or the daemon stops, so a Podman that is slow
/// or briefly down at boot neither delays the daemon nor leaves `/metrics` unreachable for good. The
/// first failure is a warning, the retries are debug lines; `doctor` always shows the last error.
pub async fn keep_joined<P: PodmanClient>(
    podman: &P,
    config: &MetricsConfig,
    addr: SocketAddr,
    status: &StatusCell,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut delay = RETRY_FIRST;
    let mut first = true;
    loop {
        let attempt = tokio::select! {
            result = join_network(podman, config) => result,
            _ = shutdown.wait_for(|stop| *stop) => return,
        };
        match attempt {
            Ok(()) => {
                tracing::info!(network = %config.network, "metrics network joined");
                status.set(ListenerStatus::Listening {
                    addr,
                    network: config.network.clone(),
                });
                return;
            }
            Err(error) => {
                if first {
                    tracing::warn!(%error, "cannot join the metrics network yet; retrying");
                } else {
                    tracing::debug!(%error, "still cannot join the metrics network");
                }
                first = false;
                status.set(ListenerStatus::Joining {
                    addr,
                    network: config.network.clone(),
                    last_error: Some(error),
                });
            }
        }
        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            _ = shutdown.wait_for(|stop| *stop) => return,
        }
        delay = (delay * 2).min(RETRY_MAX);
    }
}

/// Creates the network (idempotent) and joins the daemon's own container to it. Any error is returned
/// as text for the log and for `doctor`.
pub async fn join_network<P: PodmanClient>(
    podman: &P,
    config: &MetricsConfig,
) -> Result<(), String> {
    let network = &config.network;
    podman
        .network_create(&NetworkSpec {
            name: network.clone(),
            // Nothing on this network needs a route out; the daemon keeps its other networks.
            internal: true,
            labels: [("weglarka.managed".to_owned(), "metrics".to_owned())].into(),
        })
        .await
        .map_err(|e| format!("create network {network}: {e}"))?;
    let own = own_container(podman).await?;
    if own.networks.contains(network) {
        return Ok(());
    }
    match podman.network_connect(network, &own.name).await {
        // Connected by a concurrent start in the meantime.
        Ok(()) | Err(PodmanError::Conflict(_)) => Ok(()),
        Err(e) => Err(format!("join network {network}: {e}")),
    }
}

/// The daemon's own container: the hostname of a container is its id prefix; the well-known name is
/// the fallback (the same lookup as the ingress forwarder's).
async fn own_container<P: PodmanClient>(
    podman: &P,
) -> Result<weglarka_model::podman::ContainerInfo, String> {
    let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
    let hostname = hostname.trim();
    if !hostname.is_empty()
        && let Ok(info) = podman.container_inspect(hostname).await
    {
        return Ok(info);
    }
    podman
        .container_inspect(SERVICE_NAME)
        .await
        .map_err(|e| format!("find own container {SERVICE_NAME}: {e}"))
}
