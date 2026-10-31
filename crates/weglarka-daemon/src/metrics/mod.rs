//! The optional `GET /metrics` listener (issue #350, `docs/decisions/0061-metrics-listener.md`).
//!
//! It is built from its own router with exactly one route and shares nothing with the admin route
//! table, so it can never serve an admin endpoint. Values are computed at scrape time by a
//! [`MetricsSource`]; later sources (per-app resources, daemon counters, host numbers) are added
//! there without touching the encoder or the listener.
//!
//! Label contract (ADR 0061, decision 8): `app` is a validated instance name, `role` is one of
//! `active`, `challenger`, `retiring`, one-off containers are skipped, and a label value is never free
//! text (failure reasons, image references, command lines).

pub mod encode;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use weglarka_model::config::MetricsConfig;
use weglarka_model::podman::{NetworkSpec, PodmanClient, PodmanError};

use crate::service::SERVICE_NAME;
use encode::{Family, Kind, Sample};

/// Path of the one route.
pub const PATH: &str = "/metrics";

/// Where metric values come from. Called once per scrape.
pub trait MetricsSource: Send + Sync + 'static {
    fn collect(&self) -> impl Future<Output = Vec<Family>> + Send;
}

/// The sources of this daemon. `weglarka_build_info` for now; #351, #352 and #353 add theirs here.
#[derive(Debug, Default)]
pub struct DaemonMetrics;

impl MetricsSource for DaemonMetrics {
    async fn collect(&self) -> Vec<Family> {
        vec![build_info()]
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
    Listening { addr: SocketAddr, network: String },
    Failed(String),
}

/// Creates the network (idempotent) and joins the daemon's own container to it. Any error is returned
/// as text for the log and for `doctor`; the caller does not bind then.
pub async fn join_network<P: PodmanClient>(
    podman: &P,
    config: &MetricsConfig,
) -> Result<(), String> {
    let network = &config.network;
    podman
        .network_create(&NetworkSpec {
            name: network.clone(),
            internal: false,
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
