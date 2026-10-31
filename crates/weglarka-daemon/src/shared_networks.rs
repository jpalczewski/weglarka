//! Admin endpoints for networks shared by groups of instances (issue #128,
//! [`docs/decisions/0030-shared-networks.md`](../../../docs/decisions/0030-shared-networks.md)):
//! `GET /v1/networks` lists the declarations, `PUT /v1/networks/{network}` declares one
//! (idempotent, no body) and `DELETE /v1/networks/{network}` drops the declaration.
//!
//! Membership is part of the app specs (`AppSpec::shared_networks`): declaring a network only makes
//! the name joinable. The engine creates the Podman network (`net-shared-<name>`, labelled
//! `weglarka.shared-network`) on the first member's deploy.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use futures_util::future::join_all;
use weglarka_api::{ErrorCode, ListSharedNetworksResponse, SharedNetworkSummary, endpoints};
use weglarka_model::app::SharedNetworkName;
use weglarka_model::labels;
use weglarka_model::podman::{PodmanClient, PodmanResultExt};
use weglarka_model::shared_networks;
use weglarka_model::state;

use crate::admin::{Fail, mutating};
use crate::app::Daemon;

type Shared<P> = State<Arc<Daemon<P>>>;

pub fn routes<P: PodmanClient + 'static>() -> Router<Arc<Daemon<P>>> {
    Router::new()
        .route(
            endpoints::SHARED_NETWORKS_LIST.path,
            get(list_shared_networks::<P>),
        )
        .route(
            endpoints::SHARED_NETWORKS_DECLARE.path,
            put(declare_shared_network::<P>),
        )
        .route(
            endpoints::SHARED_NETWORKS_REMOVE.path,
            axum::routing::delete(remove_shared_network::<P>),
        )
}

fn parse_network(raw: &str) -> Result<SharedNetworkName, Fail> {
    SharedNetworkName::new(raw).map_err(|e| Fail(ErrorCode::InvalidRequest, e.to_string()))
}

/// `GET /v1/networks`: every declaration with its members and whether Podman knows the network.
async fn list_shared_networks<P: PodmanClient + 'static>(
    State(d): Shared<P>,
) -> Result<Response, Fail> {
    let apps = state::load_apps(&d.paths.state.apps).map_err(Fail::internal)?;
    let existing = d
        .engine
        .podman()
        .network_list()
        .await
        .ignore_not_found()
        .map_err(Fail::internal)?
        .unwrap_or_default()
        .into_iter()
        .map(|n| n.name)
        .collect::<Vec<_>>();
    // Independent lookups; keeps the shape of the shared-volume listing without extra round trips.
    let rows = join_all(apps.shared_networks.keys().map(|name| {
        let podman_name = labels::shared_network_name(name);
        let exists = existing.contains(&podman_name);
        let members = shared_networks::members(&apps, name);
        let name = name.clone();
        async move {
            SharedNetworkSummary {
                name,
                podman_name,
                members,
                exists,
            }
        }
    }))
    .await;
    Ok(axum::Json(ListSharedNetworksResponse { networks: rows }).into_response())
}

/// `PUT /v1/networks/{network}`: declares a shared network (idempotent).
async fn declare_shared_network<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    Path(raw): Path<String>,
) -> Result<StatusCode, Fail> {
    let name = parse_network(&raw)?;
    {
        // Serializes with the desired-state edits of `apps add`/`apps update` (both write apps.toml).
        let _g = d.desired_lock.lock().await;
        mutating(d.engine.declare_shared_network(name)).await?;
    }
    d.changed();
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /v1/networks/{network}`: drops the declaration; refused while an app joins it.
async fn remove_shared_network<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    Path(raw): Path<String>,
) -> Result<StatusCode, Fail> {
    let name = parse_network(&raw)?;
    {
        let _g = d.desired_lock.lock().await;
        mutating(d.engine.remove_shared_network(&name)).await?;
    }
    d.changed();
    Ok(StatusCode::NO_CONTENT)
}
