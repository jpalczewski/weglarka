//! `GET /v1/stats` and `GET /v1/apps/{name}/stats` (`read` scope, docs/decisions/0065): projections of
//! the daemon's shared [`ResourceSnapshot`](crate::resources::ResourceSnapshot); nothing here calls libpod.
//!
//! [`container_view`] is the allowlist: it destructures [`ContainerResources`] without `..`, so a new
//! snapshot field does not compile until someone decides what a `read` caller sees of it. The
//! container id is dropped on purpose. System containers are not shown yet (#420).

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::response::Response;
use axum::routing::get;
use weglarka_api::{AppStatsResponse, ContainerStatsView, StatsResponse, StatsRole, endpoints};
use weglarka_model::app::InstanceName;
use weglarka_model::podman::PodmanClient;

use crate::admin::{ApiResult, json, load_spec, parse_name};
use crate::app::Daemon;
use crate::events::rfc3339;
use crate::resources::{ContainerResources, Owner, Role};

type Shared<P> = State<Arc<Daemon<P>>>;

pub fn routes<P: PodmanClient + 'static>() -> Router<Arc<Daemon<P>>> {
    Router::new()
        .route(endpoints::STATS.path, get(all::<P>))
        .route(endpoints::APPS_STATS.path, get(one::<P>))
}

fn role_view(role: Role) -> StatsRole {
    match role {
        Role::Active => StatsRole::Active,
        Role::Challenger => StatsRole::Challenger,
        Role::Retiring => StatsRole::Retiring,
    }
}

/// The app and the row of an app container; `None` for a system container (#420).
fn container_view(c: &ContainerResources) -> Option<(InstanceName, ContainerStatsView)> {
    let ContainerResources {
        owner,
        role,
        // Never leaves the daemon (ADR 0065 decision 1).
        container_id: _,
        restarts,
        oom_killed,
        memory_limit,
        memory_bytes,
        cpu_nanos,
        cpu_rate,
        pids,
        block_read_bytes,
        block_write_bytes,
        network_rx_bytes,
        network_tx_bytes,
    } = c;
    let Owner::App(app) = owner else {
        return None;
    };
    Some((
        app.clone(),
        ContainerStatsView {
            role: role_view(*role),
            restarts: *restarts,
            oom_killed: *oom_killed,
            memory_bytes: *memory_bytes,
            memory_limit_bytes: *memory_limit,
            cpu_ratio: cpu_rate.map(|r| r.cores),
            cpu_window_secs: cpu_rate.map(|r| r.window.as_secs_f64()),
            cpu_seconds_total: cpu_nanos.map(|n| n as f64 / 1e9),
            pids: *pids,
            block_read_bytes: *block_read_bytes,
            block_write_bytes: *block_write_bytes,
            net_rx_bytes: *network_rx_bytes,
            net_tx_bytes: *network_tx_bytes,
        },
    ))
}

/// Rows per app, each app's rows ordered active, challenger, retiring.
async fn grouped<P: PodmanClient>(
    d: &Daemon<P>,
) -> (
    Option<String>,
    bool,
    BTreeMap<InstanceName, Vec<ContainerStatsView>>,
) {
    match d.resources.snapshot(d.engine.podman()).await {
        Ok(snapshot) => {
            let mut apps: BTreeMap<InstanceName, Vec<ContainerStatsView>> = BTreeMap::new();
            for (app, view) in snapshot.containers.iter().filter_map(container_view) {
                apps.entry(app).or_default().push(view);
            }
            for rows in apps.values_mut() {
                rows.sort_by_key(|v| match v.role {
                    StatsRole::Active => 0,
                    StatsRole::Challenger => 1,
                    StatsRole::Retiring => 2,
                });
            }
            (Some(rfc3339(snapshot.taken_at)), true, apps)
        }
        // The cause went to the log when the snapshot failed; a `read` caller learns only that there is none.
        Err(_) => (None, false, BTreeMap::new()),
    }
}

async fn all<P: PodmanClient + 'static>(State(d): Shared<P>) -> ApiResult<Response> {
    let (sampled_at, available, apps) = grouped(&d).await;
    Ok(json(StatsResponse {
        sampled_at: sampled_at.clone(),
        available,
        apps: apps
            .into_iter()
            .map(|(app, containers)| AppStatsResponse {
                app: app.to_string(),
                sampled_at: sampled_at.clone(),
                available,
                containers,
            })
            .collect(),
    }))
}

async fn one<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    Path(raw): Path<String>,
) -> ApiResult<Response> {
    let name = parse_name(&raw)?;
    load_spec(&d, &name)?;
    let (sampled_at, available, mut apps) = grouped(&d).await;
    Ok(json(AppStatsResponse {
        app: name.to_string(),
        sampled_at,
        available,
        containers: apps.remove(&name).unwrap_or_default(),
    }))
}
