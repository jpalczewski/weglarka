//! Admin endpoints for volumes shared between instances (issue #33,
//! [`docs/decisions/0017-shared-volumes.md`](../../../docs/decisions/0017-shared-volumes.md)):
//! `GET /v1/volumes` lists the declarations, `PUT /v1/volumes/{volume}[?group=]` declares one
//! (idempotent, no body) and `DELETE /v1/volumes/{volume}?purge=true` drops the declaration — with `purge` also
//! its data.
//!
//! The mounts are part of the app specs (`AppSpec::shared_volumes`): declaring a volume only makes
//! the name mountable. The volume's group (its own name unless `?group=` says otherwise, issue #129)
//! owns one uid/gid range and every member container runs in it; the engine creates the Podman
//! volume (`wg-shared-<name>`, labelled `weglarka.shared-volume` and `weglarka.shared-group`) on the
//! first member's deploy. This module is the API surface plus the read model
//! ([`SharedVolumeSummary`]): `apps.toml` + `state.toml` + what Podman knows.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use futures_util::future::join_all;
use weglarka_api::{ErrorCode, ListSharedVolumesResponse, SharedVolumeSummary, endpoints};
use weglarka_model::app::SharedVolumeName;
use weglarka_model::labels;
use weglarka_model::podman::{PodmanClient, PodmanResultExt};
use weglarka_model::shared_volumes;
use weglarka_model::state;

use crate::admin::{Fail, mutating};
use crate::app::Daemon;
use crate::volumes::flag;

type Shared<P> = State<Arc<Daemon<P>>>;

pub fn routes<P: PodmanClient + 'static>() -> Router<Arc<Daemon<P>>> {
    Router::new()
        .route(
            endpoints::SHARED_VOLUMES_LIST.path,
            get(list_shared_volumes::<P>),
        )
        .route(
            endpoints::SHARED_VOLUMES_DECLARE.path,
            put(declare_shared_volume::<P>),
        )
        .route(
            endpoints::SHARED_VOLUMES_REMOVE.path,
            axum::routing::delete(remove_shared_volume::<P>),
        )
}

fn parse_volume(raw: &str) -> Result<SharedVolumeName, Fail> {
    SharedVolumeName::new(raw).map_err(|e| Fail(ErrorCode::InvalidRequest, e.to_string()))
}

/// `GET /v1/volumes`: every declaration with its members, uid range and whether Podman knows it.
async fn list_shared_volumes<P: PodmanClient + 'static>(
    State(d): Shared<P>,
) -> Result<Response, Fail> {
    let apps = state::load_apps(&d.paths.state.apps).map_err(Fail::internal)?;
    let st = state::load_state(&d.paths.state.state).map_err(Fail::internal)?;
    // The `exists` probe is per declaration and independent: ask Podman for all of them at once.
    let daemon = d.clone();
    let probes = apps.shared_volumes.keys().map(|name| {
        let daemon = daemon.clone();
        let podman_name = labels::shared_volume_name(name);
        async move {
            let exists = daemon
                .engine
                .podman()
                .volume_inspect(&podman_name)
                .await
                .exists()
                .map_err(Fail::internal)?;
            Ok((name.clone(), podman_name, exists))
        }
    });
    let probed: Vec<(SharedVolumeName, String, bool)> = join_all(probes)
        .await
        .into_iter()
        .collect::<Result<_, Fail>>()?;
    let volumes = probed
        .into_iter()
        .map(|(name, podman_name, exists)| SharedVolumeSummary {
            members: shared_volumes::members(&apps, &name),
            // `state.toml` is keyed by group: volumes of one group report the same range.
            group: Some(shared_volumes::volume_group(&apps, &name)),
            uid_range: st
                .shared_volumes
                .get(&shared_volumes::volume_group(&apps, &name))
                .and_then(|s| s.uid_range),
            name,
            podman_name,
            exists,
        })
        .collect();
    Ok(axum::Json(ListSharedVolumesResponse { volumes }).into_response())
}

/// Value of `key` in a raw query string (no percent-decoding: names are `[a-z0-9-]`).
fn query_value<'a>(query: Option<&'a str>, key: &str) -> Option<&'a str> {
    query?
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .find_map(|(k, v)| (k == key).then_some(v))
}

/// `PUT /v1/volumes/{volume}?group=<name>`: declares a shared volume (idempotent), optionally in a
/// group that shares one uid range (issue #129).
async fn declare_shared_volume<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    Path(raw): Path<String>,
    RawQuery(query): RawQuery,
) -> Result<StatusCode, Fail> {
    let name = parse_volume(&raw)?;
    let group = query_value(query.as_deref(), "group")
        .map(parse_volume)
        .transpose()?;
    {
        // Serializes with the desired-state edits of `apps add`/`apps update` (both write apps.toml).
        let _g = d.desired_lock.lock().await;
        mutating(d.engine.declare_shared_volume(name, group)).await?;
    }
    d.changed();
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /v1/volumes/{volume}?purge=true`: drops the declaration; `purge` also deletes the data.
async fn remove_shared_volume<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    Path(raw): Path<String>,
    RawQuery(query): RawQuery,
) -> Result<StatusCode, Fail> {
    let name = parse_volume(&raw)?;
    let purge = flag(query.as_deref(), "purge");
    {
        let _g = d.desired_lock.lock().await;
        mutating(d.engine.remove_shared_volume(&name, purge)).await?;
    }
    d.changed();
    Ok(StatusCode::NO_CONTENT)
}
