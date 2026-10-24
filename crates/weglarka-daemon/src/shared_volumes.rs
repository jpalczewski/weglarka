//! Admin endpoints for volumes shared between instances (issue #33,
//! [`docs/decisions/0014-shared-volumes.md`](../../../docs/decisions/0014-shared-volumes.md)):
//! `GET /v1/volumes` lists the declarations, `PUT /v1/volumes/{volume}` declares one (idempotent,
//! no body) and `DELETE /v1/volumes/{volume}?purge=true` drops the declaration — with `purge` also
//! its data.
//!
//! The mounts are part of the app specs (`AppSpec::shared_volumes`): declaring a volume only makes
//! the name mountable. The volume owns one uid/gid range and every member container runs in it; the
//! engine creates the Podman volume (`wg-shared-<name>`, labelled `weglarka.shared-volume`) on the
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
use weglarka_core::app::SharedVolumeName;
use weglarka_core::labels;
use weglarka_core::podman::{PodmanClient, PodmanError};
use weglarka_core::shared_volumes;
use weglarka_core::state;

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
            let exists = match daemon.engine.podman().volume_inspect(&podman_name).await {
                Ok(_) => true,
                Err(PodmanError::NotFound(_)) => false,
                Err(e) => return Err(Fail::internal(e)),
            };
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
            uid_range: st.shared_volumes.get(&name).and_then(|s| s.uid_range),
            name,
            podman_name,
            exists,
        })
        .collect();
    Ok(axum::Json(ListSharedVolumesResponse { volumes }).into_response())
}

/// `PUT /v1/volumes/{volume}`: declares a shared volume (idempotent).
async fn declare_shared_volume<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    Path(raw): Path<String>,
) -> Result<StatusCode, Fail> {
    let name = parse_volume(&raw)?;
    {
        // Serializes with the desired-state edits of `apps add`/`apps update` (both write apps.toml).
        let _g = d.desired_lock.lock().await;
        mutating(d.engine.declare_shared_volume(name)).await?;
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
