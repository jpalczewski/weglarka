//! Admin endpoints of the identity integration (#91): external OIDC clients and secret rotation.
//! The provider's files are re-rendered by the generated config pipeline; rotation drives it
//! synchronously so the app is recreated only after the provider knows the new digest.

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use weglarka_api::{
    ErrorCode, ListOidcClientsResponse, OidcRotateResponse, PutOidcClientRequest, endpoints,
};
use weglarka_model::identity::ClientId;
use weglarka_model::labels;
use weglarka_model::podman::{ContainerState, PodmanClient};
use weglarka_model::state;

use crate::admin::{Fail, parse_json, parse_name};
use crate::app::Daemon;

type Shared<P> = State<Arc<Daemon<P>>>;

pub fn routes<P: PodmanClient + 'static>() -> Router<Arc<Daemon<P>>> {
    Router::new()
        .route(endpoints::OIDC_ROTATE.path, post(rotate::<P>))
        .route(endpoints::OIDC_CLIENTS_LIST.path, get(list_clients::<P>))
        .route(
            endpoints::OIDC_CLIENT_PUT.path,
            axum::routing::put(put_client::<P>).delete(remove_client::<P>),
        )
}

fn parse_id(raw: &str) -> Result<ClientId, Fail> {
    ClientId::new(raw).map_err(|e| Fail(ErrorCode::InvalidRequest, e))
}

async fn list_clients<P: PodmanClient + 'static>(State(d): Shared<P>) -> Result<Response, Fail> {
    let apps = state::load_apps(&d.paths.state.apps).map_err(Fail::internal)?;
    Ok(axum::Json(ListOidcClientsResponse {
        clients: apps.oidc_clients,
    })
    .into_response())
}

async fn put_client<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    Path(raw): Path<String>,
    body: Bytes,
) -> Result<StatusCode, Fail> {
    let id = parse_id(&raw)?;
    let req: PutOidcClientRequest = parse_json(&body)?;
    {
        let _g = d.desired_lock.lock().await;
        crate::admin::mutating(d.engine.set_oidc_client(id, req.spec)).await?;
    }
    d.changed();
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_client<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    Path(raw): Path<String>,
) -> Result<StatusCode, Fail> {
    let id = parse_id(&raw)?;
    {
        let _g = d.desired_lock.lock().await;
        crate::admin::mutating(d.engine.remove_oidc_client(&id)).await?;
    }
    d.changed();
    Ok(StatusCode::NO_CONTENT)
}

/// rotate → render with the pending digest → validate → apply to the provider → promote → recreate
/// the app. A provider that rejects the new files leaves everything as it was (the new pair is
/// discarded, the old secret and digest stay live), so the operator can fix the provider and retry.
async fn rotate<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    Path(raw): Path<String>,
) -> Result<Response, Fail> {
    let name = parse_name(&raw)?;
    {
        let _g = d.desired_lock.lock().await;
        let wiring = d.generated.as_ref().map(|worker| worker.wiring());
        d.engine
            .rotate_oidc_secret(&name, wiring.as_ref())
            .await
            .map_err(|e| match e {
                weglarka_engine::reconcile::EngineError::Generated { message, .. } => Fail(
                    ErrorCode::Conflict,
                    format!(
                        "the provider config could not be applied: {message}; nothing was rotated, \
                         fix it and re-run `weglarka oidc rotate {name}`"
                    ),
                ),
                other => Fail::from(other),
            })?;
    }
    let running = matches!(
        d.engine
            .podman()
            .container_inspect(&labels::container_name(&name))
            .await,
        Ok(info) if info.state == ContainerState::Running
    );
    if running {
        // A forced deploy: like `apps reload --recreate`, it holds the engine through the health gate.
        d.engine.deploy(&name, true).await.map_err(Fail::from)?;
    }
    d.changed();
    Ok(axum::Json(OidcRotateResponse {
        name,
        recreated: running,
    })
    .into_response())
}
