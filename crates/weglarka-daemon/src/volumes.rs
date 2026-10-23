//! Admin endpoints for volumes (`VOLUMES_LIST`, `VOLUMES_EXPORT`, `VOLUMES_IMPORT`); the
//! `?purge_volumes` flag of `APPS_REMOVE` is handled by `admin.rs` through [`flag`].
//!
//! Tars are streamed in both directions: nothing is buffered in the daemon. Węglarka extracts no
//! archive itself — Podman does, in its own chroot — so there is no path-traversal surface in this
//! module; what it does enforce is a cap on the number of bytes it forwards ([`MAX_IMPORT_BYTES`]).
//!
//! Two import modes, because the ids inside a tar mean different things (docs/decisions/0009):
//! * default — a **Węglarka export** (namespace ids, same range): `volume_import`, lossless. Mixing
//!   the modes up is the dangerous error: a foreign tar imported this way lands on wrong uids silently;
//! * `?foreign=true` — a tar made elsewhere (Coolify, `docker cp`…): extracted through a helper
//!   container of the instance so its uids are mapped into the instance's range.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, RawQuery, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use futures_util::StreamExt;
use weglarka_api::{ErrorCode, ListVolumesResponse, VolumeSummary, endpoints};
use weglarka_core::app::{AppSpec, InstanceName, VolumeMount};
use weglarka_core::labels;
use weglarka_core::podman::{PodmanClient, PodmanError, TarStream};
use weglarka_core::state;
use weglarka_core::volumes::ImportMode;

use crate::admin::Fail;
use crate::app::{Daemon, MUTATION_TIMEOUT};

/// Most bytes one import forwards to Podman. Generous for the data Węglarka manages (SQLite files,
/// uploads) and a stop against filling the disk by accident or from a runaway client.
pub const MAX_IMPORT_BYTES: u64 = 8 * 1024 * 1024 * 1024;

type Shared<P> = State<Arc<Daemon<P>>>;
type ApiResult<T> = Result<T, Fail>;

pub fn routes<P: PodmanClient + 'static>() -> Router<Arc<Daemon<P>>> {
    Router::new()
        .route(endpoints::VOLUMES_LIST.path, get(list_volumes::<P>))
        .route(endpoints::VOLUMES_EXPORT.path, get(export_volume::<P>))
        .route(
            endpoints::VOLUMES_IMPORT.path,
            axum::routing::put(import_volume::<P>).layer(DefaultBodyLimit::disable()),
        )
}

/// `true` if the raw query string contains `key` as a flag (`key`, `key=true`, `key=1`).
pub fn flag(query: Option<&str>, key: &str) -> bool {
    query.unwrap_or_default().split('&').any(|kv| {
        let (k, v) = kv.split_once('=').unwrap_or((kv, "true"));
        k == key && matches!(v, "true" | "1")
    })
}

fn parse_name(raw: &str) -> ApiResult<InstanceName> {
    InstanceName::new(raw).map_err(|e| Fail(ErrorCode::InvalidRequest, e.to_string()))
}

fn load_spec<P: PodmanClient>(d: &Daemon<P>, name: &InstanceName) -> ApiResult<AppSpec> {
    state::load_apps(&d.paths.state.apps)
        .map_err(|e| Fail(ErrorCode::Internal, e.to_string()))?
        .apps
        .remove(name)
        .ok_or_else(|| Fail(ErrorCode::NotFound, format!("unknown app: {name}")))
}

fn declared_volume<P: PodmanClient>(
    d: &Daemon<P>,
    app: &str,
    volume: &str,
) -> ApiResult<(InstanceName, VolumeMount)> {
    let name = parse_name(app)?;
    let mount = load_spec(d, &name)?
        .volumes
        .into_iter()
        .find(|v| v.name == volume)
        .ok_or_else(|| {
            Fail(
                ErrorCode::NotFound,
                format!("{name} declares no volume {volume:?}"),
            )
        })?;
    Ok((name, mount))
}

fn podman_fail(e: PodmanError, what: &str) -> Fail {
    match e {
        PodmanError::NotFound(_) => Fail(
            ErrorCode::NotFound,
            format!("{what} does not exist yet; deploy the app once first"),
        ),
        other => Fail(ErrorCode::Internal, other.to_string()),
    }
}

async fn list_volumes<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    Path(app): Path<String>,
) -> ApiResult<Response> {
    let name = parse_name(&app)?;
    let spec = load_spec(&d, &name)?;
    let mut volumes = Vec::with_capacity(spec.volumes.len());
    for v in spec.volumes {
        let podman_name = labels::volume_name(&name, &v.name);
        let exists = match d.engine.podman().volume_inspect(&podman_name).await {
            Ok(_) => true,
            Err(PodmanError::NotFound(_)) => false,
            Err(e) => return Err(Fail(ErrorCode::Internal, e.to_string())),
        };
        volumes.push(VolumeSummary {
            name: v.name,
            target: v.target,
            podman_name,
            exists,
        });
    }
    Ok(axum::Json(ListVolumesResponse { volumes }).into_response())
}

async fn export_volume<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    Path((app, volume)): Path<(String, String)>,
) -> ApiResult<Response> {
    let (name, mount) = declared_volume(&d, &app, &volume)?;
    let podman_name = labels::volume_name(&name, &mount.name);
    let tar = d
        .engine
        .podman()
        .volume_export(&podman_name)
        .await
        .map_err(|e| podman_fail(e, &format!("volume {podman_name}")))?;
    Ok((
        [(header::CONTENT_TYPE, "application/x-tar")],
        Body::from_stream(tar),
    )
        .into_response())
}

async fn import_volume<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    Path((app, volume)): Path<(String, String)>,
    RawQuery(query): RawQuery,
    body: Body,
) -> ApiResult<StatusCode> {
    let (name, mount) = declared_volume(&d, &app, &volume)?;
    let mode = if flag(query.as_deref(), "foreign") {
        ImportMode::Foreign
    } else {
        ImportMode::Own
    };
    d.engine
        .import_volume(
            &name,
            &mount.name,
            mode,
            capped(body, MAX_IMPORT_BYTES),
            MUTATION_TIMEOUT,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Request body as a tar stream that fails once more than `limit` bytes have passed through.
fn capped(body: Body, limit: u64) -> TarStream {
    let mut seen: u64 = 0;
    body.into_data_stream()
        .map(move |chunk| {
            let chunk =
                chunk.map_err(|e| PodmanError::Protocol(format!("upload interrupted: {e}")))?;
            seen += chunk.len() as u64;
            if seen > limit {
                return Err(PodmanError::Protocol(format!(
                    "import larger than the {limit}-byte limit"
                )));
            }
            Ok(chunk)
        })
        .boxed()
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use futures_util::stream;

    use super::*;

    #[test]
    fn flag_parses_bare_and_valued_forms() {
        assert!(flag(Some("purge_volumes"), "purge_volumes"));
        assert!(flag(Some("a=b&purge_volumes=true"), "purge_volumes"));
        assert!(flag(Some("purge_volumes=1"), "purge_volumes"));
        assert!(!flag(Some("purge_volumes=false"), "purge_volumes"));
        assert!(!flag(Some("xpurge_volumes=true"), "purge_volumes"));
        assert!(!flag(None, "purge_volumes"));
    }

    #[tokio::test]
    async fn cap_stops_the_stream_past_the_limit() {
        let chunks = [Bytes::from_static(b"1234"), Bytes::from_static(b"5678")];
        let body = Body::from_stream(stream::iter(chunks.map(Ok::<_, std::io::Error>)));
        let mut s = capped(body, 6);
        assert_eq!(s.next().await.unwrap().unwrap().len(), 4);
        assert!(s.next().await.unwrap().is_err());
    }
}
