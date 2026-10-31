//! Admin endpoints for volumes (`VOLUMES_LIST`, `VOLUMES_EXPORT`, `VOLUMES_IMPORT`); the
//! `?purge_volumes` flag of `APPS_REMOVE` is handled by `admin.rs` through [`flag`].
//!
//! A `{volume}` segment resolves to a private volume of the instance (`<instance>.<name>`) or to a
//! shared volume the app mounts (`wg-shared-<name>`, issue #33); in both cases the path segment is
//! the name declared in the spec. The shared volumes' own endpoints live in
//! [`crate::shared_volumes`].
//!
//! Tars are streamed in both directions: nothing is buffered in the daemon. Węglarka extracts no
//! archive itself — Podman does, in its own chroot — so there is no path-traversal surface in this
//! module; what it does enforce is a cap on the number of bytes it forwards ([`MAX_IMPORT_BYTES`]).
//!
//! Two import modes, because the ids inside a tar mean different things (docs/decisions/0009):
//! * default — a **Węglarka export** (namespace ids, same range): `volume_import`, lossless. Mixing
//!   the modes up is the dangerous error: a foreign tar imported this way lands on wrong uids silently;
//! * `?foreign=true` — a tar made elsewhere (Coolify, `docker cp`…): extracted through a helper
//!   container of the instance; libpod chowns the extracted files to the container's user.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, RawQuery, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use futures_util::StreamExt;
use weglarka_api::{
    AppVolumeSummary, ErrorCode, ListAppVolumesResponse, ListVolumesResponse, VolumeSummary,
    endpoints,
};
use weglarka_engine::volumes::ImportMode;
use weglarka_model::app::{AppSpec, InstanceName};
use weglarka_model::labels;
use weglarka_model::podman::{PodmanClient, PodmanError, TarStream};
use weglarka_model::state;

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
        .route(endpoints::APP_VOLUMES_LIST.path, get(list_app_volumes::<P>))
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

/// A volume the endpoints can address: a private volume of the instance, or a shared volume the app
/// mounts (issue #33). `name` is the `{volume}` path segment — the private volume's name within the
/// instance or the shared volume's declared name (`kajet-data`, not `wg-shared-kajet-data`).
struct VolumeTarget {
    instance: InstanceName,
    name: String,
    podman_name: String,
    shared: bool,
}

fn declared_volume<P: PodmanClient>(
    d: &Daemon<P>,
    app: &str,
    volume: &str,
) -> ApiResult<VolumeTarget> {
    let name = parse_name(app)?;
    let spec = load_spec(d, &name)?;
    if let Some(v) = spec.volumes.iter().find(|v| v.name == volume) {
        return Ok(VolumeTarget {
            podman_name: labels::volume_name(&name, &v.name),
            name: v.name.clone(),
            instance: name,
            shared: false,
        });
    }
    if let Some(v) = spec
        .shared_volumes
        .iter()
        .find(|v| v.name.as_str() == volume)
    {
        return Ok(VolumeTarget {
            podman_name: labels::shared_volume_name(&v.name),
            name: v.name.to_string(),
            instance: name,
            shared: true,
        });
    }
    Err(Fail(
        ErrorCode::NotFound,
        format!("{name} declares no volume {volume:?}"),
    ))
}

/// What to tell the operator when the Podman volume does not exist yet (the volume endpoints are
/// usable only after a deploy creates it).
fn not_found_hint(target: &VolumeTarget) -> &'static str {
    if target.shared {
        "deploy one of its members once first"
    } else {
        "deploy the app once first"
    }
}

fn podman_fail(e: PodmanError, what: &str, hint: &str) -> Fail {
    match e {
        PodmanError::NotFound(_) => Fail(
            ErrorCode::NotFound,
            format!("{what} does not exist yet; {hint}"),
        ),
        other => Fail(ErrorCode::Internal, other.to_string()),
    }
}

async fn volume_exists<P: PodmanClient>(d: &Daemon<P>, podman_name: &str) -> ApiResult<bool> {
    match d.engine.podman().volume_inspect(podman_name).await {
        Ok(_) => Ok(true),
        Err(PodmanError::NotFound(_)) => Ok(false),
        Err(e) => Err(Fail(ErrorCode::Internal, e.to_string())),
    }
}

async fn volume_summaries<P: PodmanClient>(
    d: &Daemon<P>,
    name: &InstanceName,
    spec: &AppSpec,
) -> ApiResult<Vec<VolumeSummary>> {
    let mut volumes = Vec::with_capacity(spec.volumes.len() + spec.shared_volumes.len());
    for v in &spec.volumes {
        let podman_name = labels::volume_name(name, &v.name);
        volumes.push(VolumeSummary {
            name: v.name.clone(),
            target: v.target.clone(),
            exists: volume_exists(d, &podman_name).await?,
            podman_name,
            shared: false,
        });
    }
    // Shared volumes the app mounts: same list, marked `shared`, addressed by their declared name.
    for v in &spec.shared_volumes {
        let podman_name = labels::shared_volume_name(&v.name);
        volumes.push(VolumeSummary {
            name: v.name.to_string(),
            target: v.target.clone(),
            exists: volume_exists(d, &podman_name).await?,
            podman_name,
            shared: true,
        });
    }
    Ok(volumes)
}

async fn list_volumes<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    Path(app): Path<String>,
) -> ApiResult<Response> {
    let name = parse_name(&app)?;
    let spec = load_spec(&d, &name)?;
    let volumes = volume_summaries(&d, &name, &spec).await?;
    Ok(axum::Json(ListVolumesResponse { volumes }).into_response())
}

/// The volumes of every app, one row each with its owner (`apps.toml` order is by name).
async fn list_app_volumes<P: PodmanClient + 'static>(State(d): Shared<P>) -> ApiResult<Response> {
    let apps = state::load_apps(&d.paths.state.apps)
        .map_err(|e| Fail(ErrorCode::Internal, e.to_string()))?
        .apps;
    let mut volumes = Vec::new();
    for (name, spec) in &apps {
        volumes.extend(
            volume_summaries(&d, name, spec)
                .await?
                .into_iter()
                .map(|volume| AppVolumeSummary {
                    app: name.clone(),
                    volume,
                }),
        );
    }
    Ok(axum::Json(ListAppVolumesResponse { volumes }).into_response())
}

async fn export_volume<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    Path((app, volume)): Path<(String, String)>,
) -> ApiResult<Response> {
    let target = declared_volume(&d, &app, &volume)?;
    let tar = d
        .engine
        .podman()
        .volume_export(&target.podman_name)
        .await
        .map_err(|e| {
            podman_fail(
                e,
                &format!("volume {}", target.podman_name),
                not_found_hint(&target),
            )
        })?;
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
    let target = declared_volume(&d, &app, &volume)?;
    let mode = if flag(query.as_deref(), "foreign") {
        ImportMode::Foreign
    } else {
        ImportMode::Own
    };
    // The engine resolves the name to the private volume or to a shared volume the app mounts; for a
    // shared volume it also refuses while another member runs (issue #33).
    d.engine
        .import_volume_with(
            &target.instance,
            &target.name,
            mode,
            flag(query.as_deref(), "replace"),
            capped(body, MAX_IMPORT_BYTES),
            MUTATION_TIMEOUT,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Request body as a tar stream that fails once more than `limit` bytes have passed through.
pub(crate) fn capped(body: Body, limit: u64) -> TarStream {
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
