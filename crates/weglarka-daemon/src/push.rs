//! `PUT /v1/apps/{name}/image` (`APPS_PUSH_IMAGE`, issue #109, docs/decisions/0042): an image archive
//! built on the operator's machine, loaded into Podman's store and deployed like any other digest.
//!
//! The archive is streamed to Podman, never buffered here; Węglarka reads none of it, so there is no
//! extraction surface in this module — what it enforces is a cap on the bytes it forwards
//! ([`MAX_PUSH_BYTES`]). The deploy that follows (health gate, rollback) holds the engine lock without
//! a timeout, as `apps deploy` does; the upload before it does not hold it at all.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::response::Response;
use axum::routing::put;
use weglarka_api::endpoints;
use weglarka_core::podman::PodmanClient;

use crate::admin::{Fail, deploy_response, parse_name};
use crate::app::Daemon;
use crate::volumes::capped;

/// Most bytes one push forwards to Podman: a stop against filling the disk by accident or from a
/// runaway client. A layered application image is far below it.
pub const MAX_PUSH_BYTES: u64 = 8 * 1024 * 1024 * 1024;

type Shared<P> = State<Arc<Daemon<P>>>;

pub fn routes<P: PodmanClient + 'static>() -> Router<Arc<Daemon<P>>> {
    Router::new().route(
        endpoints::APPS_PUSH_IMAGE.path,
        put(push_image::<P>).layer(DefaultBodyLimit::disable()),
    )
}

async fn push_image<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    Path(raw): Path<String>,
    body: Body,
) -> Result<Response, Fail> {
    let name = parse_name(&raw)?;
    let outcome = d
        .engine
        .push_archive(&name, capped(body, MAX_PUSH_BYTES))
        .await?;
    deploy_response(&d, &name, outcome)
}
