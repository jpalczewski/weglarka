//! Admin endpoints for image retention (issue #40, `docs/decisions/0020`):
//! `POST /v1/images/prune` removes the images of a repository Węglarka deploys that are neither the
//! app's current nor its previous image and that no container uses. `{"dry_run": true}` only reports
//! them; the automatic retention after a successful deploy uses the same planner.

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::routing::post;
use weglarka_api::{ErrorCode, PruneImagesRequest, PruneImagesResponse, PrunedImage, endpoints};
use weglarka_core::images::PruneReport;
use weglarka_core::podman::{ImageInfo, PodmanClient};

use crate::admin::{Fail, mutating};
use crate::app::Daemon;

type Shared<P> = State<Arc<Daemon<P>>>;

pub fn routes<P: PodmanClient + 'static>() -> Router<Arc<Daemon<P>>> {
    Router::new().route(endpoints::IMAGES_PRUNE.path, post(prune_images::<P>))
}

/// `POST /v1/images/prune`. The body is optional: no body (or `{}`) removes, `{"dry_run": true}`
/// only reports. Parsed by hand rather than with the `Json` extractor, so a missing
/// `Content-Type` never silently turns a dry run into a real one. Serialises with deploys through
/// the engine mutex.
async fn prune_images<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    body: Bytes,
) -> Result<Json<PruneImagesResponse>, Fail> {
    let request: PruneImagesRequest = if body.is_empty() {
        PruneImagesRequest::default()
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| Fail(ErrorCode::InvalidRequest, format!("invalid JSON body: {e}")))?
    };
    let report = mutating(d.engine.prune_images(request.dry_run)).await?;
    Ok(Json(response(report)))
}

fn response(report: PruneReport) -> PruneImagesResponse {
    PruneImagesResponse {
        dry_run: report.dry_run,
        removed: report.removed.into_iter().map(image).collect(),
        reclaimed_bytes: report.reclaimed_bytes,
        failed: report
            .failed
            .into_iter()
            .map(|(id, error)| format!("{id}: {error}"))
            .collect(),
    }
}

fn image(info: ImageInfo) -> PrunedImage {
    PrunedImage {
        id: info.id,
        tags: info.repo_tags,
        digests: info.repo_digests,
        size_bytes: info.size_bytes,
    }
}
