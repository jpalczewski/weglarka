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
use weglarka_api::{
    AbandonReservationRequest, AbandonReservationResponse, ErrorCode, PruneImagesRequest,
    PruneImagesResponse, PrunedImage, endpoints,
};
use weglarka_engine::images::PruneReport;
use weglarka_model::podman::{ImageInfo, PodmanClient};

use crate::admin::{Fail, mutating};
use crate::app::Daemon;

type Shared<P> = State<Arc<Daemon<P>>>;

pub fn routes<P: PodmanClient + 'static>() -> Router<Arc<Daemon<P>>> {
    Router::new()
        .route(endpoints::IMAGES_PRUNE.path, post(prune_images::<P>))
        .route(
            endpoints::IMAGES_RESERVATION_ABANDON.path,
            post(abandon_reservation::<P>),
        )
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
    Ok(Json(reply(report)?))
}

/// A blocked pass (provenance could not be read or written) is an error, not an empty report: the
/// operator must see that cleanup did not run, and the response has no field for it.
fn reply(report: PruneReport) -> Result<PruneImagesResponse, Fail> {
    if report.blocked {
        let removed = report.removed.len();
        let mut message = report.diagnostics.join("; ");
        if removed > 0 {
            message.push_str(&format!(
                "; {removed} image(s) had already been removed in this pass"
            ));
        }
        return Err(Fail::internal(message));
    }
    Ok(response(report))
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
        diagnostics: report.diagnostics,
    }
}

/// `POST /v1/images/reservations/abandon`: the explicit operator command from the contract. It is
/// the only way (besides a changed boot without a referencing transaction) to free reservation
/// capacity; it never deletes an image or a provenance record.
async fn abandon_reservation<P: PodmanClient + 'static>(
    State(d): Shared<P>,
    body: Bytes,
) -> Result<Json<AbandonReservationResponse>, Fail> {
    let request: AbandonReservationRequest = serde_json::from_slice(&body)
        .map_err(|e| Fail(ErrorCode::InvalidRequest, format!("invalid JSON body: {e}")))?;
    let operation = weglarka_model::image_inventory::OperationId::new(request.operation_id)
        .map_err(|e| Fail(ErrorCode::InvalidRequest, e.to_string()))?;
    let abandoned = mutating(d.engine.abandon_reservation(&operation)).await?;
    Ok(Json(AbandonReservationResponse { abandoned }))
}

fn image(info: ImageInfo) -> PrunedImage {
    PrunedImage {
        id: info.id,
        tags: info.repo_tags,
        digests: info.repo_digests,
        size_bytes: info.size_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_blocked_report_is_an_error_naming_the_reason() {
        let report = PruneReport {
            blocked: true,
            diagnostics: vec!["image retention is blocked: managed-images.toml: bad".into()],
            ..PruneReport::default()
        };
        let Err(Fail(code, message)) = reply(report) else {
            panic!("a blocked pass must not look like an empty prune");
        };
        assert_eq!(code, ErrorCode::Internal);
        assert!(message.contains("managed-images.toml"), "{message}");
    }

    #[test]
    fn an_unblocked_report_is_a_response() {
        assert!(reply(PruneReport::default()).is_ok());
    }
}
