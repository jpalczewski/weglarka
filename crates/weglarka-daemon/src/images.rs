//! Admin endpoints for image retention (issue #40, `docs/decisions/0020`):
//! `POST /v1/images/prune` removes the images of a repository Węglarka deploys that are neither the
//! app's current nor its previous image and that no container uses. `{"dry_run": true}` only reports
//! them; the automatic retention after a successful deploy uses the same planner.

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::routing::{get, post};
use weglarka_api::{
    AbandonReservationRequest, AbandonReservationResponse, ErrorCode, ListReservationsResponse,
    PruneImagesRequest, PruneImagesResponse, PrunedImage, ReservationView, endpoints,
};
use weglarka_engine::images::{PruneReport, ReservationInfo};
use weglarka_engine::reconcile::Reconciler;
use weglarka_model::image_inventory::{MAX_RESERVATIONS, ReservationPhase};
use weglarka_model::podman::{ImageInfo, PodmanClient};

use crate::admin::{Fail, mutating};
use crate::app::Daemon;

type Shared<P> = State<Arc<Daemon<P>>>;

pub fn routes<P: PodmanClient + 'static>() -> Router<Arc<Daemon<P>>> {
    Router::new()
        .route(endpoints::IMAGES_PRUNE.path, post(prune_images::<P>))
        .route(
            endpoints::IMAGES_RESERVATIONS_LIST.path,
            get(list_reservations::<P>),
        )
        .route(
            endpoints::IMAGES_RESERVATION_ABANDON.path,
            post(abandon_reservation::<P>),
        )
}

/// Reclaims the reservations a previous boot left behind (`reclaim_stale_reservations`): once, at
/// daemon start, before the first reconcile or deploy can create a reservation of this boot. A
/// reservation of the current boot is never touched, nor one a nonterminal platform transaction
/// references. Bookkeeping trouble is logged, never fatal: cleanup stays disabled and `doctor` says
/// why.
pub async fn reclaim_at_startup<P: PodmanClient>(engine: &Reconciler<P>) {
    match engine.reclaim_stale_reservations().await {
        Ok(reclaimed) if reclaimed.is_empty() => {}
        Ok(reclaimed) => {
            let operations: Vec<String> = reclaimed.iter().map(ToString::to_string).collect();
            tracing::info!(
                reclaimed = operations.len(),
                operations = %operations.join(", "),
                "reclaimed image reservations left by a previous boot"
            );
        }
        Err(error) => tracing::warn!(%error, "cannot reclaim stale image reservations"),
    }
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
    Ok(Json(reply(report)))
}

/// A blocked pass (provenance could not be read or written) is a normal answer with `blocked: true`
/// and the reason in `diagnostics`, so `--json` callers and the CLI see what happened (and the true
/// `removed` list when only the final write failed). It is not an HTTP error: the request itself
/// was valid and served.
fn reply(report: PruneReport) -> PruneImagesResponse {
    let mut response = response(report);
    if response.blocked && !response.removed.is_empty() {
        response.diagnostics.push(format!(
            "{} image(s) had already been removed in this pass",
            response.removed.len()
        ));
    }
    response
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
        blocked: report.blocked,
    }
}

/// `GET /v1/images/reservations`: the durable reservations, oldest first. Read-only: it does not
/// wait for a running deploy.
async fn list_reservations<P: PodmanClient + 'static>(
    State(d): Shared<P>,
) -> Result<Json<ListReservationsResponse>, Fail> {
    let reservations = d
        .engine
        .list_reservations()
        .map_err(|e| Fail::internal(e.to_string()))?
        .into_iter()
        .map(reservation_view)
        .collect();
    Ok(Json(ListReservationsResponse {
        reservations,
        capacity: MAX_RESERVATIONS,
    }))
}

/// An allowlist projection: every field of [`ReservationInfo`] is bound, none with `..`.
fn reservation_view(info: ReservationInfo) -> ReservationView {
    let ReservationInfo {
        operation_id,
        phase,
        component,
        pid,
        started_at,
        previous_boot,
        referenced,
        protections,
    } = info;
    ReservationView {
        operation_id,
        phase: match phase {
            ReservationPhase::Loading => "loading",
            ReservationPhase::Loaded => "loaded",
            ReservationPhase::Deploying => "deploying",
            ReservationPhase::Coordinating => "coordinating",
        }
        .to_owned(),
        component,
        pid,
        started_at,
        previous_boot,
        referenced,
        protections,
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
    fn a_blocked_report_is_a_response_naming_the_reason() {
        let report = PruneReport {
            blocked: true,
            diagnostics: vec!["image retention is blocked: managed-images.toml: bad".into()],
            ..PruneReport::default()
        };
        let response = reply(report);
        assert!(
            response.blocked,
            "a blocked pass must not look like an empty prune"
        );
        assert!(response.removed.is_empty());
        assert!(response.diagnostics[0].contains("managed-images.toml"));
    }

    #[test]
    fn a_blocked_report_after_removals_says_how_many_images_are_gone() {
        let gone = ImageInfo {
            id: "e".repeat(64),
            digest: None,
            standalone_digest: None,
            repo_tags: Vec::new(),
            repo_digests: Vec::new(),
            size_bytes: 100,
            labels: Default::default(),
        };
        let report = PruneReport {
            blocked: true,
            removed: vec![gone.clone(), gone],
            diagnostics: vec!["managed-images.toml: disk full".into()],
            ..PruneReport::default()
        };
        let response = reply(report);
        assert!(response.blocked);
        assert_eq!(response.removed.len(), 2, "the true removed list is kept");
        let text = response.diagnostics.join("; ");
        assert!(text.contains("disk full"), "{text}");
        assert!(
            text.contains("2 image(s) had already been removed"),
            "{text}"
        );
    }

    #[test]
    fn an_unblocked_report_is_not_blocked() {
        assert!(!reply(PruneReport::default()).blocked);
    }
}
