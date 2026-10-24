//! Webhook listener (TCP, separate router): `POST /webhook/{source}/{instance}` (`github`, and `forgejo` when configured).
//!
//! The HMAC secret is per app (`<instance>.webhook-hmac`), hence the instance is in the path.
//! Order: secret → signature (401) → normalization (204/400) → 202 and `handle_webhook` in the background.

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use weglarka_core::app::InstanceName;
use weglarka_core::deploy::instances_tracking;
use weglarka_core::podman::PodmanClient;
use weglarka_core::secret_store::{SecretStore, scoped_name};
use weglarka_core::state;
use weglarka_core::webhook::{WebhookError, WebhookRequest, WebhookSource};

use crate::app::{Daemon, WEBHOOK_SECRET};

/// Matches nginx's `webhook_max_body_bytes` (1 MiB).
pub const BODY_LIMIT: usize = 1024 * 1024;

pub const PATH: &str = "/webhook/{source}/{instance}";

pub fn router<P: PodmanClient + 'static>(daemon: Arc<Daemon<P>>) -> Router {
    Router::new()
        .route(PATH, post(receive::<P>))
        .fallback(|| async { StatusCode::NOT_FOUND })
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .with_state(daemon)
}

fn request_from(source: &dyn WebhookSource, headers: &HeaderMap, body: &Bytes) -> WebhookRequest {
    WebhookRequest {
        headers: source
            .headers()
            .iter()
            .filter_map(|k| {
                let v = headers.get(*k)?.to_str().ok()?;
                Some(((*k).to_owned(), v.to_owned()))
            })
            .collect(),
        body: body.to_vec(),
    }
}

async fn receive<P: PodmanClient + 'static>(
    State(d): State<Arc<Daemon<P>>>,
    Path((source, raw)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    // An unknown or disabled source (e.g. Forgejo without `[webhook.forgejo]`) is a plain 404.
    let Some(source) = d.webhook_source(&source) else {
        return StatusCode::NOT_FOUND;
    };
    let req = request_from(source, &headers, &body);
    // The delivery id is untrusted until the signature is verified; only a short, safe one goes to logs.
    let delivery = req
        .header(source.delivery_header())
        .filter(|v| v.len() <= 64 && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
        .unwrap_or("-")
        .to_owned();
    let reject = |reason: &str, status: StatusCode| {
        // No secret contents or body — only the reason and identifiers.
        tracing::warn!(instance = ?raw, delivery = ?delivery, reason, "webhook rejected");
        status
    };

    // An unknown app and a missing secret are indistinguishable from a bad signature (401).
    let Ok(instance) = InstanceName::new(raw.clone()) else {
        return reject("invalid instance name", StatusCode::UNAUTHORIZED);
    };
    let store = d.secrets.clone();
    let key = scoped_name(&instance, WEBHOOK_SECRET);
    let secret = match tokio::task::spawn_blocking(move || store.get(&key)).await {
        Ok(Ok(Some(s))) => s,
        Ok(Ok(None)) => return reject("no webhook secret for app", StatusCode::UNAUTHORIZED),
        Ok(Err(e)) => {
            tracing::error!(error = %e, "cannot read webhook secret");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR,
    };
    if source.verify(&req, secret.expose()).is_err() {
        return reject("bad signature", StatusCode::UNAUTHORIZED);
    }

    let event = match source.normalize(&req) {
        Ok(Some(e)) => e,
        Ok(None) => return StatusCode::NO_CONTENT,
        Err(WebhookError::BadPayload(_)) => return reject("bad payload", StatusCode::BAD_REQUEST),
        Err(WebhookError::BadSignature) => {
            return reject("bad signature", StatusCode::UNAUTHORIZED);
        }
    };

    // The signature belongs to this app — the event must concern it (an image it tracks).
    match state::load_apps(&d.paths.state.apps) {
        Ok(apps) if instances_tracking(&apps, &event.image_ref).contains(&instance) => {}
        Ok(_) => return StatusCode::NO_CONTENT,
        Err(e) => {
            tracing::error!(error = %e, "cannot load apps for webhook");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    }

    tracing::info!(instance = %instance, delivery = ?delivery, image = %event.image_ref, "webhook accepted");
    let daemon = d.clone();
    d.spawn_tracked(async move {
        match daemon.engine.handle_webhook(&event).await {
            Ok(outcome) => {
                for (inst, result) in &outcome.results {
                    match result {
                        Ok(o) => tracing::info!(instance = %inst, outcome = ?o, "webhook deploy finished"),
                        Err(e) => tracing::error!(instance = %inst, error = %e, "webhook deploy failed"),
                    }
                }
                if outcome.duplicate {
                    tracing::info!(delivery = ?event.delivery_id, "duplicate delivery ignored");
                }
            }
            Err(e) => tracing::error!(error = %e, "webhook handling failed"),
        }
        daemon.changed();
    });
    StatusCode::ACCEPTED
}
