//! Listener webhooków (TCP, osobny router): `POST /webhook/github/{instance}`.
//!
//! Sekret HMAC jest per apka (`<instancja>.webhook-hmac`), więc instancja siedzi w ścieżce.
//! Kolejność: sekret → podpis (401) → normalizacja (204/400) → 202 i `handle_webhook` w tle.

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
use weglarka_core::webhook::{WebhookError, WebhookRequest};

use crate::app::{Daemon, WEBHOOK_SECRET};
use crate::github::{DELIVERY_HEADER, EVENT_HEADER, SIGNATURE_HEADER};

/// Zgodny z `webhook_max_body_bytes` nginxa (1 MiB).
pub const BODY_LIMIT: usize = 1024 * 1024;

pub const GITHUB_PATH: &str = "/webhook/github/{instance}";

pub fn router<P: PodmanClient + 'static>(daemon: Arc<Daemon<P>>) -> Router {
    Router::new()
        .route(GITHUB_PATH, post(github::<P>))
        .fallback(|| async { StatusCode::NOT_FOUND })
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .with_state(daemon)
}

fn request_from(headers: &HeaderMap, body: &Bytes) -> WebhookRequest {
    let keep = [SIGNATURE_HEADER, EVENT_HEADER, DELIVERY_HEADER];
    WebhookRequest {
        headers: keep
            .iter()
            .filter_map(|k| {
                let v = headers.get(*k)?.to_str().ok()?;
                Some(((*k).to_owned(), v.to_owned()))
            })
            .collect(),
        body: body.to_vec(),
    }
}

async fn github<P: PodmanClient + 'static>(
    State(d): State<Arc<Daemon<P>>>,
    Path(raw): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let req = request_from(&headers, &body);
    // Identyfikator dostawy jest niezaufany do chwili podpisu; do logów tylko krótki, bezpieczny.
    let delivery = req
        .header(DELIVERY_HEADER)
        .filter(|v| v.len() <= 64 && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
        .unwrap_or("-")
        .to_owned();
    let reject = |reason: &str, status: StatusCode| {
        // Bez treści sekretów i ciała — tylko powód i identyfikatory.
        tracing::warn!(instance = ?raw, delivery = ?delivery, reason, "webhook rejected");
        status
    };

    // Nieznana apka i brak sekretu są nieodróżnialne od złego podpisu (401).
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
    if d.github.verify(&req, secret.expose()).is_err() {
        return reject("bad signature", StatusCode::UNAUTHORIZED);
    }

    let event = match d.github.normalize(&req) {
        Ok(Some(e)) => e,
        Ok(None) => return StatusCode::NO_CONTENT,
        Err(WebhookError::BadPayload(_)) => return reject("bad payload", StatusCode::BAD_REQUEST),
        Err(WebhookError::BadSignature) => {
            return reject("bad signature", StatusCode::UNAUTHORIZED);
        }
    };

    // Podpis dotyczy tej apki — zdarzenie musi ją dotyczyć (obraz śledzony przez nią).
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
    let instance = instance.clone();
    d.spawn_tracked(async move {
        match daemon.engine.handle_webhook_for(&event, Some(&instance)).await {
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
