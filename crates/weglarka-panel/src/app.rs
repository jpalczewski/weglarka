//! The HTTP app. Two route groups:
//!
//! - **public**: `GET /healthz` (no auth, no daemon call) and `/static/*` (embedded, not secret);
//! - **protected**: everything else, behind [`require_session`], which today refuses every
//!   request. Sessions (OIDC login) replace its body without touching the routes around it.
//!
//! [`headers::security_headers`] wraps the whole router, so every response carries the policy.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::get;

use crate::config::PanelConfig;
use crate::daemon::DaemonClient;
use crate::pages::ErrorPage;
use crate::{assets, headers};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<PanelConfig>,
    pub daemon: DaemonClient,
}

impl AppState {
    pub fn new(config: PanelConfig) -> Self {
        let daemon = DaemonClient::from_config(&config);
        Self {
            config: Arc::new(config),
            daemon,
        }
    }
}

pub fn router(state: AppState) -> Router {
    // Routes that need a session go here: add them with `.route(..)` *before* the layer, which
    // wraps what exists at that point. The fallback is wrapped too, so an unknown path is refused
    // the same way as a known one.
    let protected = Router::new()
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_session,
        ));

    Router::new()
        .route("/healthz", get(healthz))
        .route("/static/{file}", get(assets::serve))
        .merge(protected)
        .layer(middleware::from_fn(headers::security_headers))
        .with_state(state)
}

async fn healthz() -> &'static str {
    "ok\n"
}

async fn not_found() -> Response {
    ErrorPage {
        title: "Not found",
        message: "There is nothing here.",
    }
    .respond(StatusCode::NOT_FOUND)
}

/// The single authentication point: default-deny. A later change resolves the session cookie here,
/// puts the session in the request extensions and calls `next`; until then nobody gets past.
/// Unauthenticated callers cannot tell a real route from a missing one.
async fn require_session(
    State(_state): State<AppState>,
    _request: Request,
    _next: Next,
) -> Response {
    ErrorPage {
        title: "Sign-in required",
        message: "You need to sign in to use the panel.",
    }
    .respond(StatusCode::UNAUTHORIZED)
}
