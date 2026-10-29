//! The HTTP app. Two route groups:
//!
//! - **public**: `GET /healthz` (no auth, no daemon call), `/static/*` (embedded, not secret) and
//!   the login flow, `GET /auth/login` and `GET /auth/callback`;
//! - **protected**: everything else, behind [`auth::require_session`], which is default-deny: no
//!   valid session cookie, no answer but 401. State-changing requests there also need a CSRF token.
//!
//! [`headers::security_headers`] wraps the whole router, so every response carries the policy.

use std::sync::Arc;

use axum::Extension;
use axum::Router;
use axum::http::StatusCode;
use axum::middleware;
use axum::response::Response;
use axum::routing::{get, post};
use weglarka_api::ListAppsResponse;
use weglarka_api::endpoints::APPS_LIST;
use weglarka_http::{HttpError, Purpose};

use crate::config::PanelConfig;
use crate::daemon::{Call, DaemonClient, DaemonError};
use crate::oidc::OidcClient;
use crate::pages::{ErrorPage, IndexPage};
use crate::session::{Clock, PendingLogins, SessionStore, SessionView};
use crate::{assets, auth, headers};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<PanelConfig>,
    pub daemon: DaemonClient,
    pub oidc: Arc<OidcClient>,
    pub sessions: Arc<SessionStore>,
    pub logins: Arc<PendingLogins>,
    pub clock: Clock,
}

impl AppState {
    pub fn new(config: PanelConfig) -> Result<Self, HttpError> {
        Self::with_clock(config, Clock::default())
    }

    /// [`AppState::new`] with a clock the caller can move (tests age sessions with it).
    pub fn with_clock(config: PanelConfig, clock: Clock) -> Result<Self, HttpError> {
        let http = weglarka_http::client(Purpose::Api)?;
        let daemon = DaemonClient::from_config(&config);
        let sessions = Arc::new(SessionStore::new(
            config.session_idle,
            config.session_max,
            clock.clone(),
        ));
        let config = Arc::new(config);
        Ok(Self {
            oidc: Arc::new(OidcClient::new(config.clone(), http, clock.clone())),
            logins: Arc::new(PendingLogins::new(clock.clone())),
            sessions,
            daemon,
            config,
            clock,
        })
    }
}

pub fn router(state: AppState) -> Router {
    // Routes that need a session go here: add them with `.route(..)` *before* the layer, which
    // wraps what exists at that point. The fallback is wrapped too, so an unknown path is refused
    // the same way as a known one.
    let protected = Router::new()
        .route("/", get(index))
        .route("/auth/logout", post(auth::logout))
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_session,
        ));

    Router::new()
        .route("/healthz", get(healthz))
        .route("/static/{file}", get(assets::serve))
        .route("/auth/login", get(auth::login))
        .route("/auth/callback", get(auth::callback))
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
        sign_in: None,
    }
    .respond(StatusCode::NOT_FOUND)
}

/// The signed-in placeholder; the real pages replace it.
async fn index(
    axum::extract::State(state): axum::extract::State<AppState>,
    Extension(view): Extension<SessionView>,
) -> Response {
    let daemon = match state
        .daemon
        .send::<ListAppsResponse>(&view.token, &Call::new(&APPS_LIST))
        .await
    {
        Ok(list) => format!("The daemon answers: {} app(s).", list.apps.len()),
        // The listing needs the lowest scope: refused here means the daemon gives this identity
        // no access at all (no group, or a token it no longer accepts), so the session ends.
        Err(DaemonError::Unauthorized | DaemonError::Forbidden) => {
            let mut response = ErrorPage {
                title: "Sign-in required",
                message: "The daemon does not accept your session.",
                sign_in: Some("/auth/login"),
            }
            .respond(StatusCode::UNAUTHORIZED);
            response.extensions_mut().insert(auth::EndSession);
            return response;
        }
        Err(e) => format!("The daemon says: {e}."),
    };
    IndexPage {
        user: &view.user.name,
        csrf: &view.csrf,
        daemon: &daemon,
    }
    .respond()
}
