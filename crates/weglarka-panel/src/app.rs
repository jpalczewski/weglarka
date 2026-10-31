//! The HTTP app. Two route groups:
//!
//! - **public**: `GET /healthz` (no auth, no daemon call), `/static/*` (embedded, not secret), the
//!   login flow, `GET /auth/login` and `GET /auth/callback`, and `/_weglarka/api/*`, the bearer-only relay to
//!   the daemon ([`relay`], docs/decisions/0060);
//! - **protected**: everything else, behind [`auth::require_session`], which is default-deny: no
//!   valid session cookie, no answer but 401. State-changing requests there also need a CSRF token.
//!
//! [`headers::security_headers`] wraps the whole router, so every response carries the policy.

use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use axum::middleware;
use axum::response::Response;
use axum::routing::{any, get, post};
use weglarka_http::{HttpError, Purpose};

use crate::config::PanelConfig;
use crate::daemon::DaemonClient;
use crate::limit::{self, AddressLimiter};
use crate::live::StreamSlots;
use crate::oidc::OidcClient;
use crate::pages::ErrorPage;
use crate::session::{Clock, PendingLogins, SessionStore};
use crate::{assets, auth, headers, live, relay, routes};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<PanelConfig>,
    pub daemon: DaemonClient,
    pub oidc: Arc<OidcClient>,
    pub sessions: Arc<SessionStore>,
    pub logins: Arc<PendingLogins>,
    /// Login callbacks per client address, checked before `logins` records anything.
    pub callback_limit: Arc<AddressLimiter>,
    pub clock: Clock,
    /// Live streams held per session.
    pub streams: Arc<StreamSlots>,
    /// `/api` requests per client address (docs/decisions/0060).
    pub api_limit: Arc<AddressLimiter>,
    /// Relayed requests in flight, streams included.
    pub api_slots: Arc<tokio::sync::Semaphore>,
    /// Warns once about a proxy missing from `PANEL_TRUSTED_PROXIES`.
    pub proxy_notice: Arc<limit::UntrustedProxyNotice>,
    /// How often the events stream asks the daemon for news.
    pub stream_poll: std::time::Duration,
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
            callback_limit: Arc::new(AddressLimiter::new(clock.clone())),
            sessions,
            daemon,
            config,
            api_limit: Arc::new(AddressLimiter::with_limits(
                clock.clone(),
                relay::LIMIT,
                relay::LIMIT_WINDOW,
            )),
            clock,
            api_slots: Arc::new(tokio::sync::Semaphore::new(relay::MAX_CONCURRENT)),
            streams: Arc::new(StreamSlots::default()),
            proxy_notice: Arc::default(),
            stream_poll: std::time::Duration::from_secs(3),
        })
    }
}

impl AppState {
    /// The client behind a request, for the per-address limits; see [`limit::client_addr`].
    pub fn client_addr(
        &self,
        peer: std::net::IpAddr,
        headers: &axum::http::HeaderMap,
    ) -> std::net::IpAddr {
        let trusted = &self.config.trusted_proxies;
        self.proxy_notice.note(peer, headers, trusted);
        limit::client_addr(peer, headers, trusted)
    }
}

pub fn router(state: AppState) -> Router {
    // Routes that need a session go here: add them with `.route(..)` *before* the layer, which
    // wraps what exists at that point. The fallback is wrapped too, so an unknown path is refused
    // the same way as a known one.
    let protected = Router::new()
        .route("/", get(routes::dashboard))
        .route("/apps", get(routes::apps))
        .route("/apps/{name}", get(routes::app))
        .route("/apps/{name}/stats", get(routes::app_stats))
        .route("/apps/{name}/logs", get(live::logs_section))
        .route("/apps/{name}/logs/stream", get(live::logs_stream))
        .route("/apps/{name}/access", get(live::access_section))
        .route("/apps/{name}/access/stream", get(live::access_stream))
        .route("/doctor", get(routes::doctor))
        .route("/volumes", get(routes::volumes))
        .route("/networks", get(routes::networks))
        .route("/sites", get(routes::sites))
        .route("/notifications", get(routes::notifications))
        .route("/certificates", get(routes::certificates))
        .route("/events", get(routes::events))
        .route("/events/stream", get(live::events_stream))
        .route("/config", get(routes::config))
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
        // Bearer-only, outside `require_session` on purpose: no cookie ever authenticates here.
        .route(&format!("{}/{{*rest}}", relay::PREFIX), any(relay::handle))
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
