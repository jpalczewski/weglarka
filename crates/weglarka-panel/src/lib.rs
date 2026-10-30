//! The Węglarka admin panel: a server-rendered backend-for-frontend (docs/decisions/0057).
//!
//! The browser gets HTML and a session cookie; the bearer token for the admin API lives only in
//! this process and goes out only over the daemon's token socket (docs/decisions/0056).
//!
//! - [`config`]: typed, validated configuration from the environment; secrets never print.
//! - [`daemon`]: the admin API client (`weglarka-unix-http`), one typed call per [`weglarka_api::Endpoint`].
//! - [`app`]: the axum router: `/healthz`, embedded assets, the login flow, and default-deny for everything else.
//! - [`oidc`]: the OIDC client (discovery, PKCE, token exchange and refresh, id token verification).
//! - [`session`]: server-side sessions and pending logins; [`auth`]: login/callback/logout and the session middleware;
//!   [`csrf`]: the check for state-changing requests; [`secure`]: randomness and constant-time comparison.
//! - [`limit`]: the per-address limit on login callbacks and how the client address is found.
//! - [`headers`]: the security headers every response carries.
//! - [`assets`]: static files embedded in the binary.
//! - [`pages`]: compile-time templates.
//! - [`server`]: serving with graceful shutdown.

pub mod app;
pub mod assets;
pub mod auth;
pub mod config;
pub mod csrf;
pub mod daemon;
pub mod headers;
pub mod limit;
pub mod live;
pub mod oidc;
pub mod pages;
pub mod relay;
pub mod routes;
pub mod secure;
pub mod server;
pub mod session;
pub mod views;

pub use app::{AppState, router};
pub use config::{ConfigError, PanelConfig, Secret};
pub use daemon::{Call, DaemonClient, DaemonError};
