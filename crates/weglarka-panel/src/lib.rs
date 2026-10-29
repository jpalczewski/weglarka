//! The Węglarka admin panel: a server-rendered backend-for-frontend (docs/decisions/0057).
//!
//! The browser gets HTML and a session cookie; the bearer token for the admin API lives only in
//! this process and goes out only over the daemon's token socket (docs/decisions/0056).
//!
//! - [`config`]: typed, validated configuration from the environment; secrets never print.
//! - [`daemon`]: the admin API client (`weglarka-unix-http`), one typed call per [`weglarka_api::Endpoint`].
//! - [`app`]: the axum router: `/healthz`, embedded assets, and default-deny for everything else.
//! - [`headers`]: the security headers every response carries.
//! - [`assets`]: static files embedded in the binary.
//! - [`pages`]: compile-time templates.
//! - [`server`]: serving with graceful shutdown.

pub mod app;
pub mod assets;
pub mod config;
pub mod daemon;
pub mod headers;
pub mod pages;
pub mod server;

pub use app::{AppState, router};
pub use config::{ConfigError, PanelConfig, Secret};
pub use daemon::{Call, DaemonClient, DaemonError};
