//! HTTP probe of the health gate (`health.http`): the daemon requests `GET path` through the ingress
//! nginx (the same route as real traffic) and compares the status. **Owner: session 2 (iteration 2).**
//!
//! Contract: `weglarka_core::app::HttpProbe` (+ validation in `state::validate_app`: needs `port`).
//! Gate rule: when both `health.command` and `health.http` are set, both must pass. The gate itself
//! lives in `weglarka-core/src/deploy.rs` (one call site); keep the probe here, behind a trait if the
//! engine needs to stay free of HTTP.

/// Placeholder so the module exists; session 2 replaces it with the probe.
pub const OWNER: &str = "session 2";
