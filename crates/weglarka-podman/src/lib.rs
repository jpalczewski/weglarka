//! libpod v6 client over a unix socket (hyper + hyper-util, tokio).
//! Implements `weglarka_model::podman::PodmanClient`.
//!
//! The wire models (`wire`) are serde with `#[serde(default)]`, only the used fields, unknown fields
//! ignored; this crate converts them to the domain (`weglarka_model::podman`). Each call
//! opens its own socket connection (a local socket is cheap; no pool, no shared state).
//! Integration tests against a real Podman: `tests/` (require `WEGLARKA_PODMAN_SOCKET`).

mod client;
mod registry_auth;
mod transport;
mod wire;

pub use client::LibpodClient;
