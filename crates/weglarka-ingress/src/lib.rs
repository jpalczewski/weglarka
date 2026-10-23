//! Pure ingress config generators (no I/O, `insta` snapshot tests). **Owner: session c.**
//!
//! Input: [`HostConfig`](weglarka_core::config::HostConfig) + apps (`InstanceName → AppSpec`).
//! Both generators first build a shared, validated [`Plan`]; only then is any text produced.
//! Values from app data reach the config only as types with a restricted alphabet
//! ([`Domain`], `InstanceName`, `u16`), so nginx directives or YAML cannot be injected.

pub mod nginx;
mod plan;
pub mod traefik;

pub use plan::{AppRoute, Cidr, Domain, IngressError, Plan, WEBHOOK_UPSTREAM_HOST, WebhookRoute};
