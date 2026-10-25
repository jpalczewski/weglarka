//! Pure ingress config generators (no I/O, `insta` snapshot tests). **Owner: session c.**
//!
//! Input: [`HostConfig`](weglarka_core::config::HostConfig) + apps (`InstanceName → AppSpec`).
//! Both generators first build a shared, validated [`Plan`]; only then is any text produced.
//! Values from app data reach the config only as types with a restricted alphabet
//! ([`Domain`], [`PathPrefix`], `InstanceName`, `u16`), so nginx directives or YAML cannot be injected.

mod cdn;
pub mod nginx;
mod plan;
pub mod traefik;

pub use cdn::{CLOUDFLARE_ETAG, CLOUDFLARE_RANGES, CdnTrust, RangeSource};
pub use plan::{
    AppRoute, Cidr, Domain, IngressError, PathPrefix, Plan, RouteRow, WEBHOOK_UPSTREAM_HOST,
    WebhookRoute,
};
