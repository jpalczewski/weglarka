//! Czyste generatory configu ingressu (bez I/O, snapshot testy `insta`). **Własność: sesja c.**
//!
//! Wejście: [`HostConfig`](weglarka_core::config::HostConfig) + apki (`InstanceName → AppSpec`).
//! Oba generatory budują najpierw wspólny, zwalidowany [`Plan`]; dopiero z niego powstaje tekst.
//! Wartości z danych apki trafiają do configu wyłącznie jako typy o ograniczonym alfabecie
//! ([`Domain`], `InstanceName`, `u16`), więc nie da się wstrzyknąć dyrektyw nginx ani YAML-a.

pub mod nginx;
mod plan;
pub mod traefik;

pub use plan::{AppRoute, Cidr, Domain, IngressError, Plan, WEBHOOK_UPSTREAM_HOST, WebhookRoute};
