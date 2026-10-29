//! Węglarka model: the domain types, state files, validation and adapter traits that every other
//! crate builds on. No reconcile or deploy logic lives here — that is `weglarka-engine`.
//!
//! Types and traits in this crate are a **contract** for the other crates; changes to it must be
//! additive. The crate calls no Podman and runs no tasks: it must stay cheap to depend on for
//! model-only consumers (API contract, ingress generators, notifications, ACME, DNS, registry).

pub mod admin_auth;
pub mod app;
pub mod config;
pub mod delivery;
pub mod depends;
pub mod environments;
pub mod events;
pub mod fsutil;
pub mod generated;
pub mod generated_state;
pub mod hash;
pub mod host_ports;
pub mod identity;
pub mod labels;
pub mod limits;
pub mod podman;
pub mod secret_ops;
pub mod secret_store;
pub mod secrets;
/// Self-update bookkeeping shared by the daemon and the host-side switcher (issue #99).
pub mod self_update;
pub mod shared_networks;
pub mod shared_volumes;
pub mod state;
pub mod uid_range;
pub mod webhook;
