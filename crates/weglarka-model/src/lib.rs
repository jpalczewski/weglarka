//! Węglarka model: the domain types, state files, validation and adapter traits that every other
//! crate builds on. No reconcile or deploy logic lives here — that is `weglarka-engine`.
//!
//! Types and traits in this crate are a **contract** for the other crates; changes to it must be
//! additive. The crate calls no Podman and runs no tasks: it must stay cheap to depend on for
//! model-only consumers (API contract, ingress generators, notifications, ACME, DNS, registry).

pub mod admin_auth;
pub mod app;
pub mod basic_auth;
pub mod config;
pub mod credential;
pub mod delivery;
pub mod depends;
/// Line diff shared by the CLI (`update --dry-run`) and `platform install --check`.
pub mod diff;
pub mod environments;
pub mod events;
pub mod fsutil;
pub mod generated;
pub mod generated_state;
pub mod hash;
pub mod history;
pub mod host_ports;
pub mod identity;
pub mod image_inventory;
pub mod image_ref;
pub mod ingress_logs;
pub mod internal_hosts;
pub mod labels;
pub mod limits;
pub mod platform_transitions;
pub mod platform_update;
pub mod podman;
/// Contract suite every `PodmanClient` implementation must pass (feature `testing`).
#[cfg(feature = "testing")]
pub mod podman_contract;
pub mod release_set;
pub mod secret_ops;
pub mod secret_store;
pub mod secrets;
/// Self-update bookkeeping shared by the daemon and the host-side switcher (issue #99).
pub mod self_update;
pub mod shared_networks;
pub mod shared_services;
pub mod shared_volumes;
pub mod size_limit;
pub mod state;
pub mod uid_range;
pub mod units;
pub mod user_groups;
pub mod webhook;
