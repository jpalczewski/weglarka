//! Węglarka core: domain types, adapter traits and (in session b's modules) the reconcile logic.
//!
//! File ownership — see `CLAUDE.md`. Types and traits in this crate are a **contract** for the other
//! crates; changes to it must be additive, and breaking ones are agreed via the owner (session b).

pub mod app;
pub mod config;
pub mod events;
pub mod hash;
pub mod labels;
pub mod platform;
pub mod podman;
pub mod secret_store;
pub mod state;
pub mod uid_range;
pub mod webhook;

// Logic — owned by session b (stubs). `limits` / `volumes`: iteration 2, sessions 2 / 1 (see CLAUDE.md).
pub mod deploy;
pub mod limits;
pub mod reconcile;
pub mod secrets;
pub mod volumes;
pub mod waiting;

#[cfg(feature = "testing")]
pub mod testing;

#[cfg(all(test, feature = "testing"))]
mod engine_tests;
