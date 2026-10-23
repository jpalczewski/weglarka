//! Rdzeń Węglarki: typy domenowe, traity adapterów i (w modułach sesji b) logika reconcile.
//!
//! Własność plików — patrz `CLAUDE.md`. Typy i traity w tym crate to **kontrakt** dla pozostałych
//! crate'ów; zmiany w nim muszą być addytywne, a łamiące uzgadnia się przez właściciela (sesja b).

pub mod app;
pub mod config;
pub mod events;
pub mod hash;
pub mod labels;
pub mod platform;
pub mod podman;
pub mod secret_store;
pub mod state;
pub mod webhook;

// Logika — własność sesji b (zalążki).
pub mod deploy;
pub mod reconcile;
pub mod secrets;

#[cfg(feature = "testing")]
pub mod testing;

#[cfg(all(test, feature = "testing"))]
mod engine_tests;
