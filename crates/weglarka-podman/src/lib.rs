//! Klient libpod v6 po unix sockecie (hyper + hyper-util, tokio).
//! Implementuje `weglarka_core::podman::PodmanClient`.
//!
//! Modele wire (`wire`) to serde z `#[serde(default)]`, tylko używane pola, nieznane pola
//! ignorowane; do domeny (`weglarka_core::podman`) konwertuje je ten crate. Każde wywołanie
//! otwiera własne połączenie z socketem (lokalny socket — tanie, bez puli i stanu współdzielonego).
//! Testy integracyjne z prawdziwym Podmanem: `tests/` (wymagają `WEGLARKA_PODMAN_SOCKET`).

mod client;
mod transport;
mod wire;

pub use client::LibpodClient;
