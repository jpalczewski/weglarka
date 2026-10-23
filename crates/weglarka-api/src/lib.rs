//! Kontrakt admin API Węglarki: typy request/response, lista endpointów i wersja.
//! Współdzielony przez demona (serwer) i CLI (klient). Bez serwera i klienta HTTP.
//!
//! Admin API słucha wyłącznie na sockecie unix (`admin.socket`); ciała to JSON.
//! Błędy: [`ApiError`] z odpowiednim kodem HTTP (patrz [`ErrorCode::http_status`]).

pub mod doctor;
pub mod endpoints;
pub mod types;

pub use doctor::{CheckStatus, DoctorCheck, DoctorReport};
pub use endpoints::{ENDPOINTS, Endpoint, Method};
pub use types::*;

/// Wersja kontraktu; prefiks ścieżek (`/v1/...`). Zmiana łamiąca = nowy prefiks.
pub const API_VERSION: &str = "v1";
