//! Admin endpoints for volumes (`VOLUMES_LIST`, `VOLUMES_EXPORT`, `VOLUMES_IMPORT`) and
//! `?purge_volumes` on `APPS_REMOVE`. **Owner: session 1 (iteration 2).**
//!
//! Hook (one line in `admin.rs::router`, do not grow `admin.rs`): `.merge(volumes::routes())`.
//! Types: `weglarka_api::{ListVolumesResponse, VolumeSummary, RemoveAppQuery}`. Export/import stream
//! the tar through `PodmanClient::volume_export` / `volume_import` (no buffering in the daemon).

/// Placeholder so the module exists; session 1 replaces it with `routes()` and the handlers.
pub const OWNER: &str = "session 1";
