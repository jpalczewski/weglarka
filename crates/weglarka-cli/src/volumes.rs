//! `weglarka volumes list|export|import` (API: `VOLUMES_*`) and `apps remove --purge-volumes`.
//! **Owner: session 1 (iteration 2).** Hook: one `Volumes(...)` variant in `cli.rs::Command` and one
//! dispatch line in `commands.rs`. Export/import stream the tar (file or stdin/stdout).
#![allow(dead_code)] // Stub until session 1 wires it in.

/// Placeholder so the module exists.
pub const OWNER: &str = "session 1";
