//! `weglarka apps update <name>` (API: `APPS_UPDATE`, full spec replacement) and rendering of the
//! "waiting for secret" state. **Owner: session 3 (iteration 2).** Hook: one `Update(...)` variant in
//! `cli.rs::AppsCommand` and one dispatch line in `commands.rs`. Read-modify-write: `GET` the spec,
//! apply the flags, `PUT` it back.
#![allow(dead_code)] // Stub until session 3 wires it in.

/// Placeholder so the module exists.
pub const OWNER: &str = "session 3";
