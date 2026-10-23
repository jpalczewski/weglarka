//! `apps update` (`PUT /v1/apps/{name}`, [`weglarka_api::UpdateAppRequest`]) and the "waiting for
//! secret" state. **Owner: session 3 (iteration 2).**
//!
//! Hook (one line in `admin.rs::router`): add `put(update::update_app::<P>)` to the `APPS_SHOW` route.
//! Semantics: full spec replacement — validate, persist `apps.toml`, reconcile; see the request type.
//! "Waiting for secret": `AppState::waiting_for_secrets` + `RuntimeState::WaitingForSecret`; setting
//! the last missing secret (`set_secret` in `admin.rs`) triggers the deploy.

/// Placeholder so the module exists; session 3 replaces it with the handler.
pub const OWNER: &str = "session 3";
