//! Pure renderers of the identity provider's generated config (issue #42, stage P3).
//!
//! Two files, both JSON text — JSON is valid YAML, so Authelia (go-yaml) reads it from a `.yml` name and
//! no YAML emitter is needed:
//!
//! - [`render_oidc_clients`] → `oidc-clients.yml` (`identity_providers.oidc.clients` + `claims_policies`, #91);
//! - [`render_access_control`] → `access-control.yml` (the whole `access_control` section, #90).
//!
//! No I/O, no engine: the caller (the config pipeline, #212) passes model types in and writes the text.
//! Output is deterministic (clients sorted by id, rules by instance) so the pipeline's fingerprint is
//! stable. Client secrets appear only as the stored digest, never as plaintext.
//!
//! The provider replaces lists wholesale and takes scalars from the last config source, so these files
//! must be loaded last (`--config=/weglarka/generated/current`, #88); that is checked elsewhere.

mod access_control;
mod oidc;

pub use access_control::{ForwardApp, render_access_control};
pub use oidc::{AppClient, render_oidc_clients};

/// Why a file could not be rendered. Every case is an input the model validation should have kept out,
/// so a hit means a caller bug or a hand-edited state file; rendering fails closed instead of guessing.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RenderError {
    #[error("OIDC client {0:?} is listed twice (an instance and an external client share the id)")]
    DuplicateClient(String),
    #[error("OIDC client {0:?} is confidential but has no secret digest")]
    MissingDigest(String),
    #[error("OIDC client {0:?} is public and must not carry a secret digest")]
    UnexpectedDigest(String),
    #[error("OIDC client {0:?} has a malformed secret digest (expected argon2id or pbkdf2)")]
    InvalidDigest(String),
    #[error("invalid issuer {0:?}: {1}")]
    Issuer(String, &'static str),
    #[error("{0}: forward auth needs at least one domain")]
    NoDomains(String),
    #[error("{0}: invalid domain {1:?}")]
    InvalidDomain(String, String),
    #[error("{0}: invalid auth group {1:?}")]
    InvalidGroup(String, String),
    #[error("{0}: invalid path prefix {1:?}: {2}")]
    InvalidPath(String, String, &'static str),
}

fn to_text<T: serde::Serialize>(value: &T) -> String {
    // Maps and structs with string keys cannot fail to serialize.
    let mut text = serde_json::to_string_pretty(value).expect("string-keyed JSON");
    text.push('\n');
    text
}
