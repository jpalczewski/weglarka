//! `SecretStore` trait — secret storage. MVP: `secrets.toml` (0600); `age` later.
//! Synchronous (local I/O on small files; callers use `spawn_blocking`) and dyn-compatible.

use std::fmt;

use sha2::{Digest as _, Sha256};

use crate::app::InstanceName;

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("secret not found: {0}")]
    NotFound(String),
    #[error("secret store i/o error: {0}")]
    Io(String),
    #[error("secret store is corrupt: {0}")]
    Corrupt(String),
    #[error("invalid secret name {0:?}: expected <instance>.<name>")]
    InvalidName(String),
    /// A host-scoped name must be a bare `<name>` (`valid_secret_name`), no `<instance>.` prefix.
    #[error("invalid host secret name {0:?}: expected [A-Za-z0-9_-]{{1,64}} without a dot")]
    InvalidHostName(String),
    #[error("secret value for {0} is not valid UTF-8")]
    NotUtf8(String),
    /// A reserved secret whose value has the wrong shape. Never carries the value.
    #[error("secret {name} is malformed: {reason}")]
    Malformed { name: String, reason: &'static str },
    #[error("invalid mint request: {0}")]
    InvalidMint(&'static str),
    #[error("insecure permissions on {path}: {reason}")]
    Permissions { path: String, reason: String },
}

/// Secret value; `Debug` does not reveal the contents.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(Vec<u8>);

impl SecretValue {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue(<redacted>)")
    }
}

/// Metadata for `secrets list` — never the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMeta {
    pub name: String,
    /// RFC 3339.
    pub updated_at: String,
    /// Value fingerprint (first 8 hex of SHA-256) — for change detection.
    pub fingerprint: String,
}

pub fn fingerprint(value: &SecretValue) -> String {
    hex::encode(&Sha256::digest(value.expose())[..4])
}

/// Reserved app secret holding the registry credentials for the app's image pulls
/// (`<instance>.registry-auth`, value `<username>:<password>`; docs/decisions/0026). The engine
/// reads it on a pull; it is never bound to the container.
pub const REGISTRY_AUTH_SECRET: &str = "registry-auth";

/// Reserved app secrets of an OIDC client (#213): the 72-char client secret (injected into the app)
/// and its PBKDF2 digest (what the identity provider stores). Written only by `SecretOps` minting,
/// so `secrets set`/`remove` refuse them: one call must not split the pair.
pub const OIDC_CLIENT_SECRET: &str = "oidc-client-secret";
pub const OIDC_CLIENT_DIGEST: &str = "oidc-client-digest";

/// Whether `name` (the `<name>` part) is one of the reserved OIDC credential secrets.
pub fn is_oidc_reserved(name: &str) -> bool {
    name == OIDC_CLIENT_SECRET || name == OIDC_CLIENT_DIGEST
}

/// Reserved app secret holding the HMAC key of the app's webhook (`<instance>.webhook-hmac`); the
/// daemon verifies deliveries with it and it is never handed to a container.
pub const WEBHOOK_HMAC_SECRET: &str = "webhook-hmac";

/// Secrets the daemon manages for itself — registry credentials, the webhook key, the OIDC pair.
/// None of them may be handed to a container that the spec does not already give it (for example
/// by `run --secret`).
pub const DAEMON_MANAGED_SECRETS: &[&str] = &[
    REGISTRY_AUTH_SECRET,
    WEBHOOK_HMAC_SECRET,
    OIDC_CLIENT_SECRET,
    OIDC_CLIENT_DIGEST,
];

/// Whether `name` (the `<name>` part) is one of [`DAEMON_MANAGED_SECRETS`].
pub fn is_daemon_managed(name: &str) -> bool {
    DAEMON_MANAGED_SECRETS.contains(&name)
}

/// Secret name in Podman and in the store: `<instance>.<name>` (a dot is not allowed in an
/// instance name, so the composition is unambiguous).
pub fn scoped_name(instance: &InstanceName, name: &str) -> String {
    format!("{instance}.{name}")
}

/// The `<name>` part of `<instance>.<name>`: `[A-Za-z0-9_-]`, 1–64 chars (no dot — composition
/// with the instance name is unambiguous).
pub fn valid_secret_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Splits `<instance>.<name>` and validates both parts.
pub fn split_scoped(scoped: &str) -> Result<(InstanceName, &str), SecretError> {
    let bad = || SecretError::InvalidName(scoped.to_owned());
    let (inst, name) = scoped.split_once('.').ok_or_else(bad)?;
    let inst = InstanceName::new(inst).map_err(|_| bad())?;
    if !valid_secret_name(name) {
        return Err(bad());
    }
    Ok((inst, name))
}

/// Which namespace a store's keys live in. `App` (the default) composes `<instance>.<name>`;
/// `Host` takes a bare `<name>` with the [`valid_secret_name`] rules (no dot). `secrets.toml` stays
/// app-scoped; host credentials live in a separate `host-secrets.toml` (ADR 0080).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecretScope {
    #[default]
    App,
    Host,
}

impl SecretScope {
    /// Validates `name` against this scope's key rule.
    pub fn validate_name(self, name: &str) -> Result<(), SecretError> {
        match self {
            Self::App => split_scoped(name).map(|_| ()),
            Self::Host if valid_secret_name(name) => Ok(()),
            Self::Host => Err(SecretError::InvalidHostName(name.to_owned())),
        }
    }
}

pub trait SecretStore: Send + Sync {
    fn get(&self, name: &str) -> Result<Option<SecretValue>, SecretError>;
    /// Creates or overwrites. Values are not readable via the CLI — this API is for the daemon only.
    fn set(&self, name: &str, value: SecretValue) -> Result<(), SecretError>;
    fn remove(&self, name: &str) -> Result<(), SecretError>;
    fn list(&self) -> Result<Vec<SecretMeta>, SecretError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_managed_table_is_what_the_predicate_accepts() {
        for name in DAEMON_MANAGED_SECRETS {
            assert!(is_daemon_managed(name), "{name}");
        }
        for name in ["secrets", "webhook-secret", "registry", ""] {
            assert!(!is_daemon_managed(name), "{name}");
        }
        assert_eq!(
            DAEMON_MANAGED_SECRETS,
            [
                REGISTRY_AUTH_SECRET,
                WEBHOOK_HMAC_SECRET,
                OIDC_CLIENT_SECRET,
                OIDC_CLIENT_DIGEST
            ]
        );
    }
}
