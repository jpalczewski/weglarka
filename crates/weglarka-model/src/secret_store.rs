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

pub trait SecretStore: Send + Sync {
    fn get(&self, name: &str) -> Result<Option<SecretValue>, SecretError>;
    /// Creates or overwrites. Values are not readable via the CLI — this API is for the daemon only.
    fn set(&self, name: &str, value: SecretValue) -> Result<(), SecretError>;
    fn remove(&self, name: &str) -> Result<(), SecretError>;
    fn list(&self) -> Result<Vec<SecretMeta>, SecretError>;
}
