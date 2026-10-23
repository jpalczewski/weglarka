//! Trait `SecretStore` — magazyn sekretów. MVP: `secrets.toml` (0600); później `age`.
//! Synchroniczny (lokalne I/O małych plików; wywołujący używa `spawn_blocking`) i dyn-compatible.

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
    #[error("insecure permissions on {path}: {reason}")]
    Permissions { path: String, reason: String },
}

/// Wartość sekretu; `Debug` nie ujawnia zawartości.
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

/// Metadane do `secrets list` — nigdy wartość.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMeta {
    pub name: String,
    /// RFC 3339.
    pub updated_at: String,
    /// Skrót wartości (pierwsze 8 hex SHA-256) — do wykrywania zmian.
    pub fingerprint: String,
}

pub fn fingerprint(value: &SecretValue) -> String {
    hex::encode(&Sha256::digest(value.expose())[..4])
}

/// Nazwa sekretu w Podmanie i w magazynie: `<instancja>.<nazwa>` (kropka jest niedozwolona
/// w nazwie instancji, więc złożenie jest jednoznaczne).
pub fn scoped_name(instance: &InstanceName, name: &str) -> String {
    format!("{instance}.{name}")
}

pub trait SecretStore: Send + Sync {
    fn get(&self, name: &str) -> Result<Option<SecretValue>, SecretError>;
    /// Tworzy lub nadpisuje. Brak odczytu wartości przez CLI — to API tylko dla demona.
    fn set(&self, name: &str, value: SecretValue) -> Result<(), SecretError>;
    fn remove(&self, name: &str) -> Result<(), SecretError>;
    fn list(&self) -> Result<Vec<SecretMeta>, SecretError>;
}
