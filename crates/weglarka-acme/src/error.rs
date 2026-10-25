use std::io;
use std::path::PathBuf;

use crate::cert::CertIdError;

/// Everything that can go wrong while issuing, storing or inspecting a certificate.
///
/// Messages carry names and paths only — never key material or key authorizations.
#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    #[error(transparent)]
    InvalidId(#[from] CertIdError),
    #[error("invalid certificate name {name:?}: {reason}")]
    InvalidName { name: String, reason: &'static str },
    #[error("challenge {kind} is not supported by this solver")]
    UnsupportedChallenge { kind: &'static str },
    #[error("invalid challenge token for {name}")]
    InvalidToken { name: String },
    #[error("challenge failed for {name}: {reason}")]
    Challenge { name: String, reason: String },
    #[error("ACME account: {0}")]
    AccountKey(String),
    #[error("ACME order failed: {0}")]
    Order(String),
    #[error("cannot read the expiry of the certificate: {0}")]
    Expiry(String),
    #[error("{}: {source}", path.display())]
    Io { path: PathBuf, source: io::Error },
}
