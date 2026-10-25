use std::fs;
use std::future::Future;
use std::io;
use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest as _, Sha256};
use weglarka_core::state::write_atomic;

use crate::cert::base_name;
use crate::error::AcmeError;

/// Which ACME challenge type a solver can satisfy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeKind {
    Http01,
    Dns01,
}

impl ChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http01 => "http-01",
            Self::Dns01 => "dns-01",
        }
    }
}

/// One challenge to present, as handed out by the CA for one name.
///
/// The name is the identifier being validated: [`Challenge::new`] reduces a wildcard identifier
/// (`*.example.eu`) to its base name, so solvers never see the `*.` prefix.
/// `key_authorization` is not a secret — it is served publicly at the challenge URL — but it is
/// kept out of `Debug` anyway so logs stay boring.
#[derive(Clone, PartialEq, Eq)]
pub struct Challenge {
    name: String,
    token: String,
    key_authorization: String,
}

impl Challenge {
    /// `identifier` is the name as the CA reports it, wildcard form included.
    pub fn new(identifier: &str, token: String, key_authorization: String) -> Self {
        Self {
            name: base_name(identifier).to_owned(),
            token,
            key_authorization,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Value of the DNS-01 TXT record at `_acme-challenge.<name>` (RFC 8555 §8.4).
    pub fn dns01_txt_value(&self) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(self.key_authorization.as_bytes()))
    }
}

impl std::fmt::Debug for Challenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Challenge")
            .field("name", &self.name)
            .field("token", &self.token)
            .finish_non_exhaustive()
    }
}

/// Presents and removes one challenge. The seam between the ACME client and the way a challenge is
/// answered: HTTP-01 writes a file ([`Http01Solver`]); DNS-01 (issue #97) sets a TXT record.
///
/// `cleanup` must be idempotent and is called by the client after validation, **also when the
/// order failed**; its own errors are logged and never mask the order result.
pub trait ChallengeSolver: Send + Sync {
    fn kind(&self) -> ChallengeKind;

    fn present(&self, challenge: &Challenge) -> impl Future<Output = Result<(), AcmeError>> + Send;

    fn cleanup(&self, challenge: &Challenge) -> impl Future<Output = Result<(), AcmeError>> + Send;
}

/// HTTP-01: writes the key authorization to `<webroot>/<token>` (`0644`), which the ingress serves
/// at `/.well-known/acme-challenge/<token>`. The webroot directory itself is owned by the ingress
/// manager; this solver only creates and removes token files.
#[derive(Debug, Clone)]
pub struct Http01Solver {
    webroot: PathBuf,
}

impl Http01Solver {
    pub fn new(webroot: impl Into<PathBuf>) -> Self {
        Self {
            webroot: webroot.into(),
        }
    }

    /// The token comes from the CA, so it is untrusted input for a file name: base64url only.
    fn token_path(&self, challenge: &Challenge) -> Result<PathBuf, AcmeError> {
        let t = &challenge.token;
        let ok = !t.is_empty()
            && t.len() <= 128
            && t.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !ok {
            return Err(AcmeError::InvalidToken {
                name: challenge.name().to_owned(),
            });
        }
        Ok(self.webroot.join(t))
    }
}

impl ChallengeSolver for Http01Solver {
    fn kind(&self) -> ChallengeKind {
        ChallengeKind::Http01
    }

    async fn present(&self, challenge: &Challenge) -> Result<(), AcmeError> {
        let path = self.token_path(challenge)?;
        write_atomic(&path, challenge.key_authorization.as_bytes(), 0o644)
            .map_err(|source| AcmeError::Io { path, source })
    }

    async fn cleanup(&self, challenge: &Challenge) -> Result<(), AcmeError> {
        let path = self.token_path(challenge)?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(AcmeError::Io { path, source }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn challenge(token: &str) -> Challenge {
        Challenge::new(
            "app.example.eu",
            token.into(),
            format!("{token}.thumbprint"),
        )
    }

    #[tokio::test]
    async fn http01_writes_world_readable_token_and_cleans_up_idempotently() {
        let dir = tempfile::tempdir().unwrap();
        let solver = Http01Solver::new(dir.path());
        let c = challenge("abc-DEF_123");
        solver.present(&c).await.unwrap();
        let path = dir.path().join("abc-DEF_123");
        assert_eq!(fs::read_to_string(&path).unwrap(), "abc-DEF_123.thumbprint");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
        solver.cleanup(&c).await.unwrap();
        assert!(!path.exists());
        solver.cleanup(&c).await.unwrap();
    }

    #[tokio::test]
    async fn http01_rejects_tokens_that_are_not_file_names() {
        let dir = tempfile::tempdir().unwrap();
        let solver = Http01Solver::new(dir.path());
        for bad in ["", "../x", "a/b", ".hidden", "a b", &"a".repeat(129)] {
            let c = challenge(bad);
            assert!(matches!(
                solver.present(&c).await,
                Err(AcmeError::InvalidToken { .. })
            ));
            assert!(solver.cleanup(&c).await.is_err());
        }
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn dns01_value_is_unpadded_base64url_sha256() {
        // RFC 8555 §8.4: base64url(SHA-256(key authorization)), 43 characters, no padding.
        let v = challenge("tok").dns01_txt_value();
        assert_eq!(v.len(), 43);
        assert!(!v.contains('=') && !v.contains('+') && !v.contains('/'));
    }

    #[test]
    fn challenge_debug_hides_the_key_authorization() {
        assert!(!format!("{:?}", challenge("tok")).contains("thumbprint"));
    }
}
