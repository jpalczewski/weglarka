//! `SecretOps` — operations on secrets that never return the value (#213, seed of #199).
//!
//! The daemon needs a plain client secret only to hand it to Podman. Minting therefore goes through
//! this trait, whose methods return at most a [`Pbkdf2Digest`]: a future vault process (#200) can
//! implement it over IPC and the daemon never reads the plaintext. Today every [`SecretStore`] gets
//! the operations from the blanket impl below (no wrapper type); the digest is kept next to the
//! value as `<scope>.<name>-digest` — an implementation detail callers never see.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};

use crate::secret_store::{SecretError, SecretStore, SecretValue, split_scoped};

/// PBKDF2-HMAC-SHA512 iterations (Authelia's default for this variant; the CLI's own default is lower).
pub const PBKDF2_ITERATIONS: u32 = 310_000;
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 64;
const PREFIX: &str = "$pbkdf2-sha512$";
/// Longest value a mint may request; keeps a typo from allocating megabytes.
const MAX_MINT_LEN: usize = 1024;

/// Characters a minted value may be drawn from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alphabet {
    /// RFC 3986 unreserved set `[A-Za-z0-9-._~]`: safe in URLs, env files and basic-auth.
    Rfc3986Unreserved,
}

impl Alphabet {
    fn chars(self) -> &'static [u8] {
        match self {
            Self::Rfc3986Unreserved => {
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
            }
        }
    }
}

/// What to mint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MintSpec {
    pub len: usize,
    pub alphabet: Alphabet,
}

/// PBKDF2 digest in the crypt form Authelia stores: `$pbkdf2-sha512$<iter>$<salt>$<key>`, salt and
/// key in adapted base64 (standard alphabet, no padding, `+` → `.`). Not secret, but `Debug` stays
/// terse; `Display` is the crypt string.
#[derive(Clone, PartialEq, Eq)]
pub struct Pbkdf2Digest(String);

impl Pbkdf2Digest {
    /// Derives the digest of `password` with an explicit salt (known-answer tests, minting).
    pub(crate) fn derive(password: &[u8], salt: &[u8; SALT_LEN], iterations: u32) -> Self {
        let iter = std::num::NonZeroU32::new(iterations).expect("iterations must be non-zero");
        let mut key = [0u8; KEY_LEN];
        pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA512, iter, salt, password, &mut key);
        Self(format!(
            "{PREFIX}{iterations}${}${}",
            adapted_b64(salt),
            adapted_b64(&key)
        ))
    }

    fn mint(password: &[u8]) -> Result<Self, SecretError> {
        let mut salt = [0u8; SALT_LEN];
        SystemRandom::new()
            .fill(&mut salt)
            .map_err(|_| SecretError::Io("system random failed".into()))?;
        Ok(Self::derive(password, &salt, PBKDF2_ITERATIONS))
    }

    /// Validates the shape of a stored digest (`name` only labels the error, never the value).
    pub fn parse(name: &str, s: &str) -> Result<Self, SecretError> {
        let bad = |reason| SecretError::Malformed {
            name: name.to_owned(),
            reason,
        };
        let rest = s
            .strip_prefix(PREFIX)
            .ok_or_else(|| bad("not a pbkdf2-sha512 digest"))?;
        let mut parts = rest.split('$');
        let (Some(iter), Some(salt), Some(key), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(bad("expected iterations, salt and key"));
        };
        if iter.parse::<u32>().is_ok_and(|n| n > 0) {
            let adapted = |p: &str, len: usize| {
                p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'/')
                    && STANDARD_NO_PAD
                        .decode(p.replace('.', "+"))
                        .is_ok_and(|v| v.len() == len)
            };
            if adapted(salt, SALT_LEN) && adapted(key, KEY_LEN) {
                return Ok(Self(s.to_owned()));
            }
        }
        Err(bad("invalid iterations, salt or key"))
    }
}

fn adapted_b64(bytes: &[u8]) -> String {
    STANDARD_NO_PAD.encode(bytes).replace('+', ".")
}

impl fmt::Display for Pbkdf2Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Pbkdf2Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Pbkdf2Digest(pbkdf2-sha512)")
    }
}

/// Operations on secrets that never return the value. Synchronous and dyn-safe, like [`SecretStore`].
pub trait SecretOps: Send + Sync {
    /// Idempotent: when `name` is absent draws a random value from `spec` and stores it with its
    /// digest; returns the digest either way. Never returns the value.
    fn mint_hashed(&self, name: &str, spec: &MintSpec) -> Result<Pbkdf2Digest, SecretError>;
    /// Replaces value and digest; returns the new digest.
    fn rotate_hashed(&self, name: &str, spec: &MintSpec) -> Result<Pbkdf2Digest, SecretError>;
    /// The stored digest of a minted secret, `None` when it was not minted. Reads the digest entry
    /// only: a digest-only orphan (value removed out of band) still yields `Some`.
    fn digest(&self, name: &str) -> Result<Option<Pbkdf2Digest>, SecretError>;
}

/// Where the digest of `name` lives: `<scope>.<stem>-digest` for `<scope>.<stem>-secret`, else
/// `<name>-digest`.
pub fn digest_name(name: &str) -> Result<String, SecretError> {
    split_scoped(name)?;
    let base = name.strip_suffix("-secret").unwrap_or(name);
    let digest = format!("{base}-digest");
    split_scoped(&digest)?;
    Ok(digest)
}

fn draw(spec: &MintSpec) -> Result<SecretValue, SecretError> {
    if spec.len == 0 || spec.len > MAX_MINT_LEN {
        return Err(SecretError::InvalidMint("length must be 1..=1024"));
    }
    let chars = spec.alphabet.chars();
    // Rejection sampling: bytes at or above the largest multiple of the alphabet size would bias
    // the draw.
    let limit = 256 - 256 % chars.len();
    let rng = SystemRandom::new();
    let mut out = Vec::with_capacity(spec.len);
    let mut buf = [0u8; 64];
    while out.len() < spec.len {
        rng.fill(&mut buf)
            .map_err(|_| SecretError::Io("system random failed".into()))?;
        out.extend(
            buf.iter()
                .filter(|b| usize::from(**b) < limit)
                .map(|b| chars[usize::from(*b) % chars.len()])
                .take(spec.len - out.len()),
        );
    }
    Ok(SecretValue::new(out))
}

impl<S: SecretStore + ?Sized> SecretOps for S {
    fn mint_hashed(&self, name: &str, spec: &MintSpec) -> Result<Pbkdf2Digest, SecretError> {
        let dname = digest_name(name)?;
        if let Some(value) = self.get(name)? {
            return match self.digest(name)? {
                Some(d) => Ok(d),
                // A crash between the two writes: derive the missing half from the stored value.
                None => {
                    let d = Pbkdf2Digest::mint(value.expose())?;
                    self.set(&dname, SecretValue::new(d.to_string()))?;
                    Ok(d)
                }
            };
        }
        let value = draw(spec)?;
        let d = Pbkdf2Digest::mint(value.expose())?;
        // Both land before anything reads them; a value without a digest is repaired above.
        self.set(name, value)?;
        self.set(&dname, SecretValue::new(d.to_string()))?;
        Ok(d)
    }

    fn rotate_hashed(&self, name: &str, spec: &MintSpec) -> Result<Pbkdf2Digest, SecretError> {
        let dname = digest_name(name)?;
        let value = draw(spec)?;
        let d = Pbkdf2Digest::mint(value.expose())?;
        // Drop the old digest first: a crash after any later step leaves "value, no digest" (which
        // `mint_hashed` repairs), never a new value next to a stale digest.
        match self.remove(&dname) {
            Ok(()) | Err(SecretError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }
        self.set(name, value)?;
        self.set(&dname, SecretValue::new(d.to_string()))?;
        Ok(d)
    }

    fn digest(&self, name: &str) -> Result<Option<Pbkdf2Digest>, SecretError> {
        let dname = digest_name(name)?;
        self.get(&dname)?
            .map(|v| {
                let s = std::str::from_utf8(v.expose())
                    .map_err(|_| SecretError::NotUtf8(dname.clone()))?;
                Pbkdf2Digest::parse(&dname, s)
            })
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::FileSecretStore;

    const SPEC: MintSpec = MintSpec {
        len: 72,
        alphabet: Alphabet::Rfc3986Unreserved,
    };

    fn store() -> (tempfile::TempDir, FileSecretStore) {
        let dir = tempfile::tempdir().unwrap();
        let s = FileSecretStore::new(dir.path().join("secrets.toml"));
        (dir, s)
    }

    /// Salt `00 01 .. 0f`, password `kat-fixed-password`. The expected string was derived with an
    /// independent implementation (Python `hashlib.pbkdf2_hmac`); it pins the algorithm, iteration
    /// count and the adapted base64 (`+` → `.`, no padding).
    #[test]
    fn known_answer_independent_implementation() {
        let salt: [u8; 16] = std::array::from_fn(|i| i as u8);
        let d = Pbkdf2Digest::derive(b"kat-fixed-password", &salt, 310_000);
        assert_eq!(
            d.to_string(),
            "$pbkdf2-sha512$310000$AAECAwQFBgcICQoLDA0ODw$31Ke/9pKTxgWdh833OyYNKiarzrCrr9aQiMFBKAdzmuciCeyDEk.Rqx3K2l3Kf4.Ip56NG0Z2ic7H0g1DF8RRw"
        );
    }

    /// Authelia-generated vector: `authelia crypto hash generate pbkdf2 --variant sha512
    /// --iterations 310000 --password <fixed>`; the encoder must re-derive the digest from the
    /// salt in the fixture. TODO(#213): add the fixture from a CI step that runs the Authelia CLI
    /// (not available when P1 was written); until then the vector above is the only evidence.
    #[test]
    #[ignore = "needs the Authelia-generated fixture (see TODO)"]
    fn known_answer_authelia() {
        todo!("commit the Authelia CLI vector (--iterations 310000) and assert re-derivation");
    }

    #[test]
    fn mint_is_idempotent_and_shaped() {
        let (_d, s) = store();
        let a = s.mint_hashed("app.oidc-client-secret", &SPEC).unwrap();
        let b = s.mint_hashed("app.oidc-client-secret", &SPEC).unwrap();
        assert_eq!(a, b);
        assert_eq!(s.digest("app.oidc-client-secret").unwrap(), Some(a.clone()));
        let v = s.get("app.oidc-client-secret").unwrap().unwrap();
        assert_eq!(v.expose().len(), 72);
        assert!(
            v.expose()
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(b))
        );
        assert!(s.get("app.oidc-client-digest").unwrap().is_some());
        // The stored digest is exactly the hash of the stored value.
        let salt_b64 = a.to_string().split('$').nth(3).unwrap().replace('.', "+");
        let salt: [u8; 16] = STANDARD_NO_PAD
            .decode(salt_b64)
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            Pbkdf2Digest::derive(v.expose(), &salt, PBKDF2_ITERATIONS),
            a
        );
    }

    #[test]
    fn rotate_replaces_both() {
        let (_d, s) = store();
        let a = s.mint_hashed("app.oidc-client-secret", &SPEC).unwrap();
        let old = s.get("app.oidc-client-secret").unwrap().unwrap();
        let b = s.rotate_hashed("app.oidc-client-secret", &SPEC).unwrap();
        assert_ne!(a, b);
        assert_ne!(s.get("app.oidc-client-secret").unwrap().unwrap(), old);
        assert_eq!(s.digest("app.oidc-client-secret").unwrap(), Some(b));
    }

    #[test]
    fn missing_digest_is_repaired_and_none_when_unminted() {
        let (_d, s) = store();
        assert_eq!(s.digest("app.oidc-client-secret").unwrap(), None);
        s.set("app.oidc-client-secret", SecretValue::new("x"))
            .unwrap();
        let d = s.mint_hashed("app.oidc-client-secret", &SPEC).unwrap();
        assert_eq!(s.digest("app.oidc-client-secret").unwrap(), Some(d));
        assert_eq!(
            s.get("app.oidc-client-secret").unwrap().unwrap().expose(),
            b"x"
        );
    }

    #[test]
    fn half_finished_rotation_is_repaired_by_mint() {
        let (_d, s) = store();
        s.mint_hashed("app.oidc-client-secret", &SPEC).unwrap();
        // Crash after the new value landed: rotate has already dropped the old digest.
        s.set("app.oidc-client-secret", SecretValue::new("other"))
            .unwrap();
        s.remove("app.oidc-client-digest").unwrap();
        let d = s.mint_hashed("app.oidc-client-secret", &SPEC).unwrap();
        let salt_b64 = d.to_string().split('$').nth(3).unwrap().replace('.', "+");
        let salt: [u8; 16] = STANDARD_NO_PAD
            .decode(salt_b64)
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(Pbkdf2Digest::derive(b"other", &salt, PBKDF2_ITERATIONS), d);
    }

    #[test]
    fn corrupt_digest_is_an_error_without_the_value() {
        let (_d, s) = store();
        s.set("app.oidc-client-digest", SecretValue::new("hunter2"))
            .unwrap();
        let err = s.digest("app.oidc-client-secret").unwrap_err().to_string();
        assert!(
            err.contains("malformed") && !err.contains("hunter2"),
            "{err}"
        );
    }

    #[test]
    fn works_through_dyn_and_rejects_bad_specs() {
        let (_d, s) = store();
        let ops: &dyn SecretOps = &s;
        assert!(
            ops.mint_hashed("app.k", &MintSpec { len: 0, ..SPEC })
                .is_err()
        );
        assert!(ops.mint_hashed("nodot", &SPEC).is_err());
        assert!(ops.mint_hashed("app.k", &SPEC).is_ok());
        assert!(s.get("app.k-digest").unwrap().is_some());
    }

    /// Nothing the trait hands back or derives `Debug` for exposes the plain value.
    #[test]
    fn debug_never_shows_the_value() {
        let (_d, s) = store();
        let d = s.mint_hashed("app.oidc-client-secret", &SPEC).unwrap();
        let plain = String::from_utf8(
            s.get("app.oidc-client-secret")
                .unwrap()
                .unwrap()
                .expose()
                .to_vec(),
        )
        .unwrap();
        for text in [
            format!("{d:?}"),
            format!("{SPEC:?}"),
            format!("{:?}", s.list().unwrap()),
            format!("{d}"),
        ] {
            assert!(!text.contains(&plain), "{text}");
        }
        assert_eq!(format!("{d:?}"), "Pbkdf2Digest(pbkdf2-sha512)");
    }
}
