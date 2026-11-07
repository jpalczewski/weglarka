//! `SecretOps` — operations on secrets that never return the value (#213, seed of #199).
//!
//! The daemon needs a plain client secret only to hand it to Podman. Minting therefore goes through
//! this trait, whose methods return at most a [`Digest`] of one of the [`DigestKind`]s — a PBKDF2
//! digest for Authelia, the unsalted SHA-256 hex of a Redis ACL file, a SCRAM-SHA-256 verifier for
//! Postgres roles: a future vault process (#200) can implement it over IPC and the daemon never
//! reads the plaintext. Today every [`SecretStore`] gets the operations from the blanket impl below
//! (no wrapper type); the digest is kept next to the value as `<scope>.<name>-digest` — an
//! implementation detail callers never see.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use ring::digest;
use ring::hmac;
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

/// Redis ACL password digest (#591, managed Redis contract in #593): 64 lower-case hex characters of
/// SHA-256 over the password bytes, written into `users.acl` as `#<hex>`. Unsalted on purpose: the
/// minted values are high-entropy, and no operator-chosen password ever gets this digest.
#[derive(Clone, PartialEq, Eq)]
pub struct RedisAclSha256(String);

impl RedisAclSha256 {
    /// Digest of `password` (known-answer tests, minting).
    pub fn derive(password: &[u8]) -> Self {
        Self(hex::encode(digest::digest(&digest::SHA256, password)))
    }

    /// Validates the shape of a stored digest (`name` only labels the error, never the value).
    pub fn parse(name: &str, s: &str) -> Result<Self, SecretError> {
        let lower_hex = |b: u8| matches!(b, b'0'..=b'9' | b'a'..=b'f');
        if s.len() == 2 * SHA256_LEN && s.bytes().all(lower_hex) {
            return Ok(Self(s.to_owned()));
        }
        Err(SecretError::Malformed {
            name: name.to_owned(),
            reason: "expected 64 lower-case hex characters of a SHA-256 digest",
        })
    }
}

impl fmt::Display for RedisAclSha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for RedisAclSha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RedisAclSha256(sha256)")
    }
}

/// SCRAM iteration count of a [`ScramSha256Verifier`] (Postgres' default, RFC 7677's example).
pub const SCRAM_ITERATIONS: u32 = 4096;
/// Salt length of a [`ScramSha256Verifier`].
pub const SCRAM_SALT_LEN: usize = 16;
/// Length of the two SCRAM keys (RFC 5802: the output of SHA-256).
const SCRAM_KEY_LEN: usize = 32;
/// Bytes of a SHA-256 digest.
const SHA256_LEN: usize = 32;
const SCRAM_PREFIX: &str = "SCRAM-SHA-256$";

/// SCRAM-SHA-256 verifier in the form Postgres stores (#591, managed Postgres contract in #596):
/// `SCRAM-SHA-256$<iter>:<salt b64>$<StoredKey b64>:<ServerKey b64>` (RFC 5802/7677, standard
/// base64 with padding). A random salt per mint; the verifier is stored next to the value, so the
/// same secret renders the same bytes until it is minted again or rotated.
#[derive(Clone, PartialEq, Eq)]
pub struct ScramSha256Verifier(String);

impl ScramSha256Verifier {
    /// Derives the verifier of `password` with an explicit salt (known-answer tests, minting).
    ///
    /// RFC 5802/7677: SaltedPassword = PBKDF2-HMAC-SHA256(password, salt, iterations), ClientKey =
    /// HMAC(SaltedPassword, "Client Key"), StoredKey = SHA-256(ClientKey), ServerKey =
    /// HMAC(SaltedPassword, "Server Key"). The client proof is what a server checks StoredKey
    /// against; the plain password never has to be stored.
    pub fn derive(password: &[u8], salt: &[u8], iterations: u32) -> Self {
        let iter = std::num::NonZeroU32::new(iterations).expect("iterations must be non-zero");
        let mut salted = [0u8; SCRAM_KEY_LEN];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            iter,
            salt,
            password,
            &mut salted,
        );
        let sign = |key: &[u8], message: &[u8]| {
            hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), message)
        };
        let client_key = sign(&salted, b"Client Key");
        let stored_key = digest::digest(&digest::SHA256, client_key.as_ref());
        let server_key = sign(&salted, b"Server Key");
        Self(format!(
            "{SCRAM_PREFIX}{iterations}:{}${}:{}",
            STANDARD.encode(salt),
            STANDARD.encode(stored_key.as_ref()),
            STANDARD.encode(server_key.as_ref())
        ))
    }

    /// Validates the shape of a stored verifier (`name` only labels the error, never the value).
    /// The salt must be at least one byte, not exactly [`SCRAM_SALT_LEN`]: the verifier also has to
    /// read back a salt another implementation chose (the contract fixtures use 17 bytes).
    pub fn parse(name: &str, s: &str) -> Result<Self, SecretError> {
        let bad = |reason| SecretError::Malformed {
            name: name.to_owned(),
            reason,
        };
        let rest = s
            .strip_prefix(SCRAM_PREFIX)
            .ok_or_else(|| bad("not a SCRAM-SHA-256 verifier"))?;
        let (head, keys) = rest
            .split_once('$')
            .ok_or_else(|| bad("expected iterations, salt and two keys"))?;
        let (iter, salt) = head
            .split_once(':')
            .ok_or_else(|| bad("expected iterations and salt"))?;
        let (stored, server) = keys
            .split_once(':')
            .ok_or_else(|| bad("expected a StoredKey and a ServerKey"))?;
        let decoded = |field: &str| STANDARD.decode(field).ok();
        let well_formed = iter.bytes().all(|b| b.is_ascii_digit())
            && iter.parse::<u32>().is_ok_and(|n| n > 0)
            && decoded(salt).is_some_and(|v| !v.is_empty())
            && decoded(stored).is_some_and(|v| v.len() == SCRAM_KEY_LEN)
            && decoded(server).is_some_and(|v| v.len() == SCRAM_KEY_LEN);
        if well_formed {
            return Ok(Self(s.to_owned()));
        }
        Err(bad("invalid iterations, salt or keys"))
    }
}

impl fmt::Display for ScramSha256Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for ScramSha256Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScramSha256Verifier(scram-sha-256)")
    }
}

/// Which digest a consumer stores for a minted secret: one kind per consumer (#591).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestKind {
    /// Authelia (`$pbkdf2-sha512$…`).
    Pbkdf2Sha512,
    /// Redis ACL files (`#<sha256 hex>`).
    RedisAclSha256,
    /// Postgres roles (`SCRAM-SHA-256$…`).
    ScramSha256,
}

/// A digest of one of the [`DigestKind`]s. `Display` is the stored form; `Debug` names the kind only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Digest {
    Pbkdf2(Pbkdf2Digest),
    RedisAcl(RedisAclSha256),
    Scram(ScramSha256Verifier),
}

impl Digest {
    pub fn kind(&self) -> DigestKind {
        match self {
            Self::Pbkdf2(_) => DigestKind::Pbkdf2Sha512,
            Self::RedisAcl(_) => DigestKind::RedisAclSha256,
            Self::Scram(_) => DigestKind::ScramSha256,
        }
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pbkdf2(d) => d.fmt(f),
            Self::RedisAcl(d) => d.fmt(f),
            Self::Scram(d) => d.fmt(f),
        }
    }
}

impl DigestKind {
    /// The digest of `value` in this kind's stored form, drawing a random salt where the kind has
    /// one. The single place that knows which algorithm backs which consumer.
    fn mint(self, value: &[u8]) -> Result<Digest, SecretError> {
        match self {
            Self::Pbkdf2Sha512 => Ok(Digest::Pbkdf2(Pbkdf2Digest::mint(value)?)),
            Self::RedisAclSha256 => Ok(Digest::RedisAcl(RedisAclSha256::derive(value))),
            Self::ScramSha256 => {
                let mut salt = [0u8; SCRAM_SALT_LEN];
                SystemRandom::new()
                    .fill(&mut salt)
                    .map_err(|_| SecretError::Io("system random failed".into()))?;
                Ok(Digest::Scram(ScramSha256Verifier::derive(
                    value,
                    &salt,
                    SCRAM_ITERATIONS,
                )))
            }
        }
    }

    /// Parses `stored` as this kind, `name` labelling the error only (never the string, never the
    /// value). A digest of another kind fails here: the formats do not overlap.
    fn parse(self, name: &str, stored: &str) -> Result<Digest, SecretError> {
        match self {
            Self::Pbkdf2Sha512 => Pbkdf2Digest::parse(name, stored).map(Digest::Pbkdf2),
            Self::RedisAclSha256 => RedisAclSha256::parse(name, stored).map(Digest::RedisAcl),
            Self::ScramSha256 => ScramSha256Verifier::parse(name, stored).map(Digest::Scram),
        }
    }
}

/// The PBKDF2 digest out of `digest`, which callers of the [`DigestKind::Pbkdf2Sha512`] methods
/// expect. The kind and the variant cannot disagree; a mismatch is an internal error, not a panic.
fn pbkdf2_digest(digest: Digest, name: &str) -> Result<Pbkdf2Digest, SecretError> {
    match digest {
        Digest::Pbkdf2(d) => Ok(d),
        Digest::RedisAcl(_) | Digest::Scram(_) => Err(SecretError::Malformed {
            name: digest_name(name)?,
            reason: "expected a pbkdf2-sha512 digest",
        }),
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
    /// [`SecretOps::mint_hashed`] for any [`DigestKind`] (#591). A stored digest of another kind is
    /// an error, never silently replaced.
    fn mint_digest(
        &self,
        name: &str,
        spec: &MintSpec,
        kind: DigestKind,
    ) -> Result<Digest, SecretError>;
    /// [`SecretOps::rotate_hashed`] for any [`DigestKind`] (#591).
    fn rotate_digest(
        &self,
        name: &str,
        spec: &MintSpec,
        kind: DigestKind,
    ) -> Result<Digest, SecretError>;
    /// [`SecretOps::digest`] for any [`DigestKind`] (#591): `None` when not minted, an error when
    /// the stored digest is of another kind or malformed.
    fn stored_digest(&self, name: &str, kind: DigestKind) -> Result<Option<Digest>, SecretError>;
}

/// Where the digest of `name` lives: `<scope>.<stem>-digest` for `<scope>.<stem>-secret`, else
/// `<name>-digest`. App-scope only: it validates through [`split_scoped`], so a host-scoped store
/// ([`SecretScope::Host`](crate::secret_store::SecretScope), ADR 0080) rejects every mint — minting
/// is an app-secret operation, host credentials are set directly.
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
        pbkdf2_digest(
            self.mint_digest(name, spec, DigestKind::Pbkdf2Sha512)?,
            name,
        )
    }

    fn rotate_hashed(&self, name: &str, spec: &MintSpec) -> Result<Pbkdf2Digest, SecretError> {
        pbkdf2_digest(
            self.rotate_digest(name, spec, DigestKind::Pbkdf2Sha512)?,
            name,
        )
    }

    fn digest(&self, name: &str) -> Result<Option<Pbkdf2Digest>, SecretError> {
        self.stored_digest(name, DigestKind::Pbkdf2Sha512)?
            .map(|d| pbkdf2_digest(d, name))
            .transpose()
    }

    fn mint_digest(
        &self,
        name: &str,
        spec: &MintSpec,
        kind: DigestKind,
    ) -> Result<Digest, SecretError> {
        let dname = digest_name(name)?;
        if let Some(value) = self.get(name)? {
            return match self.stored_digest(name, kind)? {
                Some(d) => Ok(d),
                // A crash between the two writes: derive the missing half from the stored value.
                None => {
                    let d = kind.mint(value.expose())?;
                    self.set(&dname, SecretValue::new(d.to_string()))?;
                    Ok(d)
                }
            };
        }
        let value = draw(spec)?;
        let d = kind.mint(value.expose())?;
        // Both land before anything reads them; a value without a digest is repaired above.
        self.set(name, value)?;
        self.set(&dname, SecretValue::new(d.to_string()))?;
        Ok(d)
    }

    fn rotate_digest(
        &self,
        name: &str,
        spec: &MintSpec,
        kind: DigestKind,
    ) -> Result<Digest, SecretError> {
        let dname = digest_name(name)?;
        let value = draw(spec)?;
        let d = kind.mint(value.expose())?;
        // Drop the old digest first: a crash after any later step leaves "value, no digest" (which
        // `mint_digest` repairs), never a new value next to a stale digest.
        match self.remove(&dname) {
            Ok(()) | Err(SecretError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }
        self.set(name, value)?;
        self.set(&dname, SecretValue::new(d.to_string()))?;
        Ok(d)
    }

    fn stored_digest(&self, name: &str, kind: DigestKind) -> Result<Option<Digest>, SecretError> {
        let dname = digest_name(name)?;
        self.get(&dname)?
            .map(|v| {
                let s = std::str::from_utf8(v.expose())
                    .map_err(|_| SecretError::NotUtf8(dname.clone()))?;
                kind.parse(&dname, s)
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
        FileSecretStore::in_tempdir()
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

    const KINDS: [DigestKind; 3] = [
        DigestKind::Pbkdf2Sha512,
        DigestKind::RedisAclSha256,
        DigestKind::ScramSha256,
    ];

    /// The digest `kind` gives `value` when the salt is taken from an already stored digest, so a
    /// mint can be re-derived from the value and compared with what landed in the store.
    fn rederive(kind: DigestKind, value: &[u8], digest: &Digest) -> Digest {
        match (kind, digest) {
            (DigestKind::Pbkdf2Sha512, Digest::Pbkdf2(d)) => {
                let salt: [u8; SALT_LEN] = STANDARD_NO_PAD
                    .decode(d.to_string().split('$').nth(3).unwrap().replace('.', "+"))
                    .unwrap()
                    .try_into()
                    .unwrap();
                Digest::Pbkdf2(Pbkdf2Digest::derive(value, &salt, PBKDF2_ITERATIONS))
            }
            (DigestKind::RedisAclSha256, Digest::RedisAcl(_)) => {
                Digest::RedisAcl(RedisAclSha256::derive(value))
            }
            (DigestKind::ScramSha256, Digest::Scram(d)) => {
                let (iterations, salt) = scram_parameters(&d.to_string());
                Digest::Scram(ScramSha256Verifier::derive(value, &salt, iterations))
            }
            (kind, digest) => panic!("{kind:?} and {digest:?} disagree"),
        }
    }

    /// Iterations and salt of a stored SCRAM verifier (the fields a verifier has to carry).
    fn scram_parameters(stored: &str) -> (u32, Vec<u8>) {
        let rest = stored.strip_prefix("SCRAM-SHA-256$").unwrap();
        let (head, _keys) = rest.split_once('$').unwrap();
        let (iterations, salt) = head.split_once(':').unwrap();
        (iterations.parse().unwrap(), STANDARD.decode(salt).unwrap())
    }

    /// Redis fixtures (#593): both digests come from an independent implementation (Python
    /// `hashlib.sha256`). They pin the lower-case hex form written to `users.acl` as `#<hex>`.
    #[test]
    fn redis_acl_sha256_known_answers() {
        for (password, expected) in [
            (
                "example-member-password-not-a-secret-0001",
                "dae08700a6ef0788315e69bf4410fd3951d3dfae0012814ee694c1443360d7ce",
            ),
            (
                "example-member-password-not-a-secret-0002",
                "201d82e986e84dcccec748b71c11117353cecace8a8ec1fb7e197d2bdc555acf",
            ),
        ] {
            let d = RedisAclSha256::derive(password.as_bytes());
            assert_eq!(d.to_string(), expected);
            assert_eq!(
                RedisAclSha256::parse("redis.role-digest", &d.to_string()).unwrap(),
                d
            );
        }
    }

    /// RFC 7677's vector (password `pencil`), re-derived from the salt the verifier carries: it pins
    /// SaltedPassword, ClientKey/StoredKey/ServerKey, the iteration count and the padded base64
    /// (Python `hashlib.pbkdf2_hmac` + `hmac` + `base64` gave the same string).
    #[test]
    fn scram_sha256_known_answer_rfc7677() {
        let salt = STANDARD.decode("W22ZaJ0SNY7soEsUEjb6gQ==").unwrap();
        let d = ScramSha256Verifier::derive(b"pencil", &salt, SCRAM_ITERATIONS);
        assert_eq!(
            d.to_string(),
            "SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ==$WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=:wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU="
        );
        assert_eq!(
            ScramSha256Verifier::parse("pg.role-digest", &d.to_string()).unwrap(),
            d
        );
        assert_eq!(scram_parameters(&d.to_string()), (SCRAM_ITERATIONS, salt));
    }

    /// Each `parse` accepts what its `derive` produces — including salt lengths other than the one
    /// minting uses (the contract fixtures carry 17-byte salts).
    #[test]
    fn derived_digests_parse_themselves() {
        let redis = RedisAclSha256::derive(b"x");
        assert_eq!(
            RedisAclSha256::parse("redis.role-digest", &redis.to_string()).unwrap(),
            redis
        );
        for salt_len in [1, SCRAM_SALT_LEN, 17] {
            let d = ScramSha256Verifier::derive(b"x", &vec![9u8; salt_len], SCRAM_ITERATIONS);
            assert_eq!(
                ScramSha256Verifier::parse("pg.role-digest", &d.to_string()).unwrap(),
                d,
                "salt of {salt_len} bytes"
            );
        }
        let pbkdf2 = Pbkdf2Digest::derive(b"x", &[0u8; SALT_LEN], PBKDF2_ITERATIONS);
        assert_eq!(
            Pbkdf2Digest::parse("app.oidc-client-digest", &pbkdf2.to_string()).unwrap(),
            pbkdf2
        );
    }

    fn scram(iterations: &str, salt: &str, stored: &str, server: &str) -> String {
        format!("SCRAM-SHA-256${iterations}:{salt}${stored}:{server}")
    }

    #[test]
    fn parse_rejects_bad_shapes() {
        let bad_redis = [
            "dae08700a6ef0788315e69bf4410fd3951d3dfae0012814ee694c1443360d7c",
            "dae08700a6ef0788315e69bf4410fd3951d3dfae0012814ee694c1443360d7ce0",
            "DAE08700A6EF0788315E69BF4410FD3951D3DFAE0012814EE694C1443360D7CE",
            "#dae08700a6ef0788315e69bf4410fd3951d3dfae0012814ee694c1443360d7ce",
            "",
            "hunter2",
        ];
        for bad in bad_redis {
            let err = RedisAclSha256::parse("redis.role-digest", bad)
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("malformed") && err.contains("redis.role-digest"),
                "{err}"
            );
            // The empty digest itself is trivially "contained" in any message.
            if !bad.is_empty() {
                assert!(!err.contains(bad), "{err}");
            }
        }

        const SALT: &str = "W22ZaJ0SNY7soEsUEjb6gQ==";
        const STORED: &str = "WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=";
        const SERVER: &str = "wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=";
        // The positive control: every rejection below differs from this string in one way.
        let good = scram("4096", SALT, STORED, SERVER);
        assert_eq!(
            ScramSha256Verifier::parse("pg.role-digest", &good).unwrap(),
            ScramSha256Verifier::derive(
                b"pencil",
                &STANDARD.decode(SALT).unwrap(),
                SCRAM_ITERATIONS
            )
        );
        let short = STANDARD.encode([0u8; SCRAM_KEY_LEN - 1]);
        let bad_scram = [
            // No iterations at all.
            format!("SCRAM-SHA-256${SALT}${STORED}:{SERVER}"),
            // One key.
            format!("SCRAM-SHA-256$4096:{SALT}${STORED}"),
            // No separator between the two keys.
            format!("SCRAM-SHA-256$4096:{SALT}${STORED}{SERVER}"),
            // Zero and negative iteration counts, and one that is not a number.
            scram("0", SALT, STORED, SERVER),
            scram("-1", SALT, STORED, SERVER),
            scram("4k", SALT, STORED, SERVER),
            // Empty salt.
            scram("4096", "", STORED, SERVER),
            // Not base64.
            scram("4096", "not base64!", STORED, SERVER),
            // Keys of the wrong length (31 bytes).
            scram("4096", SALT, &short, SERVER),
            scram("4096", SALT, STORED, &short),
            // A digest of another kind is not a verifier.
            Pbkdf2Digest::derive(b"x", &[0u8; SALT_LEN], 4096).to_string(),
            RedisAclSha256::derive(b"x").to_string(),
        ];
        for bad in bad_scram {
            assert_ne!(bad, good);
            let err = ScramSha256Verifier::parse("pg.role-digest", &bad)
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("malformed") && err.contains("pg.role-digest"),
                "{err}"
            );
            assert!(!err.contains(&bad), "{err}");
        }
    }

    #[test]
    fn mint_digest_is_idempotent_for_every_kind() {
        for kind in KINDS {
            let (_d, s) = store();
            let a = s.mint_digest("redis.role-secret", &SPEC, kind).unwrap();
            let b = s.mint_digest("redis.role-secret", &SPEC, kind).unwrap();
            assert_eq!(a, b, "{kind:?}");
            assert_eq!(a.kind(), kind);
            assert_eq!(
                s.stored_digest("redis.role-secret", kind).unwrap(),
                Some(a.clone())
            );
            assert!(s.get("redis.role-digest").unwrap().is_some());
            let value = s.get("redis.role-secret").unwrap().unwrap();
            assert_eq!(value.expose().len(), SPEC.len);
            // The stored digest is exactly the digest of the stored value.
            assert_eq!(rederive(kind, value.expose(), &a), a, "{kind:?}");
            if kind == DigestKind::ScramSha256 {
                let (iterations, salt) = scram_parameters(&a.to_string());
                assert_eq!(iterations, SCRAM_ITERATIONS);
                assert_eq!(salt.len(), SCRAM_SALT_LEN);
            }
            // A digest-only orphan (value removed out of band) still reads.
            s.remove("redis.role-secret").unwrap();
            assert_eq!(
                s.stored_digest("redis.role-secret", kind).unwrap(),
                Some(a),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn rotate_digest_changes_value_and_digest() {
        for kind in KINDS {
            let (_d, s) = store();
            let a = s.mint_digest("redis.role-secret", &SPEC, kind).unwrap();
            let old = s.get("redis.role-secret").unwrap().unwrap();
            let b = s.rotate_digest("redis.role-secret", &SPEC, kind).unwrap();
            assert_ne!(a, b, "{kind:?}");
            assert_eq!(b.kind(), kind);
            assert_ne!(s.get("redis.role-secret").unwrap().unwrap(), old);
            assert_eq!(
                s.stored_digest("redis.role-secret", kind).unwrap(),
                Some(b),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn value_without_digest_is_repaired_by_mint_digest() {
        for kind in KINDS {
            let (_d, s) = store();
            s.set("redis.role-secret", SecretValue::new("x")).unwrap();
            let d = s.mint_digest("redis.role-secret", &SPEC, kind).unwrap();
            assert_eq!(rederive(kind, b"x", &d), d, "{kind:?}");
            assert_eq!(s.get("redis.role-secret").unwrap().unwrap().expose(), b"x");
            assert_eq!(s.stored_digest("redis.role-secret", kind).unwrap(), Some(d));
        }
    }

    /// A digest of another kind is an error that neither yields `None` nor reveals the value, and
    /// minting does not replace it behind the caller's back.
    #[test]
    fn digest_of_another_kind_is_an_error() {
        let (_d, s) = store();
        let pbkdf2 = s.mint_hashed("redis.role-secret", &SPEC).unwrap();
        let value = s.get("redis.role-secret").unwrap().unwrap();
        let plain = String::from_utf8(value.expose().to_vec()).unwrap();
        for kind in [DigestKind::RedisAclSha256, DigestKind::ScramSha256] {
            let err = s
                .stored_digest("redis.role-secret", kind)
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("malformed") && err.contains("redis.role-digest"),
                "{err}"
            );
            assert!(
                !err.contains(&plain) && !err.contains(&pbkdf2.to_string()),
                "{err}"
            );
            let err = s
                .mint_digest("redis.role-secret", &SPEC, kind)
                .unwrap_err()
                .to_string();
            assert!(err.contains("malformed"), "{err}");
            assert_eq!(s.digest("redis.role-secret").unwrap(), Some(pbkdf2.clone()));
        }
    }

    #[test]
    fn digest_ops_work_through_dyn() {
        let (_d, s) = store();
        let ops: &dyn SecretOps = &s;
        // One name per kind: a stored digest of another kind is an error by design.
        for (i, kind) in KINDS.into_iter().enumerate() {
            let name = format!("app.k{i}");
            assert_eq!(ops.stored_digest(&name, kind).unwrap(), None, "{kind:?}");
            assert!(ops.mint_digest("nodot", &SPEC, kind).is_err(), "{kind:?}");
            let d = ops.mint_digest(&name, &SPEC, kind).unwrap();
            assert_eq!(ops.stored_digest(&name, kind).unwrap(), Some(d.clone()));
            assert_eq!(ops.mint_digest(&name, &SPEC, kind).unwrap(), d);
            assert_ne!(ops.rotate_digest(&name, &SPEC, kind).unwrap(), d);
        }
    }

    /// Nothing the trait hands back or derives `Debug` for exposes the plain value.
    #[test]
    fn debug_never_shows_the_value() {
        let (_d, s) = store();
        let plain = |s: &FileSecretStore| {
            String::from_utf8(
                s.get("app.oidc-client-secret")
                    .unwrap()
                    .unwrap()
                    .expose()
                    .to_vec(),
            )
            .unwrap()
        };
        let mut texts = vec![format!("{SPEC:?}")];
        for kind in KINDS {
            let d = s
                .rotate_digest("app.oidc-client-secret", &SPEC, kind)
                .unwrap();
            texts.extend([format!("{d:?}"), format!("{d}"), format!("{kind:?}")]);
        }
        let value = plain(&s);
        texts.push(format!("{:?}", s.list().unwrap()));
        for text in texts {
            assert!(!text.contains(&value), "{text}");
        }
        assert_eq!(
            format!("{:?}", Pbkdf2Digest::derive(b"x", &[0u8; SALT_LEN], 4096)),
            "Pbkdf2Digest(pbkdf2-sha512)"
        );
        assert_eq!(
            format!("{:?}", RedisAclSha256::derive(b"x")),
            "RedisAclSha256(sha256)"
        );
        assert_eq!(
            format!("{:?}", ScramSha256Verifier::derive(b"x", &[0u8; 16], 4096)),
            "ScramSha256Verifier(scram-sha-256)"
        );
    }
}
