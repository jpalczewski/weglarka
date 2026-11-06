//! Independent known-answer tests for the service digests of `SecretOps` (#591).
//!
//! The crate derives every digest with `ring`. Three references check it:
//! - the published vectors: RFC 7677 and the managed-service contract fixtures in #593/#596;
//! - for SCRAM-SHA-256, `postgres-protocol` (the rust-postgres implementation that follows
//!   libpq's `PQencryptPasswordConn`), on every value the store mints;
//! - for the Redis digest, plain SHA-256 from `sha2`.
//!
//! A wrong implementation cannot agree with all of them by accident.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest as _, Sha256};
use weglarka_model::secret_ops::{
    Alphabet, Digest, DigestKind, MintSpec, RedisAclSha256, SCRAM_ITERATIONS, ScramSha256Verifier,
    SecretOps,
};
use weglarka_model::secret_store::SecretStore;
use weglarka_model::secrets::FileSecretStore;

// ---------------------------------------------------------------- references

/// Redis ACL password digest: lower-case hex SHA-256 over the password bytes.
fn reference_redis(password: &[u8]) -> String {
    hex::encode(Sha256::digest(password))
}

/// Checks the crate's SCRAM derivation against `postgres-protocol` for `password`. That crate draws
/// its own random salt, so its verifier is read back and re-derived with the same salt and
/// iteration count. SASLprep, which it applies first, leaves the minted alphabet unchanged.
fn assert_scram_agrees_with_postgres_protocol(password: &[u8]) {
    let reference = postgres_protocol::password::scram_sha_256(password);
    let parts = scram_parts(&reference);
    assert_eq!(
        ScramSha256Verifier::derive(password, &parts.salt, parts.iterations).to_string(),
        reference
    );
}

// ---------------------------------------------------------------- published vectors

/// RFC 7677 §3: password `pencil`, 4096 iterations, 16-byte salt; the verifier is the RFC's
/// `ClientKey`/`ServerKey`.
const RFC_7677_PASSWORD: &str = "pencil";
const RFC_7677_SALT_B64: &str = "W22ZaJ0SNY7soEsUEjb6gQ==";
const RFC_7677_VERIFIER: &str = "SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ==$WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=:wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=";

/// Managed Postgres contract (#596) fixtures: password, salt as ASCII bytes, expected verifier.
const POSTGRES_FIXTURES: [(&str, &[u8], &str); 2] = [
    (
        "example-member-password-not-a-secret-0001",
        b"salt-fixture-0001",
        "SCRAM-SHA-256$4096:c2FsdC1maXh0dXJlLTAwMDE=$HhJkw0KtYXJyFs11DOflUXguOIoXQBArvygy5CoieH0=:O0r1V43ZJF33DcUZT1W+2q1qmnApK+CV2L2/eeZVnjg=",
    ),
    (
        "example-member-password-not-a-secret-0002",
        b"salt-fixture-0002",
        "SCRAM-SHA-256$4096:c2FsdC1maXh0dXJlLTAwMDI=$03Dm9qqaJFuDyPxhZZbZUTXJNqYoKsGEb7RKJIHf5dI=:XqCsBzfibSlBsEUmmlPdCQ3JVFaPdXodX/eD6KKB+Bs=",
    ),
];

/// Managed Redis contract (#593) fixtures: password, expected SHA-256 hex.
const REDIS_FIXTURES: [(&str, &str); 2] = [
    (
        "example-member-password-not-a-secret-0001",
        "dae08700a6ef0788315e69bf4410fd3951d3dfae0012814ee694c1443360d7ce",
    ),
    (
        "example-member-password-not-a-secret-0002",
        "201d82e986e84dcccec748b71c11117353cecace8a8ec1fb7e197d2bdc555acf",
    ),
];

#[test]
fn the_redis_reference_matches_the_managed_redis_contract() {
    for (password, expected) in REDIS_FIXTURES {
        assert_eq!(reference_redis(password.as_bytes()), expected, "{password}");
    }
}

#[test]
fn scram_agrees_with_postgres_protocol() {
    let mut passwords: Vec<&[u8]> = vec![RFC_7677_PASSWORD.as_bytes(), b"a"];
    passwords.extend(POSTGRES_FIXTURES.iter().map(|(p, _, _)| p.as_bytes()));
    for password in passwords {
        assert_scram_agrees_with_postgres_protocol(password);
    }
}

// ---------------------------------------------------------------- helpers over the public API

const NAME: &str = "api.svc-cache";
const SPEC: MintSpec = MintSpec {
    len: 48,
    alphabet: Alphabet::Rfc3986Unreserved,
};

fn store() -> (tempfile::TempDir, FileSecretStore) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = FileSecretStore::new(dir.path().join("secrets.toml"));
    (dir, store)
}

fn stored(store: &FileSecretStore, name: &str) -> Vec<u8> {
    store
        .get(name)
        .expect("read")
        .expect("minted value exists")
        .expose()
        .to_vec()
}

fn assert_minted_shape(value: &[u8]) {
    assert_eq!(value.len(), 48, "minted length");
    assert!(
        value
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(b)),
        "minted value leaves [A-Za-z0-9-._~]"
    );
}

struct ScramParts {
    iterations: u32,
    salt: Vec<u8>,
    stored_key: String,
    server_key: String,
}

/// Splits a stored verifier without any help from the crate.
fn scram_parts(verifier: &str) -> ScramParts {
    let rest = verifier
        .strip_prefix("SCRAM-SHA-256$")
        .expect("SCRAM-SHA-256 prefix");
    let (header, keys) = rest.split_once('$').expect("salt and key parts");
    let (iterations, salt_b64) = header.split_once(':').expect("iterations and salt");
    let (stored_key, server_key) = keys.split_once(':').expect("stored and server key");
    ScramParts {
        iterations: iterations.parse().expect("iteration count"),
        salt: STANDARD.decode(salt_b64).expect("standard base64 salt"),
        stored_key: stored_key.to_owned(),
        server_key: server_key.to_owned(),
    }
}

/// A digest minted for `value`: the redis digest is the reference over the value; the SCRAM verifier
/// is the crate's derivation over the value with the salt and iteration count it carries, and that
/// derivation agrees with `postgres-protocol` for the same value.
fn assert_digest_of(kind: DigestKind, digest: &Digest, value: &[u8]) {
    assert_eq!(digest.kind(), kind);
    match kind {
        DigestKind::RedisAclSha256 => assert_eq!(digest.to_string(), reference_redis(value)),
        DigestKind::ScramSha256 => {
            let parts = scram_parts(&digest.to_string());
            assert_eq!(parts.iterations, SCRAM_ITERATIONS, "iteration count");
            assert_eq!(parts.salt.len(), 16, "salt length");
            assert!(!parts.stored_key.is_empty() && !parts.server_key.is_empty());
            assert_eq!(
                digest.to_string(),
                ScramSha256Verifier::derive(value, &parts.salt, parts.iterations).to_string()
            );
            assert_scram_agrees_with_postgres_protocol(value);
        }
        DigestKind::Pbkdf2Sha512 => panic!("not covered by this test"),
    }
}

// ---------------------------------------------------------------- derivations against the published values

#[test]
fn redis_digest_matches_the_published_values() {
    for (password, expected) in REDIS_FIXTURES {
        let digest = RedisAclSha256::derive(password.as_bytes());
        assert_eq!(digest.to_string(), expected);
        assert_eq!(digest.to_string(), reference_redis(password.as_bytes()));
        // Shaped like a digest, so parsing it back is a round trip.
        let parsed = RedisAclSha256::parse(NAME, &digest.to_string()).expect("parses");
        assert_eq!(parsed, digest);
        assert_eq!(parsed.to_string(), digest.to_string());
    }
}

#[test]
fn scram_verifier_matches_the_published_values() {
    let salt = STANDARD.decode(RFC_7677_SALT_B64).expect("base64 salt");
    let mut cases: Vec<(&str, Vec<u8>, &str)> = vec![(RFC_7677_PASSWORD, salt, RFC_7677_VERIFIER)];
    for (password, salt, verifier) in POSTGRES_FIXTURES {
        cases.push((password, salt.to_vec(), verifier));
    }
    for (password, salt, expected) in cases {
        let derived = ScramSha256Verifier::derive(password.as_bytes(), &salt, 4096);
        assert_eq!(derived.to_string(), expected);
        let parsed = ScramSha256Verifier::parse(NAME, &derived.to_string()).expect("parses");
        assert_eq!(parsed, derived);
        assert_eq!(parsed.to_string(), derived.to_string());
    }
}

// ---------------------------------------------------------------- minting through the store

#[test]
fn mint_digest_matches_the_references_for_each_kind() {
    for kind in [DigestKind::RedisAclSha256, DigestKind::ScramSha256] {
        let (_dir, store) = store();
        let digest = store.mint_digest(NAME, &SPEC, kind).expect("mint");
        let value = stored(&store, NAME);
        assert_minted_shape(&value);
        assert_digest_of(kind, &digest, &value);

        // Same secret, same bytes: a second mint returns the stored digest and keeps the value.
        let again = store.mint_digest(NAME, &SPEC, kind).expect("second mint");
        assert_eq!(again.to_string(), digest.to_string());
        assert_eq!(stored(&store, NAME), value);

        let stored_digest = store
            .stored_digest(NAME, kind)
            .expect("stored digest")
            .expect("a digest was minted");
        assert_eq!(stored_digest.to_string(), digest.to_string());
        assert_eq!(stored_digest.kind(), kind);
    }
}

#[test]
fn rotate_digest_changes_the_value_and_matches_the_references() {
    for kind in [DigestKind::RedisAclSha256, DigestKind::ScramSha256] {
        let (_dir, store) = store();
        let first = store.mint_digest(NAME, &SPEC, kind).expect("mint");
        let before = stored(&store, NAME);
        let rotated = store.rotate_digest(NAME, &SPEC, kind).expect("rotate");
        let after = stored(&store, NAME);

        assert_ne!(before, after, "rotation replaced the value");
        assert_minted_shape(&after);
        assert_ne!(rotated.to_string(), first.to_string());
        assert_digest_of(kind, &rotated, &after);
        assert_eq!(
            store
                .stored_digest(NAME, kind)
                .expect("stored digest")
                .expect("a digest exists")
                .to_string(),
            rotated.to_string()
        );
    }
}

#[test]
fn scram_mints_of_two_names_use_distinct_salts() {
    let (_dir, store) = store();
    let a = store
        .mint_digest("api.svc-cache", &SPEC, DigestKind::ScramSha256)
        .expect("mint");
    let b = store
        .mint_digest("api.svc-search", &SPEC, DigestKind::ScramSha256)
        .expect("mint");
    let (a, b) = (scram_parts(&a.to_string()), scram_parts(&b.to_string()));
    assert_eq!(a.salt.len(), 16);
    assert_eq!(b.salt.len(), 16);
    assert_ne!(a.salt, b.salt, "a salt per mint");
}

/// A digest of another kind is an error, never silently replaced (trait documentation of
/// `mint_digest` / `stored_digest`).
#[test]
fn a_digest_of_another_kind_is_an_error() {
    let (_dir, store) = store();
    store
        .mint_digest(NAME, &SPEC, DigestKind::RedisAclSha256)
        .expect("mint");
    assert!(store.stored_digest(NAME, DigestKind::ScramSha256).is_err());
    assert!(
        store
            .mint_digest(NAME, &SPEC, DigestKind::ScramSha256)
            .is_err()
    );
}

// ---------------------------------------------------------------- no plaintext in `Debug`

#[test]
fn debug_of_a_minted_digest_never_shows_the_value() {
    for kind in [DigestKind::RedisAclSha256, DigestKind::ScramSha256] {
        let (_dir, store) = store();
        let digest = store.mint_digest(NAME, &SPEC, kind).expect("mint");
        let plain = String::from_utf8(stored(&store, NAME)).expect("utf-8 value");
        let debug = format!("{digest:?}");
        assert!(!debug.contains(&plain), "{debug}");
        assert!(!debug.contains(&digest.to_string()), "{debug}");
    }
}
