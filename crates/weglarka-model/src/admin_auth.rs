//! Bearer-token validation for the token admin listener (docs/decisions/0056): a pure function from
//! `(token, JWKS, expected claims, now)` to a [`Principal`], plus the group → [`Scope`] mapping.
//!
//! No I/O and no clock reads live here: the daemon fetches and caches the JWKS (over the ingress probe
//! socket) and passes `now` in, so everything is testable with a fixed key. Tokens are RFC 9068 JWT
//! access tokens signed with `RS256` or `ES256`; `none`, HMAC and every other algorithm are refused,
//! and the algorithm must match the type of the key the `kid` selects. Error values never contain
//! any part of the token.

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey};
use serde::Deserialize;

/// Directory under the state dir that holds the token listener's socket (`0700`); mounted into
/// the `[admin.http] clients` only.
pub const SOCKET_SUBDIR: &str = "run/admin-token";
pub const SOCKET_NAME: &str = "api.sock";
/// Where a client container sees the token socket.
pub const CONTAINER_SOCKET_DIR: &str = "/run/weglarka-admin";
pub const CONTAINER_SOCKET: &str = "/run/weglarka-admin/api.sock";

/// What a token may do on the token listener. `Admin` implies `Read`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    Read,
    Admin,
}

/// A verified caller: the token's `sub` and the scopes its groups map to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub sub: String,
    pub scopes: BTreeSet<Scope>,
}

impl Principal {
    pub fn has(&self, scope: Scope) -> bool {
        self.scopes.contains(&scope)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    #[error("malformed bearer token")]
    Malformed,
    #[error("token header: unsupported algorithm (only RS256 and ES256 are accepted)")]
    UnsupportedAlg,
    #[error("token header: typ is not at+jwt")]
    WrongType,
    #[error("token header: no kid")]
    NoKeyId,
    #[error("token is signed with a key that is not in the provider's JWKS")]
    UnknownKey,
    #[error("token header: the algorithm does not match the type of the signing key")]
    KeyMismatch,
    #[error("signature does not verify")]
    BadSignature,
    #[error("token issuer is not the configured provider")]
    WrongIssuer,
    #[error("token audience does not include the configured audience")]
    WrongAudience,
    #[error("token has expired")]
    Expired,
    #[error("token is not valid yet")]
    NotYetValid,
    #[error("token carries no groups mapped to a scope")]
    NoScope,
    #[error("the token's scopes do not allow this endpoint")]
    Forbidden,
}

/// Largest bearer token the listener looks at; a real access token is well below 4 KiB.
pub const MAX_TOKEN_BYTES: usize = 8 * 1024;
/// Clock skew allowed on `exp` and `nbf`.
pub const LEEWAY: Duration = Duration::from_secs(60);

/// What the daemon expects of a token (`[identity] issuer` and `[admin.http]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validation {
    pub issuer: String,
    pub audience: String,
    pub read_groups: BTreeSet<String>,
    pub admin_groups: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum KeyMaterial {
    Rsa {
        n: Vec<u8>,
        e: Vec<u8>,
    },
    /// Uncompressed SEC1 point `04 || x || y`.
    EcP256(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Key {
    kid: String,
    material: KeyMaterial,
}

/// The signing keys of the provider (a parsed `jwks.json`); keys it cannot verify with are skipped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JwkSet {
    keys: Vec<Key>,
}

#[derive(Deserialize)]
struct RawJwkSet {
    #[serde(default)]
    keys: Vec<RawJwk>,
}

#[derive(Deserialize)]
struct RawJwk {
    #[serde(default)]
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default, rename = "use")]
    use_: Option<String>,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
}

fn b64(value: &Option<String>) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(value.as_deref()?).ok()
}

impl JwkSet {
    /// Parses a `jwks.json` body. Only RSA and P-256 signing keys with a `kid` are kept.
    pub fn from_json(body: &[u8]) -> Result<Self, AuthError> {
        let raw: RawJwkSet = serde_json::from_slice(body).map_err(|_| AuthError::Malformed)?;
        let keys = raw
            .keys
            .into_iter()
            .filter(|k| k.use_.as_deref().is_none_or(|u| u == "sig"))
            .filter_map(|k| {
                let kid = k.kid.clone()?;
                let material = match k.kty.as_str() {
                    "RSA" => KeyMaterial::Rsa {
                        n: b64(&k.n)?,
                        e: b64(&k.e)?,
                    },
                    "EC" if k.crv.as_deref() == Some("P-256") => {
                        let (x, y) = (b64(&k.x)?, b64(&k.y)?);
                        if x.len() != 32 || y.len() != 32 {
                            return None;
                        }
                        let mut point = vec![0x04];
                        point.extend_from_slice(&x);
                        point.extend_from_slice(&y);
                        KeyMaterial::EcP256(point)
                    }
                    _ => return None,
                };
                Some(Key { kid, material })
            })
            .collect();
        Ok(Self { keys })
    }

    pub fn contains(&self, kid: &str) -> bool {
        self.keys.iter().any(|k| k.kid == kid)
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

#[derive(Deserialize)]
struct Header {
    #[serde(default)]
    alg: String,
    #[serde(default)]
    typ: Option<String>,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
struct Claims {
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    aud: Option<Audience>,
    #[serde(default)]
    exp: Option<f64>,
    #[serde(default)]
    nbf: Option<f64>,
    #[serde(default)]
    groups: Vec<String>,
}

struct Parts<'a> {
    signing_input: &'a str,
    header: Header,
    payload: &'a str,
    signature: Vec<u8>,
}

fn split(token: &str) -> Result<Parts<'_>, AuthError> {
    if token.len() > MAX_TOKEN_BYTES {
        return Err(AuthError::Malformed);
    }
    let mut it = token.split('.');
    let (Some(h), Some(p), Some(s), None) = (it.next(), it.next(), it.next(), it.next()) else {
        return Err(AuthError::Malformed);
    };
    let header_json = URL_SAFE_NO_PAD
        .decode(h)
        .map_err(|_| AuthError::Malformed)?;
    let header: Header = serde_json::from_slice(&header_json).map_err(|_| AuthError::Malformed)?;
    let signature = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| AuthError::Malformed)?;
    Ok(Parts {
        signing_input: &token[..h.len() + 1 + p.len()],
        header,
        payload: p,
        signature,
    })
}

/// The `kid` in the token's header, so the caller can refresh the JWKS when it is unknown. Nothing
/// is verified here: the value only decides whether to fetch, never whether to trust.
pub fn key_id(token: &str) -> Result<String, AuthError> {
    split(token)?.header.kid.ok_or(AuthError::NoKeyId)
}

fn epoch(now: SystemTime) -> f64 {
    now.duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

/// Verifies `token` and maps its groups to scopes.
pub fn validate(
    token: &str,
    keys: &JwkSet,
    expected: &Validation,
    now: SystemTime,
) -> Result<Principal, AuthError> {
    let parts = split(token)?;
    let alg = match parts.header.alg.as_str() {
        "RS256" | "ES256" => parts.header.alg.as_str(),
        _ => return Err(AuthError::UnsupportedAlg),
    };
    let typ = parts.header.typ.as_deref().ok_or(AuthError::WrongType)?;
    let typ = typ.strip_prefix("application/").unwrap_or(typ);
    if !typ.eq_ignore_ascii_case("at+jwt") {
        return Err(AuthError::WrongType);
    }
    let kid = parts.header.kid.as_deref().ok_or(AuthError::NoKeyId)?;
    let key = keys
        .keys
        .iter()
        .find(|k| k.kid == kid)
        .ok_or(AuthError::UnknownKey)?;
    let message = parts.signing_input.as_bytes();
    let verified = match (&key.material, alg) {
        (KeyMaterial::Rsa { n, e }, "RS256") => RsaPublicKeyComponents { n, e }
            .verify(
                &signature::RSA_PKCS1_2048_8192_SHA256,
                message,
                &parts.signature,
            )
            .is_ok(),
        (KeyMaterial::EcP256(point), "ES256") => {
            UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
                .verify(message, &parts.signature)
                .is_ok()
        }
        _ => return Err(AuthError::KeyMismatch),
    };
    if !verified {
        return Err(AuthError::BadSignature);
    }

    let claims_json = URL_SAFE_NO_PAD
        .decode(parts.payload)
        .map_err(|_| AuthError::Malformed)?;
    let claims: Claims = serde_json::from_slice(&claims_json).map_err(|_| AuthError::Malformed)?;
    if claims.iss.as_deref() != Some(expected.issuer.as_str()) {
        return Err(AuthError::WrongIssuer);
    }
    let audience_ok = match &claims.aud {
        Some(Audience::One(a)) => *a == expected.audience,
        Some(Audience::Many(list)) => list.contains(&expected.audience),
        None => false,
    };
    if !audience_ok {
        return Err(AuthError::WrongAudience);
    }
    let now = epoch(now);
    let leeway = LEEWAY.as_secs_f64();
    // A token without `exp` never expires: refuse it rather than trust it forever.
    match claims.exp {
        Some(exp) if now <= exp + leeway => {}
        _ => return Err(AuthError::Expired),
    }
    if claims.nbf.is_some_and(|nbf| now + leeway < nbf) {
        return Err(AuthError::NotYetValid);
    }
    let sub = claims
        .sub
        .filter(|s| !s.is_empty())
        .ok_or(AuthError::Malformed)?;
    let scopes = scopes_for(&claims.groups, expected);
    if scopes.is_empty() {
        return Err(AuthError::NoScope);
    }
    Ok(Principal { sub, scopes })
}

fn scopes_for(groups: &[String], expected: &Validation) -> BTreeSet<Scope> {
    let mut scopes = BTreeSet::new();
    if groups.iter().any(|g| expected.admin_groups.contains(g)) {
        scopes.extend([Scope::Read, Scope::Admin]);
    }
    if groups.iter().any(|g| expected.read_groups.contains(g)) {
        scopes.insert(Scope::Read);
    }
    scopes
}

/// Checks `principal` against the scope an endpoint declares (`None` = open to everyone).
pub fn authorize(principal: &Principal, required: Option<Scope>) -> Result<(), AuthError> {
    match required {
        None => Ok(()),
        Some(scope) if principal.has(scope) => Ok(()),
        Some(_) => Err(AuthError::Forbidden),
    }
}

/// Token minting for tests of this crate and of the daemon (feature `testing`).
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair};

    pub const ISSUER: &str = "https://auth.example.com";
    pub const AUDIENCE: &str = "https://admin.example.com/api/";

    /// An ES256 signing key that also renders the matching `jwks.json`.
    pub struct TestIssuer {
        pub kid: String,
        pair: EcdsaKeyPair,
    }

    impl TestIssuer {
        pub fn new(kid: &str) -> Self {
            let rng = SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                    .expect("generate key");
            let pair = EcdsaKeyPair::from_pkcs8(
                &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                pkcs8.as_ref(),
                &rng,
            )
            .expect("load key");
            Self {
                kid: kid.to_owned(),
                pair,
            }
        }

        pub fn jwks_json(&self) -> String {
            let point = self.pair.public_key().as_ref();
            let (x, y) = (&point[1..33], &point[33..65]);
            format!(
                r#"{{"keys":[{{"kty":"EC","crv":"P-256","use":"sig","alg":"ES256","kid":"{}","x":"{}","y":"{}"}}]}}"#,
                self.kid,
                URL_SAFE_NO_PAD.encode(x),
                URL_SAFE_NO_PAD.encode(y)
            )
        }

        pub fn jwks(&self) -> JwkSet {
            JwkSet::from_json(self.jwks_json().as_bytes()).expect("own jwks parses")
        }

        /// Signs `claims` (a JSON object) under a header of the given `typ` (`None` omits it).
        pub fn sign_with_typ(&self, typ: Option<&str>, claims: &serde_json::Value) -> String {
            let mut header = serde_json::json!({"alg": "ES256", "kid": self.kid});
            if let Some(typ) = typ {
                header["typ"] = typ.into();
            }
            let input = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(header.to_string()),
                URL_SAFE_NO_PAD.encode(claims.to_string())
            );
            let sig = self
                .pair
                .sign(&SystemRandom::new(), input.as_bytes())
                .expect("sign");
            format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()))
        }

        pub fn sign(&self, claims: &serde_json::Value) -> String {
            self.sign_with_typ(Some("at+jwt"), claims)
        }

        /// A token for [`validation`] that expires in an hour (from the real clock).
        pub fn token(&self, sub: &str, groups: &[&str]) -> String {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_secs();
            self.sign(&serde_json::json!({
                "iss": ISSUER, "aud": [AUDIENCE], "sub": sub,
                "exp": now + 3600, "nbf": now - 5, "groups": groups,
            }))
        }
    }

    /// Expectations matching [`TestIssuer::token`]: group `viewers` reads, `admins` administers.
    pub fn validation() -> Validation {
        Validation {
            issuer: ISSUER.to_owned(),
            audience: AUDIENCE.to_owned(),
            read_groups: ["viewers".to_owned()].into(),
            admin_groups: ["admins".to_owned()].into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;
    use ring::signature::RsaKeyPair;
    use serde_json::json;

    const NOW: u64 = 1_800_000_000;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn claims() -> serde_json::Value {
        json!({"iss": ISSUER, "aud": AUDIENCE, "sub": "alice", "exp": NOW + 600,
               "nbf": NOW - 5, "groups": ["admins"]})
    }

    fn check(issuer: &TestIssuer, claims: &serde_json::Value) -> Result<Principal, AuthError> {
        validate(&issuer.sign(claims), &issuer.jwks(), &validation(), at(NOW))
    }

    #[test]
    fn accepts_a_valid_token_and_maps_groups() {
        let issuer = TestIssuer::new("k1");
        let p = check(&issuer, &claims()).unwrap();
        assert_eq!(p.sub, "alice");
        assert_eq!(p.scopes, BTreeSet::from([Scope::Read, Scope::Admin]));

        let mut reader = claims();
        reader["groups"] = json!(["viewers", "unrelated"]);
        let p = check(&issuer, &reader).unwrap();
        assert_eq!(p.scopes, BTreeSet::from([Scope::Read]));
    }

    #[test]
    fn no_mapped_group_means_no_access() {
        let issuer = TestIssuer::new("k1");
        let mut c = claims();
        c["groups"] = json!(["other"]);
        assert_eq!(check(&issuer, &c), Err(AuthError::NoScope));
        c.as_object_mut().unwrap().remove("groups");
        assert_eq!(check(&issuer, &c), Err(AuthError::NoScope));
    }

    #[test]
    fn audience_may_be_a_string_or_a_list_and_must_match_exactly() {
        let issuer = TestIssuer::new("k1");
        let mut c = claims();
        c["aud"] = json!(["other", AUDIENCE]);
        assert!(check(&issuer, &c).is_ok());
        c["aud"] = json!("https://admin.example.com/api");
        assert_eq!(check(&issuer, &c), Err(AuthError::WrongAudience));
        c.as_object_mut().unwrap().remove("aud");
        assert_eq!(check(&issuer, &c), Err(AuthError::WrongAudience));
    }

    #[test]
    fn issuer_must_match() {
        let issuer = TestIssuer::new("k1");
        let mut c = claims();
        c["iss"] = json!("https://evil.example.com");
        assert_eq!(check(&issuer, &c), Err(AuthError::WrongIssuer));
    }

    #[test]
    fn time_claims_use_a_one_minute_leeway() {
        let issuer = TestIssuer::new("k1");
        let mut c = claims();
        c["exp"] = json!(NOW - 30);
        assert!(check(&issuer, &c).is_ok());
        c["exp"] = json!(NOW - 61);
        assert_eq!(check(&issuer, &c), Err(AuthError::Expired));
        c["exp"] = json!(NOW + 600);
        c["nbf"] = json!(NOW + 30);
        assert!(check(&issuer, &c).is_ok());
        c["nbf"] = json!(NOW + 61);
        assert_eq!(check(&issuer, &c), Err(AuthError::NotYetValid));
        c.as_object_mut().unwrap().remove("exp");
        assert_eq!(check(&issuer, &c), Err(AuthError::Expired));
    }

    #[test]
    fn type_must_be_at_jwt() {
        let issuer = TestIssuer::new("k1");
        for (typ, ok) in [
            (Some("at+jwt"), true),
            (Some("AT+JWT"), true),
            (Some("application/at+jwt"), true),
            (Some("JWT"), false),
            (None, false),
        ] {
            let token = issuer.sign_with_typ(typ, &claims());
            let got = validate(&token, &issuer.jwks(), &validation(), at(NOW));
            assert_eq!(got.is_ok(), ok, "{typ:?}");
        }
    }

    #[test]
    fn rejects_none_hmac_and_foreign_keys() {
        let issuer = TestIssuer::new("k1");
        let header = |alg: &str| {
            URL_SAFE_NO_PAD.encode(json!({"alg": alg, "typ": "at+jwt", "kid": "k1"}).to_string())
        };
        let body = URL_SAFE_NO_PAD.encode(claims().to_string());
        for alg in ["none", "HS256", "PS256", "ES384"] {
            let token = format!("{}.{body}.{}", header(alg), URL_SAFE_NO_PAD.encode("x"));
            assert_eq!(
                validate(&token, &issuer.jwks(), &validation(), at(NOW)),
                Err(AuthError::UnsupportedAlg),
                "{alg}"
            );
        }
        // A well-formed token signed by a key the provider never published.
        let stranger = TestIssuer::new("k1");
        let token = stranger.sign(&claims());
        assert_eq!(
            validate(&token, &issuer.jwks(), &validation(), at(NOW)),
            Err(AuthError::BadSignature)
        );
        let other_kid = TestIssuer::new("k2").sign(&claims());
        assert_eq!(
            validate(&other_kid, &issuer.jwks(), &validation(), at(NOW)),
            Err(AuthError::UnknownKey)
        );
    }

    #[test]
    fn tampered_payload_fails_the_signature() {
        let issuer = TestIssuer::new("k1");
        let token = issuer.sign(&claims());
        let mut parts: Vec<_> = token.split('.').map(str::to_owned).collect();
        let mut forged = claims();
        forged["sub"] = json!("mallory");
        parts[1] = URL_SAFE_NO_PAD.encode(forged.to_string());
        assert_eq!(
            validate(&parts.join("."), &issuer.jwks(), &validation(), at(NOW)),
            Err(AuthError::BadSignature)
        );
    }

    #[test]
    fn garbage_and_oversized_tokens_are_malformed() {
        let issuer = TestIssuer::new("k1");
        for token in [
            "",
            "a.b",
            "a.b.c.d",
            "!!.!!.!!",
            &"a".repeat(MAX_TOKEN_BYTES + 1),
        ] {
            assert_eq!(
                validate(token, &issuer.jwks(), &validation(), at(NOW)),
                Err(AuthError::Malformed)
            );
        }
    }

    #[test]
    fn key_id_reads_the_header_only() {
        let issuer = TestIssuer::new("k9");
        assert_eq!(key_id(&issuer.sign(&claims())).as_deref(), Ok("k9"));
        assert_eq!(key_id("nonsense"), Err(AuthError::Malformed));
    }

    #[test]
    fn jwks_keeps_only_usable_signing_keys() {
        let issuer = TestIssuer::new("good");
        let mut doc: serde_json::Value = serde_json::from_str(&issuer.jwks_json()).unwrap();
        let keys = doc["keys"].as_array_mut().unwrap();
        keys.push(json!({"kty": "oct", "kid": "hmac", "k": "AAAA"}));
        keys.push(json!({"kty": "EC", "crv": "P-384", "kid": "p384", "x": "AA", "y": "AA"}));
        keys.push(json!({"kty": "RSA", "use": "enc", "kid": "enc", "n": "AQAB", "e": "AQAB"}));
        keys.push(json!({"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"}));
        let set = JwkSet::from_json(doc.to_string().as_bytes()).unwrap();
        assert!(set.contains("good"));
        for kid in ["hmac", "p384", "enc"] {
            assert!(!set.contains(kid), "{kid}");
        }
        assert!(JwkSet::from_json(b"not json").is_err());
        assert!(JwkSet::from_json(b"{}").unwrap().is_empty());
    }

    #[test]
    fn authorize_checks_the_declared_scope() {
        let reader = Principal {
            sub: "r".into(),
            scopes: BTreeSet::from([Scope::Read]),
        };
        assert_eq!(authorize(&reader, None), Ok(()));
        assert_eq!(authorize(&reader, Some(Scope::Read)), Ok(()));
        assert_eq!(
            authorize(&reader, Some(Scope::Admin)),
            Err(AuthError::Forbidden)
        );
    }

    // PKCS#8 RSA-2048 key generated for this test only; it signs nothing outside it.
    const RSA_PKCS8_B64: &str = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDSoBSBlEcenuEbE16YzAkxBkD5SpoeRVcwSjuJ8tePfj0jn0qDiyFiA+dGTJiHPzQ6TN98NWzlGY1AGdobAb7LcPxC5W0ScvjHyW+C8G/TZjsAryS2rfiju6jNoWy8ZbZVlkTsa39mh1SAHcjs6+cOLNqQhHurWTu0glL7rAPqfsQY1DooaZbRtBN5wUFhinqUW7yHS7GcwOZSdrWC/QFB/VQalN8CK6lPElnzm3Tvm30WawyelucCZD1m8pmFz7LP/S5dRIa5tkW9A70c84RbbePdvPxOzmPoIb9FpvjLcC2GcvhEk78gpocQgLr18UuJUYa4CKo6Lt6ZYHMZRx9bAgMBAAECggEAEmv13y982OzEe33CNFMEKsmFPUiNGkCuU4bqljIrMF22MztnZQHyNYRp4fgpDws0IjU/BroVgCQv+n9IWDxa16hWJ/OxCoALyk2P9z/YSAEVAAZRi7jDmm57YSDRRdkPjYTLGnJ8fhcwCNSSEka/urmplCJCPsZbNnp/j4uH/CZZiOqKYE8LiJ7Do/5DqM/AH7ng5ufyxfDq0RW+HQatuphkIQQ2GZFxVNIYE1ihU8D8cpiR7y/lSSzoRS2WFOU23nBhujvY5iafQHfqMJ/wPzMgJrHfQmIONQvCrtyGi/1p+9qyS6jSdRorfv8/oCk9JEi3p9XncPKRB8j1XOz3wQKBgQD12Vp1Fb0RUja3d/AqM4OSivvuNjLCIHbPpGa30QexqelkwO6nZq6mx8sipXH5d5QJDqXe/Y6U/V7dWMm3fBrSrY0Sl50ys3j+XZDkDaNggWkvU1PFaCCzd6BoNrjxp/rabdYe0nnPHI77EfNFCh3ChWWpp8A5MIc1jt/tsitscwKBgQDbUmimwSXUS8IgZQ8YpnX7iE1gl82mg3L2+Fqzbu44feadpWFMm6/5I0MRMHmqFBAE7ltlYKNdOfsguK8UTijT0suRYhPOIQ7EpPqtzaejQ84RiLZ7Ie4ndT2lMDF+RcKXGowjqEVBCRDpBFNIkkk0cplU6Rb9JcqWLZtESplveQKBgAYrv36C3i0KID94rjmQ83OBM5OmHp4KzJCnssBYadYGysnxocvn4uhiyXGEL5kwbDHSAU3YlXSd63yo1t9ZKR8ypgDad2KnaJkR5iojQX+Rn/9FGywwUenPTeJvxTKjocNL0H0TkWUmdVxN9go8l8SjLosUn9mPo0Uv4eUIfNiLAoGAMMkqAj3gnlKjwfT44LDWebceDyh1VF7VCd7Avj0kvGg1DkglVpcjE7YmSwKPbae80Hv81JYkgK5PED5Eo62nI0c2hQZeBXIRCOjx4gtnCMgiZIAWp1kq0pgfuEj6GW6HFHmRRrU9gnPz0QFnTTNNGV+Mf/jBZlorsDBA43X8n3ECgYEApiKgfuLGLenw9zWvE6ivqKij4tTt0Al8hUEpbIL9JN7QG2GDc0jmq++zbP2dZcUGB0TnYckt3eKfxdJQJesRw7vu3gua2A5saUS3Xf2P59hhxFIHbSOnN6hIzv8sfBshrGX5qDPZ8bcY5Um9YFawhjac7iPsBT/yLOAmOR3cBxA=";

    #[test]
    fn rs256_tokens_verify_and_alg_must_match_the_key_type() {
        let der = base64::engine::general_purpose::STANDARD
            .decode(RSA_PKCS8_B64)
            .unwrap();
        let pair = RsaKeyPair::from_pkcs8(&der).unwrap();
        let public: RsaPublicKeyComponents<Vec<u8>> = pair.public().into();
        let jwks = JwkSet::from_json(
            json!({"keys": [{
                "kty": "RSA", "use": "sig", "kid": "rsa1",
                "n": URL_SAFE_NO_PAD.encode(&public.n),
                "e": URL_SAFE_NO_PAD.encode(&public.e),
            }]})
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        let sign = |alg: &str| {
            let header = json!({"alg": alg, "typ": "at+jwt", "kid": "rsa1"}).to_string();
            let input = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(header),
                URL_SAFE_NO_PAD.encode(claims().to_string())
            );
            let mut sig = vec![0; pair.public().modulus_len()];
            pair.sign(
                &signature::RSA_PKCS1_SHA256,
                &ring::rand::SystemRandom::new(),
                input.as_bytes(),
                &mut sig,
            )
            .unwrap();
            format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig))
        };
        let p = validate(&sign("RS256"), &jwks, &validation(), at(NOW)).unwrap();
        assert_eq!(p.sub, "alice");
        // Same signature, header claiming ES256: refused before any verification happens.
        assert_eq!(
            validate(&sign("ES256"), &jwks, &validation(), at(NOW)),
            Err(AuthError::KeyMismatch)
        );
    }
}
