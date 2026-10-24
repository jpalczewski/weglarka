//! Cosign "simple signing" payload parsing and key-based verification.
//!
//! `cosign sign --key` stores a signature over a small JSON document next to the image. The
//! document binds the signature to the image digest and to the repository it was signed for; both
//! are checked here before the signature itself. The JSON keys are matched case-insensitively
//! because the cosign specification writes `Docker-manifest-digest` while implementations emit
//! `docker-manifest-digest`.
//!
//! Verification is only as good as the pinned key: this module trusts the caller to have parsed
//! [`crate::PublicKey`] from a key the operator pinned, and never falls back to a keyless path.

use std::fmt;

use serde_json::{Map, Value};
use weglarka_core::app::Digest;

use crate::image_ref::ImageRef;
use crate::key::PublicKey;

/// Payload cap: a simple-signing payload is a few hundred bytes; this is a hostile-peer limit, not
/// a format definition.
pub(crate) const MAX_PAYLOAD_BYTES: usize = 64 * 1024;

/// `critical.type` of a `cosign sign` (key-based) payload.
const COSIGN_TYPE: &str = "cosign container image signature";
/// Digest field in `critical.image`.
const DIGEST_KEY: &str = "docker-manifest-digest";
/// Repository field in `critical.identity`.
const REFERENCE_KEY: &str = "docker-reference";

/// A signature as stored in the registry: the exact payload bytes and the ASN.1 DER signature over
/// them.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature {
    /// Bytes the signature was computed over, exactly as fetched from the blob.
    pub payload: Vec<u8>,
    /// ASN.1 DER ECDSA P-256 / SHA-256 signature (already base64-decoded).
    pub signature: Vec<u8>,
}

impl fmt::Debug for Signature {
    // Payloads are public data, but they are also up to 64 KiB and useless in a log line.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signature")
            .field("payload_len", &self.payload.len())
            .field("signature_len", &self.signature.len())
            .finish()
    }
}

/// Verifies that `sig` is a valid cosign signature of `digest` for `image`, made by the holder of
/// `key`.
///
/// Checks, in order: the payload is a bounded JSON object; `critical.type` is the key-based cosign
/// type; the digest field names `digest`; `critical.identity.docker-reference` names the same
/// repository as `image`; and finally the signature over the exact payload bytes.
pub fn verify(
    sig: &Signature,
    key: &PublicKey,
    image: &ImageRef,
    digest: &Digest,
) -> Result<(), VerifyError> {
    if sig.payload.len() > MAX_PAYLOAD_BYTES {
        return Err(VerifyError::PayloadTooLarge {
            len: sig.payload.len(),
            max: MAX_PAYLOAD_BYTES,
        });
    }
    let value: Value = serde_json::from_slice(&sig.payload)
        .map_err(|e| VerifyError::InvalidJson(e.to_string()))?;
    let root = value.as_object().ok_or(VerifyError::InvalidPayload(
        "the payload is not a JSON object",
    ))?;
    let critical = root
        .get("critical")
        .and_then(Value::as_object)
        .ok_or(VerifyError::MissingField("critical"))?;
    let kind = critical
        .get("type")
        .and_then(Value::as_str)
        .ok_or(VerifyError::MissingField("critical.type"))?;
    if kind != COSIGN_TYPE {
        return Err(VerifyError::WrongType(kind.to_owned()));
    }
    let signed_image = critical
        .get("image")
        .and_then(Value::as_object)
        .ok_or(VerifyError::MissingField("critical.image"))?;
    let signed_digest = field_case_insensitive(signed_image, DIGEST_KEY)
        .and_then(Value::as_str)
        .ok_or(VerifyError::MissingField(
            "critical.image.docker-manifest-digest",
        ))?;
    if !signed_digest.eq_ignore_ascii_case(digest.as_str()) {
        return Err(VerifyError::DigestMismatch {
            found: signed_digest.to_owned(),
            expected: digest.as_str().to_owned(),
        });
    }
    let identity = critical
        .get("identity")
        .and_then(Value::as_object)
        .ok_or(VerifyError::MissingField("critical.identity"))?;
    let signed_repository = field_case_insensitive(identity, REFERENCE_KEY)
        .and_then(Value::as_str)
        .ok_or(VerifyError::MissingField(
            "critical.identity.docker-reference",
        ))?;
    let expected_repository = image.repository_reference();
    if !strip_tag(signed_repository).eq_ignore_ascii_case(&expected_repository) {
        return Err(VerifyError::IdentityMismatch {
            found: signed_repository.to_owned(),
            expected: expected_repository,
        });
    }
    if !key.verify(&sig.payload, &sig.signature) {
        return Err(VerifyError::BadSignature);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    #[error("the signature payload is {len} bytes, the limit is {max}")]
    PayloadTooLarge { len: usize, max: usize },
    #[error("the signature payload is not valid JSON: {0}")]
    InvalidJson(String),
    #[error("the signature payload is not valid: {0}")]
    InvalidPayload(&'static str),
    #[error("the signature payload is missing the {0} field")]
    MissingField(&'static str),
    #[error("unsupported signature type {0:?}: expected \"cosign container image signature\"")]
    WrongType(String),
    #[error("the signature is for digest {found}, the image digest is {expected}")]
    DigestMismatch { found: String, expected: String },
    #[error("the signature is for {found:?}, not for the repository {expected:?}")]
    IdentityMismatch { found: String, expected: String },
    #[error("the signature does not verify against the pinned public key")]
    BadSignature,
}

/// Looks up `name` in a JSON object ignoring ASCII case (the cosign payload capitalizes some keys).
fn field_case_insensitive<'a>(object: &'a Map<String, Value>, name: &str) -> Option<&'a Value> {
    object
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
}

/// `registry/repository:tag` → `registry/repository`; a `:tag` or `@digest` suffix at the last path
/// component is dropped. Colons in a registry port are not a suffix (they precede a `/`).
fn strip_tag(reference: &str) -> &str {
    let component = reference.rfind('/').map_or(0, |slash| slash + 1);
    match reference[component..].find([':', '@']) {
        Some(offset) => &reference[..component + offset],
        None => reference,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{TestSigner, payload_for};
    use serde_json::json;

    fn image() -> ImageRef {
        ImageRef::parse("ghcr.io/jpalczewski/weglarka:edge").unwrap()
    }

    fn digest() -> Digest {
        Digest::new(format!("sha256:{}", "ab".repeat(32))).unwrap()
    }

    /// Signs an arbitrary payload with a fresh key.
    fn sign(payload: Value) -> (Signature, TestSigner) {
        let signer = TestSigner::generate().unwrap();
        let bytes = serde_json::to_vec(&payload).unwrap();
        (signer.sign(&bytes).unwrap(), signer)
    }

    fn valid_payload() -> Value {
        json!({
            "critical": {
                "identity": { "docker-reference": "ghcr.io/jpalczewski/weglarka" },
                "image": { "docker-manifest-digest": digest().as_str() },
                "type": "cosign container image signature",
            },
            "optional": null,
        })
    }

    #[test]
    fn a_valid_signature_verifies() {
        let signer = TestSigner::generate().unwrap();
        let sig = signer.sign_for(&image(), &digest()).unwrap();
        verify(&sig, signer.public_key(), &image(), &digest()).unwrap();
    }

    #[test]
    fn the_signing_helper_and_the_payload_builder_agree() {
        let signer = TestSigner::generate().unwrap();
        let sig = signer.sign_for(&image(), &digest()).unwrap();
        assert_eq!(sig.payload, payload_for(&image(), &digest()).unwrap());
        verify(&sig, signer.public_key(), &image(), &digest()).unwrap();
    }

    #[test]
    fn a_tampered_payload_is_rejected() {
        let (mut sig, signer) = sign(valid_payload());
        sig.payload.push(b' ');
        assert_eq!(
            verify(&sig, signer.public_key(), &image(), &digest()).unwrap_err(),
            VerifyError::BadSignature
        );
        // Same bytes re-signed by a different key.
        let other = TestSigner::generate().unwrap();
        let sig = other.sign(&sig.payload).unwrap();
        assert_eq!(
            verify(&sig, signer.public_key(), &image(), &digest()).unwrap_err(),
            VerifyError::BadSignature
        );
    }

    #[test]
    fn a_tampered_or_malformed_signature_is_rejected() {
        let (mut sig, signer) = sign(valid_payload());
        sig.signature.truncate(sig.signature.len() - 1);
        assert_eq!(
            verify(&sig, signer.public_key(), &image(), &digest()).unwrap_err(),
            VerifyError::BadSignature
        );
        let mut sig = sign(valid_payload()).0;
        sig.signature.clear();
        assert_eq!(
            verify(&sig, signer.public_key(), &image(), &digest()).unwrap_err(),
            VerifyError::BadSignature
        );
        let mut sig = sign(valid_payload()).0;
        sig.signature = vec![0x30, 0x02, 0x01, 0x02];
        assert_eq!(
            verify(&sig, signer.public_key(), &image(), &digest()).unwrap_err(),
            VerifyError::BadSignature
        );
    }

    #[test]
    fn the_digest_and_the_repository_must_match() {
        let signer = TestSigner::generate().unwrap();
        let sig = signer.sign_for(&image(), &digest()).unwrap();
        let other = Digest::new(format!("sha256:{}", "cd".repeat(32))).unwrap();
        assert_eq!(
            verify(&sig, signer.public_key(), &image(), &other).unwrap_err(),
            VerifyError::DigestMismatch {
                found: digest().as_str().to_owned(),
                expected: other.as_str().to_owned(),
            }
        );
        let other_image = ImageRef::parse("ghcr.io/someone/else:edge").unwrap();
        assert_eq!(
            verify(&sig, signer.public_key(), &other_image, &digest()).unwrap_err(),
            VerifyError::IdentityMismatch {
                found: "ghcr.io/jpalczewski/weglarka".into(),
                expected: "ghcr.io/someone/else".into(),
            }
        );
    }

    #[test]
    fn a_keyless_signature_type_is_rejected() {
        let mut payload = valid_payload();
        payload["critical"]["type"] = json!("https://sigstore.dev/cosign/sign/v1");
        let (sig, signer) = sign(payload);
        assert_eq!(
            verify(&sig, signer.public_key(), &image(), &digest()).unwrap_err(),
            VerifyError::WrongType("https://sigstore.dev/cosign/sign/v1".into())
        );
    }

    #[test]
    fn the_digest_key_and_the_hex_are_case_insensitive() {
        let mut payload = valid_payload();
        payload["critical"]["image"] = json!({
            "Docker-manifest-digest": digest().as_str().to_uppercase().replace("SHA256:", "sha256:"),
        });
        let (sig, signer) = sign(payload);
        verify(&sig, signer.public_key(), &image(), &digest()).unwrap();
    }

    #[test]
    fn an_identity_with_a_tag_or_digest_is_the_same_repository() {
        for reference in [
            "ghcr.io/jpalczewski/weglarka:latest",
            "ghcr.io/jpalczewski/weglarka@sha256:0000",
            "GHCR.IO/JPalczewski/weglarka:edge",
            "ghcr.io:443/jpalczewski/weglarka:edge",
        ] {
            let mut payload = valid_payload();
            payload["critical"]["identity"] = json!({ "docker-reference": reference });
            let (sig, signer) = sign(payload);
            let outcome = verify(&sig, signer.public_key(), &image(), &digest());
            if reference.starts_with("ghcr.io:443") {
                // A registry port is part of the name; the image has no port, so it differs.
                assert!(matches!(outcome, Err(VerifyError::IdentityMismatch { .. })));
            } else {
                outcome.unwrap();
            }
        }
    }

    #[test]
    fn missing_fields_are_reported_precisely() {
        let cases: Vec<(Value, &'static str)> = vec![
            (json!({}), "critical"),
            (json!({ "critical": {} }), "critical.type"),
            (
                json!({ "critical": { "type": "cosign container image signature" } }),
                "critical.image",
            ),
            (
                json!({ "critical": { "type": "cosign container image signature", "image": {} } }),
                "critical.image.docker-manifest-digest",
            ),
            (
                json!({ "critical": {
                    "type": "cosign container image signature",
                    "image": { "docker-manifest-digest": digest().as_str() },
                } }),
                "critical.identity",
            ),
            (
                json!({ "critical": {
                    "type": "cosign container image signature",
                    "image": { "docker-manifest-digest": digest().as_str() },
                    "identity": {},
                } }),
                "critical.identity.docker-reference",
            ),
        ];
        for (payload, field) in cases {
            let (sig, signer) = sign(payload);
            assert_eq!(
                verify(&sig, signer.public_key(), &image(), &digest()).unwrap_err(),
                VerifyError::MissingField(field)
            );
        }
    }

    #[test]
    fn payloads_that_are_not_objects_or_too_large_are_rejected() {
        let (mut sig, signer) = sign(json!([1, 2, 3]));
        assert_eq!(
            verify(&sig, signer.public_key(), &image(), &digest()).unwrap_err(),
            VerifyError::InvalidPayload("the payload is not a JSON object")
        );

        sig.payload = b"not json".to_vec();
        assert!(matches!(
            verify(&sig, signer.public_key(), &image(), &digest()).unwrap_err(),
            VerifyError::InvalidJson(_)
        ));

        sig.payload = vec![b'a'; MAX_PAYLOAD_BYTES + 1];
        assert_eq!(
            verify(&sig, signer.public_key(), &image(), &digest()).unwrap_err(),
            VerifyError::PayloadTooLarge {
                len: MAX_PAYLOAD_BYTES + 1,
                max: MAX_PAYLOAD_BYTES
            }
        );
    }

    #[test]
    fn debug_does_not_dump_the_payload() {
        let sig = Signature {
            payload: vec![b'x'; 100],
            signature: vec![0; 70],
        };
        let text = format!("{sig:?}");
        assert!(text.contains("payload_len: 100"), "{text}");
        assert!(!text.contains("xxx"), "{text}");
    }

    #[test]
    fn tag_stripping_handles_ports_tags_and_digests() {
        assert_eq!(strip_tag("ghcr.io/repo"), "ghcr.io/repo");
        assert_eq!(strip_tag("ghcr.io/repo:edge"), "ghcr.io/repo");
        assert_eq!(strip_tag("ghcr.io/repo@sha256:abcd"), "ghcr.io/repo");
        assert_eq!(strip_tag("localhost:5000/repo:tag"), "localhost:5000/repo");
        assert_eq!(strip_tag("localhost:5000/repo"), "localhost:5000/repo");
        assert_eq!(strip_tag("repo:tag"), "repo");
    }
}
