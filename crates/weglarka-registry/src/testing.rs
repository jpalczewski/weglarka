//! Test doubles: an in-memory [`Registry`] and a throw-away P-256 signing key.
//!
//! Compiled for this crate's own tests and for consumers that enable the `testing` feature (the
//! daemon's self-update tests). Nothing here is meant for production: [`FakeRegistry`] returns
//! whatever it was scripted with, and [`TestSigner`] holds a private key generated at runtime, so
//! no test needs an external `cosign` binary or a fixture secret.

use std::fmt;
use std::sync::{Mutex, PoisonError};

use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use serde_json::json;
use weglarka_model::app::Digest;

use crate::cosign::Signature;
use crate::image_ref::ImageRef;
use crate::key::{self, KeyError, PublicKey};
use crate::registry::{Registry, RegistryError};

/// One recorded [`Registry::cosign_signatures`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub image: ImageRef,
    pub digest: Digest,
}

/// A [`Registry`] that returns scripted signatures (or a scripted error) and records its calls.
#[derive(Debug, Default)]
pub struct FakeRegistry {
    state: Mutex<FakeState>,
}

#[derive(Debug, Default)]
struct FakeState {
    signatures: Vec<Signature>,
    failure: Option<RegistryError>,
    calls: Vec<Call>,
}

impl FakeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// A fake that always returns `signatures`.
    pub fn with_signatures(signatures: impl IntoIterator<Item = Signature>) -> Self {
        let fake = Self::default();
        fake.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .signatures = signatures.into_iter().collect();
        fake
    }

    /// Adds a signature to the scripted answer.
    pub fn push_signature(&self, signature: Signature) {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .signatures
            .push(signature);
    }

    /// The **next** call fails with `error`; later calls return the scripted signatures again.
    pub fn fail_once(&self, error: RegistryError) {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .failure = Some(error);
    }

    /// Every call received so far, in order.
    pub fn calls(&self) -> Vec<Call> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .calls
            .clone()
    }

    pub fn clear_calls(&self) {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .calls
            .clear();
    }
}

impl Registry for FakeRegistry {
    async fn cosign_signatures(
        &self,
        image: &ImageRef,
        digest: &Digest,
    ) -> Result<Vec<Signature>, RegistryError> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.calls.push(Call {
            image: image.clone(),
            digest: digest.clone(),
        });
        if let Some(failure) = state.failure.take() {
            return Err(failure);
        }
        Ok(state.signatures.clone())
    }
}

/// Why a [`TestSigner`] could not be created or used.
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("cannot generate a test key: {0}")]
    KeyGeneration(String),
    #[error("the generated key is not a P-256 point")]
    Point,
    #[error("cannot parse the generated public key: {0}")]
    PublicKey(#[from] KeyError),
    #[error("cannot sign the test payload: {0}")]
    Sign(String),
    #[error("cannot encode the test payload: {0}")]
    Payload(#[from] serde_json::Error),
}

/// A freshly generated P-256 key pair that can sign cosign simple-signing payloads.
pub struct TestSigner {
    key_pair: EcdsaKeyPair,
    public_key: PublicKey,
    public_key_pem: String,
    rng: SystemRandom,
}

impl fmt::Debug for TestSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The private key must not be printable, but its public half is public data.
        f.debug_struct("TestSigner")
            .field("public_key_pem", &self.public_key_pem)
            .finish_non_exhaustive()
    }
}

impl TestSigner {
    /// Generates a P-256 key pair with the process RNG (`ring`), no fixtures involved.
    pub fn generate() -> Result<Self, SigningError> {
        let rng = SystemRandom::new();
        let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .map_err(|e| SigningError::KeyGeneration(e.to_string()))?;
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, document.as_ref(), &rng)
                .map_err(|e| SigningError::KeyGeneration(e.to_string()))?;
        let point: [u8; 65] = key_pair
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| SigningError::Point)?;
        let der = key::spki_der(&point);
        let public_key = PublicKey::from_der(&der)?;
        Ok(Self {
            key_pair,
            public_key,
            public_key_pem: pem_encode(&der),
            rng,
        })
    }

    /// The matching public key, as [`crate::verify`] needs it.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// The matching public key as a `PUBLIC KEY` PEM (for daemon tests that pin a key by text).
    pub fn public_key_pem(&self) -> &str {
        &self.public_key_pem
    }

    /// Signs arbitrary payload bytes exactly as `cosign sign --key` would (ASN.1 DER over SHA-256).
    pub fn sign(&self, payload: &[u8]) -> Result<Signature, SigningError> {
        let signature = self
            .key_pair
            .sign(&self.rng, payload)
            .map_err(|e| SigningError::Sign(e.to_string()))?;
        Ok(Signature {
            payload: payload.to_vec(),
            signature: signature.as_ref().to_vec(),
        })
    }

    /// Builds the simple-signing payload for `image`/`digest` with [`payload_for`] and signs it.
    pub fn sign_for(&self, image: &ImageRef, digest: &Digest) -> Result<Signature, SigningError> {
        let payload = payload_for(image, digest)?;
        self.sign(&payload)
    }
}

/// The simple-signing payload `cosign sign` stores: the image digest, the repository identity and
/// the key-based signature type.
pub fn payload_for(image: &ImageRef, digest: &Digest) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(&json!({
        "critical": {
            "identity": { "docker-reference": image.repository_reference() },
            "image": { "docker-manifest-digest": digest.as_str() },
            "type": "cosign container image signature",
        },
        "optional": null,
    }))
}

fn pem_encode(der: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        if let Ok(text) = std::str::from_utf8(chunk) {
            pem.push_str(text);
        }
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    pem
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_key_signs_payloads_that_verify() {
        let signer = TestSigner::generate().unwrap();
        let image = ImageRef::parse("ghcr.io/jpalczewski/weglarka:edge").unwrap();
        let digest = Digest::new(format!("sha256:{}", "ab".repeat(32))).unwrap();
        let signature = signer.sign_for(&image, &digest).unwrap();
        crate::verify(&signature, signer.public_key(), &image, &digest).unwrap();
        // The PEM round-trips through the strict parser, so daemon tests can pin it as text.
        let pinned = PublicKey::from_pem(signer.public_key_pem()).unwrap();
        assert_eq!(&pinned, signer.public_key());
        assert!(signer.public_key_pem().contains("BEGIN PUBLIC KEY"));
        // The debug form shows the public half only.
        let debug = format!("{signer:?}");
        assert!(debug.contains("BEGIN PUBLIC KEY"), "{debug}");
    }

    #[test]
    fn different_generated_keys_do_not_verify_each_others_signatures() {
        let first = TestSigner::generate().unwrap();
        let second = TestSigner::generate().unwrap();
        assert_ne!(first.public_key(), second.public_key());
        let image = ImageRef::parse("ghcr.io/jpalczewski/weglarka:edge").unwrap();
        let digest = Digest::new(format!("sha256:{}", "cd".repeat(32))).unwrap();
        let signature = first.sign_for(&image, &digest).unwrap();
        assert!(matches!(
            crate::verify(&signature, second.public_key(), &image, &digest).unwrap_err(),
            crate::VerifyError::BadSignature
        ));
    }
}
