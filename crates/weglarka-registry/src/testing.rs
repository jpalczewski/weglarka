//! Test doubles: an in-memory [`Registry`] and a throw-away P-256 signing key.
//!
//! Compiled for this crate's own tests and for consumers that enable the `testing` feature (the
//! daemon's self-update tests). Nothing here is meant for production: [`FakeRegistry`] returns
//! whatever it was scripted with, and [`TestSigner`] holds a private key generated at runtime, so
//! no test needs an external `cosign` binary or a fixture secret.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Mutex, PoisonError};

use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use sha2::{Digest as _, Sha256};
use weglarka_model::app::Digest;
use weglarka_model::release_set::{Repository, StrictDigest};

use crate::cosign::Signature;
use crate::image_ref::ImageRef;
use crate::key::{self, KeyError, PublicKey, pem_encode};
use crate::registry::{FetchedManifest, Registry, RegistryError, ReleaseRegistry};

pub use crate::cosign::payload_for;

/// One recorded [`Registry::cosign_signatures`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub image: ImageRef,
    pub digest: Digest,
}

/// A [`Registry`] that returns scripted signatures (or a scripted error) and records its calls.
///
/// [`FakeRegistry::new`] models a `.sig` manifest that exists but holds no key-based layer (the real
/// client answers `Ok` with an empty list, e.g. for a keyless-only signature).
/// [`FakeRegistry::without_signature_tag`] models an unsigned image: no `.sig` tag, so a `404`.
#[derive(Debug, Default)]
pub struct FakeRegistry {
    state: Mutex<FakeState>,
}

#[derive(Debug, Default)]
struct FakeState {
    signatures: Vec<Signature>,
    /// No `.sig` tag exists: unless `failure` is set, every call answers `404`.
    no_signature_tag: bool,
    failure: Option<RegistryError>,
    calls: Vec<Call>,
}

impl FakeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// A fake for an unsigned image: the `.sig` tag is absent, so every call fails with the `404` the
    /// HTTP client reports (`RegistryError::is_not_found()`), until signatures are pushed.
    pub fn without_signature_tag() -> Self {
        let fake = Self::default();
        fake.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .no_signature_tag = true;
        fake
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
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.signatures.push(signature);
        // The tag exists from now on.
        state.no_signature_tag = false;
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
        if state.no_signature_tag {
            return Err(RegistryError::Status {
                status: 404,
                what: "signature manifest",
            });
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

/// An in-memory release repository: manifests, blobs, tags and the legacy `.sig` documents.
///
/// It behaves like the registry for the operations the publisher uses, so the release tool's
/// tests drive the real code paths (sequence allocation, immutable-tag comparison, pointer moves,
/// signature lookup) without a network or a token endpoint. `cosign_signatures` reads the `.sig`
/// manifest this fake stored, so the signature layout is exercised end to end.
#[derive(Debug, Default)]
pub struct FakeReleaseRegistry {
    state: Mutex<FakeReleaseState>,
}

#[derive(Debug, Default)]
struct FakeReleaseState {
    /// `(repository, tag)` → exact manifest bytes.
    manifests: BTreeMap<(String, String), Vec<u8>>,
    /// `(repository, digest)` → blob bytes.
    blobs: BTreeMap<(String, String), Vec<u8>>,
    /// Every call, as `(repository, reference)`, for assertions about write ordering.
    calls: Vec<(String, String)>,
    /// Tags hidden from listings while their manifest stays readable (a stale tag list or a
    /// concurrent push the allocating run did not see).
    hidden: BTreeSet<(String, String)>,
}

impl FakeReleaseRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// The tags currently stored in `repository`, sorted.
    pub fn tags_of(&self, repository: &Repository) -> Vec<String> {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let mut tags: Vec<String> = state
            .manifests
            .keys()
            .filter(|(repo, _)| repo == repository.as_str())
            .filter(|key| !state.hidden.contains(*key))
            .map(|(_, tag)| tag.clone())
            .filter(|tag| !tag.starts_with("sha256:"))
            .collect();
        tags.sort();
        tags
    }

    /// The bytes stored under `tag`, if any.
    pub fn manifest_bytes(&self, repository: &Repository, tag: &str) -> Option<Vec<u8>> {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state
            .manifests
            .get(&(repository.as_str().to_owned(), tag.to_owned()))
            .cloned()
    }

    /// Hides `tag` from listings while keeping the manifest readable: simulates a stale tag list
    /// (the allocation must still refuse to overwrite the immutable bytes).
    pub fn hide_tag(&self, repository: &Repository, tag: &str) {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .hidden
            .insert((repository.as_str().to_owned(), tag.to_owned()));
    }

    /// Every call received, in order.
    pub fn calls(&self) -> Vec<(String, String)> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .calls
            .clone()
    }

    fn record(&self, repository: &Repository, reference: &str) {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .calls
            .push((repository.as_str().to_owned(), reference.to_owned()));
    }
}

impl Registry for FakeReleaseRegistry {
    async fn cosign_signatures(
        &self,
        image: &ImageRef,
        digest: &Digest,
    ) -> Result<Vec<Signature>, RegistryError> {
        let repository = image.repository_reference();
        let tag = format!("{}.sig", digest.as_str().replace(':', "-"));
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        // Same answer as the HTTP client for a missing `.sig` tag, so callers see one contract.
        let bytes =
            state
                .manifests
                .get(&(repository.clone(), tag))
                .ok_or(RegistryError::Status {
                    status: 404,
                    what: "signature manifest",
                })?;
        // A deliberately lenient read of the signature manifest, enough for the verifier: one
        // simple-signing layer with the signature annotation and the payload blob behind it.
        let document: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|error| RegistryError::MalformedJson {
                what: "signature manifest",
                detail: error.to_string(),
            })?;
        let mut signatures = Vec::new();
        for layer in document["layers"].as_array().into_iter().flatten() {
            if layer["mediaType"].as_str()
                != Some("application/vnd.dev.cosign.simplesigning.v1+json")
            {
                continue;
            }
            let encoded = layer["annotations"]["dev.cosignproject.cosign/signature"]
                .as_str()
                .ok_or(RegistryError::MissingAnnotation {
                    annotation: "dev.cosignproject.cosign/signature",
                })?;
            let signature = {
                use base64::Engine as _;
                base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .map_err(|error| RegistryError::SignatureBase64(error.to_string()))?
            };
            let digest = layer["digest"]
                .as_str()
                .ok_or(RegistryError::UnsupportedLayerDigest {
                    digest: String::new(),
                })?;
            let payload = state
                .blobs
                .get(&(repository.clone(), digest.to_owned()))
                .ok_or(RegistryError::Status {
                    status: 404,
                    what: "signature payload",
                })?
                .clone();
            signatures.push(Signature { payload, signature });
        }
        Ok(signatures)
    }
}

impl ReleaseRegistry for FakeReleaseRegistry {
    async fn manifest(
        &self,
        repository: &Repository,
        reference: &str,
        _max_body: usize,
    ) -> Result<FetchedManifest, RegistryError> {
        self.record(repository, reference);
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let bytes = match state
            .manifests
            .get(&(repository.as_str().to_owned(), reference.to_owned()))
        {
            Some(bytes) => bytes.clone(),
            None if reference.starts_with("sha256:") => state
                .manifests
                .iter()
                .filter(|((repo, _), _)| repo == repository.as_str())
                .find(|(_, bytes)| {
                    format!(
                        "sha256:{}",
                        crate::registry::hex_lower(&Sha256::digest(bytes))
                    ) == reference
                })
                .map(|(_, bytes)| bytes.clone())
                .ok_or(RegistryError::Status {
                    status: 404,
                    what: "release-set manifest",
                })?,
            None => {
                return Err(RegistryError::Status {
                    status: 404,
                    what: "release-set manifest",
                });
            }
        };
        let digest = StrictDigest::new(format!(
            "sha256:{}",
            crate::registry::hex_lower(&Sha256::digest(&bytes))
        ))
        .map_err(|_| RegistryError::InvalidDigest {
            digest: reference.to_owned(),
        })?;
        Ok(FetchedManifest { bytes, digest })
    }

    async fn blob(
        &self,
        repository: &Repository,
        digest: &StrictDigest,
        _max_body: usize,
    ) -> Result<Vec<u8>, RegistryError> {
        self.record(repository, digest.as_str());
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state
            .blobs
            .get(&(repository.as_str().to_owned(), digest.as_str().to_owned()))
            .cloned()
            .ok_or(RegistryError::Status {
                status: 404,
                what: "release-set blob",
            })
    }

    async fn tags(&self, repository: &Repository) -> Result<Vec<String>, RegistryError> {
        self.record(repository, "tags/list");
        Ok(self.tags_of(repository))
    }

    async fn put_blob(
        &self,
        repository: &Repository,
        bytes: &[u8],
    ) -> Result<StrictDigest, RegistryError> {
        let digest = StrictDigest::new(format!(
            "sha256:{}",
            crate::registry::hex_lower(&Sha256::digest(bytes))
        ))
        .map_err(|_| RegistryError::InvalidDigest {
            digest: "computed sha256".to_owned(),
        })?;
        self.record(repository, digest.as_str());
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .blobs
            .insert(
                (repository.as_str().to_owned(), digest.as_str().to_owned()),
                bytes.to_vec(),
            );
        Ok(digest)
    }

    async fn put_manifest(
        &self,
        repository: &Repository,
        tag: &str,
        bytes: &[u8],
    ) -> Result<StrictDigest, RegistryError> {
        self.record(repository, tag);
        let digest = StrictDigest::new(format!(
            "sha256:{}",
            crate::registry::hex_lower(&Sha256::digest(bytes))
        ))
        .map_err(|_| RegistryError::InvalidDigest {
            digest: tag.to_owned(),
        })?;
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .manifests
            .insert(
                (repository.as_str().to_owned(), tag.to_owned()),
                bytes.to_vec(),
            );
        Ok(digest)
    }
}

/// A generated P-256 key pair in the form the publisher's [`SigningKey`] takes (unencrypted
/// PKCS#8), so tests exercise signing without a fixture secret.
pub struct TestSigningKey {
    signing_key: crate::SigningKey,
    pkcs8: Vec<u8>,
}

impl fmt::Debug for TestSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestSigningKey")
            .field("public_key_pem", &self.signing_key.public_key_pem())
            .finish_non_exhaustive()
    }
}

impl TestSigningKey {
    pub fn generate() -> Result<Self, SigningError> {
        let rng = SystemRandom::new();
        let document = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .map_err(|e| SigningError::KeyGeneration(e.to_string()))?;
        let pkcs8 = document.as_ref().to_vec();
        let signing_key = crate::SigningKey::from_der(&pkcs8)?;
        Ok(Self { signing_key, pkcs8 })
    }

    pub fn signing_key(&self) -> &crate::SigningKey {
        &self.signing_key
    }

    pub fn public_key(&self) -> &PublicKey {
        self.signing_key.public_key()
    }

    /// The PEM form, for a CLI-level test that must write a key file.
    pub fn pem(&self) -> String {
        use base64::Engine as _;

        let encoded = base64::engine::general_purpose::STANDARD.encode(&self.pkcs8);
        let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
        for chunk in encoded.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
            pem.push('\n');
        }
        pem.push_str("-----END PRIVATE KEY-----\n");
        pem
    }
}
