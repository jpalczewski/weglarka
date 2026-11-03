//! Registry access: the cosign signature manifest next to an image, and the payload blobs it
//! points at.
//!
//! Cosign stores a key-based signature as an OCI image manifest in the same repository under the
//! tag `<algorithm>-<hex>.sig` (for an image digest `sha256:<hex>`: `sha256-<hex>.sig`). The
//! manifest has one layer per signature; the layer of media type
//! `application/vnd.dev.cosign.simplesigning.v1+json` carries the base64 signature in the
//! `dev.cosignproject.cosign/signature` annotation, and its blob is the payload the signature was
//! computed over. A layer with a `dev.sigstore.cosign/certificate` annotation is a keyless
//! (Fulcio) signature and is skipped: this crate verifies with a pinned key only.
//!
//! The payload blob's sha256 is checked against the layer digest before the payload is used, so a
//! registry cannot hand over a different payload signed for the same digest. The `Accept` header
//! for the manifest lists the OCI and Docker manifest types, as GHCR serves the OCI one.
//!
//! Registries may require a Bearer token even for public repositories: the first `401` challenge
//! carries the realm, service and scope, an anonymous token is fetched (≤ 8 KiB), and it is cached
//! in memory per registry+repository. The token never leaves the process: it is not logged, not
//! part of any error message, and [`HttpRegistry`] deliberately has no `Debug` that would show it.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::sync::{Mutex, PoisonError};

use base64::Engine as _;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use weglarka_model::app::Digest;
use weglarka_model::release_set::{Repository, StrictDigest};

use weglarka_http::reqwest::Url;

use crate::cosign::{MAX_PAYLOAD_BYTES, Signature};
use crate::http::{self, HttpError};
use crate::image_ref::ImageRef;

/// Token response limit: GHCR tokens are ~1–3 KiB; the cap protects the daemon from a hostile or
/// broken token endpoint.
const MAX_TOKEN_BYTES: usize = 8 * 1024;
/// Signature manifest limit; the cosign `.sig` manifests are a few hundred bytes.
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
/// Signature annotation limit (base64 before decoding).
const MAX_SIGNATURE_ANNOTATION: usize = 2 * 1024;
/// DER signature limit (a P-256 ECDSA signature is ~72 bytes).
const MAX_SIGNATURE_BYTES: usize = 1024;
/// `WWW-Authenticate` header limit.
const MAX_CHALLENGE_BYTES: usize = 4 * 1024;
/// Manifest types accepted when asking for the `.sig` manifest.
const ACCEPT_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json, \
     application/vnd.docker.distribution.manifest.v2+json, \
     application/vnd.oci.image.index.v1+json, \
     application/vnd.docker.distribution.manifest.list.v2+json";
/// Media type of a cosign simple-signing layer.
const SIMPLE_SIGNING_MEDIA_TYPE: &str = "application/vnd.dev.cosign.simplesigning.v1+json";
/// Annotation with the base64 signature of a simple-signing layer.
const SIGNATURE_ANNOTATION: &str = "dev.cosignproject.cosign/signature";
/// Annotation that marks a keyless (Fulcio) signature, which this crate cannot verify.
const CERTIFICATE_ANNOTATION: &str = "dev.sigstore.cosign/certificate";

/// Fetches the cosign signatures of an image digest.
///
/// Implementations return every key-based signature for `digest` in `image`'s repository (possibly
/// none); they must check that each payload really hangs off `digest` (as [`HttpRegistry`] does),
/// but the signature itself is only trusted after [`crate::verify`].
pub trait Registry: Send + Sync {
    /// The signatures cosign stored for `digest` in `image`'s repository.
    fn cosign_signatures(
        &self,
        image: &ImageRef,
        digest: &Digest,
    ) -> impl Future<Output = Result<Vec<Signature>, RegistryError>> + Send;
}

/// A manifest as the registry served it, with the digest it resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedManifest {
    /// The exact manifest bytes; the release-set parser consumes these, not a re-serialization.
    pub bytes: Vec<u8>,
    /// The digested identity of `bytes` (the registry's `Docker-Content-Digest`, or the SHA-256 of
    /// the bytes when the registry did not send one).
    pub digest: StrictDigest,
}

/// Reads and writes the generic OCI objects a release set needs (manifests, blobs, tags).
///
/// This is separate from [`Registry`] because the host only ever reads a cosign `.sig` next to an
/// image, while the publisher pushes release-set artifacts and allocates a tag sequence. Both
/// halves share [`HttpRegistry`], so the transport, token isolation, redirect policy and size caps
/// are the same code on the publish and on the verify path.
///
/// Every method takes explicit bounds: a registry is a hostile peer even when it is GHCR.
pub trait ReleaseRegistry: Registry {
    /// Fetches a manifest by tag or digest. A digest reference must resolve to exactly those bytes.
    fn manifest(
        &self,
        repository: &Repository,
        reference: &str,
        max_body: usize,
    ) -> impl Future<Output = Result<FetchedManifest, RegistryError>> + Send;

    /// Fetches a blob and checks it against `digest`.
    fn blob(
        &self,
        repository: &Repository,
        digest: &StrictDigest,
        max_body: usize,
    ) -> impl Future<Output = Result<Vec<u8>, RegistryError>> + Send;

    /// Lists every tag of `repository`, bounded by [`MAX_TAGS`].
    fn tags(
        &self,
        repository: &Repository,
    ) -> impl Future<Output = Result<Vec<String>, RegistryError>> + Send;

    /// Uploads a blob (idempotent: an existing identical blob is fine) and returns its digest.
    fn put_blob(
        &self,
        repository: &Repository,
        bytes: &[u8],
    ) -> impl Future<Output = Result<StrictDigest, RegistryError>> + Send;

    /// Stores `bytes` under `tag` and returns the manifest digest.
    fn put_manifest(
        &self,
        repository: &Repository,
        tag: &str,
        bytes: &[u8],
    ) -> impl Future<Output = Result<StrictDigest, RegistryError>> + Send;
}

/// Page size for a tag listing request; GHCR caps `n` itself.
const TAG_PAGE_SIZE: usize = 1000;
/// Hard bound on tags read for one sequence allocation.
pub const MAX_TAGS: usize = 10_000;
/// Pagination pages followed before giving up.
const MAX_TAG_PAGES: usize = 64;
/// Response cap for a write acknowledgement (registries answer with an empty body).
const MAX_WRITE_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error(transparent)]
    Http(#[from] HttpError),
    #[error("{what} {reference:?} is not a valid tag or digest")]
    InvalidReference {
        what: &'static str,
        reference: String,
    },
    #[error("the manifest resolves to {actual}, not to the requested digest {expected}")]
    ManifestDigestMismatch { expected: String, actual: String },
    #[error("the blob {expected} hashes to {actual}")]
    BlobDigestMismatch { expected: String, actual: String },
    #[error("the registry started a blob upload without a usable Location header")]
    MissingUploadLocation,
    #[error("the registry's upload Location is not a usable URL")]
    InvalidUploadLocation,
    #[error(
        "the tag list exceeded the {MAX_TAGS}-tag limit, so the sequence cannot be allocated safely"
    )]
    TooManyTags,
    #[error("{digest:?} is not a canonical lower-case sha256 digest")]
    InvalidDigest { digest: String },
    #[error("{tag:?} is not a valid immutable OCI tag")]
    InvalidTag { tag: String },
    #[error("the registry credentials are not a safe HTTP Basic value")]
    InvalidCredentials,
    #[error("the registry's pagination Link is not a usable URL")]
    InvalidLink,
    #[error("the release signing key cannot be used: {0}")]
    Signing(String),
    #[error("the registry returned status {status} for the {what}")]
    Status { status: u16, what: &'static str },
    #[error("the registry's WWW-Authenticate response is not a usable Bearer challenge")]
    AuthChallenge,
    #[error("the registry did not return an authentication token")]
    MissingToken,
    #[error("the authentication token is not a safe HTTP header value")]
    InvalidToken,
    #[error("the {what} is not valid JSON: {detail}")]
    MalformedJson { what: &'static str, detail: String },
    #[error("a cosign signature layer has no {annotation:?} annotation")]
    MissingAnnotation { annotation: &'static str },
    #[error("a cosign signature is not valid base64: {0}")]
    SignatureBase64(String),
    #[error("the {what} is {len} bytes, the limit is {limit}")]
    TooLarge {
        what: &'static str,
        len: usize,
        limit: usize,
    },
    #[error("unsupported signature layer digest {digest:?}: only sha256 is supported")]
    UnsupportedLayerDigest { digest: String },
    #[error("the signature payload hashes to {actual}, not to the layer digest {expected}")]
    PayloadDigestMismatch { expected: String, actual: String },
}

/// [`Registry`] over the shared HTTP client (see [`crate::http`]).
///
/// The anonymous Bearer token is cached in memory for the last registry+repository pair. The
/// struct has no `Debug` field for the token: it must not end up in a log line.
pub struct HttpRegistry {
    client: http::Client,
    token: Mutex<Option<CachedToken>>,
    /// HTTP Basic credentials for the token endpoint, `Authorization: Basic <value>`. Only a
    /// publisher sets them; the host stays anonymous. Never printed (`Debug` is custom).
    basic: Option<String>,
}

struct CachedToken {
    registry: String,
    repository: String,
    token: String,
}

/// Registry and repository path a request addresses. The host reaches images through [`ImageRef`];
/// release sets use the model's tag-free [`Repository`]. Both reduce to the same two fields.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RepoAddress {
    registry: String,
    repository: String,
}

impl RepoAddress {
    fn from_image(image: &ImageRef) -> Self {
        Self {
            registry: image.registry.clone(),
            repository: image.repository.clone(),
        }
    }

    /// Splits `host[:port]/lowercase/path`; the model has already validated both halves.
    fn split(repository: &Repository) -> Result<Self, RegistryError> {
        let (registry, path) =
            repository
                .as_str()
                .split_once('/')
                .ok_or_else(|| RegistryError::InvalidReference {
                    what: "repository",
                    reference: repository.as_str().to_owned(),
                })?;
        Ok(Self {
            registry: registry.to_owned(),
            repository: path.to_owned(),
        })
    }
}

impl fmt::Debug for HttpRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRegistry")
            .field("authenticated", &self.basic.is_some())
            .finish_non_exhaustive()
    }
}

impl HttpRegistry {
    /// A client that trusts the bundled `webpki-roots` and speaks HTTP/1.1.
    pub fn new() -> Result<Self, RegistryError> {
        Ok(Self {
            client: http::Client::new()?,
            token: Mutex::new(None),
            basic: None,
        })
    }

    /// A client that authenticates the token endpoint with HTTP Basic credentials (`user:token`).
    /// Used by the publisher only; verification stays anonymous.
    pub fn with_basic_credentials(username: &str, password: &str) -> Result<Self, RegistryError> {
        if !username
            .bytes()
            .chain(std::iter::once(b':'))
            .chain(password.bytes())
            .all(|byte| (0x20..0x7f).contains(&byte))
        {
            return Err(RegistryError::InvalidCredentials);
        }
        let mut client = Self::new()?;
        client.basic = Some(
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}")),
        );
        Ok(client)
    }

    fn cached_token(&self, repo: &RepoAddress) -> Option<String> {
        let cache = self.token.lock().unwrap_or_else(PoisonError::into_inner);
        cache
            .as_ref()
            .filter(|token| token.registry == repo.registry && token.repository == repo.repository)
            .map(|token| token.token.clone())
    }

    /// Sends one request, answers a single Bearer challenge and reuses the cached token. A `401`
    /// always re-fetches, so a pull token cached earlier cannot mask a missing `push` scope.
    async fn authorized(
        &self,
        request: http::Request<'_>,
        repo: &RepoAddress,
    ) -> Result<http::Response, RegistryError> {
        let what = request.what;
        let cached = self.cached_token(repo);
        let response = self
            .client
            .request(request.clone().with_bearer(cached.as_deref()))
            .await?;
        let response = if response.status == 401 {
            let token = self.fetch_token(&response, repo).await?;
            self.client
                .request(request.with_bearer(Some(&token)))
                .await?
        } else {
            response
        };
        if !(200..300).contains(&response.status) {
            return Err(RegistryError::Status {
                status: response.status,
                what,
            });
        }
        Ok(response)
    }

    /// Fetches a token for the Bearer challenge in `response` and caches it. With credentials
    /// configured this is an authenticated token (push scope); otherwise it stays anonymous.
    async fn fetch_token(
        &self,
        response: &http::Response,
        repo: &RepoAddress,
    ) -> Result<String, RegistryError> {
        let challenge = response
            .challenge
            .as_deref()
            .ok_or(RegistryError::AuthChallenge)?;
        let challenge = Challenge::parse(challenge)?;
        tracing::debug!(
            registry = repo.registry.as_str(),
            authenticated = self.basic.is_some(),
            "requesting a registry token"
        );
        let mut url = challenge.realm;
        let mut query = Vec::new();
        if let Some(service) = challenge.service {
            query.push(format!("service={}", http::percent_encode(&service)));
        }
        let scope = challenge
            .scope
            .unwrap_or_else(|| format!("repository:{}:pull", repo.repository));
        query.push(format!("scope={}", http::percent_encode(&scope)));
        url.push(if url.contains('?') { '&' } else { '?' });
        url.push_str(&query.join("&"));
        let url = http::parse_url(&url)?;
        let response = self
            .client
            .get_with_basic(
                &url,
                self.basic.as_deref(),
                None,
                MAX_TOKEN_BYTES,
                "auth token",
            )
            .await?;
        if !(200..300).contains(&response.status) {
            return Err(RegistryError::Status {
                status: response.status,
                what: "auth token",
            });
        }
        let token: TokenResponse =
            serde_json::from_slice(&response.body).map_err(|e| RegistryError::MalformedJson {
                what: "auth token",
                detail: e.to_string(),
            })?;
        if token.token.is_empty() {
            return Err(RegistryError::MissingToken);
        }
        if !token.token.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(RegistryError::InvalidToken);
        }
        let mut cache = self.token.lock().unwrap_or_else(PoisonError::into_inner);
        *cache = Some(CachedToken {
            registry: repo.registry.clone(),
            repository: repo.repository.clone(),
            token: token.token.clone(),
        });
        Ok(token.token)
    }

    /// `GET` a registry URL for an image (the signature path).
    async fn authorized_get(
        &self,
        url: &Url,
        image: &ImageRef,
        accept: Option<&str>,
        max_body: usize,
        what: &'static str,
    ) -> Result<http::Response, RegistryError> {
        self.authorized(
            http::Request {
                method: weglarka_http::reqwest::Method::GET,
                url,
                bearer: None,
                basic: None,
                accept,
                content_type: None,
                body: None,
                max_body,
                what,
            },
            &RepoAddress::from_image(image),
        )
        .await
    }
}

impl Registry for HttpRegistry {
    async fn cosign_signatures(
        &self,
        image: &ImageRef,
        digest: &Digest,
    ) -> Result<Vec<Signature>, RegistryError> {
        let tag = signature_tag(digest);
        tracing::debug!(
            registry = image.registry.as_str(),
            repository = image.repository.as_str(),
            tag = tag.as_str(),
            "fetching the cosign signature manifest"
        );
        let url = http::registry_url(
            &image.registry,
            &format!("/v2/{}/manifests/{tag}", image.repository),
        )?;
        let response = self
            .authorized_get(
                &url,
                image,
                Some(ACCEPT_MANIFEST),
                MAX_MANIFEST_BYTES,
                "signature manifest",
            )
            .await?;
        let manifest: SignatureManifest =
            serde_json::from_slice(&response.body).map_err(|e| RegistryError::MalformedJson {
                what: "signature manifest",
                detail: e.to_string(),
            })?;
        let mut signatures = Vec::new();
        for layer in &manifest.layers {
            if layer.media_type != SIMPLE_SIGNING_MEDIA_TYPE {
                continue;
            }
            if layer.annotations.contains_key(CERTIFICATE_ANNOTATION) {
                // Keyless signature: we verify with a pinned key only, never with Fulcio.
                tracing::debug!("skipping a keyless cosign signature layer");
                continue;
            }
            let encoded = layer.annotations.get(SIGNATURE_ANNOTATION).ok_or(
                RegistryError::MissingAnnotation {
                    annotation: SIGNATURE_ANNOTATION,
                },
            )?;
            let signature = decode_signature(encoded)?;
            let expected = layer_digest(&layer.digest)?;
            let url = http::registry_url(
                &image.registry,
                &format!("/v2/{}/blobs/{}", image.repository, layer.digest),
            )?;
            let response = self
                .authorized_get(&url, image, None, MAX_PAYLOAD_BYTES, "signature payload")
                .await?;
            let actual = hex_lower(&Sha256::digest(&response.body));
            if actual != expected {
                return Err(RegistryError::PayloadDigestMismatch {
                    expected: layer.digest.clone(),
                    actual,
                });
            }
            signatures.push(Signature {
                payload: response.body,
                signature,
            });
        }
        Ok(signatures)
    }
}

impl ReleaseRegistry for HttpRegistry {
    async fn manifest(
        &self,
        repository: &Repository,
        reference: &str,
        max_body: usize,
    ) -> Result<FetchedManifest, RegistryError> {
        validate_reference(reference)?;
        let repo = RepoAddress::split(repository)?;
        let url = http::registry_url(
            &repo.registry,
            &format!("/v2/{}/manifests/{reference}", repo.repository),
        )?;
        let response = self
            .authorized(
                http::Request {
                    method: weglarka_http::reqwest::Method::GET,
                    url: &url,
                    bearer: None,
                    basic: None,
                    accept: Some(ACCEPT_MANIFEST),
                    content_type: None,
                    body: None,
                    max_body,
                    what: "release-set manifest",
                },
                &repo,
            )
            .await?;
        let actual = digest_of(&response.body)?;
        // A digest reference must resolve to exactly the requested identity; a tag may move.
        if reference.starts_with("sha256:") && reference != actual.as_str() {
            return Err(RegistryError::ManifestDigestMismatch {
                expected: reference.to_owned(),
                actual: actual.as_str().to_owned(),
            });
        }
        // The registry's own header, when present, must agree with the bytes it returned: a
        // registry that reports one digest and serves another bytes is rejected here, before any
        // model parser sees the document.
        if let Some(reported) = response.digest
            && reported != actual.as_str()
        {
            return Err(RegistryError::ManifestDigestMismatch {
                expected: reported,
                actual: actual.as_str().to_owned(),
            });
        }
        Ok(FetchedManifest {
            bytes: response.body,
            digest: actual,
        })
    }

    async fn blob(
        &self,
        repository: &Repository,
        digest: &StrictDigest,
        max_body: usize,
    ) -> Result<Vec<u8>, RegistryError> {
        let repo = RepoAddress::split(repository)?;
        let url = http::registry_url(
            &repo.registry,
            &format!("/v2/{}/blobs/{}", repo.repository, digest.as_str()),
        )?;
        let response = self
            .authorized(
                http::Request {
                    method: weglarka_http::reqwest::Method::GET,
                    url: &url,
                    bearer: None,
                    basic: None,
                    accept: None,
                    content_type: None,
                    body: None,
                    max_body,
                    what: "release-set blob",
                },
                &repo,
            )
            .await?;
        let actual = digest_of(&response.body)?;
        if actual != *digest {
            return Err(RegistryError::BlobDigestMismatch {
                expected: digest.as_str().to_owned(),
                actual: actual.as_str().to_owned(),
            });
        }
        Ok(response.body)
    }

    async fn tags(&self, repository: &Repository) -> Result<Vec<String>, RegistryError> {
        let repo = RepoAddress::split(repository)?;
        let mut url = http::registry_url(
            &repo.registry,
            &format!("/v2/{}/tags/list?n={TAG_PAGE_SIZE}", repo.repository),
        )?;
        let mut tags = Vec::new();
        for _ in 0..MAX_TAG_PAGES {
            let response = self
                .authorized(
                    http::Request {
                        method: weglarka_http::reqwest::Method::GET,
                        url: &url,
                        bearer: None,
                        basic: None,
                        accept: None,
                        content_type: None,
                        body: None,
                        max_body: MAX_WRITE_RESPONSE_BYTES,
                        what: "tag list",
                    },
                    &repo,
                )
                .await?;
            let page: TagPage = serde_json::from_slice(&response.body).map_err(|e| {
                RegistryError::MalformedJson {
                    what: "tag list",
                    detail: e.to_string(),
                }
            })?;
            let count = page.tags.as_ref().map_or(0, Vec::len);
            if count == 0 {
                break;
            }
            tags.extend(page.tags.into_iter().flatten());
            if tags.len() > MAX_TAGS {
                return Err(RegistryError::TooManyTags);
            }
            let Some(next) = response.link.as_deref().and_then(next_link) else {
                break;
            };
            // A Link is relative to the registry in practice; resolving against the current URL
            // keeps the same authority (a redirect to another host is refused by the client).
            url = url.join(&next).map_err(|_| RegistryError::InvalidLink)?;
        }
        Ok(tags)
    }

    async fn put_blob(
        &self,
        repository: &Repository,
        bytes: &[u8],
    ) -> Result<StrictDigest, RegistryError> {
        let repo = RepoAddress::split(repository)?;
        let upload = http::registry_url(
            &repo.registry,
            &format!("/v2/{}/blobs/uploads/", repo.repository),
        )?;
        let response = self
            .authorized(
                http::Request {
                    method: weglarka_http::reqwest::Method::POST,
                    url: &upload,
                    bearer: None,
                    basic: None,
                    accept: None,
                    content_type: None,
                    body: None,
                    max_body: MAX_WRITE_RESPONSE_BYTES,
                    what: "blob upload",
                },
                &repo,
            )
            .await?;
        let location = response
            .location
            .ok_or(RegistryError::MissingUploadLocation)?;
        let mut target = upload
            .join(&location)
            .map_err(|_| RegistryError::InvalidUploadLocation)?;
        let digest = digest_of(bytes)?;
        target
            .query_pairs_mut()
            .append_pair("digest", digest.as_str());
        self.authorized(
            http::Request {
                method: weglarka_http::reqwest::Method::PUT,
                url: &target,
                bearer: None,
                basic: None,
                accept: None,
                content_type: Some("application/octet-stream"),
                body: Some(bytes.to_vec()),
                max_body: MAX_WRITE_RESPONSE_BYTES,
                what: "blob upload",
            },
            &repo,
        )
        .await?;
        Ok(digest)
    }

    async fn put_manifest(
        &self,
        repository: &Repository,
        tag: &str,
        bytes: &[u8],
    ) -> Result<StrictDigest, RegistryError> {
        if !valid_tag(tag) {
            return Err(RegistryError::InvalidTag {
                tag: tag.to_owned(),
            });
        }
        let repo = RepoAddress::split(repository)?;
        let url = http::registry_url(
            &repo.registry,
            &format!("/v2/{}/manifests/{tag}", repo.repository),
        )?;
        let response = self
            .authorized(
                http::Request {
                    method: weglarka_http::reqwest::Method::PUT,
                    url: &url,
                    bearer: None,
                    basic: None,
                    accept: None,
                    content_type: Some("application/vnd.oci.image.manifest.v1+json"),
                    body: Some(bytes.to_vec()),
                    max_body: MAX_WRITE_RESPONSE_BYTES,
                    what: "manifest upload",
                },
                &repo,
            )
            .await?;
        let actual = digest_of(bytes)?;
        if let Some(reported) = response.digest
            && reported != actual.as_str()
        {
            return Err(RegistryError::ManifestDigestMismatch {
                expected: actual.as_str().to_owned(),
                actual: reported,
            });
        }
        Ok(actual)
    }
}

/// Signs `digest` with `key` and stores the legacy cosign `.sig` manifest and its payload blob in
/// `repository`. The caller passes the exact repository identity because the signature payload
/// binds it: the host refuses a signature made for another repository.
pub async fn push_signature<R: ReleaseRegistry + ?Sized>(
    registry: &R,
    repository: &Repository,
    image: &ImageRef,
    digest: &StrictDigest,
    key: &crate::SigningKey,
) -> Result<(), RegistryError> {
    let payload = crate::cosign::payload_for(image, digest.as_digest())
        .map_err(|error| RegistryError::Signing(error.to_string()))?;
    let signature = key
        .sign(&payload)
        .map_err(|error| RegistryError::Signing(error.to_string()))?;
    let payload_digest = registry.put_blob(repository, &payload).await?;
    let manifest = crate::cosign::signature_manifest(
        payload_digest.as_str(),
        payload.len() as u64,
        &signature,
    );
    let tag = format!("{}.sig", digest.as_str().replace(':', "-"));
    registry.put_manifest(repository, &tag, &manifest).await?;
    Ok(())
}

/// A tag moves; a digest must not. Rejects anything that is neither.
fn validate_reference(reference: &str) -> Result<(), RegistryError> {
    if reference.starts_with("sha256:") {
        StrictDigest::new(reference).map_err(|_| RegistryError::InvalidDigest {
            digest: reference.to_owned(),
        })?;
        return Ok(());
    }
    if valid_tag(reference) {
        Ok(())
    } else {
        Err(RegistryError::InvalidReference {
            what: "manifest reference",
            reference: reference.to_owned(),
        })
    }
}

/// OCI tag grammar (`[A-Za-z0-9_][A-Za-z0-9._-]{0,127}`).
fn valid_tag(tag: &str) -> bool {
    let mut bytes = tag.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    let rest = bytes.collect::<Vec<_>>();
    tag.len() <= 128
        && (first.is_ascii_alphanumeric() || first == b'_')
        && rest
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

fn digest_of(bytes: &[u8]) -> Result<StrictDigest, RegistryError> {
    StrictDigest::new(format!("sha256:{}", hex_lower(&Sha256::digest(bytes)))).map_err(|_| {
        RegistryError::InvalidDigest {
            digest: "computed sha256".to_owned(),
        }
    })
}

/// Extracts the `rel="next"` target from a `Link` header.
fn next_link(header: &str) -> Option<String> {
    header.split(',').find_map(|link| {
        let (target, parameters) = link.split_once(';')?;
        let target = target.trim().trim_start_matches('<').trim_end_matches('>');
        if parameters
            .split(';')
            .any(|parameter| parameter.trim().replace(' ', "") == "rel=\"next\"")
        {
            Some(target.to_owned())
        } else {
            None
        }
    })
}

/// The `tags` array of a tag-list page. External format, so lenient like the signature manifest.
#[derive(Debug, Deserialize)]
struct TagPage {
    #[serde(default)]
    tags: Option<Vec<String>>,
}

/// `<registry>/<repo>:sha256-<hex>.sig` — the tag cosign stores a payload signature under.
fn signature_tag(digest: &Digest) -> String {
    format!("{}.sig", digest.as_str().replace(':', "-"))
}

/// Validates a layer digest and returns its lowercase hex part; only sha256 is accepted.
fn layer_digest(digest: &str) -> Result<String, RegistryError> {
    let hex =
        digest
            .strip_prefix("sha256:")
            .ok_or_else(|| RegistryError::UnsupportedLayerDigest {
                digest: digest.to_owned(),
            })?;
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(RegistryError::UnsupportedLayerDigest {
            digest: digest.to_owned(),
        });
    }
    Ok(hex.to_ascii_lowercase())
}

fn decode_signature(encoded: &str) -> Result<Vec<u8>, RegistryError> {
    use base64::Engine as _;

    if encoded.len() > MAX_SIGNATURE_ANNOTATION {
        return Err(RegistryError::TooLarge {
            what: "signature annotation",
            len: encoded.len(),
            limit: MAX_SIGNATURE_ANNOTATION,
        });
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| RegistryError::SignatureBase64(e.to_string()))?;
    if decoded.len() > MAX_SIGNATURE_BYTES {
        return Err(RegistryError::TooLarge {
            what: "signature",
            len: decoded.len(),
            limit: MAX_SIGNATURE_BYTES,
        });
    }
    Ok(decoded)
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The parts of a `WWW-Authenticate: Bearer …` challenge this client uses.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Challenge {
    realm: String,
    service: Option<String>,
    scope: Option<String>,
}

impl Challenge {
    fn parse(header: &str) -> Result<Self, RegistryError> {
        // The header is ASCII by the time it gets here (the HTTP head parser rejects anything
        // else); the explicit check keeps the byte-indexed parameter scanner panic-free regardless.
        if header.len() > MAX_CHALLENGE_BYTES || !header.is_ascii() {
            return Err(RegistryError::AuthChallenge);
        }
        let (scheme, parameters) = header.split_once(' ').ok_or(RegistryError::AuthChallenge)?;
        if !scheme.eq_ignore_ascii_case("bearer") {
            return Err(RegistryError::AuthChallenge);
        }
        let mut realm = None;
        let mut service = None;
        let mut scope = None;
        for (key, value) in challenge_parameters(parameters)? {
            match key.as_str() {
                "realm" => realm = Some(value),
                "service" => service = Some(value),
                "scope" => scope = Some(value),
                _ => {}
            }
        }
        let realm = realm
            .filter(|realm| !realm.is_empty())
            .ok_or(RegistryError::AuthChallenge)?;
        Ok(Self {
            realm,
            service,
            scope,
        })
    }
}

/// Parses `key="value", key=value` pairs; quoted values cannot contain control characters or
/// escapes (the values this client uses are plain realm/service/scope strings).
fn challenge_parameters(input: &str) -> Result<Vec<(String, String)>, RegistryError> {
    let bytes = input.as_bytes();
    let mut parameters = Vec::new();
    let mut index = 0;
    loop {
        while index < bytes.len() && matches!(bytes[index], b' ' | b'\t' | b',') {
            index += 1;
        }
        if index == bytes.len() {
            return Ok(parameters);
        }
        let key_start = index;
        while index < bytes.len() && bytes[index] != b'=' {
            index += 1;
        }
        if index == bytes.len() {
            return Err(RegistryError::AuthChallenge);
        }
        let key = input[key_start..index].trim().to_ascii_lowercase();
        if key.is_empty() {
            return Err(RegistryError::AuthChallenge);
        }
        index += 1; // the '='
        let value = if bytes.get(index) == Some(&b'"') {
            index += 1;
            let start = index;
            while bytes.get(index) != Some(&b'"') {
                match bytes.get(index) {
                    Some(byte) if (0x20..0x7f).contains(byte) && *byte != b'\\' => index += 1,
                    _ => return Err(RegistryError::AuthChallenge),
                }
            }
            let value = input[start..index].to_owned();
            index += 1;
            value
        } else {
            let start = index;
            while index < bytes.len() && bytes[index] != b',' {
                index += 1;
            }
            let value = input[start..index].trim();
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_graphic()) {
                return Err(RegistryError::AuthChallenge);
            }
            value.to_owned()
        };
        parameters.push((key, value));
        if parameters.len() > 8 {
            return Err(RegistryError::AuthChallenge);
        }
    }
}

/// The `layers[]` subset of an OCI image manifest. External format: lenient (`serde(default)`),
/// unknown fields ignored (conventions for models we do not own).
#[derive(Debug, Deserialize)]
struct SignatureManifest {
    #[serde(default)]
    layers: Vec<ManifestLayer>,
}

#[derive(Debug, Deserialize)]
struct ManifestLayer {
    #[serde(rename = "mediaType", default)]
    media_type: String,
    #[serde(default)]
    digest: String,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    #[serde(default)]
    token: String,
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex as StdMutex};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::testing::{FakeRegistry, TestSigner, payload_for};

    const TIMEOUT: Duration = Duration::from_secs(10);

    #[test]
    fn the_signature_tag_is_the_cosign_convention() {
        let digest = Digest::new(format!("sha256:{}", "ab".repeat(32))).unwrap();
        assert_eq!(
            signature_tag(&digest),
            format!("sha256-{}.sig", "ab".repeat(32))
        );
    }

    #[test]
    fn layer_digests_are_validated_strictly() {
        let hex = "ab".repeat(32);
        assert_eq!(layer_digest(&format!("sha256:{hex}")).unwrap(), hex);
        assert_eq!(
            layer_digest(&format!("sha256:{}", hex.to_uppercase())).unwrap(),
            hex
        );
        for digest in [
            format!("sha512:{hex}"),
            "sha256:".to_owned(),
            format!("sha256:{}", "ab".repeat(16)),
            format!("sha256:{}", "zz".repeat(32)),
            format!("sha256:{hex}/../evil"),
        ] {
            assert!(
                matches!(
                    layer_digest(&digest).unwrap_err(),
                    RegistryError::UnsupportedLayerDigest { .. }
                ),
                "{digest}"
            );
        }
    }

    #[test]
    fn challenge_parsing_uses_the_bearer_parameters() {
        let challenge = Challenge::parse(
            "Bearer realm=\"https://ghcr.io/token\",service=\"ghcr.io\",scope=\"repository:jpalczewski/weglarka:pull\"",
        )
        .unwrap();
        assert_eq!(challenge.realm, "https://ghcr.io/token");
        assert_eq!(challenge.service.as_deref(), Some("ghcr.io"));
        assert_eq!(
            challenge.scope.as_deref(),
            Some("repository:jpalczewski/weglarka:pull")
        );

        let challenge = Challenge::parse("bearer realm=http://127.0.0.1:5000/token").unwrap();
        assert_eq!(challenge.realm, "http://127.0.0.1:5000/token");
        assert!(challenge.service.is_none() && challenge.scope.is_none());

        for header in [
            "Basic realm=\"x\"",
            "Bearer",
            "Bearer service=\"ghcr.io\"",
            "Bearer realm=\"\"",
            "Bearer realm=\"a\\\"b\"",
            "Bearer realm=\"unterminated",
            "Bearer realm=\"a\" extra",
        ] {
            assert!(
                matches!(
                    Challenge::parse(header).unwrap_err(),
                    RegistryError::AuthChallenge
                ),
                "{header:?}"
            );
        }
    }

    #[test]
    fn base64_signatures_are_bounded() {
        let encoded = base64::engine::general_purpose::STANDARD.encode([1u8; 8]);
        assert_eq!(decode_signature(&encoded).unwrap(), vec![1u8; 8]);
        assert!(matches!(
            decode_signature("not base64!").unwrap_err(),
            RegistryError::SignatureBase64(_)
        ));
        let encoded =
            base64::engine::general_purpose::STANDARD.encode([0u8; MAX_SIGNATURE_BYTES + 1]);
        assert!(matches!(
            decode_signature(&encoded).unwrap_err(),
            RegistryError::TooLarge {
                what: "signature",
                ..
            }
        ));
    }

    // ---- test HTTP server ----------------------------------------------------------------

    #[derive(Debug, Clone)]
    struct Request {
        path: String,
        headers: Vec<(String, String)>,
    }

    impl Request {
        fn parse(head: &str) -> Self {
            let mut lines = head.split("\r\n");
            let path = lines
                .next()
                .and_then(|line| line.split(' ').nth(1))
                .unwrap_or_default()
                .to_owned();
            let mut headers = Vec::new();
            for line in lines {
                if line.is_empty() {
                    break;
                }
                if let Some((name, value)) = line.split_once(':') {
                    headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
                }
            }
            Self { path, headers }
        }

        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(header, _)| header == name)
                .map(|(_, value)| value.as_str())
        }

        fn has_authorization(&self) -> bool {
            self.header("authorization").is_some()
        }
    }

    struct ResponseSpec {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    fn response(status: u16) -> ResponseSpec {
        ResponseSpec {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    fn with_header(mut spec: ResponseSpec, name: &str, value: &str) -> ResponseSpec {
        spec.headers.push((name.to_owned(), value.to_owned()));
        spec
    }

    fn with_body(mut spec: ResponseSpec, body: Vec<u8>) -> ResponseSpec {
        spec.body = body;
        spec
    }

    /// A loopback HTTP server; the handler receives each request and returns the response.
    struct TestServer {
        requests: Arc<StdMutex<Vec<Request>>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl TestServer {
        fn start(
            listener: TcpListener,
            handler: impl Fn(&Request) -> ResponseSpec + Send + Sync + 'static,
        ) -> Self {
            let requests = Arc::new(StdMutex::new(Vec::new()));
            let recorded = Arc::clone(&requests);
            let handler = Arc::new(handler);
            let task = tokio::spawn(async move {
                loop {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        return;
                    };
                    let handler = Arc::clone(&handler);
                    let recorded = Arc::clone(&recorded);
                    tokio::spawn(async move {
                        let Some(request) = read_request(&mut stream).await else {
                            return;
                        };
                        recorded.lock().unwrap().push(request.clone());
                        let spec = handler(&request);
                        write_response(&mut stream, spec).await;
                    });
                }
            });
            Self { requests, task }
        }

        fn requests(&self) -> Vec<Request> {
            self.requests.lock().unwrap().clone()
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn read_request(stream: &mut TcpStream) -> Option<Request> {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
            if buffer.len() > 64 * 1024 {
                return None;
            }
            let read = stream.read(&mut chunk).await.ok()?;
            if read == 0 {
                return None;
            }
            buffer.extend_from_slice(&chunk[..read]);
        }
        Some(Request::parse(&String::from_utf8_lossy(&buffer)))
    }

    async fn write_response(stream: &mut TcpStream, spec: ResponseSpec) {
        let mut head = format!("HTTP/1.1 {}\r\n", spec.status);
        for (name, value) in &spec.headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str(&format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            spec.body.len()
        ));
        let _ = stream.write_all(head.as_bytes()).await;
        let _ = stream.write_all(&spec.body).await;
        let _ = stream.shutdown().await;
    }

    // ---- fixtures ------------------------------------------------------------------------

    fn digest(c: char) -> Digest {
        Digest::new(format!("sha256:{}", c.to_string().repeat(64))).unwrap()
    }

    fn sha256_hex(payload: &[u8]) -> String {
        hex_lower(&Sha256::digest(payload))
    }

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn layer(payload: &[u8], signature: Option<&[u8]>, certificate: bool) -> serde_json::Value {
        let mut annotations = serde_json::Map::new();
        if let Some(signature) = signature {
            annotations.insert(
                SIGNATURE_ANNOTATION.to_owned(),
                serde_json::json!(b64(signature)),
            );
        }
        if certificate {
            annotations.insert(CERTIFICATE_ANNOTATION.to_owned(), serde_json::json!("cert"));
        }
        serde_json::json!({
            "mediaType": SIMPLE_SIGNING_MEDIA_TYPE,
            "digest": format!("sha256:{}", sha256_hex(payload)),
            "size": payload.len(),
            "annotations": annotations,
        })
    }

    fn manifest(layers: Vec<serde_json::Value>) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "layers": layers,
        }))
        .unwrap()
    }

    fn token_json(token: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({ "token": token })).unwrap()
    }

    /// Binds a listener and returns `(listener, address-as-a-registry-host)`.
    async fn loopback() -> (TcpListener, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        (listener, addr)
    }

    // ---- tests ---------------------------------------------------------------------------

    #[tokio::test]
    async fn fetches_the_manifest_and_the_payload_with_an_anonymous_token() {
        let signer = TestSigner::generate().unwrap();
        let digest = digest('a');
        let (listener, addr) = loopback().await;
        let image = ImageRef::parse(&format!(
            "127.0.0.1:{}/jpalczewski/weglarka:edge",
            addr.port()
        ))
        .unwrap();
        let payload = payload_for(&image, &digest).unwrap();
        let signature = signer.sign(&payload).unwrap();
        let manifest = manifest(vec![layer(&payload, Some(&signature.signature), false)]);
        let auth = format!(
            "Bearer realm=\"http://127.0.0.1:{}/token\",service=\"test\",scope=\"repository:jpalczewski/weglarka:pull\"",
            addr.port()
        );
        let server = TestServer::start(listener, move |request| {
            if request.path.starts_with("/token") {
                return with_body(response(200), token_json("tok-123"));
            }
            if request.path.contains("/blobs/") {
                assert_eq!(request.header("authorization"), Some("Bearer tok-123"));
                return with_body(response(200), payload.clone());
            }
            if request.path.contains("/manifests/") {
                if request.header("authorization") == Some("Bearer tok-123") {
                    return with_body(response(200), manifest.clone());
                }
                return with_header(response(401), "WWW-Authenticate", &auth);
            }
            response(404)
        });
        let registry = HttpRegistry::new().unwrap();
        let signatures = tokio::time::timeout(TIMEOUT, registry.cosign_signatures(&image, &digest))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(signatures.len(), 1);
        crate::verify(&signatures[0], signer.public_key(), &image, &digest).unwrap();

        let requests = server.requests();
        let paths: Vec<&str> = requests
            .iter()
            .map(|request| request.path.as_str())
            .collect();
        assert_eq!(paths.len(), 4, "{paths:?}");
        assert!(paths[0].contains("/manifests/sha256-"));
        assert!(paths[0].ends_with(".sig"));
        assert!(paths[1].starts_with("/token?service=test&scope=repository%3A"));
        assert!(paths[2].contains("/manifests/"));
        assert!(paths[3].contains("/blobs/"));
        assert!(!requests[0].has_authorization());
        assert_eq!(requests[2].header("authorization"), Some("Bearer tok-123"));

        // The token is cached: a second fetch reuses it and does not hit the token endpoint.
        registry.cosign_signatures(&image, &digest).await.unwrap();
        assert_eq!(
            server
                .requests()
                .iter()
                .filter(|request| request.path.starts_with("/token"))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn keyless_signature_layers_are_skipped() {
        let signer = TestSigner::generate().unwrap();
        let digest = digest('b');
        let (listener, addr) = loopback().await;
        let image = ImageRef::parse(&format!(
            "127.0.0.1:{}/jpalczewski/weglarka:edge",
            addr.port()
        ))
        .unwrap();
        let payload = payload_for(&image, &digest).unwrap();
        let signature = signer.sign(&payload).unwrap();
        let manifest = manifest(vec![
            // A keyless signature: certificate, no key signature. It must not be fetched or used.
            layer(&payload, None, true),
            layer(&payload, Some(&signature.signature), false),
        ]);
        let served = payload.clone();
        let server = TestServer::start(listener, move |request| {
            if request.path.contains("/blobs/") {
                return with_body(response(200), served.clone());
            }
            with_body(response(200), manifest.clone())
        });
        let registry = HttpRegistry::new().unwrap();
        let signatures = registry.cosign_signatures(&image, &digest).await.unwrap();
        assert_eq!(signatures.len(), 1);
        assert_eq!(signatures[0].payload, payload);
        assert_eq!(signatures[0].signature, signature.signature);
        assert_eq!(
            server
                .requests()
                .iter()
                .filter(|request| request.path.contains("/blobs/"))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn a_redirect_to_another_port_drops_the_authorization_header() {
        let (result, cdn_requests) = blob_redirect("/blob").await;
        result.unwrap();
        assert_eq!(cdn_requests.len(), 1, "the blob was fetched from the CDN");
        assert!(!cdn_requests[0].has_authorization(), "{cdn_requests:?}");
        assert!(
            cdn_requests[0].header("referer").is_none(),
            "{cdn_requests:?}"
        );
    }

    /// registry → CDN `/a` → CDN `/b`: `reqwest` alone rebuilds the second hop from the original headers
    /// and, seeing the same authority as the previous hop, would send the token to the CDN. The policy
    /// refuses the chain instead; whatever the CDN did see carried no token.
    #[tokio::test]
    async fn a_second_hop_inside_the_cdn_never_gets_the_token() {
        let (result, cdn_requests) = blob_redirect("/a").await;
        let error = result.unwrap_err();
        assert!(
            matches!(error, RegistryError::Http(HttpError::Redirect { .. })),
            "{error}"
        );
        assert!(!cdn_requests.is_empty());
        assert!(
            cdn_requests
                .iter()
                .all(|request| !request.has_authorization()),
            "{cdn_requests:?}"
        );
    }

    /// Runs a signature fetch whose blob request is redirected to a CDN at `cdn_path`; `/a` there
    /// redirects on to `/b`. Returns the outcome and every request the CDN received.
    async fn blob_redirect(cdn_path: &str) -> (Result<(), RegistryError>, Vec<Request>) {
        let signer = TestSigner::generate().unwrap();
        let digest = digest('c');
        let (registry_listener, registry_addr) = loopback().await;
        let (cdn_listener, cdn_addr) = loopback().await;
        let image = ImageRef::parse(&format!(
            "127.0.0.1:{}/jpalczewski/weglarka:edge",
            registry_addr.port()
        ))
        .unwrap();
        let payload = payload_for(&image, &digest).unwrap();
        let signature = signer.sign(&payload).unwrap();
        let manifest = manifest(vec![layer(&payload, Some(&signature.signature), false)]);
        let auth = format!(
            "Bearer realm=\"http://127.0.0.1:{}/token\",service=\"test\",scope=\"repository:jpalczewski/weglarka:pull\"",
            registry_addr.port()
        );
        let cdn_payload = payload.clone();
        let cdn = TestServer::start(cdn_listener, move |request| {
            if request.path == "/a" {
                return with_header(response(307), "Location", "/b");
            }
            with_body(response(200), cdn_payload.clone())
        });
        let redirect_to = format!("http://127.0.0.1:{}{cdn_path}", cdn_addr.port());
        let _registry = TestServer::start(registry_listener, move |request| {
            if request.path.starts_with("/token") {
                return with_body(response(200), token_json("tok-456"));
            }
            if request.path.contains("/blobs/") {
                return with_header(response(307), "Location", &redirect_to);
            }
            if request.header("authorization") == Some("Bearer tok-456") {
                return with_body(response(200), manifest.clone());
            }
            with_header(response(401), "WWW-Authenticate", &auth)
        });
        let client = HttpRegistry::new().unwrap();
        let result = tokio::time::timeout(TIMEOUT, client.cosign_signatures(&image, &digest))
            .await
            .unwrap()
            .map(|signatures| {
                assert_eq!(signatures.len(), 1);
                crate::verify(&signatures[0], signer.public_key(), &image, &digest).unwrap();
            });
        (result, cdn.requests())
    }

    #[tokio::test]
    async fn a_redirect_to_a_non_loopback_http_url_is_rejected() {
        let digest = digest('d');
        let (listener, addr) = loopback().await;
        let image = ImageRef::parse(&format!(
            "127.0.0.1:{}/jpalczewski/weglarka:edge",
            addr.port()
        ))
        .unwrap();
        let payload = b"{}".to_vec();
        let manifest = manifest(vec![layer(&payload, Some(&[0u8; 70]), false)]);
        let server = TestServer::start(listener, move |request| {
            if request.path.contains("/blobs/") {
                return with_header(response(307), "Location", "http://example.com/blob");
            }
            with_body(response(200), manifest.clone())
        });
        let client = HttpRegistry::new().unwrap();
        let error = tokio::time::timeout(TIMEOUT, client.cosign_signatures(&image, &digest))
            .await
            .unwrap()
            .unwrap_err();
        assert!(
            matches!(error, RegistryError::Http(HttpError::Redirect { .. })),
            "{error}"
        );
        // The manifest and the blob request (which answered with the redirect) were made; the
        // redirect itself was refused before connecting to example.com.
        assert_eq!(server.requests().len(), 2);
    }

    #[tokio::test]
    async fn oversized_manifest_and_payload_bodies_are_rejected() {
        let client = HttpRegistry::new().unwrap();
        let payload = b"{}".to_vec();

        let (listener, addr) = loopback().await;
        let image = ImageRef::parse(&format!(
            "127.0.0.1:{}/jpalczewski/weglarka:edge",
            addr.port()
        ))
        .unwrap();
        let digest = digest('e');
        let _server = TestServer::start(listener, move |_request| {
            with_body(response(200), vec![b'x'; MAX_MANIFEST_BYTES + 1])
        });
        let error = client.cosign_signatures(&image, &digest).await.unwrap_err();
        assert!(
            matches!(
                error,
                RegistryError::Http(HttpError::TooLarge {
                    what: "signature manifest",
                    ..
                })
            ),
            "{error}"
        );

        // The same for the payload blob.
        let (listener, addr) = loopback().await;
        let image = ImageRef::parse(&format!(
            "127.0.0.1:{}/jpalczewski/weglarka:edge",
            addr.port()
        ))
        .unwrap();
        let manifest = manifest(vec![layer(&payload, Some(&[0u8; 70]), false)]);
        let _server = TestServer::start(listener, move |request| {
            if request.path.contains("/blobs/") {
                return with_body(response(200), vec![b'x'; MAX_PAYLOAD_BYTES + 1]);
            }
            with_body(response(200), manifest.clone())
        });
        let error = client.cosign_signatures(&image, &digest).await.unwrap_err();
        assert!(
            matches!(
                error,
                RegistryError::Http(HttpError::TooLarge {
                    what: "signature payload",
                    ..
                })
            ),
            "{error}"
        );
    }

    #[tokio::test]
    async fn statuses_challenges_and_digest_mismatches_are_errors() {
        let signer = TestSigner::generate().unwrap();
        let client = HttpRegistry::new().unwrap();

        // 404: the image is not signed (or the tag is wrong).
        let (listener, addr) = loopback().await;
        let image = ImageRef::parse(&format!(
            "127.0.0.1:{}/jpalczewski/weglarka:edge",
            addr.port()
        ))
        .unwrap();
        let _server = TestServer::start(listener, |_request| response(404));
        let error = client
            .cosign_signatures(&image, &digest('f'))
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                RegistryError::Status {
                    status: 404,
                    what: "signature manifest"
                }
            ),
            "{error}"
        );

        // 401 without a challenge.
        let (listener, addr) = loopback().await;
        let image = ImageRef::parse(&format!(
            "127.0.0.1:{}/jpalczewski/weglarka:edge",
            addr.port()
        ))
        .unwrap();
        let _server = TestServer::start(listener, |_request| response(401));
        let error = client
            .cosign_signatures(&image, &digest('0'))
            .await
            .unwrap_err();
        assert!(matches!(error, RegistryError::AuthChallenge), "{error}");

        // A payload that does not hash to the layer digest.
        let (listener, addr) = loopback().await;
        let image = ImageRef::parse(&format!(
            "127.0.0.1:{}/jpalczewski/weglarka:edge",
            addr.port()
        ))
        .unwrap();
        let digest = digest('f');
        let payload = payload_for(&image, &digest).unwrap();
        let signature = signer.sign(&payload).unwrap();
        let mut tampered_layer = layer(&payload, Some(&signature.signature), false);
        tampered_layer["digest"] = serde_json::json!(format!("sha256:{}", "00".repeat(32)));
        let manifest = manifest(vec![tampered_layer]);
        let _server = TestServer::start(listener, move |request| {
            if request.path.contains("/blobs/") {
                return with_body(response(200), payload.clone());
            }
            with_body(response(200), manifest.clone())
        });
        let error = client.cosign_signatures(&image, &digest).await.unwrap_err();
        assert!(
            matches!(error, RegistryError::PayloadDigestMismatch { .. }),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_signing_layer_without_a_signature_annotation_is_an_error() {
        let digest = digest('1');
        let (listener, addr) = loopback().await;
        let image = ImageRef::parse(&format!(
            "127.0.0.1:{}/jpalczewski/weglarka:edge",
            addr.port()
        ))
        .unwrap();
        let payload = b"{}".to_vec();
        let manifest = manifest(vec![layer(&payload, None, false)]);
        let _server = TestServer::start(listener, move |_request| {
            with_body(response(200), manifest.clone())
        });
        let client = HttpRegistry::new().unwrap();
        let error = client.cosign_signatures(&image, &digest).await.unwrap_err();
        assert!(
            matches!(
                error,
                RegistryError::MissingAnnotation {
                    annotation: SIGNATURE_ANNOTATION
                }
            ),
            "{error}"
        );
    }

    #[tokio::test]
    async fn too_many_redirects_are_rejected() {
        let digest = digest('2');
        let (listener, addr) = loopback().await;
        let image = ImageRef::parse(&format!(
            "127.0.0.1:{}/jpalczewski/weglarka:edge",
            addr.port()
        ))
        .unwrap();
        let _server = TestServer::start(listener, |_request| {
            with_header(response(307), "Location", "/loop")
        });
        let client = HttpRegistry::new().unwrap();
        let error = client.cosign_signatures(&image, &digest).await.unwrap_err();
        assert!(
            matches!(error, RegistryError::Http(HttpError::Redirect { .. })),
            "{error}"
        );
    }

    #[tokio::test]
    async fn the_fake_registry_scripts_results_and_records_calls() {
        let image = ImageRef::parse("ghcr.io/jpalczewski/weglarka:edge").unwrap();
        let digest = digest('3');
        let signature = Signature {
            payload: b"payload".to_vec(),
            signature: vec![1, 2, 3],
        };
        let fake = FakeRegistry::with_signatures(vec![signature.clone()]);
        assert_eq!(
            fake.cosign_signatures(&image, &digest).await.unwrap(),
            vec![signature]
        );
        assert_eq!(fake.calls().len(), 1);
        assert_eq!(fake.calls()[0].image, image);
        assert_eq!(fake.calls()[0].digest, digest);

        fake.fail_once(RegistryError::Status {
            status: 500,
            what: "signature manifest",
        });
        assert!(matches!(
            fake.cosign_signatures(&image, &digest).await.unwrap_err(),
            RegistryError::Status { status: 500, .. }
        ));
        // The failure is one-shot: the scripted signatures are returned again afterwards.
        assert_eq!(
            fake.cosign_signatures(&image, &digest).await.unwrap().len(),
            1
        );
        assert_eq!(fake.calls().len(), 3);

        fake.push_signature(Signature {
            payload: b"second".to_vec(),
            signature: vec![4],
        });
        assert_eq!(
            fake.cosign_signatures(&image, &digest).await.unwrap().len(),
            2
        );
        fake.clear_calls();
        assert!(fake.calls().is_empty());
    }

    // ---- release-set transport -----------------------------------------------------------

    fn loopback_repository(address: SocketAddr) -> Repository {
        Repository::new(format!("{address}/example/releases")).unwrap()
    }

    fn challenge(address: SocketAddr, scope: &str) -> String {
        format!("Bearer realm=\"http://{address}/token\",service=\"test\",scope=\"{scope}\"")
    }

    /// Every registry request needs a Bearer token; the token endpoint is anonymous unless the
    /// client is authenticated.
    fn authorized_or_challenge(request: &Request, address: SocketAddr) -> Option<ResponseSpec> {
        if request.has_authorization() {
            return None;
        }
        let scope = if request.path.contains("uploads") || request.path.contains("manifests") {
            "repository:example/releases:pull,push"
        } else {
            "repository:example/releases:pull"
        };
        Some(with_header(
            response(401),
            "WWW-Authenticate",
            &challenge(address, scope),
        ))
    }

    #[tokio::test]
    async fn release_tags_follow_pagination_and_share_one_token() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = TestServer::start(listener, move |request| {
            if request.path.starts_with("/token") {
                return with_body(response(200), br#"{"token":"tok"}"#.to_vec());
            }
            if let Some(challenge) = authorized_or_challenge(request, address) {
                return challenge;
            }
            assert_eq!(request.header("authorization"), Some("Bearer tok"));
            if request.path.contains("last=set-stable-1") {
                return with_body(
                    response(200),
                    br#"{"name":"example/releases","tags":["set-stable-2"]}"#.to_vec(),
                );
            }
            with_header(
                with_body(
                    response(200),
                    br#"{"name":"example/releases","tags":["set-stable-1"]}"#.to_vec(),
                ),
                "Link",
                &format!(
                    "<http://{address}/v2/example/releases/tags/list?n=1&last=set-stable-1>; rel=\"next\""
                ),
            )
        });
        let registry = HttpRegistry::new().unwrap();
        let tags = registry.tags(&loopback_repository(address)).await.unwrap();
        assert_eq!(tags, vec!["set-stable-1", "set-stable-2"]);
        // One anonymous token fetch; registry requests carry the token, never the credentials.
        let requests = server.requests();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.path.starts_with("/token"))
                .count(),
            1
        );
        assert!(!format!("{registry:?}").contains("tok"));
    }

    #[tokio::test]
    async fn release_publish_uses_authenticated_tokens_and_the_upload_location() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = TestServer::start(listener, move |request| {
            if request.path.starts_with("/token") {
                // The token endpoint is called with HTTP Basic, not with a Bearer token.
                assert!(
                    request
                        .header("authorization")
                        .unwrap()
                        .starts_with("Basic ")
                );
                return with_body(response(200), br#"{"token":"push-token"}"#.to_vec());
            }
            if let Some(challenge) = authorized_or_challenge(request, address) {
                return challenge;
            }
            assert_eq!(request.header("authorization"), Some("Bearer push-token"));
            if request.path.contains("/blobs/uploads/") {
                if request.path.ends_with("/u1?digest=sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a") {
                    return response(201);
                }
                return with_header(
                    response(202),
                    "Location",
                    "/v2/example/releases/blobs/uploads/u1",
                );
            }
            if request.path.contains("/manifests/set-stable-1") {
                return response(201);
            }
            response(404)
        });
        let registry = HttpRegistry::with_basic_credentials("user", "s3cret").unwrap();
        let repository = loopback_repository(address);
        let digest = registry.put_blob(&repository, b"{}").await.unwrap();
        assert_eq!(
            digest.as_str(),
            weglarka_model::release_set::EMPTY_CONFIG_DIGEST
        );
        let manifest = br#"{"schemaVersion":2}"#;
        let digest = registry
            .put_manifest(&repository, "set-stable-1", manifest)
            .await
            .unwrap();
        assert_eq!(
            digest.as_str(),
            format!("sha256:{}", hex_lower(&Sha256::digest(manifest)))
        );
        assert!(format!("{registry:?}").contains("authenticated: true"));
        assert!(!format!("{registry:?}").contains("s3cret"));
        assert_eq!(server.requests().len(), 5);
    }

    #[tokio::test]
    async fn a_manifest_must_match_the_digest_it_was_requested_by() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let body =
            br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}"#
                .to_vec();
        let digest = format!("sha256:{}", hex_lower(&Sha256::digest(&body)));
        let served = body.clone();
        let served_digest = digest.clone();
        let server = TestServer::start(listener, move |_request| {
            with_header(
                with_body(response(200), served.clone()),
                "Docker-Content-Digest",
                &served_digest,
            )
        });
        let registry = HttpRegistry::new().unwrap();
        let repository = loopback_repository(address);
        let fetched = registry.manifest(&repository, &digest, 1024).await.unwrap();
        assert_eq!(fetched.digest.as_str(), digest);
        assert_eq!(fetched.bytes, body);
        let other = format!("sha256:{}", "ab".repeat(32));
        let error = registry
            .manifest(&repository, &other, 1024)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            RegistryError::ManifestDigestMismatch { .. }
        ));
        assert_eq!(server.requests().len(), 2);
    }

    #[tokio::test]
    async fn a_registry_reporting_another_digest_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = TestServer::start(listener, move |_request| {
            with_header(
                with_body(response(200), b"{}".to_vec()),
                "Docker-Content-Digest",
                &format!("sha256:{}", "cd".repeat(32)),
            )
        });
        let registry = HttpRegistry::new().unwrap();
        let error = registry
            .manifest(&loopback_repository(address), "stable", 1024)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            RegistryError::ManifestDigestMismatch { .. }
        ));
        assert_eq!(server.requests().len(), 1);
    }

    #[test]
    fn tag_and_reference_validation_matches_the_oci_grammar() {
        assert!(valid_tag("set-stable-1"));
        assert!(valid_tag("sha256-abc.sig"));
        assert!(valid_tag("_x"));
        assert!(!valid_tag(""));
        assert!(!valid_tag("-x"));
        assert!(!valid_tag("a/b"));
        assert!(!valid_tag(&"a".repeat(129)));
        assert!(validate_reference("stable").is_ok());
        assert!(validate_reference(&format!("sha256:{}", "ab".repeat(32))).is_ok());
        assert!(validate_reference("sha256:AB").is_err());
        assert!(validate_reference("bad tag").is_err());
        assert_eq!(
            next_link("<http://x/v2/a/tags/list?last=b>; rel=\"next\""),
            Some("http://x/v2/a/tags/list?last=b".to_owned())
        );
        assert_eq!(next_link("<http://x/p>; rel=\"prev\""), None);
        assert_eq!(next_link("garbage"), None);
    }
}
