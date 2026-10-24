//! Cosign signatures from an OCI registry and their key-based verification (issue #99).
//!
//! The host-side self-update pulls the daemon image, reads the digest it pulled, fetches the cosign
//! signature stored next to the image (`<registry>/<repo>:sha256-<hex>.sig`) and verifies it against
//! a pinned public key before it replaces the running image. This crate is one half of that: it
//! implements the registry wire format and the ECDSA P-256 verification; it deliberately does **not**
//! implement keyless signatures (Fulcio, Rekor, TUF) — only `cosign sign --key`.
//!
//! The pieces are small on purpose, because a bug in any of them is a remote code execution on the
//! host:
//!
//! * [`ImageRef`] validates an image reference (`host[:port]/repository:tag`); digest references are
//!   rejected, because a signature is looked up for a tag.
//! * [`PublicKey`] strictly parses a PEM/DER SubjectPublicKeyInfo and accepts exactly one curve
//!   (P-256); RSA, P-384 and malformed DER are distinct errors.
//! * [`Registry`] fetches the signature manifest and the payload blobs (implemented by
//!   [`HttpRegistry`] over a minimal HTTP/1.1 + rustls client, and by a fake for tests).
//! * [`verify`] parses the simple-signing payload, checks the type, the image digest and the
//!   repository identity, and finally checks the signature over the exact payload bytes.
//!
//! Wire format, limits and the token flow follow what GHCR really serves; `docs/decisions/0027`
//! records the decision. In short: anonymous Bearer token per registry+repository (cached in
//! memory), the `.sig` manifest, only layers of media type
//! `application/vnd.dev.cosign.simplesigning.v1+json` with a `dev.cosignproject.cosign/signature`
//! annotation (keyless layers with a certificate are skipped), and the payload blob whose sha256
//! must match the layer digest. Every response is size-capped (token 8 KiB, manifest 1 MiB, payload
//! 64 KiB), redirects are limited to 5, the `Authorization` header is never sent to a different
//! authority than the registry, and plain HTTP is allowed only for loopback hosts (tests).

mod cosign;
mod http;
mod image_ref;
mod key;
mod registry;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// PEM-encoded P-256 public key embedded in the daemon binary (`cosign.pub` in the repository root).
pub const DEFAULT_PUBLIC_KEY_PEM: &str = include_str!("../../../cosign.pub");

pub use cosign::{Signature, VerifyError, verify};
pub use http::HttpError;
pub use image_ref::{ImageRef, ImageRefError};
pub use key::{KeyError, PublicKey};
pub use registry::{HttpRegistry, Registry, RegistryError};
