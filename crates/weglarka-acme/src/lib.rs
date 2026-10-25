//! ACME certificate issuance and renewal for the edge ingress (issue #96, part of #45).
//!
//! The ingress already serves `/.well-known/acme-challenge/` from a webroot and builds a TLS server
//! for every domain that has `tls/<id>.crt|key` (docs/decisions/0036). This crate is what fills
//! those files. It is split into small seams so that new challenge types plug in without touching
//! the engine (DNS-01 for wildcard certificates, issue #97):
//!
//! * [`CertSpec`] / [`CertId`] — one *certificate* is a list of names; the file stem on disk comes
//!   from the id, never from a name (a literal `*` in a file name is a path-safety problem).
//! * [`ChallengeSolver`] — `present` / `cleanup` for one challenge; [`Http01Solver`] writes the
//!   token into the webroot. A DNS-01 solver is just another implementation.
//! * [`AcmeClient`] — talks to the CA for one certificate and drives the solver; [`CertInspector`]
//!   reads the expiry of an issued chain. Both are implemented by [`testing::FakeAcme`] for tests.
//! * [`CertStore`] — writes the pair atomically, **key first, then certificate**, so the ingress
//!   fingerprint (which needs both files) never sees a mismatched pair.
//! * [`renewal::decide`] — the pure renewal policy.
//! * [`Manager::pass`] — one reconcile pass over the configured certificates.
//!
//! Private keys only ever live in [`PrivateKeyPem`], whose `Debug` is redacted. Errors and logs
//! carry names and paths, never key material.

mod cert;
mod client;
mod error;
mod instant;
mod manager;
mod solver;
mod store;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub mod renewal;

pub use cert::{CertId, CertIdError, CertSpec, Issued, PrivateKeyPem};
pub use client::{AcmeClient, CertInspector};
pub use error::AcmeError;
pub use instant::{InstantAcme, InstantAcmeSettings};
pub use manager::{Manager, Outcome, PassReport};
pub use solver::{Challenge, ChallengeKind, ChallengeSolver, Http01Solver};
pub use store::CertStore;
