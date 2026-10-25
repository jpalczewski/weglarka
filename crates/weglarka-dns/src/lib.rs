//! DNS-provider adapters for ACME DNS-01 (issue #97).
//!
//! A [`DnsProvider`] publishes and removes the `_acme-challenge` TXT records that prove control of a
//! domain; the ACME solver (crate `weglarka-acme`) drives it. [`Cloudflare`] is the first adapter. The
//! API token is a secret: it only ever lives in a [`weglarka_core::secret_store::SecretValue`] and
//! never reaches `Debug`, logs or error messages.
//!
//! The crate depends on `weglarka-core` only, so adapters can be developed and tested without the
//! ACME machinery (`docs/decisions/0039-acme-dns01.md`).

mod cloudflare;
mod http;
mod name;
mod provider;
#[cfg(feature = "testing")]
pub mod testing;

pub use cloudflare::Cloudflare;
pub use http::HttpError;
pub use name::{valid_record_name, valid_txt_value};
pub use provider::{DnsError, DnsProvider, RecordHandle};
