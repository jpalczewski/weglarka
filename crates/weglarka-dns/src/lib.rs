//! DNS-provider adapters for ACME DNS-01 (issue #97).
//!
//! A [`DnsProvider`] publishes and removes the `_acme-challenge` TXT records that prove control of a
//! domain; the ACME solver (crate `weglarka-acme`) drives it. [`Cloudflare`] is the first adapter. The
//! API token comes from a [`weglarka_model::credential::CredentialSource`] (a `0600` file or a host
//! secret) and is read on every request, so rotation needs no restart; it never reaches `Debug`, logs or
//! error messages.
//!
//! The crate depends on `weglarka-model` only, so adapters can be developed and tested without the
//! ACME machinery (`docs/decisions/0039-acme-dns01.md`).

mod cloudflare;
mod http;
mod name;
mod provider;
#[cfg(feature = "testing")]
pub mod testing;

pub use cloudflare::{Cloudflare, PublicIps, public_ips, public_ips_from};
pub use http::HttpError;
pub use name::{valid_record_name, valid_txt_value};
pub use provider::{DnsError, DnsProvider, RecordHandle};
