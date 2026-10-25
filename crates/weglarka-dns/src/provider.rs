//! The adapter trait.

use std::future::Future;

use crate::http::HttpError;

/// Opaque reference to a record this provider created, enough to delete exactly that record later
/// (a wildcard order publishes two TXT values on the same name, so the name alone is not a key).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecordHandle(String);

impl RecordHandle {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("invalid record name {0:?}: expected a lower-case FQDN without a trailing dot")]
    InvalidName(String),
    #[error("invalid TXT value: expected 1-255 printable ASCII characters without quotes")]
    InvalidValue,
    #[error("malformed record handle {0:?}")]
    InvalidHandle(String),
    /// No zone the token can see contains the name.
    #[error("no DNS zone for {0} is reachable with this token")]
    ZoneNotFound(String),
    /// The provider answered, but not with success. Carries the provider's own error text, never
    /// the request (which holds the token).
    #[error("DNS API error (HTTP {status}): {message}")]
    Api { status: u16, message: String },
    #[error("unexpected DNS API response: {0}")]
    Response(String),
    #[error("DNS API request failed: {0}")]
    Http(#[from] HttpError),
}

/// A DNS host the ACME solver can write challenge records to.
///
/// Native `async fn` in the trait (`docs/decisions/0001-async-traits.md`): the provider is chosen by
/// configuration and used through generics, so it does not need to be `dyn`.
pub trait DnsProvider: Send + Sync {
    /// Creates a TXT record `name` = `value` and returns a handle to delete it. Existing records on
    /// the same name are left alone.
    fn set_txt(
        &self,
        name: &str,
        value: &str,
    ) -> impl Future<Output = Result<RecordHandle, DnsError>> + Send;

    /// Deletes a record created by [`DnsProvider::set_txt`]. Idempotent: a record that is already
    /// gone is success, because cleanup also runs after a failed order.
    fn remove_txt(
        &self,
        handle: &RecordHandle,
    ) -> impl Future<Output = Result<(), DnsError>> + Send;
}
