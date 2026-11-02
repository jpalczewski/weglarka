//! The parts of an OIDC client that do not depend on how bytes travel: provider discovery with the
//! host and scheme policy, PKCE and the authorization URL, token requests (confidential or public
//! client, refresh, revocation) and the device authorization grant (RFC 8628)
//! (docs/decisions/0060).
//!
//! Everything that touches the network goes through [`Transport`], so the admin panel can use
//! `reqwest` (`weglarka-http`) and the CLI a small `hyper` client without this crate depending on
//! either. Id token and JWKS handling stay with the panel, the only client that verifies id tokens.
//!
//! No error, log line or URL built here carries a token, a code, a device code or a client secret.

mod device;
mod discovery;
mod token;

use std::fmt;
use std::future::Future;
use std::time::Duration;

pub use device::{DeviceAuthorization, DevicePoll, device_authorization, poll_device_token};
pub use discovery::{DiscoveryPolicy, Endpoints, discover};
pub use token::{
    AuthorizationRequest, ClientAuth, TokenSet, authorization_url, pkce_challenge, refresh, revoke,
    token_request,
};
pub use url::Url;

/// Largest discovery document, JWKS or token response read.
pub const MAX_BODY: usize = 256 * 1024;

/// A secret string. `Debug` never shows it; there is no `Display`, `Serialize`, `Clone` or `==`
/// (a derived comparison is not constant-time): the only way out is [`Secret::expose`].
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("provider discovery failed: {0}")]
    Discovery(String),
    #[error("cannot reach the provider: {0}")]
    Network(String),
    /// The provider answered with a 4xx other than the "come back later" ones below. Only some of
    /// them are verdicts on the grant, see [`Error::is_definitive`].
    #[error("the provider refused the request (HTTP {0})")]
    Refused(u16),
    /// The provider asked to come back later (HTTP 408, 429 or 503): a rate limit or a short
    /// outage, never a verdict on the grant. `retry_after` is the `Retry-After` header when it
    /// was strict delta-seconds.
    #[error("the provider asked to retry later (HTTP {status})")]
    Throttled {
        status: u16,
        retry_after: Option<Duration>,
    },
    /// A 5xx or any other unusable status.
    #[error("the provider failed (HTTP {0})")]
    ProviderFailed(u16),
    #[error("unexpected provider response: {0}")]
    BadResponse(&'static str),
}

impl Error {
    /// A refresh that failed for a reason retrying cannot fix (revoked or expired grant), so the
    /// caller may drop its tokens. An allowlist: only `400` (`invalid_grant` and the other token
    /// endpoint errors, RFC 6749 5.2) and `401` (`invalid_client`) are verdicts on the grant. Any
    /// other 4xx (a misrouted proxy answering `404`, a rate limit) leaves the tokens alone.
    pub fn is_definitive(&self) -> bool {
        matches!(self, Self::Refused(400 | 401) | Self::BadResponse(_))
    }
}

/// Statuses that mean "ask again later" (RFC 9110 15.5.9, 15.6.4; RFC 6585 4).
pub(crate) fn is_throttle(status: u16) -> bool {
    matches!(status, 408 | 429 | 503)
}

/// The error for a non-2xx answer: [`Error::Throttled`] for the "later" statuses (keeping a
/// usable `Retry-After`), otherwise by status class.
pub(crate) fn response_error(response: &HttpResponse) -> Error {
    if is_throttle(response.status) {
        Error::Throttled {
            status: response.status,
            retry_after: retry_after_delta(response.retry_after.as_deref()),
        }
    } else {
        status_error(response.status)
    }
}

pub(crate) fn status_error(status: u16) -> Error {
    if (400..500).contains(&status) {
        Error::Refused(status)
    } else {
        Error::ProviderFailed(status)
    }
}

/// `Retry-After` as delta-seconds (RFC 9110 10.2.3). An HTTP-date or anything malformed is
/// ignored, as is a value with a sign, a fraction or whitespace inside.
pub(crate) fn retry_after_delta(value: Option<&str>) -> Option<Duration> {
    let digits = value?.trim();
    if digits.is_empty() || digits.len() > 18 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok().map(Duration::from_secs)
}

/// An answer with its body already capped by the transport.
#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
    /// The raw `Retry-After` header value, if the answer carried one (kept as text: the device
    /// grant parses only the delta-seconds form and ignores anything else).
    pub retry_after: Option<String>,
}

/// How bytes reach the provider. Implementations enforce the `limit` while reading (a lying
/// `Content-Length` must not make the client allocate more), never follow redirects, treat
/// `authorization` as sensitive, and return the (capped) body whatever the status is: the device
/// grant reports "not yet" and "denied" as a `400` with a JSON `error`.
pub trait Transport: Send + Sync {
    fn get(
        &self,
        url: &Url,
        limit: usize,
    ) -> impl Future<Output = Result<HttpResponse, Error>> + Send;

    /// `POST` with `application/x-www-form-urlencoded`. `authorization` is the full header value.
    fn post_form(
        &self,
        url: &Url,
        authorization: Option<&Secret>,
        body: String,
        limit: usize,
    ) -> impl Future<Output = Result<HttpResponse, Error>> + Send;
}

/// `GET` with the status checked and the body capped at [`MAX_BODY`].
pub async fn get_ok<T: Transport>(transport: &T, url: &Url) -> Result<Vec<u8>, Error> {
    let response = transport.get(url, MAX_BODY).await?;
    if (200..300).contains(&response.status) {
        Ok(response.body)
    } else {
        Err(response_error(&response))
    }
}

/// `https://`, or plain `http://` to a loopback address (a test provider).
pub(crate) fn loopback_http(url: &Url) -> bool {
    url.scheme() == "http"
        && url.host_str().is_some_and(|host| {
            host.trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
        })
}

pub(crate) fn form_body(pairs: &[(&str, &str)]) -> String {
    let mut body = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in pairs {
        body.append_pair(name, value);
    }
    body.finish()
}

#[cfg(test)]
pub(crate) mod testing {
    //! A scripted transport: records requests, answers from a queue.
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    pub struct Script {
        pub answers: Mutex<Vec<Result<HttpResponse, Error>>>,
        pub seen: Mutex<Vec<(String, Option<String>, String)>>,
    }

    impl Script {
        pub fn push(&self, status: u16, body: &str) {
            self.answers.lock().unwrap().push(Ok(HttpResponse {
                status,
                body: body.as_bytes().to_vec(),
                retry_after: None,
            }));
        }

        pub fn push_with_retry_after(&self, status: u16, body: &str, retry_after: &str) {
            self.answers.lock().unwrap().push(Ok(HttpResponse {
                status,
                body: body.as_bytes().to_vec(),
                retry_after: Some(retry_after.to_owned()),
            }));
        }
    }

    impl Transport for Script {
        async fn get(&self, url: &Url, _limit: usize) -> Result<HttpResponse, Error> {
            self.seen
                .lock()
                .unwrap()
                .push((url.to_string(), None, String::new()));
            self.answers.lock().unwrap().remove(0)
        }

        async fn post_form(
            &self,
            url: &Url,
            authorization: Option<&Secret>,
            body: String,
            _limit: usize,
        ) -> Result<HttpResponse, Error> {
            self.seen.lock().unwrap().push((
                url.to_string(),
                authorization.map(|s| s.expose().to_owned()),
                body,
            ));
            self.answers.lock().unwrap().remove(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(status: u16, retry_after: Option<&str>) -> HttpResponse {
        HttpResponse {
            status,
            body: Vec::new(),
            retry_after: retry_after.map(str::to_owned),
        }
    }

    #[test]
    fn only_a_refused_grant_or_client_is_definitive() {
        for status in [400, 401] {
            assert!(
                response_error(&answer(status, None)).is_definitive(),
                "{status}"
            );
        }
        for status in [403, 404, 405, 408, 409, 429, 500, 502, 503] {
            assert!(
                !response_error(&answer(status, None)).is_definitive(),
                "{status}"
            );
        }
        assert!(Error::BadResponse("x").is_definitive());
        assert!(!Error::Network("x".into()).is_definitive());
    }

    #[test]
    fn later_statuses_are_throttling_with_a_strict_retry_after() {
        let secs = Duration::from_secs;
        for (status, header, wanted) in [
            (429, Some("30"), Some(secs(30))),
            (429, None, None),
            (408, Some(" 7 "), Some(secs(7))),
            (503, Some("Wed, 21 Oct 2026 07:28:00 GMT"), None),
            (429, Some("-5"), None),
            (429, Some("1.5"), None),
        ] {
            assert!(
                matches!(
                    response_error(&answer(status, header)),
                    Error::Throttled { status: s, retry_after } if s == status && retry_after == wanted
                ),
                "{status} {header:?}"
            );
        }
        assert!(matches!(
            response_error(&answer(404, Some("30"))),
            Error::Refused(404)
        ));
        assert!(matches!(
            response_error(&answer(502, None)),
            Error::ProviderFailed(502)
        ));
    }
}
