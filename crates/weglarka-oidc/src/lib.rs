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
    /// The provider answered with a 4xx: the grant or credentials were refused.
    #[error("the provider refused the request (HTTP {0})")]
    Refused(u16),
    /// A 5xx or any other unusable status.
    #[error("the provider failed (HTTP {0})")]
    ProviderFailed(u16),
    #[error("unexpected provider response: {0}")]
    BadResponse(&'static str),
}

impl Error {
    /// A refresh that failed for a reason retrying cannot fix (revoked or expired grant).
    pub fn is_definitive(&self) -> bool {
        matches!(self, Self::Refused(_) | Self::BadResponse(_))
    }
}

pub(crate) fn status_error(status: u16) -> Error {
    if (400..500).contains(&status) {
        Error::Refused(status)
    } else {
        Error::ProviderFailed(status)
    }
}

/// An answer with its body already capped by the transport.
#[derive(Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
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
        Err(status_error(response.status))
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
