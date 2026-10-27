//! `GET` client for the OCI registry protocol, on the shared `weglarka-http` client.
//!
//! The registry wire format is small (a challenge, a token, a manifest, blobs): one `GET` per
//! connection, no cookies, no compression, no caching. What the security of the self-update relies on:
//!
//! * TLS with the bundled `webpki-roots` (the daemon image is `scratch` and has no CA store); plain
//!   HTTP is allowed only for loopback hosts, which is where the tests put their servers.
//! * A size cap for every response body, enforced while reading (a `Content-Length` lie cannot make
//!   the daemon allocate more than the cap).
//! * At most 5 redirects, each only to `https://` (or loopback); the `Authorization` header is not
//!   forwarded to another host or port (GHCR redirects blobs to a CDN). Both come from
//!   [`Purpose::Registry`].
//! * A per-request timeout covering redirects and the body.

use weglarka_http::reqwest::header::{ACCEPT, AUTHORIZATION, HeaderValue, WWW_AUTHENTICATE};
use weglarka_http::reqwest::{StatusCode, Url};
use weglarka_http::{BodyError, Purpose, error_chain, read_capped, transport_allowed};

/// URL limit; the longest URL this client builds is a token URL with a scope.
const MAX_URL_LEN: usize = 4096;

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("URL is malformed: {0}")]
    Url(&'static str),
    #[error("unsupported URL scheme {scheme:?}: only http and https are allowed")]
    Scheme { scheme: String },
    #[error("refusing plain http to {host:?}: registry traffic to a non-loopback host needs https")]
    NotHttps { host: String },
    #[error("invalid port in the URL")]
    Port,
    #[error("the bearer token is not a safe HTTP header value")]
    InvalidToken,
    #[error("cannot build the HTTP client: {0}")]
    Client(#[from] weglarka_http::HttpError),
    /// Transport failure; the text carries the cause chain but never the URL (it may hold a scope).
    #[error("the {what} request failed: {detail}")]
    Request { what: &'static str, detail: String },
    #[error("the {what} request timed out")]
    Timeout { what: &'static str },
    /// A redirect was refused (too many hops, or to a URL that is neither https nor loopback).
    #[error("the {what} request was redirected somewhere it must not go: {detail}")]
    Redirect { what: &'static str, detail: String },
    #[error("the {what} response exceeds the {limit} byte limit")]
    TooLarge { what: &'static str, limit: usize },
}

/// Parses an absolute `http(s)://host[:port][/path][?query]` URL, with the plain-HTTP policy applied.
pub(crate) fn parse_url(url: &str) -> Result<Url, HttpError> {
    if url.is_empty() || url.len() > MAX_URL_LEN {
        return Err(HttpError::Url("URL is empty or too long"));
    }
    if !url.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(HttpError::Url(
            "URL contains whitespace or control characters",
        ));
    }
    let (scheme, rest) = url
        .split_once("://")
        .ok_or(HttpError::Url("missing scheme"))?;
    if !matches!(scheme, "http" | "https") {
        return Err(HttpError::Scheme {
            scheme: scheme.to_owned(),
        });
    }
    if rest.contains('#') {
        return Err(HttpError::Url("URL fragments are not supported"));
    }
    let authority = rest.split(['/', '?']).next().unwrap_or_default();
    if authority.contains('@') {
        return Err(HttpError::Url("URLs with credentials are not supported"));
    }
    if authority.is_empty() {
        return Err(HttpError::Url("missing host"));
    }
    let parsed = Url::parse(url).map_err(|error| {
        if error.to_string().contains("port") {
            HttpError::Port
        } else {
            HttpError::Url("not a valid URL")
        }
    })?;
    if parsed.port() == Some(0) {
        return Err(HttpError::Port);
    }
    if !transport_allowed(&parsed) {
        return Err(HttpError::NotHttps {
            host: parsed.host_str().unwrap_or_default().to_owned(),
        });
    }
    Ok(parsed)
}

/// Builds the URL for a registry (the scheme depends on whether it is a loopback test host).
pub(crate) fn registry_url(registry: &str, path: &str) -> Result<Url, HttpError> {
    if !path.starts_with('/') {
        return Err(HttpError::Url("the request path must start with '/'"));
    }
    let scheme = if is_loopback(registry_host(registry)) {
        "http"
    } else {
        "https"
    };
    parse_url(&format!("{scheme}://{registry}{path}"))
}

/// The host part of a validated `host[:port]` registry string.
fn registry_host(registry: &str) -> &str {
    match registry.strip_prefix('[') {
        Some(inner) => inner.split_once(']').map_or(inner, |(host, _)| host),
        None => registry.split_once(':').map_or(registry, |(host, _)| host),
    }
}

fn is_loopback(host: &str) -> bool {
    host == "127.0.0.1" || host == "::1"
}

/// Percent-encodes everything but the RFC 3986 unreserved characters; used to build query strings
/// from registry-controlled values without letting them inject another parameter.
pub(crate) fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
}

/// A response with its status, the Bearer challenge (if any) and its body read up to the caller's cap.
#[derive(Debug)]
pub(crate) struct Response {
    pub(crate) status: u16,
    /// The `WWW-Authenticate` header, when present, printable ASCII (the caller bounds its length).
    pub(crate) challenge: Option<String>,
    pub(crate) body: Vec<u8>,
}

/// HTTP client with one shared TLS configuration.
pub(crate) struct Client {
    client: weglarka_http::reqwest::Client,
}

impl Client {
    /// Client that trusts the bundled Mozilla root store (`webpki-roots`).
    pub(crate) fn new() -> Result<Self, HttpError> {
        Ok(Self {
            client: weglarka_http::client(Purpose::Registry)?,
        })
    }

    /// `GET` `url`, following the redirects [`Purpose::Registry`] allows, and read at most `max_body`
    /// bytes.
    ///
    /// `bearer` goes out as a *sensitive* `Authorization` header (redacted in `Debug`) and is dropped
    /// by `reqwest` when a redirect leaves the original host or port.
    pub(crate) async fn get(
        &self,
        url: &Url,
        bearer: Option<&str>,
        accept: Option<&str>,
        max_body: usize,
        what: &'static str,
    ) -> Result<Response, HttpError> {
        let mut request = self.client.get(url.clone());
        if let Some(accept) = accept {
            request = request.header(
                ACCEPT,
                HeaderValue::from_str(accept).map_err(|_| HttpError::Url("invalid Accept"))?,
            );
        }
        if let Some(token) = bearer {
            if !token.bytes().all(|b| b.is_ascii_graphic()) {
                return Err(HttpError::InvalidToken);
            }
            let mut value = HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|_| HttpError::InvalidToken)?;
            value.set_sensitive(true);
            request = request.header(AUTHORIZATION, value);
        }
        let response = request.send().await.map_err(|e| failure(e, what))?;
        let status = response.status().as_u16();
        let challenge = response
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        // A redirect that was not followed (no `Location`) has nothing worth reading.
        let body = if StatusCode::from_u16(status).is_ok_and(|s| s.is_redirection()) {
            Vec::new()
        } else {
            read_capped(response, max_body)
                .await
                .map_err(|error| match error {
                    BodyError::TooLarge { limit } => HttpError::TooLarge { what, limit },
                    BodyError::Read(error) => failure(error, what),
                })?
        };
        Ok(Response {
            status,
            challenge,
            body,
        })
    }
}

fn failure(error: weglarka_http::reqwest::Error, what: &'static str) -> HttpError {
    if error.is_timeout() {
        return HttpError::Timeout { what };
    }
    let redirect = error.is_redirect();
    let detail = error_chain(&error.without_url());
    if redirect {
        return HttpError::Redirect { what, detail };
    }
    HttpError::Request { what, detail }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_parsed_strictly() {
        let url = parse_url("https://ghcr.io/token?service=ghcr.io").unwrap();
        assert_eq!(
            (url.host_str(), url.port_or_known_default()),
            (Some("ghcr.io"), Some(443))
        );
        assert_eq!(url.query(), Some("service=ghcr.io"));
        assert!(parse_url("http://127.0.0.1:5000/token").is_ok());
        assert!(parse_url("http://[::1]:5000/token").is_ok());
        assert!(matches!(
            parse_url("http://example.com/x").unwrap_err(),
            HttpError::NotHttps { .. }
        ));
        assert!(matches!(
            parse_url("ftp://example.com/x").unwrap_err(),
            HttpError::Scheme { .. }
        ));
        for bad in [
            "",
            "example.com",
            "https://user:pass@example.com/x",
            "https://example.com/x#fragment",
            "https://exa mple.com/x",
            "https:///x",
        ] {
            assert!(
                matches!(parse_url(bad).unwrap_err(), HttpError::Url(_)),
                "{bad}"
            );
        }
        for bad in ["https://example.com:99999/x", "https://example.com:0/x"] {
            assert!(
                matches!(parse_url(bad).unwrap_err(), HttpError::Port),
                "{bad}"
            );
        }
        let long = format!("https://example.com/{}", "a".repeat(MAX_URL_LEN));
        assert!(matches!(parse_url(&long).unwrap_err(), HttpError::Url(_)));
    }

    #[test]
    fn registry_urls_use_https_except_on_loopback() {
        let url = registry_url("ghcr.io", "/v2/a/b/manifests/c").unwrap();
        assert_eq!(url.scheme(), "https");
        let url = registry_url("127.0.0.1:5000", "/v2/a/b").unwrap();
        assert_eq!((url.scheme(), url.port()), ("http", Some(5000)));
        let url = registry_url("[::1]:5000", "/v2/a/b").unwrap();
        assert_eq!(url.scheme(), "http");
        assert!(matches!(
            registry_url("ghcr.io", "v2/relative").unwrap_err(),
            HttpError::Url(_)
        ));
        assert_eq!(registry_host("ghcr.io:443"), "ghcr.io");
        assert_eq!(registry_host("[::1]:5000"), "::1");
    }

    #[test]
    fn percent_encoding_escapes_query_separators() {
        assert_eq!(
            percent_encode("repository:jpalczewski/weglarka:pull"),
            "repository%3Ajpalczewski%2Fweglarka%3Apull"
        );
        assert_eq!(percent_encode("a-b.c_d~e"), "a-b.c_d~e");
        assert_eq!(percent_encode("a&b=c"), "a%26b%3Dc");
    }
}
