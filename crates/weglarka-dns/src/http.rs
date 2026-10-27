//! The JSON-over-HTTPS call the DNS adapters make, on the shared `weglarka-http` client.
//!
//! TLS, timeouts and the no-redirect policy come from [`Purpose::Api`]; this module adds what is
//! specific to a bearer-token API: a validated base URL (HTTPS, or plain HTTP to loopback for tests,
//! so the token cannot travel in the clear to a remote machine), a *sensitive* `Authorization`
//! header, and a hard cap on the response body.

use weglarka_http::reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use weglarka_http::reqwest::{Method, Url};
use weglarka_http::{BodyError, Purpose, error_chain, read_capped, transport_allowed};

/// A Cloudflare API answer is a few hundred bytes; a hostile peer must not make the daemon allocate.
const MAX_BODY: usize = 256 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("invalid API URL: {0}")]
    Url(&'static str),
    #[error("cannot build the HTTP client: {0}")]
    Client(#[from] weglarka_http::HttpError),
    /// Transport failure; the text never carries the URL or the token.
    #[error("request failed: {0}")]
    Request(String),
    #[error("response body exceeds {limit} bytes")]
    TooLarge { limit: usize },
    #[error("invalid bearer token: it must be printable ASCII")]
    Token,
}

pub(crate) struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Where requests go and the client that sends them.
pub(crate) struct Api {
    client: weglarka_http::reqwest::Client,
    /// `scheme://host[:port][/base]` without a trailing slash.
    base: String,
    max_body: usize,
}

impl Api {
    pub(crate) fn new(base_url: &str) -> Result<Self, HttpError> {
        let base_url = base_url.trim();
        let url = Url::parse(base_url).map_err(|_| HttpError::Url("not a valid URL"))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(HttpError::Url("expected http:// or https://"));
        }
        if url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(HttpError::Url("no query, fragment or credentials allowed"));
        }
        // The URL parser reads `https:///v4` as host `v4`; an empty authority is a typo, not that.
        let empty_authority = base_url
            .split_once("://")
            .is_some_and(|(_, rest)| rest.starts_with(['/', '\\']));
        if empty_authority || url.host_str().is_none() || url.port() == Some(0) {
            return Err(HttpError::Url("invalid host or port"));
        }
        if !transport_allowed(&url) {
            return Err(HttpError::Url(
                "plain http is only allowed for a loopback host (the token would travel unencrypted)",
            ));
        }
        Ok(Self {
            client: weglarka_http::client(Purpose::Api)?,
            base: url.as_str().trim_end_matches('/').to_owned(),
            max_body: MAX_BODY,
        })
    }

    /// Lowers the response cap (a public list is far smaller than a zone listing).
    pub(crate) fn with_max_body(mut self, max_body: usize) -> Self {
        self.max_body = max_body.min(MAX_BODY);
        self
    }

    /// `path` is relative to the base and starts with `/` (it may carry a query).
    pub(crate) async fn request(
        &self,
        method: Method,
        path: &str,
        bearer: Option<&str>,
        body: Option<Vec<u8>>,
    ) -> Result<Response, HttpError> {
        let url = Url::parse(&format!("{}{path}", self.base))
            .map_err(|_| HttpError::Url("not a valid request path"))?;
        let mut request = self
            .client
            .request(method, url)
            .header(ACCEPT, "application/json");
        if let Some(bearer) = bearer {
            if bearer.is_empty() || !bearer.bytes().all(|b| b.is_ascii_graphic()) {
                return Err(HttpError::Token);
            }
            let mut value =
                HeaderValue::from_str(&format!("Bearer {bearer}")).map_err(|_| HttpError::Token)?;
            value.set_sensitive(true);
            request = request.header(AUTHORIZATION, value);
        }
        if let Some(body) = body {
            request = request.header(CONTENT_TYPE, "application/json").body(body);
        }
        let response = request.send().await.map_err(transport)?;
        let status = response.status().as_u16();
        let body = read_capped(response, self.max_body)
            .await
            .map_err(|error| match error {
                BodyError::TooLarge { limit } => HttpError::TooLarge { limit },
                BodyError::Read(error) => transport(error),
            })?;
        Ok(Response { status, body })
    }
}

fn transport(error: weglarka_http::reqwest::Error) -> HttpError {
    HttpError::Request(error_chain(&error.without_url()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_parsing() {
        let api = Api::new("https://api.cloudflare.com/client/v4/").unwrap();
        assert_eq!(api.base, "https://api.cloudflare.com/client/v4");
        let local = Api::new("http://127.0.0.1:8123").unwrap();
        assert_eq!(local.base, "http://127.0.0.1:8123");
        for bad in [
            "ftp://x.eu",
            "api.example.eu",
            "https://u:p@example.eu",
            "https://example.eu/?a=1",
            "https://example.eu:0",
            "https:///v4",
            "http://api.example.eu",
        ] {
            assert!(Api::new(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_body_cap_can_only_be_lowered() {
        let api = Api::new("https://api.example.eu").unwrap();
        assert_eq!(api.with_max_body(10 * MAX_BODY).max_body, MAX_BODY);
    }
}
