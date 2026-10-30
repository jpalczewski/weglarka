//! The panel's client for the admin API, over the daemon's token socket (docs/decisions/0056).
//!
//! One call is one [`weglarka_api::Endpoint`] plus its path parameters; the bearer token is the
//! caller's own and travels only in the `Authorization` header, never in a URL, a log line or an
//! error. The daemon verifies it on every request, so a `401`/`403` here is the final answer.

use std::time::Duration;

use http_body_util::Empty;
use serde::de::DeserializeOwned;
use weglarka_api::{ApiError, Endpoint, ErrorCode, Method};
use weglarka_model::admin_auth::Scope;
use weglarka_unix_http::{Bytes, Request, StreamingResponse, UnixClient, bearer, header};

use crate::config::{PanelConfig, Secret};

/// The longest daemon error message kept (the text comes from the daemon, not from the browser).
const MAX_MESSAGE: usize = 512;

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    /// `401`: no token, or one the daemon does not accept (expired, wrong audience): log in again.
    #[error("the daemon does not accept the session token")]
    Unauthorized,
    /// `403`: a valid token whose scope does not allow the call.
    #[error("the session is not allowed to do this")]
    Forbidden,
    #[error("not found: {0}")]
    NotFound(String),
    /// Any other `4xx`.
    #[error("the daemon refused the request ({status}): {message}")]
    Rejected { status: u16, message: String },
    /// `5xx`, including the engine being busy.
    #[error("the daemon failed ({status}): {message}")]
    Server { status: u16, message: String },
    /// The socket is missing, refused the connection or went away.
    #[error("the daemon is unreachable")]
    Unreachable,
    #[error("the daemon did not answer in time")]
    Timeout,
    /// The call itself was malformed (a bad path parameter, a token that is not a header value).
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// A success status with a body that is not the expected JSON. Only the position is kept:
    /// serde's own text can quote the offending value.
    #[error("the daemon answered with an unexpected body (line {line}, column {column})")]
    Decode { line: usize, column: usize },
}

impl From<weglarka_unix_http::Error> for DaemonError {
    fn from(e: weglarka_unix_http::Error) -> Self {
        match e {
            weglarka_unix_http::Error::Timeout => Self::Timeout,
            weglarka_unix_http::Error::InvalidRequest(reason) => Self::InvalidRequest(reason),
            // Failing to connect and a connection that breaks mid-exchange look the same to a user:
            // the daemon is not there.
            _ => Self::Unreachable,
        }
    }
}

/// One request: an endpoint with its path parameters and query. Only characters that need no
/// escaping are accepted in a path parameter, so a value can never add a path segment.
#[derive(Debug, Clone)]
pub struct Call {
    endpoint: &'static Endpoint,
    params: Vec<(&'static str, String)>,
    query: Vec<(&'static str, String)>,
    /// `None` = the client's default deadline; `Some(None)` = no deadline.
    timeout: Option<Option<Duration>>,
}

impl Call {
    /// The scope the endpoint needs on the token listener (`None` = no authentication).
    pub fn scope(&self) -> Option<Scope> {
        self.endpoint.scope
    }

    pub fn new(endpoint: &'static Endpoint) -> Self {
        Self {
            endpoint,
            params: Vec::new(),
            query: Vec::new(),
            timeout: None,
        }
    }

    /// Overrides the client's deadline for this call; `None` waits without a limit. For operations
    /// that legitimately take long (a deploy behind the health gate): dropping the connection
    /// mid-operation would leave the user told "failed" while the daemon may still be working.
    pub fn timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Fills `{name}` in the endpoint's path.
    pub fn param(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.params.push((name, value.into()));
        self
    }

    /// Adds `?name=value` (percent-encoded).
    pub fn query(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.query.push((name, value.into()));
        self
    }

    /// The request target: path with parameters filled in, plus the query.
    fn target(&self) -> Result<String, DaemonError> {
        let mut path = self.endpoint.path.to_owned();
        for (name, value) in &self.params {
            let ok = !value.is_empty()
                && value != "."
                && value != ".."
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
            if !ok {
                return Err(DaemonError::InvalidRequest(format!(
                    "path parameter `{name}` has characters that are not allowed"
                )));
            }
            let slot = format!("{{{name}}}");
            if !path.contains(&slot) {
                return Err(DaemonError::InvalidRequest(format!(
                    "{} has no parameter `{name}`",
                    self.endpoint.path
                )));
            }
            path = path.replace(&slot, value);
        }
        if path.contains('{') {
            return Err(DaemonError::InvalidRequest(format!(
                "a path parameter of {} is missing",
                self.endpoint.path
            )));
        }
        if !self.query.is_empty() {
            let mut q = url::form_urlencoded::Serializer::new(String::new());
            for (name, value) in &self.query {
                q.append_pair(name, value);
            }
            path.push('?');
            path.push_str(&q.finish());
        }
        Ok(path)
    }
}

#[derive(Debug, Clone)]
pub struct DaemonClient {
    http: UnixClient,
    timeout: Duration,
}

impl DaemonClient {
    /// `timeout` bounds every exchange after connecting (connecting has its own limit).
    pub fn new(socket: impl Into<std::path::PathBuf>, timeout: Duration) -> Self {
        Self {
            http: UnixClient::new(socket),
            timeout,
        }
    }

    pub fn from_config(config: &PanelConfig) -> Self {
        Self::new(config.socket.clone(), config.request_timeout)
    }

    /// Sends `call` with `token` and decodes a JSON success body as `R`. For endpoints that answer
    /// `204 No Content` use [`Self::send_empty`].
    pub async fn send<R: DeserializeOwned>(
        &self,
        token: &Secret,
        call: &Call,
    ) -> Result<R, DaemonError> {
        let body = self.send_raw(token, call).await?;
        serde_json::from_slice(&body).map_err(|e| DaemonError::Decode {
            line: e.line(),
            column: e.column(),
        })
    }

    /// Sends `call` and ignores the success body (`204 No Content` endpoints).
    pub async fn send_empty(&self, token: &Secret, call: &Call) -> Result<(), DaemonError> {
        self.send_raw(token, call).await.map(drop)
    }

    /// Like [`Self::send`] but returns the raw success body.
    pub async fn send_raw(&self, token: &Secret, call: &Call) -> Result<Bytes, DaemonError> {
        let request = self.request(token, call)?;
        let deadline = call.timeout.unwrap_or(Some(self.timeout));
        let http = self.http.clone().with_head_timeout(deadline);
        let reply = http.buffered(request, deadline).await?;
        let status = reply.status.as_u16();
        if reply.status.is_success() {
            Ok(reply.body)
        } else {
            Err(map_error(status, &reply.body))
        }
    }

    /// Opens a streaming endpoint. A non-success head is mapped like any other error before any
    /// body is read; on success the caller reads the body chunk by chunk and drops the stream to
    /// close the connection. Only the head is bounded by the client's deadline.
    pub async fn open(&self, token: &Secret, call: &Call) -> Result<Stream, DaemonError> {
        let request = self.request(token, call)?;
        let http = self.http.clone().with_head_timeout(Some(self.timeout));
        let response = http.open(request).await?;
        if response.status.is_success() {
            return Ok(response);
        }
        let status = response.status.as_u16();
        // An error body is a small JSON envelope; reading it is bounded like any exchange.
        let body = tokio::time::timeout(self.timeout, response.collect())
            .await
            .map_err(|_| DaemonError::Timeout)??;
        Err(map_error(status, &body))
    }

    /// Forwards a prepared request (the relay, ADR 0060) and returns as soon as the head arrives;
    /// the caller reads the body. `head_timeout` bounds only the head: a long operation answers
    /// when it is done, and a stream is not cut by it.
    pub async fn relay(
        &self,
        request: Request<RelayBody>,
        head_timeout: Duration,
    ) -> Result<RelayedResponse, DaemonError> {
        let http = self.http.clone().with_head_timeout(Some(head_timeout));
        Ok(http.open(request).await?)
    }

    fn request(&self, token: &Secret, call: &Call) -> Result<Request<Empty<Bytes>>, DaemonError> {
        let method = match call.endpoint.method {
            Method::Get => weglarka_unix_http::Method::GET,
            Method::Post => weglarka_unix_http::Method::POST,
            Method::Put => weglarka_unix_http::Method::PUT,
            Method::Delete => weglarka_unix_http::Method::DELETE,
        };
        weglarka_unix_http::Request::builder()
            .method(method)
            .uri(call.target()?)
            .header(header::AUTHORIZATION, bearer(token.expose())?)
            .header(header::ACCEPT, "application/json")
            .body(Empty::<Bytes>::new())
            .map_err(|_| DaemonError::InvalidRequest("malformed request".into()))
    }
}

/// An open response whose body is read incrementally.
pub type Stream = StreamingResponse<Empty<Bytes>>;

/// The request body the relay streams upstream: the caller's own, capped.
pub type RelayBody = http_body_util::Limited<axum::body::Body>;

/// The daemon's answer to a relayed request.
pub type RelayedResponse = StreamingResponse<RelayBody>;

/// Maps the API error envelope (or a bare status) to a [`DaemonError`]. A body that is not the
/// envelope is dropped, never quoted.
fn map_error(status: u16, body: &[u8]) -> DaemonError {
    let envelope: Option<ApiError> = serde_json::from_slice(body).ok();
    let message = envelope
        .as_ref()
        .map(|e| e.message.chars().take(MAX_MESSAGE).collect::<String>())
        .unwrap_or_default();
    match (status, envelope.map(|e| e.code)) {
        (401, _) | (_, Some(ErrorCode::Unauthorized)) => DaemonError::Unauthorized,
        (403, _) | (_, Some(ErrorCode::Forbidden)) => DaemonError::Forbidden,
        (404, _) | (_, Some(ErrorCode::NotFound)) => DaemonError::NotFound(message),
        (500.., _) => DaemonError::Server { status, message },
        _ => DaemonError::Rejected { status, message },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_fills_parameters_and_encodes_the_query() {
        let call = Call::new(&weglarka_api::endpoints::APPS_SHOW)
            .param("name", "my-app.1")
            .query("since", "a b&c");
        assert_eq!(call.target().unwrap(), "/v1/apps/my-app.1?since=a+b%26c");
    }

    #[test]
    fn target_rejects_what_could_change_the_path() {
        for bad in ["", ".", "..", "a/b", "a?b", "a%2fb", "a b", "a#b"] {
            let err = Call::new(&weglarka_api::endpoints::APPS_SHOW)
                .param("name", bad)
                .target()
                .unwrap_err();
            assert!(matches!(err, DaemonError::InvalidRequest(_)), "{bad:?}");
        }
        assert!(
            Call::new(&weglarka_api::endpoints::APPS_SHOW)
                .target()
                .is_err()
        );
        assert!(
            Call::new(&weglarka_api::endpoints::APPS_LIST)
                .param("name", "x")
                .target()
                .is_err()
        );
    }
}
