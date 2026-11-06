//! Admin API client: HTTP/1.1 over a unix socket (hyper, one connection per request).
//! Paths and methods come from `weglarka_api::endpoints`, so they can't drift from the contract.

use std::path::PathBuf;
use std::time::Duration;

use futures_util::{Stream, StreamExt};
use http_body_util::{Full, StreamBody};
use hyper::body::{Bytes, Frame};
use hyper::header::{CONTENT_TYPE, HeaderValue};
use hyper::{Request, StatusCode};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use weglarka_api::{
    ACCESS_STREAM_CONTENT_TYPE, AccessFrame, AccessQuery, ApiError, Endpoint, FrameDecoder,
    FrameKind, LOGS_STREAM_CONTENT_TYPE, LogFrame, LogsQuery, Method, RUN_STREAM_CONTENT_TYPE,
    RunFrame, RunRequest, endpoints,
};
use weglarka_unix_http::{StreamingResponse, UnixClient};

use crate::error::{CliError, Kind};
use crate::login::remote::Remote;

/// Deploy waits for the image pull and the health gate, so the overall timeout is long.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(600);
/// How long a request answered with `busy` (another mutation holds the engine, e.g. a deploy behind
/// the health gate) is retried before the error is returned.
const BUSY_WAIT: Duration = Duration::from_secs(180);
/// Pause between retries of a `busy` request (grows up to `BUSY_BACKOFF_MAX`).
const BUSY_BACKOFF_START: Duration = Duration::from_millis(500);
const BUSY_BACKOFF_MAX: Duration = Duration::from_secs(5);

/// The frames of a streaming response (`run`, `logs`), as they arrive.
pub struct FrameStream<F> {
    /// Keeps the connection's request side open for as long as the response is read.
    response: StreamingResponse<Full<Bytes>>,
    decoder: FrameDecoder<F>,
    ready: std::collections::VecDeque<F>,
    /// What the stream is called in error messages.
    what: &'static str,
}

pub type RunStream = FrameStream<RunFrame>;
pub type LogStream = FrameStream<LogFrame>;
pub type AccessStream = FrameStream<AccessFrame>;

impl<F: FrameKind> FrameStream<F> {
    fn new(response: StreamingResponse<Full<Bytes>>, what: &'static str) -> Self {
        Self {
            response,
            decoder: FrameDecoder::default(),
            ready: std::collections::VecDeque::new(),
            what,
        }
    }

    /// The next frame, or `None` when the daemon closed the stream.
    pub async fn next(&mut self) -> Result<Option<F>, CliError> {
        loop {
            if let Some(frame) = self.ready.pop_front() {
                return Ok(Some(frame));
            }
            let Some(chunk) = self.response.chunk().await else {
                return if self.decoder.is_clean() {
                    Ok(None)
                } else {
                    Err(CliError::internal(format!(
                        "{} stream ended inside a frame",
                        self.what
                    )))
                };
            };
            let data = chunk.map_err(|e| {
                CliError::internal(format!("{} stream interrupted: {e}", self.what))
            })?;
            self.ready.extend(
                self.decoder
                    .push(&data)
                    .map_err(|e| CliError::internal(e.to_string()))?,
            );
        }
    }
}

pub struct ApiClient {
    backend: Backend,
    busy_wait: Duration,
}

/// Where requests go: the local daemon's socket, or a remote host's panel relay.
enum Backend {
    Unix(UnixClient),
    Remote(Box<Remote>),
}

impl Backend {
    async fn buffered<B>(
        &self,
        request: Request<B>,
        timeout: Option<Duration>,
        what: &str,
    ) -> Result<weglarka_unix_http::Buffered, CliError>
    where
        B: hyper::body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        match self {
            Self::Unix(http) => http
                .buffered(request, timeout)
                .await
                .map_err(|e| map_transport(e, what, |cause| unreachable_socket(http, &cause))),
            Self::Remote(remote) => remote.buffered(request, timeout, what).await,
        }
    }

    async fn open<B>(
        &self,
        request: Request<B>,
        what: &str,
    ) -> Result<StreamingResponse<B>, CliError>
    where
        B: hyper::body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        match self {
            Self::Unix(http) => http
                .open(request)
                .await
                .map_err(|e| map_transport(e, what, |cause| unreachable_socket(http, &cause))),
            Self::Remote(remote) => remote.open(request, what).await,
        }
    }
}

/// Connection failures become `Unreachable` (built by `unreachable`), a timeout and everything
/// else an internal error prefixed with `what`.
pub(crate) fn map_transport(
    e: weglarka_unix_http::Error,
    what: &str,
    unreachable: impl FnOnce(String) -> CliError,
) -> CliError {
    if matches!(e, weglarka_unix_http::Error::Timeout) {
        CliError::internal("request to daemon timed out")
    } else if e.is_connect() {
        unreachable(e.to_string())
    } else {
        CliError::internal(format!("{what}: {e}"))
    }
}

fn unreachable_socket(http: &UnixClient, cause: &str) -> CliError {
    CliError::new(
        Kind::Unreachable,
        format!("cannot connect to {}: {cause}", http.socket().display()),
    )
    .with_hint(
        "is the daemon running and do you have permission for the socket? \
         Change the path with --socket / WEGLARKA_SOCKET; diagnosis without the daemon: `weglarka doctor --preflight`",
    )
}

/// Substitutes `{param}` in an endpoint path. Values must already be validated
/// (`InstanceName`, secret name) — there is no percent-encoding here.
pub fn expand_path(endpoint: Endpoint, params: &[(&str, &str)]) -> String {
    let mut path = endpoint.path.to_owned();
    for (key, value) in params {
        path = path.replace(&format!("{{{key}}}"), value);
    }
    path
}

/// Characters a query value keeps as they are: the RFC 3986 unreserved set. Everything else is
/// percent-encoded, so a value can never add a parameter or end the query.
const QUERY_VALUE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// One admin API request: the endpoint's method, the expanded path and the query string. Every
/// call — buffered, streamed, uploaded or downloaded — and every `--dry-run` is built from one, so
/// the request a dry run prints cannot drift from the one actually sent.
#[derive(Debug, Clone)]
pub(crate) struct ApiRequest {
    method: Method,
    path: String,
    /// Without the leading `?`; empty = no query.
    query: String,
}

impl ApiRequest {
    pub(crate) fn new(endpoint: Endpoint, params: &[(&str, &str)]) -> Self {
        Self {
            method: endpoint.method,
            path: expand_path(endpoint, params),
            query: String::new(),
        }
    }

    /// Adds `key=value`, the value percent-encoded.
    pub(crate) fn query(mut self, key: &str, value: &str) -> Self {
        if !self.query.is_empty() {
            self.query.push('&');
        }
        self.query.push_str(key);
        self.query.push('=');
        self.query
            .extend(utf8_percent_encode(value, QUERY_VALUE).map(|part| part.to_owned()));
        self
    }

    /// Adds `key=true` when `on`; an unset flag is not sent at all.
    pub(crate) fn flag(self, key: &str, on: bool) -> Self {
        if on { self.query(key, "true") } else { self }
    }

    /// Adds a query string the API contract builds itself (`LogsQuery::to_query_string`,
    /// `AccessQuery::to_query_string`); an empty one adds nothing.
    pub(crate) fn query_string(mut self, query: &str) -> Self {
        if !query.is_empty() {
            if !self.query.is_empty() {
                self.query.push('&');
            }
            self.query.push_str(query);
        }
        self
    }

    pub(crate) fn method(&self) -> &'static str {
        match self.method {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
        }
    }

    /// The request target: the path plus `?query` when there is one (no dangling `?`).
    pub(crate) fn target(&self) -> String {
        if self.query.is_empty() {
            self.path.clone()
        } else {
            format!("{}?{}", self.path, self.query)
        }
    }

    /// A `hyper` request for this method and target, `content_type` set when given.
    pub(crate) fn build<B>(
        &self,
        content_type: Option<&'static str>,
        body: B,
    ) -> Result<Request<B>, CliError> {
        let mut req = Request::builder().method(self.method()).uri(self.target());
        if let Some(content_type) = content_type {
            req = req.header(CONTENT_TYPE, content_type);
        }
        req.body(body)
            .map_err(|e| CliError::internal(format!("cannot build request: {e}")))
    }
}

/// The JSON encoding of a request body.
pub(crate) fn json_body(body: &(impl Serialize + ?Sized)) -> Result<Bytes, CliError> {
    serde_json::to_vec(body)
        .map(Bytes::from)
        .map_err(|e| CliError::internal(format!("cannot encode request: {e}")))
}

impl ApiClient {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            backend: Backend::Unix(
                UnixClient::new(socket).with_host(HeaderValue::from_static("weglarka")),
            ),
            busy_wait: BUSY_WAIT,
        }
    }

    /// A client of a remote host, through its panel (`weglarka login` first).
    pub fn remote(host: &str) -> Result<Self, CliError> {
        Ok(Self {
            backend: Backend::Remote(Box::new(Remote::new(host)?)),
            busy_wait: BUSY_WAIT,
        })
    }

    /// How long `busy` answers are retried (default `BUSY_WAIT`; zero = no retry).
    #[cfg(test)]
    pub fn with_busy_wait(mut self, wait: Duration) -> Self {
        self.busy_wait = wait;
        self
    }

    /// Call with a JSON response body.
    pub async fn call<Res: DeserializeOwned>(
        &self,
        endpoint: Endpoint,
        params: &[(&str, &str)],
        body: Option<&(impl Serialize + ?Sized)>,
    ) -> Result<Res, CliError> {
        self.request(&ApiRequest::new(endpoint, params), body).await
    }

    /// Call without a response body (204).
    pub async fn call_empty(
        &self,
        endpoint: Endpoint,
        params: &[(&str, &str)],
    ) -> Result<(), CliError> {
        self.request_empty(&ApiRequest::new(endpoint, params), None::<&()>)
            .await
    }

    /// Call with a JSON request body and no response body (204).
    pub async fn call_empty_json(
        &self,
        endpoint: Endpoint,
        params: &[(&str, &str)],
        body: &(impl Serialize + ?Sized),
    ) -> Result<(), CliError> {
        self.request_empty(&ApiRequest::new(endpoint, params), Some(body))
            .await
    }

    /// Sends `req` (with a query, when it has one) and parses the JSON response body.
    pub(crate) async fn request<Res: DeserializeOwned>(
        &self,
        req: &ApiRequest,
        body: Option<&(impl Serialize + ?Sized)>,
    ) -> Result<Res, CliError> {
        let bytes = self.send(req, body).await?;
        serde_json::from_slice(&bytes).map_err(|e| {
            CliError::internal(format!("unexpected response from daemon: {e}"))
                .with_hint("CLI and daemon versions may differ — check `weglarka status`")
        })
    }

    /// Sends `req` and expects no response body (204).
    pub(crate) async fn request_empty(
        &self,
        req: &ApiRequest,
        body: Option<&(impl Serialize + ?Sized)>,
    ) -> Result<(), CliError> {
        self.send(req, body).await.map(drop)
    }

    async fn send(
        &self,
        req: &ApiRequest,
        body: Option<&(impl Serialize + ?Sized)>,
    ) -> Result<Vec<u8>, CliError> {
        let payload = match body {
            Some(b) => json_body(b)?,
            None => Bytes::new(),
        };
        let content_type = body.is_some().then_some("application/json");
        retry_while_busy(self.busy_wait, || {
            self.send_once(req, content_type, payload.clone())
        })
        .await
    }

    async fn send_once(
        &self,
        req: &ApiRequest,
        content_type: Option<&'static str>,
        payload: Bytes,
    ) -> Result<Vec<u8>, CliError> {
        let req = req.build(content_type, Full::new(payload))?;
        let resp = self
            .backend
            .buffered(req, Some(REQUEST_TIMEOUT), "request to daemon failed")
            .await?;

        if resp.status.is_success() {
            Ok(resp.body.to_vec())
        } else {
            Err(error_from_response(resp.status, &resp.body))
        }
    }

    /// Streams `body` as the request body (`application/x-tar`) and expects an empty success
    /// response. No overall timeout: a volume can be large; Ctrl-C aborts.
    pub(crate) async fn upload(
        &self,
        req: &ApiRequest,
        body: impl Stream<Item = std::io::Result<Bytes>> + Send + 'static,
    ) -> Result<(), CliError> {
        self.upload_bytes(req, body).await.map(drop)
    }

    /// [`Self::upload`] for an endpoint that answers with JSON (`weglarka push`): the deploy that
    /// follows the upload is part of the same request, so there is no overall timeout here either.
    pub(crate) async fn upload_json<T: DeserializeOwned>(
        &self,
        req: &ApiRequest,
        body: impl Stream<Item = std::io::Result<Bytes>> + Send + 'static,
    ) -> Result<T, CliError> {
        let bytes = self.upload_bytes(req, body).await?;
        serde_json::from_slice(&bytes)
            .map_err(|e| CliError::internal(format!("unexpected response from the daemon: {e}")))
    }

    async fn upload_bytes(
        &self,
        req: &ApiRequest,
        body: impl Stream<Item = std::io::Result<Bytes>> + Send + 'static,
    ) -> Result<Bytes, CliError> {
        let body = StreamBody::new(body.map(|chunk| chunk.map(Frame::data)));
        let req = req.build(Some("application/x-tar"), body)?;
        let resp = self
            .backend
            .buffered(req, None, "upload to daemon failed")
            .await?;
        if resp.status.is_success() {
            Ok(resp.body)
        } else {
            Err(error_from_response(resp.status, &resp.body))
        }
    }

    /// Streams a successful response body into `sink`; returns the number of bytes written.
    pub(crate) async fn download(
        &self,
        req: &ApiRequest,
        sink: &mut (impl AsyncWrite + Unpin),
    ) -> Result<u64, CliError> {
        let mut resp = self.open(req.build(None, Full::new(Bytes::new()))?).await?;
        if !resp.status.is_success() {
            let status = resp.status;
            return Err(error_from_response(status, &self.read_rest(resp).await?));
        }
        let io = |e: &dyn std::fmt::Display| CliError::internal(format!("download failed: {e}"));
        let mut written = 0u64;
        while let Some(chunk) = resp.chunk().await {
            let data = chunk.map_err(|e| io(&e))?;
            sink.write_all(&data).await.map_err(|e| io(&e))?;
            written += data.len() as u64;
        }
        sink.flush().await.map_err(|e| io(&e))?;
        Ok(written)
    }

    /// `POST /v1/apps/{name}/run`: opens the response stream of a run. No overall timeout (a run can
    /// take hours) and no busy retry (the request has side effects once the stream starts); an
    /// error before the stream is an ordinary API error. Dropping the returned stream closes the
    /// connection, which makes the daemon kill the run.
    pub async fn open_run(&self, name: &str, request: &RunRequest) -> Result<RunStream, CliError> {
        let req = ApiRequest::new(endpoints::APPS_RUN, &[("name", name)])
            .build(Some("application/json"), Full::new(json_body(request)?))?;
        let response = self
            .open_stream(req, RUN_STREAM_CONTENT_TYPE, "run")
            .await?;
        Ok(FrameStream::new(response, "run"))
    }

    /// `GET /v1/apps/{name}/logs`: opens the response stream of an app's logs. No overall timeout
    /// (a followed log is open for as long as the token lives); an error before the stream
    /// (unknown app, no container) is an ordinary API error.
    pub async fn open_logs(&self, name: &str, query: &LogsQuery) -> Result<LogStream, CliError> {
        let req = ApiRequest::new(endpoints::APPS_LOGS, &[("name", name)])
            .query_string(&query.to_query_string())
            .build(None, Full::new(Bytes::new()))?;
        let response = self
            .open_stream(req, LOGS_STREAM_CONTENT_TYPE, "logs")
            .await?;
        Ok(FrameStream::new(response, "logs"))
    }

    /// `GET /v1/apps/{name}/access`: opens the response stream of an app's access log. Like
    /// [`Self::open_logs`]: no overall timeout, and an error before the stream is an ordinary API error.
    pub async fn open_access(
        &self,
        name: &str,
        query: &AccessQuery,
    ) -> Result<AccessStream, CliError> {
        let req = ApiRequest::new(endpoints::APPS_ACCESS, &[("name", name)])
            .query_string(&query.to_query_string())
            .build(None, Full::new(Bytes::new()))?;
        let response = self
            .open_stream(req, ACCESS_STREAM_CONTENT_TYPE, "access")
            .await?;
        Ok(FrameStream::new(response, "access"))
    }

    /// Sends `req` and returns the response head with the body still unread.
    pub(crate) async fn open(
        &self,
        req: Request<Full<Bytes>>,
    ) -> Result<StreamingResponse<Full<Bytes>>, CliError> {
        self.backend.open(req, "request to daemon failed").await
    }

    /// Reads the rest of a response body (an error body, in practice).
    async fn read_rest(&self, resp: StreamingResponse<Full<Bytes>>) -> Result<Bytes, CliError> {
        resp.collect()
            .await
            .map_err(|e| CliError::internal(format!("request to daemon failed: {e}")))
    }

    /// [`Self::open`] for a streaming endpoint: a non-success status is an ordinary API error, and a
    /// success that is not `content_type` means CLI and daemon disagree about the endpoint.
    pub(crate) async fn open_stream(
        &self,
        req: Request<Full<Bytes>>,
        content_type: &str,
        kind: &str,
    ) -> Result<StreamingResponse<Full<Bytes>>, CliError> {
        let resp = self.open(req).await?;
        if !resp.status.is_success() {
            let status = resp.status;
            return Err(error_from_response(status, &self.read_rest(resp).await?));
        }
        if resp
            .headers
            .get(CONTENT_TYPE)
            .is_none_or(|v| v != content_type)
        {
            return Err(CliError::internal(format!(
                "the daemon did not answer with a {kind} stream"
            ))
            .with_hint("CLI and daemon versions may differ"));
        }
        Ok(resp)
    }
}

pub(crate) fn error_from_response(status: StatusCode, body: &[u8]) -> CliError {
    match serde_json::from_slice::<ApiError>(body) {
        Ok(e) => CliError::from_api(e.code, e.message),
        Err(_) => CliError::internal(format!(
            "daemon returned HTTP {status} with an unrecognised body"
        ))
        .with_hint("CLI and daemon versions may differ"),
    }
}

/// Repeats `attempt` while the daemon answers `busy`, with a growing pause, for at most
/// `wait`; then returns the last error. Other errors and success return immediately.
/// Only for requests whose body can be re-sent (not for streamed uploads).
async fn retry_while_busy<F, Fut>(wait: Duration, mut attempt: F) -> Result<Vec<u8>, CliError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>, CliError>>,
{
    let deadline = tokio::time::Instant::now() + wait;
    let mut pause = BUSY_BACKOFF_START;
    let mut announced = false;
    loop {
        match attempt().await {
            Err(e) if e.is_busy() && tokio::time::Instant::now() + pause < deadline => {
                if !announced {
                    eprintln!(
                        "the daemon is busy (a deploy is in progress, or the host is limiting requests), waiting…"
                    );
                    announced = true;
                }
                tokio::time::sleep(pause).await;
                pause = (pause * 2).min(BUSY_BACKOFF_MAX);
            }
            other => return other,
        }
    }
}
