//! Admin API client: HTTP/1.1 over a unix socket (hyper, one connection per request).
//! Paths and methods come from `weglarka_api::endpoints`, so they can't drift from the contract.

use std::path::PathBuf;
use std::time::Duration;

use futures_util::{Stream, StreamExt};
use http_body_util::{Full, StreamBody};
use hyper::body::{Bytes, Frame};
use hyper::header::{CONTENT_TYPE, HeaderValue};
use hyper::{Request, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use weglarka_api::{
    ApiError, Endpoint, Method, RUN_STREAM_CONTENT_TYPE, RunFrame, RunFrameDecoder, RunRequest,
    endpoints,
};
use weglarka_unix_http::{StreamingResponse, UnixClient};

use crate::error::{CliError, Kind};

/// Deploy waits for the image pull and the health gate, so the overall timeout is long.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(600);
/// How long a request answered with `busy` (another mutation holds the engine, e.g. a deploy behind
/// the health gate) is retried before the error is returned.
const BUSY_WAIT: Duration = Duration::from_secs(180);
/// Pause between retries of a `busy` request (grows up to `BUSY_BACKOFF_MAX`).
const BUSY_BACKOFF_START: Duration = Duration::from_millis(500);
const BUSY_BACKOFF_MAX: Duration = Duration::from_secs(5);

/// The frames of a run response, as they arrive.
pub struct RunStream {
    /// Keeps the connection's request side open for as long as the response is read.
    response: StreamingResponse<Full<Bytes>>,
    decoder: RunFrameDecoder,
    ready: std::collections::VecDeque<RunFrame>,
}

impl RunStream {
    /// The next frame, or `None` when the daemon closed the stream.
    pub async fn next(&mut self) -> Result<Option<RunFrame>, CliError> {
        loop {
            if let Some(frame) = self.ready.pop_front() {
                return Ok(Some(frame));
            }
            let Some(frame) = self.response.frame().await else {
                return if self.decoder.is_clean() {
                    Ok(None)
                } else {
                    Err(CliError::internal("run stream ended inside a frame"))
                };
            };
            let frame =
                frame.map_err(|e| CliError::internal(format!("run stream interrupted: {e}")))?;
            if let Some(data) = frame.data_ref() {
                self.ready.extend(
                    self.decoder
                        .push(data)
                        .map_err(|e| CliError::internal(e.to_string()))?,
                );
            }
        }
    }
}

pub struct ApiClient {
    http: UnixClient,
    busy_wait: Duration,
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

/// The request target for `endpoint`: the expanded path plus `?query` when the query is non-empty
/// (no dangling `?`). The dry run prints the same string, so the shown request cannot drift from
/// the one actually sent.
pub(crate) fn request_path(endpoint: Endpoint, params: &[(&str, &str)], query: &str) -> String {
    append_query(expand_path(endpoint, params), query)
}

/// Appends `?query` to a path unless the query is empty.
pub(crate) fn append_query(mut path: String, query: &str) -> String {
    if !query.is_empty() {
        path.push('?');
        path.push_str(query);
    }
    path
}

pub(crate) fn method_str(m: Method) -> &'static str {
    match m {
        Method::Get => "GET",
        Method::Post => "POST",
        Method::Put => "PUT",
        Method::Delete => "DELETE",
    }
}

impl ApiClient {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            http: UnixClient::new(socket).with_host(HeaderValue::from_static("weglarka")),
            busy_wait: BUSY_WAIT,
        }
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
        let bytes = self.send(endpoint, params, body).await?;
        serde_json::from_slice(&bytes).map_err(|e| {
            CliError::internal(format!("unexpected response from daemon: {e}"))
                .with_hint("CLI and daemon versions may differ — check `weglarka status`")
        })
    }

    /// Call without a response body (204).
    pub async fn call_empty(
        &self,
        endpoint: Endpoint,
        params: &[(&str, &str)],
    ) -> Result<(), CliError> {
        self.send(endpoint, params, None::<&()>).await.map(drop)
    }

    /// Call with a JSON request body and no response body (204).
    pub async fn call_empty_json(
        &self,
        endpoint: Endpoint,
        params: &[(&str, &str)],
        body: &(impl Serialize + ?Sized),
    ) -> Result<(), CliError> {
        self.send(endpoint, params, Some(body)).await.map(drop)
    }

    async fn send(
        &self,
        endpoint: Endpoint,
        params: &[(&str, &str)],
        body: Option<&(impl Serialize + ?Sized)>,
    ) -> Result<Vec<u8>, CliError> {
        let payload = match body {
            Some(b) => Bytes::from(
                serde_json::to_vec(b)
                    .map_err(|e| CliError::internal(format!("cannot encode request: {e}")))?,
            ),
            None => Bytes::new(),
        };
        let uri = request_path(endpoint, params, "");
        let json = body.is_some();
        retry_while_busy(self.busy_wait, || {
            self.send_once(endpoint.method, &uri, json, payload.clone())
        })
        .await
    }

    async fn send_once(
        &self,
        method: Method,
        uri: &str,
        json: bool,
        payload: Bytes,
    ) -> Result<Vec<u8>, CliError> {
        let mut req = Request::builder().method(method_str(method)).uri(uri);
        if json {
            req = req.header(CONTENT_TYPE, "application/json");
        }
        let req = req
            .body(Full::new(payload))
            .map_err(|e| CliError::internal(format!("cannot build request: {e}")))?;

        let resp = self
            .http
            .buffered(req, Some(REQUEST_TIMEOUT))
            .await
            .map_err(|e| match e {
                weglarka_unix_http::Error::Timeout => {
                    CliError::internal("request to daemon timed out")
                }
                e => self.map_error(e, "request to daemon failed"),
            })?;

        if resp.status.is_success() {
            Ok(resp.body.to_vec())
        } else {
            Err(error_from_response(resp.status, &resp.body))
        }
    }

    /// Connection failures become `Unreachable` (with the socket hint); everything else is an
    /// internal error prefixed with `what`.
    fn map_error(&self, e: weglarka_unix_http::Error, what: &str) -> CliError {
        if e.is_connect() {
            self.unreachable(&e.to_string())
        } else {
            CliError::internal(format!("{what}: {e}"))
        }
    }

    /// Call without a response body (204), with an optional query string (`a=b&c`) appended to the
    /// path; an empty query leaves the path untouched.
    pub async fn call_empty_query(
        &self,
        endpoint: Endpoint,
        params: &[(&str, &str)],
        query: &str,
    ) -> Result<(), CliError> {
        let path = request_path(endpoint, params, query);
        retry_while_busy(self.busy_wait, || {
            self.send_once(endpoint.method, &path, false, Bytes::new())
        })
        .await
        .map(drop)
    }

    /// Streams `body` as the request body (`application/x-tar`) and expects an empty success
    /// response. No overall timeout: a volume can be large; Ctrl-C aborts.
    pub async fn upload(
        &self,
        endpoint: Endpoint,
        params: &[(&str, &str)],
        query: &str,
        body: impl Stream<Item = std::io::Result<Bytes>> + Send + 'static,
    ) -> Result<(), CliError> {
        self.upload_bytes(endpoint, params, query, body)
            .await
            .map(drop)
    }

    /// [`Self::upload`] for an endpoint that answers with JSON (`weglarka push`): the deploy that
    /// follows the upload is part of the same request, so there is no overall timeout here either.
    pub async fn upload_json<T: DeserializeOwned>(
        &self,
        endpoint: Endpoint,
        params: &[(&str, &str)],
        body: impl Stream<Item = std::io::Result<Bytes>> + Send + 'static,
    ) -> Result<T, CliError> {
        let bytes = self.upload_bytes(endpoint, params, "", body).await?;
        serde_json::from_slice(&bytes)
            .map_err(|e| CliError::internal(format!("unexpected response from the daemon: {e}")))
    }

    async fn upload_bytes(
        &self,
        endpoint: Endpoint,
        params: &[(&str, &str)],
        query: &str,
        body: impl Stream<Item = std::io::Result<Bytes>> + Send + 'static,
    ) -> Result<Bytes, CliError> {
        let path = request_path(endpoint, params, query);
        let body = StreamBody::new(body.map(|chunk| chunk.map(Frame::data)));
        let req = Request::builder()
            .method(method_str(endpoint.method))
            .uri(path)
            .header(CONTENT_TYPE, "application/x-tar")
            .body(body)
            .map_err(|e| CliError::internal(format!("cannot build request: {e}")))?;
        let resp = self
            .http
            .buffered(req, None)
            .await
            .map_err(|e| self.map_error(e, "upload to daemon failed"))?;
        if resp.status.is_success() {
            Ok(resp.body)
        } else {
            Err(error_from_response(resp.status, &resp.body))
        }
    }

    /// Streams a successful response body into `sink`; returns the number of bytes written.
    pub async fn download(
        &self,
        endpoint: Endpoint,
        params: &[(&str, &str)],
        sink: &mut (impl AsyncWrite + Unpin),
    ) -> Result<u64, CliError> {
        let req = Request::builder()
            .method(method_str(endpoint.method))
            .uri(request_path(endpoint, params, ""))
            .body(Full::new(Bytes::new()))
            .map_err(|e| CliError::internal(format!("cannot build request: {e}")))?;
        let mut resp = self.open(req).await?;
        if !resp.status.is_success() {
            let status = resp.status;
            return Err(error_from_response(status, &self.read_rest(resp).await?));
        }
        let io = |e: &dyn std::fmt::Display| CliError::internal(format!("download failed: {e}"));
        let mut written = 0u64;
        while let Some(frame) = resp.frame().await {
            let frame = frame.map_err(|e| io(&e))?;
            if let Some(data) = frame.data_ref() {
                sink.write_all(data).await.map_err(|e| io(&e))?;
                written += data.len() as u64;
            }
        }
        sink.flush().await.map_err(|e| io(&e))?;
        Ok(written)
    }

    /// `POST /v1/apps/{name}/run`: opens the response stream of a run. No overall timeout (a run can
    /// take hours) and no busy retry (the request has side effects once the stream starts); an
    /// error before the stream is an ordinary API error. Dropping the returned stream closes the
    /// connection, which makes the daemon kill the run.
    pub async fn open_run(&self, name: &str, request: &RunRequest) -> Result<RunStream, CliError> {
        let payload = serde_json::to_vec(request)
            .map_err(|e| CliError::internal(format!("cannot encode request: {e}")))?;
        let req = Request::builder()
            .method(method_str(endpoints::APPS_RUN.method))
            .uri(request_path(endpoints::APPS_RUN, &[("name", name)], ""))
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(payload)))
            .map_err(|e| CliError::internal(format!("cannot build request: {e}")))?;
        let response = self
            .open_stream(req, RUN_STREAM_CONTENT_TYPE, "run")
            .await?;
        Ok(RunStream {
            response,
            decoder: RunFrameDecoder::default(),
            ready: std::collections::VecDeque::new(),
        })
    }

    /// Sends `req` and returns the response head with the body still unread.
    pub(crate) async fn open(
        &self,
        req: Request<Full<Bytes>>,
    ) -> Result<StreamingResponse<Full<Bytes>>, CliError> {
        self.http
            .open(req)
            .await
            .map_err(|e| self.map_error(e, "request to daemon failed"))
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

    fn unreachable(&self, cause: &str) -> CliError {
        CliError::new(
            Kind::Unreachable,
            format!("cannot connect to {}: {cause}", self.http.socket().display()),
        )
        .with_hint(
            "is the daemon running and do you have permission for the socket? \
             Change the path with --socket / WEGLARKA_SOCKET; diagnosis without the daemon: `weglarka doctor --preflight`",
        )
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
                    eprintln!("daemon is busy (deploy in progress), waiting…");
                    announced = true;
                }
                tokio::time::sleep(pause).await;
                pause = (pause * 2).min(BUSY_BACKOFF_MAX);
            }
            other => return other,
        }
    }
}
