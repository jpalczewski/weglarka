//! Admin API client: HTTP/1.1 over a unix socket (hyper, one connection per request).
//! Paths and methods come from `weglarka_api::endpoints`, so they can't drift from the contract.

use std::path::PathBuf;
use std::time::Duration;

use futures_util::{Stream, StreamExt};
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Bytes, Frame};
use hyper::header::{CONTENT_TYPE, HOST};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;
use weglarka_api::{ApiError, Endpoint, Method};

use crate::error::{CliError, Kind};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Deploy waits for the image pull and the health gate, so the overall timeout is long.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(600);
/// How long a request answered with `busy` (another mutation holds the engine, e.g. a deploy behind
/// the health gate) is retried before the error is returned.
const BUSY_WAIT: Duration = Duration::from_secs(180);
/// Pause between retries of a `busy` request (grows up to `BUSY_BACKOFF_MAX`).
const BUSY_BACKOFF_START: Duration = Duration::from_millis(500);
const BUSY_BACKOFF_MAX: Duration = Duration::from_secs(5);

pub struct ApiClient {
    socket: PathBuf,
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

fn method_str(m: Method) -> &'static str {
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
            socket: socket.into(),
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
        let mut req = Request::builder()
            .method(method_str(method))
            .uri(uri)
            .header(HOST, "weglarka");
        if json {
            req = req.header(CONTENT_TYPE, "application/json");
        }
        let req = req
            .body(Full::new(payload))
            .map_err(|e| CliError::internal(format!("cannot build request: {e}")))?;

        let mut sender = self.connect().await?;

        let exchange = async {
            let resp = sender.send_request(req).await?;
            let status = resp.status();
            let bytes = resp.into_body().collect().await?.to_bytes();
            Ok::<_, hyper::Error>((status, bytes))
        };
        let (status, bytes) = tokio::time::timeout(REQUEST_TIMEOUT, exchange)
            .await
            .map_err(|_| CliError::internal("request to daemon timed out"))?
            .map_err(|e| CliError::internal(format!("request to daemon failed: {e}")))?;

        if status.is_success() {
            Ok(bytes.to_vec())
        } else {
            Err(error_from_response(status, &bytes))
        }
    }

    /// One HTTP/1.1 connection to the admin socket (the connection task is spawned).
    async fn connect<B>(&self) -> Result<hyper::client::conn::http1::SendRequest<B>, CliError>
    where
        B: hyper::body::Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, UnixStream::connect(&self.socket))
            .await
            .map_err(|_| self.unreachable("connection timed out"))?
            .map_err(|e| self.unreachable(&e.to_string()))?;
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| self.unreachable(&e.to_string()))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(sender)
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
        let path = request_path(endpoint, params, query);
        let body = StreamBody::new(body.map(|chunk| chunk.map(Frame::data)));
        let req = Request::builder()
            .method(method_str(endpoint.method))
            .uri(path)
            .header(HOST, "weglarka")
            .header(CONTENT_TYPE, "application/x-tar")
            .body(body)
            .map_err(|e| CliError::internal(format!("cannot build request: {e}")))?;
        let mut sender = self.connect().await?;
        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| CliError::internal(format!("upload to daemon failed: {e}")))?;
        let status = resp.status();
        let bytes = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| CliError::internal(format!("upload to daemon failed: {e}")))?
            .to_bytes();
        if status.is_success() {
            Ok(())
        } else {
            Err(error_from_response(status, &bytes))
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
            .header(HOST, "weglarka")
            .body(Full::new(Bytes::new()))
            .map_err(|e| CliError::internal(format!("cannot build request: {e}")))?;
        let mut sender = self.connect().await?;
        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| CliError::internal(format!("request to daemon failed: {e}")))?;
        let status = resp.status();
        let mut body = resp.into_body();
        if !status.is_success() {
            let bytes = body
                .collect()
                .await
                .map_err(|e| CliError::internal(format!("request to daemon failed: {e}")))?
                .to_bytes();
            return Err(error_from_response(status, &bytes));
        }
        let io = |e: &dyn std::fmt::Display| CliError::internal(format!("download failed: {e}"));
        let mut written = 0u64;
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|e| io(&e))?;
            if let Some(data) = frame.data_ref() {
                sink.write_all(data).await.map_err(|e| io(&e))?;
                written += data.len() as u64;
            }
        }
        sink.flush().await.map_err(|e| io(&e))?;
        Ok(written)
    }

    fn unreachable(&self, cause: &str) -> CliError {
        CliError::new(
            Kind::Unreachable,
            format!("cannot connect to {}: {cause}", self.socket.display()),
        )
        .with_hint(
            "is the daemon running and do you have permission for the socket? \
             Change the path with --socket / WEGLARKA_SOCKET; diagnosis without the daemon: `weglarka doctor --preflight`",
        )
    }
}

fn error_from_response(status: StatusCode, body: &[u8]) -> CliError {
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
