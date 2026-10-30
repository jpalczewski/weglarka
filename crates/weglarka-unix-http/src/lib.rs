//! HTTP/1.1 over a unix socket: one connection per request, no pooling.
//!
//! Two ways to send a request, both through [`UnixClient`]:
//! - [`UnixClient::buffered`]: the whole response is read into memory (status, headers, body);
//! - [`UnixClient::open`]: the response head is returned and the body is read chunk by chunk
//!   ([`StreamingResponse`]); dropping it closes the connection.
//!
//! Requests are plain [`Request`]s, so any body type works (buffered or streamed). The client
//! fills in `Host` when the request has none; `Authorization: Bearer …` goes through [`bearer`].
//! Timeouts are explicit: connecting always has one; the response head only with
//! [`UnixClient::with_head_timeout`]; the whole buffered exchange only when the caller passes one.
//! Streaming bodies are never capped.
//!
//! [`buffered_over`] and [`open_over`] do the same over a stream the caller connected itself (the
//! CLI's TLS connection to a remote host); they add no `Host` header and no head timeout.

use std::path::{Path, PathBuf};
use std::time::Duration;

pub use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body, Incoming};
use hyper::client::conn::http1::SendRequest;
pub use hyper::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;

#[cfg(feature = "testing")]
pub mod testing;

/// How long connecting to the socket may take.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The transport's own failure, with hyper's error kept out of the public API.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Cause(hyper::Error);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("connection timed out")]
    ConnectTimeout,
    #[error("{0}")]
    Connect(std::io::Error),
    #[error("{0}")]
    Handshake(Cause),
    /// Sending the request or reading the response failed.
    #[error("{0}")]
    Request(Cause),
    /// The response head (or, with [`UnixClient::buffered`], the whole exchange) took too long.
    #[error("request timed out")]
    Timeout,
    #[error("invalid request: {0}")]
    InvalidRequest(String),
}

impl Error {
    /// The connection could not be established (as opposed to failing mid-exchange).
    pub fn is_connect(&self) -> bool {
        matches!(
            self,
            Self::ConnectTimeout | Self::Connect(_) | Self::Handshake(_)
        )
    }
}

/// `Authorization: Bearer <token>`, marked sensitive so it stays out of `Debug` output.
pub fn bearer(token: &str) -> Result<HeaderValue, Error> {
    let mut value = HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| Error::InvalidRequest("the token is not a valid header value".into()))?;
    value.set_sensitive(true);
    Ok(value)
}

/// A response read to the end.
#[derive(Debug)]
pub struct Buffered {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

/// A response whose body is still being read. Keeps the connection's request side open for as long
/// as it lives; dropping it closes the connection.
pub struct StreamingResponse<B> {
    pub status: StatusCode,
    pub headers: HeaderMap,
    body: Incoming,
    _sender: SendRequest<B>,
}

impl<B> StreamingResponse<B> {
    /// The next chunk of body data, or `None` at the end of the body (trailers are skipped).
    /// No timeout: a stream may be quiet for as long as the caller is willing to wait.
    pub async fn chunk(&mut self) -> Option<Result<Bytes, Error>> {
        loop {
            match self.body.frame().await? {
                Err(e) => return Some(Err(Error::Request(Cause(e)))),
                Ok(frame) => {
                    if let Ok(data) = frame.into_data() {
                        return Some(Ok(data));
                    }
                }
            }
        }
    }

    /// Reads the rest of the body into memory.
    pub async fn collect(self) -> Result<Bytes, Error> {
        Ok(self
            .body
            .collect()
            .await
            .map_err(|e| Error::Request(Cause(e)))?
            .to_bytes())
    }
}

#[derive(Debug, Clone)]
pub struct UnixClient {
    socket: PathBuf,
    host: HeaderValue,
    connect_timeout: Duration,
    head_timeout: Option<Duration>,
}

impl UnixClient {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            host: HeaderValue::from_static("localhost"),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            head_timeout: None,
        }
    }

    /// The `Host` header added to requests that carry none.
    pub fn with_host(mut self, host: HeaderValue) -> Self {
        self.host = host;
        self
    }

    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// How long the server may take to answer with the response head (`None` = no limit, the
    /// default). It never caps the body, so streams and large downloads are unaffected; a caller
    /// that renders pages from the answer should set it, a caller that waits for a deploy should not.
    pub fn with_head_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.head_timeout = timeout;
        self
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// One HTTP/1.1 connection to the socket (the connection task is spawned).
    async fn connect<B>(&self) -> Result<SendRequest<B>, Error>
    where
        B: Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let stream = tokio::time::timeout(self.connect_timeout, UnixStream::connect(&self.socket))
            .await
            .map_err(|_| Error::ConnectTimeout)?
            .map_err(Error::Connect)?;
        handshake(TokioIo::new(stream)).await
    }

    /// Sends `request` and reads the whole response. `timeout` bounds the exchange after connecting
    /// (`None` = unbounded, e.g. a large upload).
    pub async fn buffered<B>(
        &self,
        request: Request<B>,
        timeout: Option<Duration>,
    ) -> Result<Buffered, Error>
    where
        B: Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let request = self.with_host_header(request);
        let sender = self.connect().await?;
        read_buffered(sender, request, timeout, self.head_timeout).await
    }

    /// Sends `request` and returns as soon as the response head arrives; no timeout.
    pub async fn open<B>(&self, request: Request<B>) -> Result<StreamingResponse<B>, Error>
    where
        B: Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let request = self.with_host_header(request);
        let sender = self.connect().await?;
        read_head(sender, request, self.head_timeout).await
    }

    fn with_host_header<B>(&self, mut request: Request<B>) -> Request<B> {
        request
            .headers_mut()
            .entry(header::HOST)
            .or_insert_with(|| self.host.clone());
        request
    }
}

/// One HTTP/1.1 client connection over `io` (the connection task is spawned).
async fn handshake<I, B>(io: I) -> Result<SendRequest<B>, Error>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| Error::Handshake(Cause(e)))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(sender)
}

/// Sends the request and waits for the response head, within `head_timeout` if one is set.
async fn send_head<B>(
    sender: &mut SendRequest<B>,
    request: Request<B>,
    head_timeout: Option<Duration>,
) -> Result<hyper::Response<Incoming>, Error>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let sent = sender.send_request(request);
    match head_timeout {
        Some(limit) => tokio::time::timeout(limit, sent)
            .await
            .map_err(|_| Error::Timeout)?,
        None => sent.await,
    }
    .map_err(|e| Error::Request(Cause(e)))
}

async fn read_buffered<B>(
    mut sender: SendRequest<B>,
    request: Request<B>,
    timeout: Option<Duration>,
    head_timeout: Option<Duration>,
) -> Result<Buffered, Error>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let exchange = async {
        let resp = send_head(&mut sender, request, head_timeout).await?;
        let (parts, body) = resp.into_parts();
        let body = body
            .collect()
            .await
            .map_err(|e| Error::Request(Cause(e)))?
            .to_bytes();
        Ok(Buffered {
            status: parts.status,
            headers: parts.headers,
            body,
        })
    };
    match timeout {
        Some(limit) => tokio::time::timeout(limit, exchange)
            .await
            .map_err(|_| Error::Timeout)?,
        None => exchange.await,
    }
}

async fn read_head<B>(
    mut sender: SendRequest<B>,
    request: Request<B>,
    head_timeout: Option<Duration>,
) -> Result<StreamingResponse<B>, Error>
where
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let resp = send_head(&mut sender, request, head_timeout).await?;
    let (parts, body) = resp.into_parts();
    Ok(StreamingResponse {
        status: parts.status,
        headers: parts.headers,
        body,
        _sender: sender,
    })
}

/// [`UnixClient::buffered`] over a stream the caller connected. `Host` must be set by the caller.
pub async fn buffered_over<I, B>(
    io: I,
    request: Request<B>,
    timeout: Option<Duration>,
) -> Result<Buffered, Error>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    read_buffered(handshake(io).await?, request, timeout, None).await
}

/// [`UnixClient::open`] over a stream the caller connected. `Host` must be set by the caller.
pub async fn open_over<I, B>(io: I, request: Request<B>) -> Result<StreamingResponse<B>, Error>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    read_head(handshake(io).await?, request, None).await
}
