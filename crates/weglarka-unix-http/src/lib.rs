//! HTTP/1.1 over a unix socket: one connection per request, no pooling.
//!
//! Three ways to send a request, all through [`UnixClient`]:
//! - [`UnixClient::buffered`]: the whole response is read into memory (status, headers, body);
//! - [`UnixClient::open`]: the response head is returned and the body is read frame by frame
//!   ([`StreamingResponse`]); dropping it closes the connection;
//! - [`UnixClient::connect`]: the raw hyper sender, for callers with special needs.
//!
//! Requests are plain [`Request`]s, so any body type works (buffered or streamed). The client
//! fills in `Host` when the request has none; `Authorization: Bearer …` goes through [`bearer`].
//! Timeouts are explicit: connecting always has one, the exchange only when the caller passes it.

use std::path::{Path, PathBuf};
use std::time::Duration;

use http_body_util::BodyExt;
use hyper::body::Body;
pub use hyper::body::{Bytes, Frame, Incoming};
use hyper::client::conn::http1::SendRequest;
pub use hyper::header::{self, HeaderMap, HeaderValue};
pub use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;

#[cfg(feature = "testing")]
pub mod testing;

/// How long connecting to the socket may take.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("connection timed out")]
    ConnectTimeout,
    #[error("{0}")]
    Connect(std::io::Error),
    #[error("{0}")]
    Handshake(hyper::Error),
    #[error("{0}")]
    Request(hyper::Error),
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
    /// The next body frame, or `None` at the end of the body.
    pub async fn frame(&mut self) -> Option<Result<Frame<Bytes>, Error>> {
        Some(self.body.frame().await?.map_err(Error::Request))
    }

    /// Reads the rest of the body into memory.
    pub async fn collect(self) -> Result<Bytes, Error> {
        Ok(self
            .body
            .collect()
            .await
            .map_err(Error::Request)?
            .to_bytes())
    }
}

#[derive(Debug, Clone)]
pub struct UnixClient {
    socket: PathBuf,
    host: HeaderValue,
    connect_timeout: Duration,
}

impl UnixClient {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            host: HeaderValue::from_static("localhost"),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
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

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// One HTTP/1.1 connection to the socket (the connection task is spawned).
    pub async fn connect<B>(&self) -> Result<SendRequest<B>, Error>
    where
        B: Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let stream = tokio::time::timeout(self.connect_timeout, UnixStream::connect(&self.socket))
            .await
            .map_err(|_| Error::ConnectTimeout)?
            .map_err(Error::Connect)?;
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(Error::Handshake)?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(sender)
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
        let mut sender = self.connect().await?;
        let exchange = async {
            let resp = sender.send_request(request).await?;
            let (parts, body) = resp.into_parts();
            let body = body.collect().await?.to_bytes();
            Ok::<_, hyper::Error>(Buffered {
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
        .map_err(Error::Request)
    }

    /// Sends `request` and returns as soon as the response head arrives; no timeout.
    pub async fn open<B>(&self, request: Request<B>) -> Result<StreamingResponse<B>, Error>
    where
        B: Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let request = self.with_host_header(request);
        let mut sender = self.connect().await?;
        let resp = sender.send_request(request).await.map_err(Error::Request)?;
        let (parts, body) = resp.into_parts();
        Ok(StreamingResponse {
            status: parts.status,
            headers: parts.headers,
            body,
            _sender: sender,
        })
    }

    fn with_host_header<B>(&self, mut request: Request<B>) -> Request<B> {
        request
            .headers_mut()
            .entry(header::HOST)
            .or_insert_with(|| self.host.clone());
        request
    }
}
