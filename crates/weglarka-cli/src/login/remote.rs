//! The CLI's connection to a remote host: the panel's `/_weglarka/api` relay over TLS, with the
//! access token of `weglarka login` (docs/decisions/0060).
//!
//! Each request is a fresh connection; the token is read (and refreshed when it is about to
//! expire) right before sending, so a long session never holds a stale one. The panel relays the
//! `Authorization` header unchanged and the daemon decides, so a refusal comes back as an ordinary
//! API error.

use std::time::Duration;

use hyper::Request;
use hyper::body::Body;
use hyper::header::{self, HeaderValue};
use hyper_util::rt::TokioIo;
use weglarka_model::admin_auth::RELAY_PREFIX;
use weglarka_oidc::Url;
use weglarka_unix_http::{Buffered, StreamingResponse, bearer};

use super::credentials::{Store, normalize_host};
use super::transport::{HyperTransport, host_header};
use super::{access_token, now_secs};
use crate::client::map_transport;
use crate::error::{CliError, Kind};

pub struct Remote {
    /// `https://host[:port]`, as stored with the credentials.
    host: String,
    origin: Url,
    transport: HyperTransport,
    store: Store,
}

impl Remote {
    pub fn new(host: &str) -> Result<Self, CliError> {
        Self::with_parts(host, HyperTransport::new(), Store::default_location()?)
    }

    fn with_parts(
        host: &str,
        transport: Result<HyperTransport, rustls::Error>,
        store: Store,
    ) -> Result<Self, CliError> {
        let host = normalize_host(host)?;
        let origin = Url::parse(&host).map_err(|_| CliError::usage("invalid --host"))?;
        Ok(Self {
            host,
            origin,
            transport: transport
                .map_err(|e| CliError::internal(format!("cannot set up TLS: {e}")))?,
            store,
        })
    }

    /// Same contract as `UnixClient::buffered`, over the relay.
    pub async fn buffered<B>(
        &self,
        request: Request<B>,
        timeout: Option<Duration>,
        what: &str,
    ) -> Result<Buffered, CliError>
    where
        B: Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let request = self.prepare(request).await?;
        let io = self.connect().await?;
        weglarka_unix_http::buffered_over(TokioIo::new(io), request, timeout)
            .await
            .map_err(|e| map_transport(e, what, |cause| self.unreachable(&cause)))
    }

    /// Same contract as `UnixClient::open`, over the relay.
    pub async fn open<B>(
        &self,
        request: Request<B>,
        what: &str,
    ) -> Result<StreamingResponse<B>, CliError>
    where
        B: Body + Send + 'static,
        B::Data: Send,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let request = self.prepare(request).await?;
        let io = self.connect().await?;
        weglarka_unix_http::open_over(TokioIo::new(io), request)
            .await
            .map_err(|e| map_transport(e, what, |cause| self.unreachable(&cause)))
    }

    async fn connect(&self) -> Result<super::transport::Stream, CliError> {
        self.transport
            .connect_origin(&self.origin)
            .await
            .map_err(|e| self.unreachable(&e.to_string()))
    }

    /// The request as the relay wants it: under [`RELAY_PREFIX`], with `Host` and the bearer.
    async fn prepare<B>(&self, request: Request<B>) -> Result<Request<B>, CliError> {
        let token = access_token(&self.transport, &self.store, &self.host, now_secs())
            .await?
            .0;
        let (mut parts, body) = request.into_parts();
        let target = parts
            .uri
            .path_and_query()
            .map_or("/", |pq| pq.as_str())
            .to_owned();
        parts.uri = format!("{RELAY_PREFIX}{target}")
            .parse()
            .map_err(|_| CliError::internal("cannot build the request address"))?;
        parts.headers.insert(
            header::HOST,
            host_header(&self.origin).map_err(|_| CliError::internal("invalid host"))?,
        );
        parts.headers.insert(
            header::USER_AGENT,
            HeaderValue::from_static(concat!("weglarka-cli/", env!("CARGO_PKG_VERSION"))),
        );
        parts.headers.insert(
            header::AUTHORIZATION,
            bearer(token.expose()).map_err(|e| CliError::internal(e.to_string()))?,
        );
        Ok(Request::from_parts(parts, body))
    }

    fn unreachable(&self, cause: &str) -> CliError {
        CliError::new(
            Kind::Unreachable,
            format!("cannot reach {}: {cause}", self.host),
        )
        .with_hint("check --host and the network; the host's panel must be up")
    }
}

#[cfg(test)]
mod tests;
