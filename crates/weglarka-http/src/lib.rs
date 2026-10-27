//! The one place that builds outbound HTTP clients for Węglarka.
//!
//! Every network-facing crate (notifications, and later registry, DNS, ACME) gets its
//! `reqwest::Client` from here, so TLS and redirect policy are decided once:
//!
//! - **TLS**: `rustls` with the `ring` provider passed explicitly (the process-wide default provider
//!   is never touched) and the bundled `webpki-roots` store, because the daemon image is `scratch` and
//!   has no CA store. TLS 1.2 and 1.3, ALPN pinned to `http/1.1`. No C crypto, no OpenSSL.
//! - **HTTP/1.1 only**: the `http2` feature of `reqwest` is off.
//! - **Per-purpose** connect/total timeouts and redirect policy ([`Purpose`]).
//!
//! The crate depends on nothing from Węglarka on purpose: only crates that really talk to the network
//! depend on it, so `reqwest` and its dependency tree stay out of the CLI, the API and the ingress.

use std::sync::Arc;
use std::time::Duration;

use reqwest::redirect::Policy;
use rustls::crypto::ring::default_provider;
use rustls::{ClientConfig, RootCertStore};

pub use reqwest;

const USER_AGENT: &str = concat!("weglarka/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("TLS configuration error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("cannot build the HTTP client: {0}")]
    Build(#[from] reqwest::Error),
}

/// What a client is for. Each purpose fixes its timeouts and redirect policy; a new consumer adds
/// a variant here rather than tuning a builder at the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// Notification delivery (ntfy): a short exchange that may carry a bearer token, so redirects are
    /// never followed. Connections are not pooled (one request per connection, as before).
    Notify,
}

impl Purpose {
    fn connect_timeout(self) -> Duration {
        match self {
            Self::Notify => Duration::from_secs(10),
        }
    }

    fn timeout(self) -> Duration {
        match self {
            Self::Notify => Duration::from_secs(10),
        }
    }

    fn redirects(self) -> Policy {
        match self {
            Self::Notify => Policy::none(),
        }
    }

    fn pooled(self) -> bool {
        match self {
            Self::Notify => false,
        }
    }
}

/// Client trusting the bundled Mozilla root store (`webpki-roots`).
pub fn client(purpose: Purpose) -> Result<reqwest::Client, HttpError> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    client_with_roots(purpose, roots)
}

/// Client with a custom root store: tests with a self-signed certificate, or a private PKI.
pub fn client_with_roots(
    purpose: Purpose,
    roots: RootCertStore,
) -> Result<reqwest::Client, HttpError> {
    Ok(builder_with_roots(purpose, roots)?.build()?)
}

/// Like [`client_with_roots`] but returns the builder, so a test can add e.g. a `resolve` override.
pub fn builder_with_roots(
    purpose: Purpose,
    roots: RootCertStore,
) -> Result<reqwest::ClientBuilder, HttpError> {
    let mut builder = reqwest::Client::builder()
        .use_preconfigured_tls(tls_config(roots)?)
        .user_agent(USER_AGENT)
        .connect_timeout(purpose.connect_timeout())
        .timeout(purpose.timeout())
        .redirect(purpose.redirects());
    if !purpose.pooled() {
        builder = builder.pool_max_idle_per_host(0);
    }
    Ok(builder)
}

fn tls_config(roots: RootCertStore) -> Result<ClientConfig, rustls::Error> {
    // Explicit provider: never touch the process-wide default (another component may install one).
    let mut config = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    // HTTP/1.1 only: without this rustls would not advertise a protocol and some servers pick h2.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// Renders an error with its `source` chain (`reqwest` hides the TLS/IO cause behind a generic head).
pub fn error_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn serve_once(response: &'static str) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap();
            stream.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        (addr, task)
    }

    #[tokio::test]
    async fn notify_clients_do_not_follow_redirects() {
        let (addr, _) = serve_once(
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        let response = client(Purpose::Notify)
            .unwrap()
            .post(format!("http://{addr}/"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 302);
    }

    #[tokio::test]
    async fn requests_carry_the_user_agent() {
        let (addr, request) = serve_once("HTTP/1.1 204 No Content\r\n\r\n").await;
        client(Purpose::Notify)
            .unwrap()
            .get(format!("http://{addr}/"))
            .send()
            .await
            .unwrap();
        let request = request.await.unwrap().to_ascii_lowercase();
        assert!(request.contains("\r\nuser-agent: weglarka/"), "{request}");
    }

    #[test]
    fn the_tls_config_offers_http1_only() {
        let config = tls_config(RootCertStore::empty()).unwrap();
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn error_chain_joins_the_causes() {
        let inner = std::io::Error::other("inner");
        let outer = std::io::Error::other(inner);
        assert!(error_chain(&outer).contains("inner"));
    }
}
