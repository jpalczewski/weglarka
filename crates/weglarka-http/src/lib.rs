//! The one place that builds outbound HTTP clients for Węglarka.
//!
//! Every network-facing crate (notifications, registry, DNS, and later ACME) gets its
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

use reqwest::Url;
use reqwest::redirect::Policy;
use rustls::crypto::ring::default_provider;
use rustls::{ClientConfig, RootCertStore};

pub use reqwest;

/// Redirect hops the [`Purpose::Registry`] client follows (GHCR uses one: blob → CDN).
const REGISTRY_MAX_REDIRECTS: usize = 5;
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
#[non_exhaustive]
pub enum Purpose {
    /// Notification delivery (ntfy): a short exchange that may carry a bearer token, so redirects are
    /// never followed. Connections are not pooled (one request per connection, as before).
    Notify,
    /// OCI registry reads (token endpoint, manifests, blobs). Redirects are followed up to
    /// [`REGISTRY_MAX_REDIRECTS`] hops and only to `https://` (or loopback, for tests); `reqwest`
    /// drops `Authorization` when a hop leaves the original host or port, which is what a GHCR blob
    /// redirect to a CDN needs.
    Registry,
    /// A JSON API called with a bearer token (the DNS provider). The API root is fixed, so redirects
    /// are never followed and the token cannot be handed to another host.
    Api,
    /// The ACME client talking to a certificate authority. JWS requests are bound to their URL, so a
    /// redirect would only fail the exchange: none is followed.
    Acme,
}

impl Purpose {
    fn connect_timeout(self) -> Duration {
        match self {
            Self::Notify | Self::Registry | Self::Api | Self::Acme => Duration::from_secs(10),
        }
    }

    /// Total time for one request, redirects and body included.
    fn timeout(self) -> Duration {
        match self {
            Self::Notify => Duration::from_secs(10),
            Self::Registry | Self::Api | Self::Acme => Duration::from_secs(30),
        }
    }

    fn redirects(self) -> Policy {
        match self {
            Self::Notify | Self::Api | Self::Acme => Policy::none(),
            Self::Registry => Policy::custom(|attempt| {
                let previous = attempt.previous();
                if previous.len() > REGISTRY_MAX_REDIRECTS {
                    attempt.error(RedirectRefused::TooMany(REGISTRY_MAX_REDIRECTS))
                } else if !transport_allowed(attempt.url()) {
                    attempt.error(RedirectRefused::Insecure)
                } else if previous
                    .last()
                    .zip(previous.first())
                    .is_some_and(|(last, first)| {
                        // `reqwest` rebuilds every hop from the original headers and strips `Authorization`
                        // only when a hop changes authority relative to the *previous* one, so a second hop
                        // within the CDN would get the token back. Leaving the original authority is
                        // therefore allowed once, and only as the final hop.
                        authority(last) != authority(first)
                    })
                {
                    attempt.error(RedirectRefused::Chained)
                } else {
                    attempt.follow()
                }
            }),
        }
    }

    fn pooled(self) -> bool {
        match self {
            Self::Notify | Self::Registry | Self::Api | Self::Acme => false,
        }
    }
}

/// Why a redirect was not followed; the cause inside the `reqwest` error of the request.
#[derive(Debug, thiserror::Error)]
enum RedirectRefused {
    #[error("more than {0} redirects")]
    TooMany(usize),
    #[error("redirect to a URL that is neither https nor loopback")]
    Insecure,
    #[error("redirect from a host other than the original one (the token must not follow)")]
    Chained,
}

fn authority(url: &Url) -> (Option<&str>, Option<u16>) {
    (url.host_str(), url.port_or_known_default())
}

/// Whether credentials may travel to `url`: `https://`, or plain `http://` to a loopback address
/// (a test server). Callers check their own target URLs with this; the registry client applies it to
/// every redirect hop.
pub fn transport_allowed(url: &Url) -> bool {
    match url.scheme() {
        "https" => true,
        "http" => url.host_str().is_some_and(|host| {
            host.trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
        }),
        _ => false,
    }
}

/// The body of `response`, at most `limit` bytes. The limit is enforced while reading, so a lying
/// `Content-Length` (or none, with a chunked stream) cannot make the daemon allocate more.
pub async fn read_capped(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, BodyError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(BodyError::TooLarge { limit });
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > limit {
            return Err(BodyError::TooLarge { limit });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[derive(Debug, thiserror::Error)]
pub enum BodyError {
    #[error("the response body exceeds {limit} bytes")]
    TooLarge { limit: usize },
    #[error("cannot read the response body: {}", error_chain(.0))]
    Read(#[from] reqwest::Error),
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
        // Never route a bearer token through a proxy picked up from the environment by accident.
        .no_proxy()
        // The default would tell a redirect target (a CDN) which registry URL the client came from.
        .referer(false)
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

    /// Serves `count` connections, each answering `302 → Location: <location>`.
    async fn serve_redirects(location: String, count: usize) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            for _ in 0..count {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 4096];
                let _ = stream.read(&mut buf).await.unwrap();
                let reply = format!(
                    "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n"
                );
                stream.write_all(reply.as_bytes()).await.unwrap();
            }
        });
        addr
    }

    #[tokio::test]
    async fn api_clients_do_not_follow_redirects() {
        let addr = serve_redirects("http://127.0.0.1:1/".into(), 1).await;
        let response = client(Purpose::Api)
            .unwrap()
            .get(format!("http://{addr}/"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 302);
    }

    #[tokio::test]
    async fn registry_clients_cap_the_redirect_chain() {
        let addr = serve_redirects("/again".into(), 16).await;
        let error = client(Purpose::Registry)
            .unwrap()
            .get(format!("http://{addr}/"))
            .send()
            .await
            .unwrap_err();
        assert!(error.is_redirect(), "{}", error_chain(&error));
        assert!(error_chain(&error).contains("more than 5 redirects"));
    }

    #[tokio::test]
    async fn registry_clients_refuse_a_redirect_to_plain_http_on_a_remote_host() {
        let addr = serve_redirects("http://example.com/blob".into(), 1).await;
        let error = client(Purpose::Registry)
            .unwrap()
            .get(format!("http://{addr}/"))
            .send()
            .await
            .unwrap_err();
        assert!(error.is_redirect(), "{}", error_chain(&error));
    }

    #[test]
    fn plain_http_is_allowed_to_loopback_only() {
        for (url, allowed) in [
            ("https://ghcr.io/", true),
            ("http://127.0.0.1:5000/", true),
            ("http://localhost/", false),
            ("http://[::1]:5000/", true),
            ("http://example.com/", false),
            ("http://10.0.0.1/", false),
            ("ftp://127.0.0.1/", false),
        ] {
            let url = Url::parse(url).unwrap();
            assert_eq!(transport_allowed(&url), allowed, "{url}");
        }
    }

    #[tokio::test]
    async fn bodies_are_read_up_to_the_cap() {
        let (addr, _) = serve_once("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello").await;
        let response = client(Purpose::Api)
            .unwrap()
            .get(format!("http://{addr}/"))
            .send()
            .await
            .unwrap();
        assert_eq!(read_capped(response, 5).await.unwrap(), b"hello");

        // A declared length over the cap is refused before reading.
        let (addr, _) = serve_once("HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n").await;
        let response = client(Purpose::Api)
            .unwrap()
            .get(format!("http://{addr}/"))
            .send()
            .await
            .unwrap();
        assert!(matches!(
            read_capped(response, 100).await,
            Err(BodyError::TooLarge { limit: 100 })
        ));

        // A chunked body has no length to check: the cap is enforced while reading.
        let (addr, _) = serve_once(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8\r\n12345678\r\n8\r\n12345678\r\n0\r\n\r\n",
        )
        .await;
        let response = client(Purpose::Api)
            .unwrap()
            .get(format!("http://{addr}/"))
            .send()
            .await
            .unwrap();
        assert!(matches!(
            read_capped(response, 10).await,
            Err(BodyError::TooLarge { limit: 10 })
        ));
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
