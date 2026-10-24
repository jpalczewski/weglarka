//! Minimal HTTP/1.1 client for notifications: one `POST` per connection, no redirects, plain
//! `http://` or `https://`.
//!
//! TLS uses `rustls` (provider `ring`) with the bundled `webpki-roots`: the daemon image is `scratch`
//! and has no CA store, and a notification may carry a bearer token, so plain HTTP to a public host is
//! not an acceptable default (`docs/decisions/0021-notifications.md`). Deliberately small — the request
//! must be easy to audit.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

/// Response head limit (status line + headers): a hostile or broken peer must not make the daemon
/// allocate without bound.
const MAX_HEAD: usize = 8 * 1024;
const USER_AGENT: &str = concat!("weglarka/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EndpointError {
    #[error("URL must start with http:// or https://")]
    Scheme,
    #[error("URL must not contain a query or a fragment: use the base URL only")]
    Query,
    #[error("URL must not contain credentials (user:password@)")]
    Credentials,
    #[error("missing or invalid host in the URL")]
    Host,
    #[error("host must be ASCII (IDN host names are not supported)")]
    NonAsciiHost,
    #[error("invalid port in the URL")]
    Port,
    #[error("invalid path in the URL (whitespace and control characters are not allowed)")]
    Path,
    #[error("invalid Host override {0:?}")]
    HostOverride(String),
}

/// Where to connect and what to send in the request line / headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub tls: bool,
    /// Address to connect to (`url` host, unless it is an internal service name).
    pub connect_host: String,
    pub connect_port: u16,
    /// `Host` header and TLS server name (SNI + certificate verification).
    pub host: String,
    /// Request target: always starts and ends with `/` (the ntfy JSON-publish endpoint is the root).
    pub path: String,
}

/// Character-safe for a request line or a header value.
fn token_safe(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_graphic())
}

fn valid_host(host: &str) -> Result<(), EndpointError> {
    if host.is_empty() || host.contains(['/', '@', '?', '#', ' ', '\\']) {
        return Err(EndpointError::Host);
    }
    if !host.is_ascii() {
        return Err(EndpointError::NonAsciiHost);
    }
    if !token_safe(host) {
        return Err(EndpointError::Host);
    }
    Ok(())
}

impl Endpoint {
    /// Parses `url` (`scheme://host[:port][/base]`); `host_override` replaces the `Host` header and
    /// the TLS server name, for an endpoint reached by service name (e.g. through the ingress).
    pub fn parse(url: &str, host_override: Option<&str>) -> Result<Self, EndpointError> {
        let url = url.trim();
        let (scheme, rest) = url.split_once("://").ok_or(EndpointError::Scheme)?;
        let tls = match scheme.to_ascii_lowercase().as_str() {
            "http" => false,
            "https" => true,
            _ => return Err(EndpointError::Scheme),
        };
        if rest.contains(['?', '#']) {
            return Err(EndpointError::Query);
        }
        if rest.contains('@') {
            return Err(EndpointError::Credentials);
        }
        let (authority, path) = match rest.split_once('/') {
            Some((authority, path)) => (authority, format!("/{path}")),
            None => (rest, "/".to_owned()),
        };
        if !path.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(EndpointError::Path);
        }
        let (host, port) = split_authority(authority)?;
        let connect_host = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            // Keep IPv6 literals bracketed for `getaddrinfo`; the Host header stays bracketed too.
            Some(inner) => format!("[{inner}]"),
            None => host.clone(),
        };
        let port = match port {
            Some(0) => return Err(EndpointError::Port),
            Some(port) => port,
            None if tls => 443,
            None => 80,
        };
        let host = match host_override {
            Some(override_host) => {
                if !token_safe(override_host) || override_host.contains(':') {
                    return Err(EndpointError::HostOverride(override_host.to_owned()));
                }
                override_host.to_owned()
            }
            None => host,
        };
        // The ntfy JSON publish endpoint is the server root; normalize to `/base/` with exactly one
        // leading and trailing slash (`//x` must not reach the server as a network-path reference).
        let path = match path.trim_matches('/') {
            "" => "/".to_owned(),
            base => format!("/{base}/"),
        };
        Ok(Self {
            tls,
            connect_host,
            connect_port: port,
            host,
            path,
        })
    }
}

/// `host`, `host:port`, `[v6]` or `[v6]:port`.
fn split_authority(authority: &str) -> Result<(String, Option<u16>), EndpointError> {
    if authority.starts_with('[') {
        let end = authority.find(']').ok_or(EndpointError::Host)?;
        let host = &authority[..=end];
        let rest = &authority[end + 1..];
        let port = match rest.strip_prefix(':') {
            Some(port) => Some(port.parse().map_err(|_| EndpointError::Port)?),
            None if rest.is_empty() => None,
            None => return Err(EndpointError::Host),
        };
        valid_host(&host[1..host.len() - 1])?;
        return Ok((host.to_owned(), port));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port.parse().map_err(|_| EndpointError::Port)?)),
        None => (authority, None),
    };
    valid_host(host)?;
    Ok((host.to_owned(), port))
}

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("cannot connect to {addr}: {source}")]
    Connect { addr: String, source: io::Error },
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("no answer: {0}")]
    Timeout(String),
    #[error("malformed response: {0}")]
    Protocol(String),
}

/// HTTPS client with one shared configuration (root store parsed once per daemon).
pub struct Client {
    tls: TlsConnector,
}

fn tls_config(roots: RootCertStore) -> Result<Arc<ClientConfig>, HttpError> {
    // Explicit provider: never touch the process-wide default (another component may install one).
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let versions = tokio_rustls::rustls::DEFAULT_VERSIONS;
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(|e| HttpError::Tls(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    // We speak HTTP/1.1 only; without this rustls would offer `h2` first and ntfy may negotiate it.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

impl Client {
    /// Client trusting the bundled Mozilla root store (`webpki-roots`).
    pub fn new() -> Result<Self, HttpError> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::with_roots(roots)
    }

    /// Client with a custom root store (the tests use a self-signed certificate).
    pub fn with_roots(roots: RootCertStore) -> Result<Self, HttpError> {
        Ok(Self {
            tls: TlsConnector::from(tls_config(roots)?),
        })
    }

    /// `POST` a JSON body and return the response status. The body is not read: the request sends
    /// `Connection: close` and the stream is dropped.
    pub async fn post_json(
        &self,
        endpoint: &Endpoint,
        bearer: Option<&str>,
        body: &[u8],
        timeout: Duration,
    ) -> Result<u16, HttpError> {
        let addr = format!("{}:{}", endpoint.connect_host, endpoint.connect_port);
        let request = build_request(endpoint, bearer, body);
        tokio::time::timeout(timeout, self.post_inner(endpoint, &addr, &request))
            .await
            .map_err(|_| {
                HttpError::Timeout(format!(
                    "no answer from {addr} within {}s",
                    timeout.as_secs()
                ))
            })?
    }

    async fn post_inner(
        &self,
        endpoint: &Endpoint,
        addr: &str,
        request: &[u8],
    ) -> Result<u16, HttpError> {
        let tcp = TcpStream::connect(addr)
            .await
            .map_err(|source| HttpError::Connect {
                addr: addr.to_owned(),
                source,
            })?;
        if endpoint.tls {
            let server_name = ServerName::try_from(endpoint.host.clone()).map_err(|e| {
                HttpError::Tls(format!("invalid server name {:?}: {e}", endpoint.host))
            })?;
            let stream = self
                .tls
                .connect(server_name, tcp)
                .await
                .map_err(|e| HttpError::Tls(e.to_string()))?;
            exchange(stream, request).await
        } else {
            exchange(tcp, request).await
        }
    }
}

fn build_request(endpoint: &Endpoint, bearer: Option<&str>, body: &[u8]) -> Vec<u8> {
    let mut head = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\n\
         Content-Type: application/json\r\nAccept: application/json\r\n\
         Content-Length: {len}\r\nConnection: close\r\n",
        path = endpoint.path,
        host = endpoint.host,
        len = body.len(),
    );
    if let Some(token) = bearer {
        head.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    head.push_str("\r\n");
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

/// Sends the request and parses the status line of the response.
async fn exchange<S>(mut stream: S, request: &[u8]) -> Result<u16, HttpError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(request).await?;
    stream.flush().await?;
    let mut head = Vec::with_capacity(256);
    let mut buf = [0u8; 256];
    loop {
        if head.windows(2).any(|w| w == b"\r\n") {
            break;
        }
        if head.len() > MAX_HEAD {
            return Err(HttpError::Protocol("response head too large".to_owned()));
        }
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        head.extend_from_slice(&buf[..n]);
    }
    parse_status(&head)
        .ok_or_else(|| HttpError::Protocol("missing or invalid status line".to_owned()))
}

/// `HTTP/1.x <code> …` → the code.
fn parse_status(head: &[u8]) -> Option<u16> {
    let line = head.split(|b| *b == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?;
    let mut parts = line.split(' ');
    parts.next().filter(|v| v.starts_with("HTTP/1."))?;
    let code: u16 = parts.next()?.trim().parse().ok()?;
    (100..=599).contains(&code).then_some(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::rustls::ServerConfig;
    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    fn endpoint(addr: &str) -> Endpoint {
        let (host, port) = addr.rsplit_once(':').unwrap();
        Endpoint {
            tls: false,
            connect_host: host.to_owned(),
            connect_port: port.parse().unwrap(),
            host: "ntfy.example.com".into(),
            path: "/".into(),
        }
    }

    /// Serves one canned response and returns the raw request it received.
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
    async fn posts_json_with_the_expected_headers() {
        let (addr, request) = serve_once("HTTP/1.1 200 OK\r\n\r\n").await;
        let client = Client::new().unwrap();
        let status = client
            .post_json(
                &endpoint(&addr),
                Some("tk_secret"),
                br#"{"topic":"wg"}"#,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(status, 200);
        let request = request.await.unwrap();
        assert!(request.starts_with("POST / HTTP/1.1\r\n"), "{request}");
        assert!(
            request.contains("\r\nHost: ntfy.example.com\r\n"),
            "{request}"
        );
        assert!(
            request.contains("\r\nAuthorization: Bearer tk_secret\r\n"),
            "{request}"
        );
        assert!(request.contains("\r\nContent-Length: 14\r\n"), "{request}");
        assert!(request.ends_with(r#"{"topic":"wg"}"#), "{request}");
    }

    #[tokio::test]
    async fn without_a_token_there_is_no_authorization_header() {
        let (addr, request) = serve_once("HTTP/1.1 204 No Content\r\n\r\n").await;
        Client::new()
            .unwrap()
            .post_json(&endpoint(&addr), None, b"{}", Duration::from_secs(5))
            .await
            .unwrap();
        let request = request.await.unwrap();
        assert!(
            !request.to_ascii_lowercase().contains("authorization"),
            "{request}"
        );
    }

    #[tokio::test]
    async fn status_codes_are_returned_and_garbage_is_an_error() {
        for (response, expected) in [
            ("HTTP/1.1 500 Internal Server Error\r\n\r\n", 500u16),
            ("HTTP/1.0 429 Too Many Requests\r\n\r\n", 429),
            ("HTTP/1.1 401 Unauthorized\r\n\r\n", 401),
        ] {
            let (addr, _) = serve_once(response).await;
            let status = Client::new()
                .unwrap()
                .post_json(&endpoint(&addr), None, b"{}", Duration::from_secs(5))
                .await
                .unwrap();
            assert_eq!(status, expected);
        }
        let (addr, _) = serve_once("garbage\r\n\r\n").await;
        let err = Client::new()
            .unwrap()
            .post_json(&endpoint(&addr), None, b"{}", Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(matches!(err, HttpError::Protocol(_)), "{err}");
    }

    #[tokio::test]
    async fn a_silent_server_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let hold = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let err = Client::new()
            .unwrap()
            .post_json(&endpoint(&addr), None, b"{}", Duration::from_millis(50))
            .await
            .unwrap_err();
        assert!(matches!(err, HttpError::Timeout(_)), "{err}");
        hold.abort();
    }

    #[tokio::test]
    async fn connection_refused_is_a_connect_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        drop(listener);
        let err = Client::new()
            .unwrap()
            .post_json(&endpoint(&addr), None, b"{}", Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(matches!(err, HttpError::Connect { .. }), "{err}");
    }

    #[tokio::test]
    async fn an_unterminated_response_head_is_rejected() {
        // A peer that never closes the status line must not make the daemon read without bound.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let hold = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let chunk = vec![b'x'; MAX_HEAD + 1];
            let _ = stream.write_all(&chunk).await;
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        let err = Client::new()
            .unwrap()
            .post_json(&endpoint(&addr), None, b"{}", Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(matches!(err, HttpError::Protocol(_)), "{err}");
        hold.abort();
    }

    /// The throwaway self-signed certificate from `tests/fixtures` (see its README).
    fn tls_fixtures() -> (
        CertificateDer<'static>,
        PrivateKeyDer<'static>,
        RootCertStore,
    ) {
        let cert = CertificateDer::from(include_bytes!("../tests/fixtures/test-cert.der").to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            include_bytes!("../tests/fixtures/test-key.der").to_vec(),
        ));
        let mut roots = RootCertStore::empty();
        roots.add(cert.clone()).unwrap();
        (cert, key, roots)
    }

    fn tls_server_config(
        cert: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
    ) -> Arc<ServerConfig> {
        let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        Arc::new(config)
    }

    /// Serves one TLS request; a failed handshake ends the task quietly (the client side is asserted).
    async fn serve_tls_once(
        config: Arc<ServerConfig>,
        response: &'static str,
    ) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let acceptor = TlsAcceptor::from(config);
        let task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let Ok(mut stream) = acceptor.accept(tcp).await else {
                return String::new();
            };
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap();
            stream.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        (addr, task)
    }

    fn tls_endpoint(addr: &str, host: &str) -> Endpoint {
        let (connect_host, port) = addr.rsplit_once(':').unwrap();
        Endpoint {
            tls: true,
            connect_host: connect_host.to_owned(),
            connect_port: port.parse().unwrap(),
            host: host.to_owned(),
            path: "/".into(),
        }
    }

    #[tokio::test]
    async fn https_is_verified_against_the_configured_roots() {
        let (cert, key, roots) = tls_fixtures();
        let (addr, request) =
            serve_tls_once(tls_server_config(cert, key), "HTTP/1.1 200 OK\r\n\r\n").await;
        let client = Client::with_roots(roots).unwrap();
        let status = client
            .post_json(
                &tls_endpoint(&addr, "localhost"),
                Some("tk_secret"),
                br#"{"topic":"wg"}"#,
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(status, 200);
        let request = request.await.unwrap();
        assert!(request.starts_with("POST / HTTP/1.1\r\n"), "{request}");
        assert!(
            request.contains("\r\nAuthorization: Bearer tk_secret\r\n"),
            "{request}"
        );
    }

    #[tokio::test]
    async fn a_hostname_that_does_not_match_the_certificate_is_rejected() {
        let (cert, key, roots) = tls_fixtures();
        let (addr, _) =
            serve_tls_once(tls_server_config(cert, key), "HTTP/1.1 200 OK\r\n\r\n").await;
        let err = Client::with_roots(roots)
            .unwrap()
            .post_json(
                &tls_endpoint(&addr, "ntfy.example.com"),
                None,
                b"{}",
                Duration::from_secs(5),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, HttpError::Tls(_)), "{err}");
    }

    #[tokio::test]
    async fn an_untrusted_certificate_is_rejected() {
        let (cert, key, _roots) = tls_fixtures();
        let (addr, _) =
            serve_tls_once(tls_server_config(cert, key), "HTTP/1.1 200 OK\r\n\r\n").await;
        // The bundled webpki roots do not contain the self-signed test certificate.
        let err = Client::new()
            .unwrap()
            .post_json(
                &tls_endpoint(&addr, "localhost"),
                None,
                b"{}",
                Duration::from_secs(5),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, HttpError::Tls(_)), "{err}");
    }

    #[test]
    fn endpoint_parsing() {
        let endpoint = Endpoint::parse("https://ntfy.example.com", None).unwrap();
        assert!(endpoint.tls);
        assert_eq!(endpoint.connect_host, "ntfy.example.com");
        assert_eq!(endpoint.connect_port, 443);
        assert_eq!(endpoint.host, "ntfy.example.com");
        assert_eq!(endpoint.path, "/");

        let endpoint =
            Endpoint::parse("http://weglarka-nginx:8080", Some("ntfy.example.com")).unwrap();
        assert!(!endpoint.tls);
        assert_eq!(endpoint.connect_host, "weglarka-nginx");
        assert_eq!(endpoint.connect_port, 8080);
        assert_eq!(endpoint.host, "ntfy.example.com");

        let endpoint = Endpoint::parse("https://example.com/ntfy", None).unwrap();
        assert_eq!(endpoint.path, "/ntfy/");
        let endpoint = Endpoint::parse("https://example.com/ntfy/", None).unwrap();
        assert_eq!(endpoint.path, "/ntfy/");
        // A doubled slash must not become a network-path reference (`//host`).
        let endpoint = Endpoint::parse("https://example.com//ntfy", None).unwrap();
        assert_eq!(endpoint.path, "/ntfy/");
        let endpoint = Endpoint::parse("http://[::1]:8080", None).unwrap();
        assert_eq!(endpoint.connect_host, "[::1]");
        assert_eq!(endpoint.connect_port, 8080);
    }

    #[test]
    fn endpoint_rejects_unsafe_or_unsupported_urls() {
        for (url, host, expected) in [
            ("ftp://x", None, EndpointError::Scheme),
            ("ntfy.example.com", None, EndpointError::Scheme),
            (
                "https://ntfy.example.com/insecure?x=1",
                None,
                EndpointError::Query,
            ),
            (
                "https://user:pass@ntfy.example.com",
                None,
                EndpointError::Credentials,
            ),
            ("https://", None, EndpointError::Host),
            ("https://ntfy.example.com:0", None, EndpointError::Port),
            ("https://ntfy.example.com:99999", None, EndpointError::Port),
            ("https://ntfy.example.com:abc", None, EndpointError::Port),
            ("https://ntfy.example.com/a b", None, EndpointError::Path),
            (
                "https://ntfy.example.com",
                Some("bad host"),
                EndpointError::HostOverride("bad host".into()),
            ),
            (
                "https://ntfy.example.com",
                Some("host:80"),
                EndpointError::HostOverride("host:80".into()),
            ),
        ] {
            assert_eq!(
                Endpoint::parse(url, host).unwrap_err(),
                expected,
                "{url} {host:?}"
            );
        }
        assert_eq!(
            Endpoint::parse("https://ntfy.例え.com", None).unwrap_err(),
            EndpointError::NonAsciiHost
        );
    }

    #[test]
    fn status_line_parsing() {
        assert_eq!(parse_status(b"HTTP/1.1 200 OK\r\n"), Some(200));
        assert_eq!(parse_status(b"HTTP/1.0 503 \r\n"), Some(503));
        assert_eq!(parse_status(b"garbage"), None);
        assert_eq!(parse_status(b"HTTP/1.1 99 x\r\n"), None);
    }

    #[test]
    fn request_never_contains_a_newline_from_the_token() {
        // Tokens are validated by the settings, but the builder must stay safe on its own.
        let endpoint = Endpoint::parse("https://ntfy.example.com", None).unwrap();
        let request = build_request(&endpoint, Some("tk-ok"), b"{}");
        let text = String::from_utf8(request).unwrap();
        assert_eq!(text.matches("\r\n\r\n").count(), 1, "{text}");
    }
}
