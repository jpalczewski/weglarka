//! Minimal HTTP/1.1 + TLS client for a JSON API with a bearer token: one request per connection
//! (`Connection: close`), no redirects, bounded response.
//!
//! TLS is `rustls` (provider `ring`) with the bundled `webpki-roots`: the daemon image is `scratch`
//! and has no CA store. Plain `http://` is accepted only for a loopback host (tests), so the token
//! cannot be sent in the clear to a remote machine. Deliberately small, like the clients in
//! `weglarka-registry` and `weglarka-notify`: the request carries a credential and must be easy to audit.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

const MAX_HEAD: usize = 16 * 1024;
const MAX_CHUNK_LINE: usize = 1024;
/// A Cloudflare API answer is a few hundred bytes; a hostile peer must not make the daemon allocate.
const MAX_BODY: usize = 256 * 1024;
const USER_AGENT: &str = concat!("weglarka/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("invalid API URL: {0}")]
    Url(&'static str),
    #[error("cannot connect to {addr}: {source}")]
    Connect { addr: String, source: io::Error },
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("no answer from {addr} within {secs}s")]
    Timeout { addr: String, secs: u64 },
    #[error("malformed response: {0}")]
    Protocol(&'static str),
    #[error("response body exceeds {limit} bytes")]
    TooLarge { limit: usize },
    #[error("invalid bearer token: it must be printable ASCII")]
    Token,
}

/// Where requests go: `scheme://host[:port][/base]`, base path without a trailing slash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Base {
    tls: bool,
    host: String,
    port: u16,
    path: String,
}

impl Base {
    pub(crate) fn parse(url: &str) -> Result<Self, HttpError> {
        let (scheme, rest) = url
            .trim()
            .split_once("://")
            .ok_or(HttpError::Url("expected http:// or https://"))?;
        let tls = match scheme.to_ascii_lowercase().as_str() {
            "https" => true,
            "http" => false,
            _ => return Err(HttpError::Url("expected http:// or https://")),
        };
        if rest.contains(['?', '#', '@']) {
            return Err(HttpError::Url("no query, fragment or credentials allowed"));
        }
        let (authority, path) = match rest.split_once('/') {
            Some((authority, path)) => (authority, format!("/{}", path.trim_end_matches('/'))),
            None => (rest, String::new()),
        };
        if !path.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(HttpError::Url("invalid path"));
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (
                host,
                Some(
                    port.parse::<u16>()
                        .ok()
                        .filter(|p| *p != 0)
                        .ok_or(HttpError::Url("invalid port"))?,
                ),
            ),
            None => (authority, None),
        };
        if host.is_empty()
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
        {
            return Err(HttpError::Url("invalid host"));
        }
        if !tls && !is_loopback(host) {
            return Err(HttpError::Url(
                "plain http is only allowed for a loopback host (the token would travel unencrypted)",
            ));
        }
        Ok(Self {
            tls,
            host: host.to_owned(),
            port: port.unwrap_or(if tls { 443 } else { 80 }),
            path,
        })
    }
}

fn is_loopback(host: &str) -> bool {
    host == "localhost" || host.starts_with("127.")
}

pub(crate) struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

/// HTTPS client with one shared TLS configuration (root store parsed once).
pub(crate) struct Client {
    tls: TlsConnector,
    base: Base,
    timeout: Duration,
    max_body: usize,
}

impl Client {
    pub(crate) fn new(base: Base, timeout: Duration) -> Result<Self, HttpError> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        // Explicit provider: never touch the process-wide default (another component may install one).
        let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(tokio_rustls::rustls::DEFAULT_VERSIONS)
            .map_err(|e| HttpError::Tls(e.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        // HTTP/1.1 only; without this rustls would offer `h2` first.
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            tls: TlsConnector::from(Arc::new(config)),
            base,
            timeout,
            max_body: MAX_BODY,
        })
    }

    /// Lowers the response cap (a public list is far smaller than a zone listing).
    pub(crate) fn with_max_body(mut self, max_body: usize) -> Self {
        self.max_body = max_body.min(MAX_BODY);
        self
    }

    /// `path` is relative to the base path and starts with `/` (it may carry a query).
    pub(crate) async fn request(
        &self,
        method: &'static str,
        path: &str,
        bearer: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<Response, HttpError> {
        if bearer.is_some_and(|b| b.is_empty() || !b.bytes().all(|b| b.is_ascii_graphic())) {
            return Err(HttpError::Token);
        }
        let addr = format!("{}:{}", self.base.host, self.base.port);
        let request = build_request(&self.base, method, path, bearer, body);
        tokio::time::timeout(self.timeout, self.exchange(&addr, &request))
            .await
            .map_err(|_| HttpError::Timeout {
                addr: addr.clone(),
                secs: self.timeout.as_secs(),
            })?
    }

    async fn exchange(&self, addr: &str, request: &[u8]) -> Result<Response, HttpError> {
        let tcp = TcpStream::connect(addr)
            .await
            .map_err(|source| HttpError::Connect {
                addr: addr.to_owned(),
                source,
            })?;
        if self.base.tls {
            let name = ServerName::try_from(self.base.host.clone())
                .map_err(|e| HttpError::Tls(format!("invalid server name: {e}")))?;
            let stream = self
                .tls
                .connect(name, tcp)
                .await
                .map_err(|e| HttpError::Tls(e.to_string()))?;
            round_trip(stream, request, self.max_body).await
        } else {
            round_trip(tcp, request, self.max_body).await
        }
    }
}

fn build_request(
    base: &Base,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: Option<&[u8]>,
) -> Vec<u8> {
    let mut head = format!(
        "{method} {base_path}{path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\n\
         Accept: application/json\r\n",
        base_path = base.path,
        host = base.host,
    );
    if let Some(bearer) = bearer {
        head.push_str(&format!("Authorization: Bearer {bearer}\r\n"));
    }
    head.push_str("Connection: close\r\n");
    if let Some(body) = body {
        head.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    head.push_str("\r\n");
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(body.unwrap_or_default());
    bytes
}

async fn round_trip<S>(
    mut stream: S,
    request: &[u8],
    max_body: usize,
) -> Result<Response, HttpError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(request).await?;
    stream.flush().await?;
    let (head, rest) = read_head(&mut stream).await?;
    let (status, headers) = parse_head(&head)?;
    if (100..=199).contains(&status) {
        return Err(HttpError::Protocol(
            "informational responses are not supported",
        ));
    }
    // `rest` holds bytes that arrived together with the head; `chain` makes them the body prefix.
    let mut reader = (&rest[..]).chain(stream);
    let body = read_body(&mut reader, &headers, max_body).await?;
    Ok(Response { status, body })
}

async fn read_head<S>(stream: &mut S) -> Result<(Vec<u8>, Vec<u8>), HttpError>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(end) = buffer
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|p| p + 4)
        {
            if end > MAX_HEAD {
                return Err(HttpError::Protocol("response head too large"));
            }
            let rest = buffer.split_off(end);
            return Ok((buffer, rest));
        }
        if buffer.len() > MAX_HEAD {
            return Err(HttpError::Protocol("response head too large"));
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(HttpError::Protocol(
                "connection closed before the response head was complete",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

fn parse_head(head: &[u8]) -> Result<(u16, Vec<(String, String)>), HttpError> {
    let text = std::str::from_utf8(head)
        .map_err(|_| HttpError::Protocol("response head is not valid UTF-8"))?;
    let mut lines = text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or(HttpError::Protocol("missing status line"))?;
    let mut parts = status_line.split(' ');
    if !parts.next().is_some_and(|v| v.starts_with("HTTP/1.")) {
        return Err(HttpError::Protocol("missing or invalid status line"));
    }
    let status: u16 = parts
        .next()
        .and_then(|code| code.trim().parse().ok())
        .filter(|code| (100..=599).contains(code))
        .ok_or(HttpError::Protocol("missing or invalid status code"))?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or(HttpError::Protocol("malformed response header"))?;
        headers.push((
            name.to_ascii_lowercase(),
            value.trim_matches([' ', '\t']).to_owned(),
        ));
    }
    Ok((status, headers))
}

async fn read_body<R>(
    reader: &mut R,
    headers: &[(String, String)],
    max_body: usize,
) -> Result<Vec<u8>, HttpError>
where
    R: AsyncRead + Unpin,
{
    let header = |name: &str| {
        headers
            .iter()
            .find(|(header, _)| header == name)
            .map(|(_, value)| value.as_str())
    };
    let chunked = header("transfer-encoding").is_some_and(|value| {
        value
            .split(',')
            .any(|token| token.trim().eq_ignore_ascii_case("chunked"))
    });
    if chunked {
        return read_chunked(reader, max_body).await;
    }
    if let Some(length) = header("content-length") {
        let length: usize = length
            .trim()
            .parse()
            .map_err(|_| HttpError::Protocol("invalid Content-Length"))?;
        if length > max_body {
            return Err(HttpError::TooLarge { limit: max_body });
        }
        let mut body = vec![0u8; length];
        reader.read_exact(&mut body).await?;
        return Ok(body);
    }
    // No length: the body runs to EOF (`Connection: close`).
    let mut body = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = reader.read(&mut chunk).await?;
        if read == 0 {
            return Ok(body);
        }
        if body.len() + read > max_body {
            return Err(HttpError::TooLarge { limit: max_body });
        }
        body.extend_from_slice(&chunk[..read]);
    }
}

async fn read_chunked<R>(reader: &mut R, max_body: usize) -> Result<Vec<u8>, HttpError>
where
    R: AsyncRead + Unpin,
{
    let mut body = Vec::new();
    loop {
        let line = read_line(reader).await?;
        let size = std::str::from_utf8(&line)
            .ok()
            .and_then(|line| line.split(';').next())
            .and_then(|size| usize::from_str_radix(size.trim(), 16).ok())
            .ok_or(HttpError::Protocol("invalid chunk size"))?;
        if size == 0 {
            // Trailers end with an empty line; they are read (bounded) and discarded.
            while !read_line(reader).await?.is_empty() {}
            return Ok(body);
        }
        if body
            .len()
            .checked_add(size)
            .is_none_or(|len| len > max_body)
        {
            return Err(HttpError::TooLarge { limit: max_body });
        }
        let mut chunk = vec![0u8; size];
        reader.read_exact(&mut chunk).await?;
        body.extend_from_slice(&chunk);
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).await?;
        if crlf != *b"\r\n" {
            return Err(HttpError::Protocol("malformed chunk terminator"));
        }
    }
}

async fn read_line<R>(reader: &mut R) -> Result<Vec<u8>, HttpError>
where
    R: AsyncRead + Unpin,
{
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if reader.read(&mut byte).await? == 0 {
            return Err(HttpError::Protocol("connection closed mid-line"));
        }
        if byte[0] == b'\n' {
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(line);
        }
        if line.len() >= MAX_CHUNK_LINE {
            return Err(HttpError::Protocol("response line too long"));
        }
        line.push(byte[0]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn answer(response: &[u8], max_body: usize) -> Result<Response, HttpError> {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        server.write_all(response).await.unwrap();
        server.shutdown().await.unwrap();
        round_trip(client, b"GET / HTTP/1.1\r\n\r\n", max_body).await
    }

    #[test]
    fn base_url_parsing() {
        let base = Base::parse("https://api.cloudflare.com/client/v4/").unwrap();
        assert_eq!(
            base,
            Base {
                tls: true,
                host: "api.cloudflare.com".into(),
                port: 443,
                path: "/client/v4".into()
            }
        );
        let local = Base::parse("http://127.0.0.1:8123").unwrap();
        assert_eq!((local.port, local.path.as_str()), (8123, ""));
        for bad in [
            "ftp://x.eu",
            "api.example.eu",
            "https://u:p@example.eu",
            "https://example.eu/?a=1",
            "https://example.eu:0",
            "https:///v4",
            "http://api.example.eu",
        ] {
            assert!(Base::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn request_carries_the_token_and_the_body_length() {
        let base = Base::parse("https://api.example.eu/v4").unwrap();
        let request = build_request(&base, "POST", "/zones/x", Some("tok"), Some(b"{}"));
        let text = String::from_utf8(request).unwrap();
        assert!(text.starts_with("POST /v4/zones/x HTTP/1.1\r\nHost: api.example.eu\r\n"));
        assert!(text.contains("Authorization: Bearer tok\r\n"));
        assert!(text.contains("Content-Length: 2\r\n"));
        assert!(text.ends_with("\r\n\r\n{}"));
        let get =
            String::from_utf8(build_request(&base, "GET", "/zones", Some("tok"), None)).unwrap();
        assert!(!get.contains("Content-Length"));
    }

    #[tokio::test]
    async fn bodies_by_length_chunks_and_eof_are_read() {
        let r = answer(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", 100)
            .await
            .unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, &b"hello"[..]));
        let r = answer(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nhel\r\n2\r\nlo\r\n0\r\n\r\n",
            100,
        )
        .await
        .unwrap();
        assert_eq!(r.body, b"hello");
        let r = answer(b"HTTP/1.1 404 Not Found\r\n\r\nbye", 100)
            .await
            .unwrap();
        assert_eq!((r.status, r.body.as_slice()), (404, &b"bye"[..]));
    }

    #[tokio::test]
    async fn hostile_responses_are_rejected() {
        assert!(matches!(
            answer(b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n", 100).await,
            Err(HttpError::TooLarge { .. })
        ));
        assert!(matches!(
            answer(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n64\r\n",
                10
            )
            .await,
            Err(HttpError::TooLarge { .. })
        ));
        assert!(matches!(
            answer(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
                10
            )
            .await,
            Err(HttpError::Protocol(_))
        ));
        assert!(matches!(
            answer(b"HTTP/1.1 99 Nope\r\n\r\n", 10).await,
            Err(HttpError::Protocol(_))
        ));
        assert!(matches!(
            answer(b"HTTP/1.1 100 Continue\r\n\r\n", 10).await,
            Err(HttpError::Protocol(_))
        ));
        assert!(matches!(
            answer(b"HTTP/1.1 200 OK\r\n", 10).await,
            Err(HttpError::Protocol(_))
        ));
        let huge = format!(
            "HTTP/1.1 200 OK\r\nX: {}\r\n\r\n",
            "a".repeat(MAX_HEAD + 10)
        );
        assert!(matches!(
            answer(huge.as_bytes(), 10).await,
            Err(HttpError::Protocol(_))
        ));
    }
}
