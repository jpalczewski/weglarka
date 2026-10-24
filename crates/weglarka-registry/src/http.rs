//! Minimal HTTP/1.1 `GET` client for the OCI registry protocol.
//!
//! The registry wire format is small (a challenge, a token, a manifest, blobs), so this is not a
//! general-purpose client: one `GET` per connection (`Connection: close`), no cookies, no
//! compression, no caching. What it does implement is what the security of the self-update relies
//! on:
//!
//! * TLS with the bundled `webpki-roots` (the daemon image is `scratch` and has no CA store);
//!   plain HTTP is allowed only for loopback hosts, which is where the tests put their servers.
//! * A size cap for every response body, enforced while reading (a `Content-Length` lie cannot make
//!   the daemon allocate more than the cap).
//! * At most 5 redirects, and the `Authorization` header is never sent to an authority other than
//!   the one the request started at (GHCR redirects blobs to another host).
//! * A per-request timeout.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

/// Response head limit (status line + headers).
const MAX_HEAD: usize = 16 * 1024;
/// URL limit; the longest URL this client builds is a token URL with a scope.
const MAX_URL_LEN: usize = 4096;
/// Longest chunk-size line or trailer line in a chunked response.
const MAX_CHUNK_LINE: usize = 1024;
/// Redirect limit; GHCR uses one (blob → CDN).
const MAX_REDIRECTS: usize = 5;
const USER_AGENT: &str = concat!("weglarka/", env!("CARGO_PKG_VERSION"));
/// One `GET` (including its redirects) may not take longer than this.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("URL is malformed: {0}")]
    Url(&'static str),
    #[error("unsupported URL scheme {scheme:?}: only http and https are allowed")]
    Scheme { scheme: String },
    #[error("refusing plain http to {host:?}: registry traffic to a non-loopback host needs https")]
    NotHttps { host: String },
    #[error("invalid port in the URL")]
    Port,
    #[error("the bearer token is not a safe HTTP header value")]
    InvalidToken,
    #[error("cannot connect to {addr}: {source}")]
    Connect { addr: String, source: io::Error },
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("the {what} request timed out")]
    Timeout { what: &'static str },
    #[error("malformed response: {0}")]
    Protocol(&'static str),
    #[error("the {what} response exceeds the {limit} byte limit")]
    TooLarge { what: &'static str, limit: usize },
    #[error("more than {0} redirects")]
    TooManyRedirects(usize),
    #[error("the redirect response has no Location header")]
    MissingLocation,
}

/// An absolute `http(s)://host[:port][/path][?query]` URL, parsed strictly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Url {
    pub(crate) tls: bool,
    /// Host for SNI and `connect`, lowercase, with IPv6 literals bare (`::1`).
    pub(crate) host: String,
    ipv6: bool,
    pub(crate) port: u16,
    /// Request target: starts with `/`, may carry a query.
    pub(crate) path: String,
}

impl Url {
    /// `scheme://host[:port][/path]`, with the plain-HTTP policy applied.
    pub(crate) fn parse(url: &str) -> Result<Self, HttpError> {
        if url.is_empty() || url.len() > MAX_URL_LEN {
            return Err(HttpError::Url("URL is empty or too long"));
        }
        if !url.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(HttpError::Url(
                "URL contains whitespace or control characters",
            ));
        }
        let (scheme, rest) = url
            .split_once("://")
            .ok_or(HttpError::Url("missing scheme"))?;
        let tls = match scheme {
            "https" => true,
            "http" => false,
            other => {
                return Err(HttpError::Scheme {
                    scheme: other.to_owned(),
                });
            }
        };
        if rest.contains('#') {
            return Err(HttpError::Url("URL fragments are not supported"));
        }
        if rest.contains('@') {
            return Err(HttpError::Url("URLs with credentials are not supported"));
        }
        let (authority, target) = match rest.find(['/', '?']) {
            Some(index) => (&rest[..index], &rest[index..]),
            None => (rest, "/"),
        };
        let (host, ipv6, port) = parse_authority(authority, tls)?;
        if !tls && !is_loopback(&host) {
            return Err(HttpError::NotHttps { host });
        }
        // The token endpoint carries a query; everything else is a plain path.
        let path = if target.starts_with('?') {
            format!("/{target}")
        } else {
            target.to_owned()
        };
        Ok(Self {
            tls,
            host,
            ipv6,
            port,
            path,
        })
    }

    /// Builds the URL for a registry (the scheme depends on whether it is a loopback test host).
    pub(crate) fn from_registry(registry: &str, path: &str) -> Result<Self, HttpError> {
        if !path.starts_with('/') {
            return Err(HttpError::Url("the request path must start with '/'"));
        }
        let scheme = if is_loopback(registry_host(registry)) {
            "http"
        } else {
            "https"
        };
        Self::parse(&format!("{scheme}://{registry}{path}"))
    }

    /// `Host` header value: host (`[v6]` bracketed) and a non-default port.
    fn authority(&self) -> String {
        let mut authority = if self.ipv6 {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let default = if self.tls { 443 } else { 80 };
        if self.port != default {
            authority.push(':');
            authority.push_str(&self.port.to_string());
        }
        authority
    }

    /// `(host, port)` — the identity used to decide whether the token may be forwarded.
    fn authority_key(&self) -> (&str, u16) {
        (self.host.as_str(), self.port)
    }
}

fn parse_authority(authority: &str, tls: bool) -> Result<(String, bool, u16), HttpError> {
    if authority.is_empty() {
        return Err(HttpError::Url("missing host"));
    }
    if let Some(inner) = authority.strip_prefix('[') {
        let (node, rest) = inner
            .split_once(']')
            .ok_or(HttpError::Url("unterminated IPv6 host"))?;
        if node.is_empty()
            || !node
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || matches!(b, b':' | b'.'))
        {
            return Err(HttpError::Url("invalid IPv6 host"));
        }
        let port = match rest {
            "" => default_port(tls),
            other => {
                let port = other
                    .strip_prefix(':')
                    .ok_or(HttpError::Url("invalid host suffix"))?;
                parse_port(port)?
            }
        };
        return Ok((node.to_ascii_lowercase(), true, port));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(parse_port(port)?)),
        None => (authority, None),
    };
    if host.is_empty()
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
    {
        return Err(HttpError::Url("invalid host"));
    }
    Ok((
        host.to_ascii_lowercase(),
        false,
        port.unwrap_or(default_port(tls)),
    ))
}

fn parse_port(port: &str) -> Result<u16, HttpError> {
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(HttpError::Port);
    }
    match port.parse::<u16>() {
        Ok(0) | Err(_) => Err(HttpError::Port),
        Ok(port) => Ok(port),
    }
}

fn default_port(tls: bool) -> u16 {
    if tls { 443 } else { 80 }
}

/// The host part of a validated `host[:port]` registry string.
fn registry_host(registry: &str) -> &str {
    match registry.strip_prefix('[') {
        Some(inner) => inner.split_once(']').map_or(inner, |(host, _)| host),
        None => registry.split_once(':').map_or(registry, |(host, _)| host),
    }
}

pub(crate) fn is_loopback(host: &str) -> bool {
    host == "127.0.0.1" || host == "::1"
}

/// Follows a `Location` value: absolute URLs are parsed (and re-checked against the policy),
/// root-relative ones keep the current scheme and authority.
fn redirect_target(base: &Url, location: &str) -> Result<Url, HttpError> {
    if location.is_empty() || !location.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(HttpError::Url("invalid redirect Location"));
    }
    if location.contains("://") {
        return Url::parse(location);
    }
    if let Some(rest) = location.strip_prefix('/') {
        // A root-relative target keeps the current (already validated) origin.
        let mut url = base.clone();
        url.path = format!("/{rest}");
        return Ok(url);
    }
    Err(HttpError::Url(
        "relative redirect targets are not supported",
    ))
}

/// Percent-encodes everything but the RFC 3986 unreserved characters; used to build query strings
/// from registry-controlled values without letting them inject another parameter.
pub(crate) fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push_str(&format!("{byte:02X}"));
        }
    }
    out
}

/// An HTTP response with its head fully read and its body read up to the caller's cap.
#[derive(Debug)]
pub(crate) struct Response {
    pub(crate) status: u16,
    /// Header names are lowercased, values are trimmed.
    headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

impl Response {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header == name)
            .map(|(_, value)| value.as_str())
    }
}

/// HTTP client with one shared TLS configuration.
pub(crate) struct Client {
    tls: TlsConnector,
    timeout: Duration,
}

impl Client {
    /// Client that trusts the bundled Mozilla root store (`webpki-roots`).
    pub(crate) fn new() -> Result<Self, HttpError> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        // Explicit provider: never touch the process-wide default (another component may install
        // one). `rustls` is configured for HTTP/1.1 only, which is all this client speaks.
        let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(tokio_rustls::rustls::DEFAULT_VERSIONS)
            .map_err(|e| HttpError::Tls(e.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            tls: TlsConnector::from(Arc::new(config)),
            timeout: REQUEST_TIMEOUT,
        })
    }

    /// `GET` `url`, following a bounded number of redirects, and read at most `max_body` bytes.
    ///
    /// `bearer` is sent only to the authority of the initial request; a redirect elsewhere (a blob
    /// CDN, in GHCR's case) gets the request without it.
    pub(crate) async fn get(
        &self,
        url: &Url,
        bearer: Option<&str>,
        accept: Option<&str>,
        max_body: usize,
        what: &'static str,
    ) -> Result<Response, HttpError> {
        if let Some(token) = bearer
            && !token.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(HttpError::InvalidToken);
        }
        tokio::time::timeout(
            self.timeout,
            self.get_inner(url, bearer, accept, max_body, what),
        )
        .await
        .map_err(|_| HttpError::Timeout { what })?
    }

    async fn get_inner(
        &self,
        url: &Url,
        bearer: Option<&str>,
        accept: Option<&str>,
        max_body: usize,
        what: &'static str,
    ) -> Result<Response, HttpError> {
        let origin = url.authority_key();
        let mut current = url.clone();
        let mut redirects = 0;
        loop {
            let bearer = if current.authority_key() == origin {
                bearer
            } else {
                None
            };
            let response = self
                .request(&current, bearer, accept, max_body, what)
                .await?;
            if !matches!(response.status, 301 | 302 | 303 | 307 | 308) {
                return Ok(response);
            }
            if redirects >= MAX_REDIRECTS {
                return Err(HttpError::TooManyRedirects(MAX_REDIRECTS));
            }
            let location = response
                .header("location")
                .ok_or(HttpError::MissingLocation)?;
            current = redirect_target(&current, location)?;
            redirects += 1;
        }
    }

    async fn request(
        &self,
        url: &Url,
        bearer: Option<&str>,
        accept: Option<&str>,
        max_body: usize,
        what: &'static str,
    ) -> Result<Response, HttpError> {
        let addr = format!("{}:{}", url.host, url.port);
        let tcp = TcpStream::connect((url.host.as_str(), url.port))
            .await
            .map_err(|source| HttpError::Connect {
                addr: addr.clone(),
                source,
            })?;
        let request = build_request(url, bearer, accept);
        if url.tls {
            let server_name = ServerName::try_from(url.host.clone())
                .map_err(|e| HttpError::Tls(format!("invalid server name {:?}: {e}", url.host)))?;
            let stream = self
                .tls
                .connect(server_name, tcp)
                .await
                .map_err(|e| HttpError::Tls(e.to_string()))?;
            exchange(stream, &request, max_body, what).await
        } else {
            exchange(tcp, &request, max_body, what).await
        }
    }
}

fn build_request(url: &Url, bearer: Option<&str>, accept: Option<&str>) -> Vec<u8> {
    let mut head = format!(
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: {USER_AGENT}\r\n",
        path = url.path,
        authority = url.authority(),
    );
    if let Some(accept) = accept {
        head.push_str("Accept: ");
        head.push_str(accept);
        head.push_str("\r\n");
    }
    if let Some(token) = bearer {
        head.push_str("Authorization: Bearer ");
        head.push_str(token);
        head.push_str("\r\n");
    }
    head.push_str("Connection: close\r\n\r\n");
    head.into_bytes()
}

async fn exchange<S>(
    mut stream: S,
    request: &[u8],
    max_body: usize,
    what: &'static str,
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
    let mut body = (&rest[..]).chain(stream);
    let body = read_body(&mut body, &headers, max_body, what).await?;
    Ok(Response {
        status,
        headers,
        body,
    })
}

async fn read_head<S>(stream: &mut S) -> Result<(Vec<u8>, Vec<u8>), HttpError>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(end) = find_head_end(&buffer) {
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

fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn parse_head(head: &[u8]) -> Result<(u16, Vec<(String, String)>), HttpError> {
    let text = std::str::from_utf8(head)
        .map_err(|_| HttpError::Protocol("response head is not valid UTF-8"))?;
    let mut lines = text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or(HttpError::Protocol("missing status line"))?;
    let status = parse_status(status_line)?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or(HttpError::Protocol("malformed response header"))?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return Err(HttpError::Protocol("malformed response header name"));
        }
        let value = value.trim_matches([' ', '\t']);
        if !value
            .bytes()
            .all(|b| b == b'\t' || (0x20..0x7f).contains(&b))
        {
            return Err(HttpError::Protocol("malformed response header value"));
        }
        headers.push((name.to_ascii_lowercase(), value.to_owned()));
    }
    Ok((status, headers))
}

/// `HTTP/1.x <code> …` → the code.
fn parse_status(line: &str) -> Result<u16, HttpError> {
    let mut parts = line.split(' ');
    if !parts.next().is_some_and(|v| v.starts_with("HTTP/1.")) {
        return Err(HttpError::Protocol("missing or invalid status line"));
    }
    let code: u16 = parts
        .next()
        .and_then(|code| code.trim().parse().ok())
        .ok_or(HttpError::Protocol("missing or invalid status code"))?;
    if !(100..=599).contains(&code) {
        return Err(HttpError::Protocol("status code out of range"));
    }
    Ok(code)
}

async fn read_body<R>(
    reader: &mut R,
    headers: &[(String, String)],
    max_body: usize,
    what: &'static str,
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
        return read_chunked(reader, max_body, what).await;
    }
    if let Some(length) = header("content-length") {
        let length: usize = length
            .trim()
            .parse()
            .map_err(|_| HttpError::Protocol("invalid Content-Length"))?;
        if length > max_body {
            return Err(HttpError::TooLarge {
                what,
                limit: max_body,
            });
        }
        let mut body = vec![0u8; length];
        reader.read_exact(&mut body).await?;
        return Ok(body);
    }
    read_to_end_capped(reader, max_body, what).await
}

async fn read_to_end_capped<R>(
    reader: &mut R,
    max_body: usize,
    what: &'static str,
) -> Result<Vec<u8>, HttpError>
where
    R: AsyncRead + Unpin,
{
    let mut body = Vec::new();
    let mut chunk = [0u8; 8 * 1024];
    loop {
        let read = reader.read(&mut chunk).await?;
        if read == 0 {
            return Ok(body);
        }
        if body.len() + read > max_body {
            return Err(HttpError::TooLarge {
                what,
                limit: max_body,
            });
        }
        body.extend_from_slice(&chunk[..read]);
    }
}

async fn read_chunked<R>(
    reader: &mut R,
    max_body: usize,
    what: &'static str,
) -> Result<Vec<u8>, HttpError>
where
    R: AsyncRead + Unpin,
{
    let mut body = Vec::new();
    loop {
        let line = read_line(reader, MAX_CHUNK_LINE).await?;
        let line = std::str::from_utf8(&line)
            .map_err(|_| HttpError::Protocol("invalid chunk size line"))?;
        let size = line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size, 16)
            .map_err(|_| HttpError::Protocol("invalid chunk size"))?;
        if size == 0 {
            // Trailers end with an empty line; they are read (bounded) and discarded.
            loop {
                let line = read_line(reader, MAX_CHUNK_LINE).await?;
                if line.is_empty() {
                    return Ok(body);
                }
            }
        }
        if body
            .len()
            .checked_add(size)
            .is_none_or(|len| len > max_body)
        {
            return Err(HttpError::TooLarge {
                what,
                limit: max_body,
            });
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

async fn read_line<R>(reader: &mut R, max: usize) -> Result<Vec<u8>, HttpError>
where
    R: AsyncRead + Unpin,
{
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let read = reader.read(&mut byte).await?;
        if read == 0 {
            return Err(HttpError::Protocol("connection closed mid-line"));
        }
        if byte[0] == b'\n' {
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(line);
        }
        if line.len() >= max {
            return Err(HttpError::Protocol("response line too long"));
        }
        line.push(byte[0]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// Runs `exchange` over an in-memory duplex pipe whose server side has already written
    /// `response` and closed its write half.
    async fn exchange_with(response: &[u8], max_body: usize) -> Result<Response, HttpError> {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        server.write_all(response).await.unwrap();
        server.shutdown().await.unwrap();
        exchange(client, b"GET / HTTP/1.1\r\n\r\n", max_body, "test").await
    }

    #[test]
    fn url_policy_allows_https_and_loopback_http_only() {
        let url = Url::parse("https://ghcr.io/v2/x/y/manifests/tag").unwrap();
        assert!(url.tls);
        assert_eq!(url.host, "ghcr.io");
        assert_eq!(url.port, 443);
        assert_eq!(url.path, "/v2/x/y/manifests/tag");
        assert_eq!(url.authority(), "ghcr.io");

        let url = Url::parse("http://127.0.0.1:5000/token?scope=a").unwrap();
        assert!(!url.tls);
        assert_eq!(url.host, "127.0.0.1");
        assert_eq!(url.port, 5000);
        assert_eq!(url.path, "/token?scope=a");
        assert_eq!(url.authority(), "127.0.0.1:5000");

        assert!(Url::parse("http://[::1]:5000/x").is_ok());
        assert!(matches!(
            Url::parse("http://example.com/x").unwrap_err(),
            HttpError::NotHttps { host } if host == "example.com"
        ));
        assert!(matches!(
            Url::parse("http://127.0.0.2/x").unwrap_err(),
            HttpError::NotHttps { host } if host == "127.0.0.2"
        ));
        assert!(matches!(
            Url::parse("ftp://example.com/x").unwrap_err(),
            HttpError::Scheme { .. }
        ));
        assert!(matches!(
            Url::parse("example.com").unwrap_err(),
            HttpError::Url(_)
        ));
        assert!(matches!(
            Url::parse("https://user:pass@example.com/x").unwrap_err(),
            HttpError::Url(_)
        ));
        assert!(matches!(
            Url::parse("https://example.com/x#fragment").unwrap_err(),
            HttpError::Url(_)
        ));
        assert!(matches!(
            Url::parse("https://example.com:99999/x").unwrap_err(),
            HttpError::Port
        ));
        assert!(matches!(
            Url::parse("https://exa mple.com/x").unwrap_err(),
            HttpError::Url(_)
        ));
    }

    #[test]
    fn registry_urls_use_https_except_on_loopback() {
        let url = Url::from_registry("ghcr.io", "/v2/a/b/manifests/c").unwrap();
        assert!(url.tls);
        let url = Url::from_registry("127.0.0.1:5000", "/v2/a/b").unwrap();
        assert!(!url.tls);
        assert_eq!(url.port, 5000);
        let url = Url::from_registry("[::1]:5000", "/v2/a/b").unwrap();
        assert!(!url.tls);
        assert!(matches!(
            Url::from_registry("ghcr.io", "v2/relative").unwrap_err(),
            HttpError::Url(_)
        ));
        assert_eq!(registry_host("ghcr.io:443"), "ghcr.io");
        assert_eq!(registry_host("[::1]:5000"), "::1");
    }

    #[test]
    fn redirect_targets_keep_or_change_the_origin() {
        let base = Url::parse("https://registry.example/v2/a/b/blobs/sha256:abcd").unwrap();
        let next = redirect_target(&base, "https://cdn.example/blob").unwrap();
        assert_eq!(next.host, "cdn.example");
        assert!(next.tls);
        let next = redirect_target(&base, "/other/path").unwrap();
        assert_eq!(next.host, "registry.example");
        assert_eq!(next.path, "/other/path");
        // A downgrade to plain HTTP is rejected by the policy, not followed.
        assert!(matches!(
            redirect_target(&base, "http://cdn.example/blob").unwrap_err(),
            HttpError::NotHttps { .. }
        ));
        assert!(matches!(
            redirect_target(&base, "relative/path").unwrap_err(),
            HttpError::Url(_)
        ));
        assert!(matches!(
            redirect_target(&base, "").unwrap_err(),
            HttpError::Url(_)
        ));
    }

    #[test]
    fn percent_encoding_escapes_query_separators() {
        assert_eq!(
            percent_encode("repository:jpalczewski/weglarka:pull"),
            "repository%3Ajpalczewski%2Fweglarka%3Apull"
        );
        assert_eq!(percent_encode("a-b.c_d~e"), "a-b.c_d~e");
        assert_eq!(percent_encode("a&b=c"), "a%26b%3Dc");
    }

    #[test]
    fn head_parsing_is_strict() {
        let (status, headers) =
            parse_head(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nWWW-Authenticate: Bearer\r\n\r\n")
                .unwrap();
        assert_eq!(status, 200);
        assert_eq!(headers.len(), 2);
        assert_eq!(
            headers
                .iter()
                .find(|(name, _)| name == "www-authenticate")
                .map(|(_, value)| value.as_str()),
            Some("Bearer")
        );

        assert!(matches!(
            parse_head(b"garbage\r\n\r\n").unwrap_err(),
            HttpError::Protocol(_)
        ));
        assert!(matches!(
            parse_head(b"HTTP/1.1 200 OK\r\nbad header\r\n\r\n").unwrap_err(),
            HttpError::Protocol(_)
        ));
        assert!(matches!(
            parse_head(b"HTTP/1.1 99 x\r\n\r\n").unwrap_err(),
            HttpError::Protocol(_)
        ));
    }

    #[tokio::test]
    async fn content_length_bodies_are_bounded() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let response = exchange_with(response, 16).await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"hello");

        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert!(matches!(
            exchange_with(response, 4).await.unwrap_err(),
            HttpError::TooLarge { limit: 4, .. }
        ));
        // A Content-Length that lies (more bytes than announced) must not leak into the body.
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhello";
        assert_eq!(exchange_with(response, 16).await.unwrap().body, b"he");
        // A truncated body is an i/o error, never a short body accepted as complete.
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello";
        assert!(matches!(
            exchange_with(response, 16).await.unwrap_err(),
            HttpError::Io(_)
        ));
    }

    #[tokio::test]
    async fn bodies_without_a_length_are_read_to_eof_with_a_cap() {
        let response = b"HTTP/1.1 200 OK\r\n\r\nhello";
        assert_eq!(exchange_with(response, 16).await.unwrap().body, b"hello");
        assert!(matches!(
            exchange_with(response, 4).await.unwrap_err(),
            HttpError::TooLarge { limit: 4, .. }
        ));
    }

    #[tokio::test]
    async fn chunked_bodies_are_decoded() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
            5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: 1\r\n\r\n";
        let response = exchange_with(response, 64).await.unwrap();
        assert_eq!(response.body, b"hello world");

        // The cap applies to the decoded size, not the chunk framing.
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
            5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n";
        assert!(matches!(
            exchange_with(response, 9).await.unwrap_err(),
            HttpError::TooLarge { limit: 9, .. }
        ));

        // A chunk terminator that is not CRLF is a protocol error.
        let response =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXX0\r\n\r\n";
        assert!(matches!(
            exchange_with(response, 64).await.unwrap_err(),
            HttpError::Protocol(_)
        ));
    }

    #[tokio::test]
    async fn oversized_heads_and_status_codes_are_rejected() {
        let mut long_head = b"HTTP/1.1 200 OK\r\n".to_vec();
        long_head.extend_from_slice(&vec![b'x'; MAX_HEAD]);
        long_head.extend_from_slice(b"\r\n\r\n");
        assert!(matches!(
            exchange_with(&long_head, 64).await.unwrap_err(),
            HttpError::Protocol(_)
        ));

        let response = b"HTTP/1.1 100 Continue\r\n\r\n";
        assert!(matches!(
            exchange_with(response, 64).await.unwrap_err(),
            HttpError::Protocol(_)
        ));
        // The connection closing before the head is complete is an error.
        let response = b"HTTP/1.1 200 OK\r\n";
        assert!(matches!(
            exchange_with(response, 64).await.unwrap_err(),
            HttpError::Protocol(_)
        ));
    }

    #[test]
    fn request_builder_sends_only_the_intended_headers() {
        let url = Url::parse("https://ghcr.io/v2/x/y/manifests/sha256-ab.sig").unwrap();
        let request = build_request(&url, Some("tok123"), Some("application/json"));
        let text = std::str::from_utf8(&request).unwrap();
        assert!(text.starts_with("GET /v2/x/y/manifests/sha256-ab.sig HTTP/1.1\r\n"));
        assert!(text.contains("\r\nHost: ghcr.io\r\n"), "{text}");
        assert!(text.contains("\r\nAuthorization: Bearer tok123\r\n"));
        assert!(text.contains("\r\nAccept: application/json\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
        assert_eq!(text.matches("\r\n\r\n").count(), 1);
    }
}
