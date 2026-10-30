//! HTTP probe of the health gate (`health.http`): the daemon requests `GET path` through the ingress
//! nginx and compares the status. **Owner: session 2 (iteration 2).**
//!
//! The request goes over the **probe socket** (docs/decisions/0054): a plain-HTTP `listen unix:` that
//! nginx adds to every app `server` in both modes, in a `0700` directory mounted into nginx only. So the
//! probe hits the same `server`, `location` and `$upstream` as real traffic and tests routing and the
//! upstream (docs/decisions/0010) — but not TLS termination, the HTTPS redirect or authentication,
//! which only a client-facing listener has. nginx routes by `Host`, hence the app's first domain
//! (`state::validate_app` requires one when `health.http` is set). The request deliberately carries no
//! `X-Forwarded-*`; on this socket `$remote_addr` is the literal `unix:`, so an upstream sees
//! `X-Real-IP: unix:` and trusts no forwarded value. The exception is the traffic to the identity
//! provider (JWKS, authz): it announces `X-Forwarded-Proto: https`, which nginx honours on this socket
//! only, because the provider's OIDC endpoints refuse a request that claims plain HTTP.

use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;
use weglarka_model::app::HttpProbe;
use weglarka_model::limits::{HttpProber, ProbeFuture};

/// Probes through the ingress nginx's probe socket at `socket` (a path on the daemon's host).
pub struct NginxProber {
    socket: PathBuf,
}

impl NginxProber {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
        }
    }
}

impl HttpProber for NginxProber {
    fn probe<'a>(&'a self, host: &'a str, probe: &'a HttpProbe) -> ProbeFuture<'a> {
        Box::pin(async move {
            let timeout = Duration::from_secs(probe.timeout_secs.max(1));
            let status = tokio::time::timeout(timeout, probe_once(&self.socket, host, &probe.path))
                .await
                .map_err(|_| format!("no answer within {}s", timeout.as_secs()))??;
            if status == probe.expect_status {
                Ok(())
            } else {
                Err(format!("status {status}, expected {}", probe.expect_status))
            }
        })
    }
}

/// Header-safe: no whitespace or control characters that could split the request line or headers.
fn token_ok(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_graphic())
}

/// Connects to the socket and sends one `GET` over it (see [`get_status`]).
async fn probe_once(socket: &std::path::Path, host: &str, path: &str) -> Result<u16, String> {
    // Validated before connecting, so a bad request never reaches nginx (`get_status` checks again).
    check_request(host, path)?;
    let mut stream = connect(socket).await?;
    get_status(&mut stream, host, path).await
}

async fn connect(socket: &std::path::Path) -> Result<UnixStream, String> {
    UnixStream::connect(socket)
        .await
        .map_err(|e| format!("cannot connect to {}: {e}", socket.display()))
}

fn check_request(host: &str, path: &str) -> Result<(), String> {
    if token_ok(host) && token_ok(path) && path.starts_with('/') {
        Ok(())
    } else {
        Err("invalid host or path for a probe".into())
    }
}

/// What the probe socket answered: the status, the header names (lowercased) with their values, and
/// the body (empty unless the caller asked for one).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ProbeResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl ProbeResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Longest response head read; nginx's own default `large_client_header_buffers` is of this order.
const MAX_HEAD: usize = 16 * 1024;
const PROBE_BUDGET: Duration = Duration::from_secs(5);

/// Requests to the identity provider claim the scheme its clients use: the provider's OIDC endpoints
/// answer 400 to a request that says it came over plain HTTP, and the probe socket itself is plain
/// HTTP. nginx honours this header only on the probe socket (issue #321). The health gate sends none.
const PROVIDER_HEADERS: &[(&str, &str)] = &[("X-Forwarded-Proto", "https")];

/// How much of the answer an exchange reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Want {
    /// Only the status line: the health gate asks nothing more, so a peer that sends a short or odd
    /// head (or none after the status line) still answers it.
    Status,
    /// The whole head, up to [`MAX_HEAD`].
    Head,
    /// The head and a body of at most this many bytes, read until the peer closes.
    Body(usize),
}

/// One `GET` on a fresh connection (`Connection: close`) with `headers` added; reads as much of the
/// answer as `want` says. A body is requested over `HTTP/1.0` so nginx answers without chunked framing;
/// the other two use `HTTP/1.1`. Redirects are not followed.
async fn exchange<S>(
    stream: &mut S,
    host: &str,
    path: &str,
    user_agent: &str,
    headers: &[(&str, &str)],
    want: Want,
) -> Result<ProbeResponse, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    check_request(host, path)?;
    if headers
        .iter()
        .any(|(n, v)| !token_ok(n) || n.contains(':') || v.bytes().any(|b| b.is_ascii_control()))
    {
        return Err("invalid header for a probe".into());
    }
    let version = if matches!(want, Want::Body(_)) {
        "1.0"
    } else {
        "1.1"
    };
    let mut request = format!(
        "GET {path} HTTP/{version}\r\nHost: {host}\r\nUser-Agent: {user_agent}\r\n\
         Accept: */*\r\nConnection: close\r\n"
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("write failed: {e}"))?;

    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break Some(i + 4);
        }
        // The status line fits well within 64 bytes: "HTTP/1.1 200 ".
        if want == Want::Status && (buf.len() >= 12 || buf.contains(&b'\n')) {
            break None;
        }
        if buf.len() >= MAX_HEAD {
            return Err("response head too large".into());
        }
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| format!("read failed: {e}"))?;
        if n == 0 {
            break None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    if buf.is_empty() {
        return Err("no response (connection closed; no server for this Host yet?)".to_owned());
    }
    let status = parse_status(&buf).ok_or_else(|| "malformed HTTP response".to_owned())?;
    let (Some(head_end), false) = (head_end, want == Want::Status) else {
        return Ok(ProbeResponse {
            status,
            ..ProbeResponse::default()
        });
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let headers = head
        .lines()
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let mut body = Vec::new();
    if let Want::Body(max_body) = want {
        body.extend_from_slice(&buf[head_end..]);
        while body.len() <= max_body {
            let n = stream
                .read(&mut chunk)
                .await
                .map_err(|e| format!("read failed: {e}"))?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }
        if body.len() > max_body {
            return Err(format!("response body longer than {max_body} bytes"));
        }
    }
    Ok(ProbeResponse {
        status,
        headers,
        body,
    })
}

/// One `GET` on a fresh connection; returns the status of the response. Only the status line is read.
async fn get_status<S>(stream: &mut S, host: &str, path: &str) -> Result<u16, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    exchange(
        stream,
        host,
        path,
        "weglarka-health-probe",
        &[],
        Want::Status,
    )
    .await
    .map(|r| r.status)
}

/// One `GET` of `path` with `Host: host` over the probe socket; the status of the answer (5 s budget).
/// `doctor identity.provider` asks the provider's health endpoint this way.
pub async fn get_over_probe(
    socket: &std::path::Path,
    host: &str,
    path: &str,
) -> Result<u16, String> {
    tokio::time::timeout(PROBE_BUDGET, probe_once(socket, host, path))
        .await
        .map_err(|_| "no answer within 5s".to_owned())?
}

/// One `GET` of `path` with `Host: host` over the probe socket, returning the head and a body of at
/// most `max_body` bytes (5 s budget). The token listener fetches the provider's JWKS this way, so it
/// announces `X-Forwarded-Proto: https` ([`PROVIDER_HEADERS`]).
pub async fn probe_get(
    socket: &std::path::Path,
    host: &str,
    path: &str,
    max_body: usize,
) -> Result<ProbeResponse, String> {
    check_request(host, path)?;
    tokio::time::timeout(PROBE_BUDGET, async {
        let mut stream = connect(socket).await?;
        exchange(
            &mut stream,
            host,
            path,
            "weglarka-daemon",
            PROVIDER_HEADERS,
            Want::Body(max_body),
        )
        .await
    })
    .await
    .map_err(|_| "no answer within 5s".to_owned())?
}

/// What the identity provider answered an authz request with (`doctor identity.forward`).
#[derive(Debug, PartialEq, Eq)]
pub struct AuthzAnswer {
    pub status: u16,
    pub has_location: bool,
}

/// Asks the provider's `/api/authz/auth-request` for `original_url` over the probe socket, with the
/// issuer's host as `Host` — the way nginx's own subrequest does, minus the session. No cookie: a
/// healthy, correctly scoped provider answers 401 with a `Location`.
pub async fn authz_probe(
    socket: &std::path::Path,
    issuer_host: &str,
    original_url: &str,
) -> Result<AuthzAnswer, String> {
    if !token_ok(issuer_host) || !token_ok(original_url) {
        return Err("invalid host or URL for an authz probe".into());
    }
    tokio::time::timeout(PROBE_BUDGET, async {
        let mut stream = connect(socket).await?;
        let answer = exchange(
            &mut stream,
            issuer_host,
            "/api/authz/auth-request",
            "weglarka-doctor",
            &[
                PROVIDER_HEADERS[0],
                ("X-Original-URL", original_url),
                ("X-Original-Method", "GET"),
            ],
            Want::Head,
        )
        .await?;
        Ok(AuthzAnswer {
            status: answer.status,
            has_location: answer.header("location").is_some(),
        })
    })
    .await
    .map_err(|_| "no answer within 5s".to_owned())?
}

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
    use tokio::net::{TcpListener, UnixListener};

    /// A probe socket in a fresh directory; the guard keeps the directory alive.
    fn socket() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("probe.sock");
        (dir, path)
    }

    /// Serves one canned response on `path`; returns the raw request it received.
    fn serve_once(
        path: &std::path::Path,
        response: &'static str,
    ) -> tokio::task::JoinHandle<String> {
        let listener = UnixListener::bind(path).unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut req = vec![0u8; 2048];
            let n = s.read(&mut req).await.unwrap();
            s.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8_lossy(&req[..n]).into_owned()
        })
    }

    fn probe(path: &str, expect: u16, timeout_secs: u64) -> HttpProbe {
        HttpProbe {
            path: path.into(),
            expect_status: expect,
            timeout_secs,
        }
    }

    #[tokio::test]
    async fn sends_host_and_no_forwarded_headers_and_matches_status() {
        let (_dir, sock) = socket();
        let req = serve_once(&sock, "HTTP/1.1 204 No Content\r\n\r\n");
        NginxProber::new(&sock)
            .probe("who.example.com", &probe("/up?x=1", 204, 2))
            .await
            .unwrap();
        let req = req.await.unwrap();
        assert!(req.starts_with("GET /up?x=1 HTTP/1.1\r\n"), "{req}");
        assert!(req.contains("\r\nHost: who.example.com\r\n"), "{req}");
        assert!(!req.to_ascii_lowercase().contains("x-forwarded"), "{req}");
    }

    #[tokio::test]
    async fn provider_requests_announce_https_and_the_health_gate_does_not() {
        let (_dir, sock) = socket();
        let req = serve_once(&sock, "HTTP/1.0 200 OK\r\n\r\n{}");
        probe_get(&sock, "auth.example.com", "/jwks.json", 1024)
            .await
            .unwrap();
        let req = req.await.unwrap();
        assert!(req.contains("\r\nX-Forwarded-Proto: https\r\n"), "{req}");
        assert!(req.contains("\r\nHost: auth.example.com\r\n"), "{req}");

        let (_dir, sock) = socket();
        let req = serve_once(&sock, "HTTP/1.1 401 Unauthorized\r\nLocation: /x\r\n\r\n");
        authz_probe(&sock, "auth.example.com", "https://app.example.com/")
            .await
            .unwrap();
        let req = req.await.unwrap();
        assert!(req.contains("\r\nX-Forwarded-Proto: https\r\n"), "{req}");
    }

    #[tokio::test]
    async fn wrong_status_is_reported_and_redirects_are_not_followed() {
        let (_dir, sock) = socket();
        let _served = serve_once(&sock, "HTTP/1.1 301 Moved\r\nLocation: /x\r\n\r\n");
        let err = NginxProber::new(&sock)
            .probe("a.example.com", &probe("/", 200, 2))
            .await
            .unwrap_err();
        assert_eq!(err, "status 301, expected 200");
    }

    #[tokio::test]
    async fn a_missing_socket_and_a_silent_peer_are_errors() {
        let (_dir, sock) = socket();
        let err = NginxProber::new(&sock)
            .probe("a.example.com", &probe("/", 200, 1))
            .await
            .unwrap_err();
        assert!(err.contains("cannot connect"), "{err}");

        // Accepts but never answers.
        let listener = UnixListener::bind(&sock).unwrap();
        let _hold = tokio::spawn(async move {
            let (_s, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let err = NginxProber::new(&sock)
            .probe("a.example.com", &probe("/", 200, 1))
            .await
            .unwrap_err();
        assert!(err.contains("no answer"), "{err}");
    }

    #[tokio::test]
    async fn authz_probe_reports_status_and_location() {
        let (_dir, sock) = socket();
        let req = serve_once(
            &sock,
            "HTTP/1.1 401 Unauthorized\r\nLocation: https://auth.example.com/\r\n\r\n",
        );
        let answer = authz_probe(&sock, "auth.example.com", "https://app.example.com/")
            .await
            .unwrap();
        assert_eq!(
            answer,
            AuthzAnswer {
                status: 401,
                has_location: true
            }
        );
        let req = req.await.unwrap();
        assert!(
            req.starts_with("GET /api/authz/auth-request HTTP/1.1\r\n"),
            "{req}"
        );
        assert!(req.contains("\r\nHost: auth.example.com\r\n"), "{req}");
        assert!(
            req.contains("\r\nX-Original-URL: https://app.example.com/\r\n"),
            "{req}"
        );
    }

    /// `get_status` is transport-generic: the same request goes over TCP.
    #[tokio::test]
    async fn get_status_works_over_any_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _served = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut req = [0u8; 512];
            let _ = s.read(&mut req).await.unwrap();
            s.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
        });
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        assert_eq!(get_status(&mut stream, "a.example.com", "/").await, Ok(200));
    }

    #[tokio::test]
    async fn header_injection_is_refused() {
        let p = NginxProber::new("/nonexistent/probe.sock");
        for (host, path) in [
            ("a.example.com\r\nX: y", "/"),
            ("a.example.com", "/ HTTP/1.1\r\nX: y"),
            ("a.example.com", "no-slash"),
        ] {
            let err = p.probe(host, &probe(path, 200, 1)).await.unwrap_err();
            assert!(err.contains("invalid"), "{err}");
        }
    }

    #[tokio::test]
    async fn probe_get_returns_headers_and_a_bounded_body() {
        let (_dir, sock) = socket();
        let req = serve_once(
            &sock,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"keys\":[]}",
        );
        let got = probe_get(&sock, "auth.example.com", "/jwks.json", 1024)
            .await
            .unwrap();
        assert_eq!(got.status, 200);
        assert_eq!(got.header("content-type"), Some("application/json"));
        assert_eq!(got.body, br#"{"keys":[]}"#);
        let req = req.await.unwrap();
        // HTTP/1.0 so nginx does not chunk the body; the Host still routes to the provider.
        assert!(req.starts_with("GET /jwks.json HTTP/1.0\r\n"), "{req}");
        assert!(req.contains("\r\nHost: auth.example.com\r\n"), "{req}");

        let (_dir, sock) = socket();
        let _served = serve_once(&sock, "HTTP/1.1 200 OK\r\n\r\n0123456789");
        let err = probe_get(&sock, "auth.example.com", "/x", 4)
            .await
            .unwrap_err();
        assert!(err.contains("longer than 4 bytes"), "{err}");
    }

    #[test]
    fn status_line_parsing() {
        assert_eq!(parse_status(b"HTTP/1.1 200 OK\r\n"), Some(200));
        assert_eq!(parse_status(b"HTTP/1.0 503 \r\n"), Some(503));
        assert_eq!(parse_status(b"garbage"), None);
        assert_eq!(parse_status(b"HTTP/1.1 99 x\r\n"), None);
    }
}
