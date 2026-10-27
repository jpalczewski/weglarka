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
//! `X-Real-IP: unix:` and trusts no forwarded value.

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
    let mut stream = UnixStream::connect(socket)
        .await
        .map_err(|e| format!("cannot connect to {}: {e}", socket.display()))?;
    get_status(&mut stream, host, path).await
}

fn check_request(host: &str, path: &str) -> Result<(), String> {
    if token_ok(host) && token_ok(path) && path.starts_with('/') {
        Ok(())
    } else {
        Err("invalid host or path for a probe".into())
    }
}

/// One `GET` on a fresh connection (`Connection: close`); returns the status of the response.
/// Redirects are not followed and the body is not read.
async fn get_status<S>(stream: &mut S, host: &str, path: &str) -> Result<u16, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    check_request(host, path)?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: weglarka-health-probe\r\n\
         Accept: */*\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("write failed: {e}"))?;
    // The status line fits well within 64 bytes: "HTTP/1.1 200 ".
    let mut head = Vec::with_capacity(64);
    let mut buf = [0u8; 64];
    while head.len() < 12 && !head.contains(&b'\n') {
        let n = stream
            .read(&mut buf)
            .await
            .map_err(|e| format!("read failed: {e}"))?;
        if n == 0 {
            break;
        }
        head.extend_from_slice(&buf[..n]);
    }
    if head.is_empty() {
        return Err("no response (connection closed; no server for this Host yet?)".to_owned());
    }
    parse_status(&head).ok_or_else(|| "malformed HTTP response".to_owned())
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

    #[test]
    fn status_line_parsing() {
        assert_eq!(parse_status(b"HTTP/1.1 200 OK\r\n"), Some(200));
        assert_eq!(parse_status(b"HTTP/1.0 503 \r\n"), Some(503));
        assert_eq!(parse_status(b"garbage"), None);
        assert_eq!(parse_status(b"HTTP/1.1 99 x\r\n"), None);
    }
}
