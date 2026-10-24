//! HTTP probe of the health gate (`health.http`): the daemon requests `GET path` through the ingress
//! nginx (the same route as real traffic) and compares the status. **Owner: session 2 (iteration 2).**
//!
//! The daemon shares `net-weglarka` with `weglarka-nginx`, so it reaches nginx by container name and
//! never joins an app network. nginx routes by `Host`, hence the app's first domain
//! (`state::validate_app` requires one when `health.http` is set). The request deliberately carries
//! no `X-Forwarded-*`: whether nginx trusts the daemon's address depends on `[ingress] trusted_proxies`
//! (by default it does not, docs/decisions/0032), and a probe must not exercise — or abuse — that trust.
//! See docs/decisions/0010-health-http-probe.md.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use weglarka_core::app::HttpProbe;
use weglarka_core::limits::{HttpProber, ProbeFuture};

use crate::ingress::NGINX_CONTAINER;

/// Probes through the ingress nginx at `addr` (`host:port`, resolved per request — the container's IP
/// changes when it is recreated).
pub struct NginxProber {
    addr: String,
}

impl NginxProber {
    pub fn new(addr: impl Into<String>) -> Self {
        Self { addr: addr.into() }
    }

    /// `weglarka-nginx` on `net-weglarka`, at the port the generated config listens on.
    pub fn default_target() -> Self {
        let port = weglarka_ingress::nginx::NginxOptions::new(Vec::new()).listen_port;
        Self::new(format!("{NGINX_CONTAINER}:{port}"))
    }
}

impl HttpProber for NginxProber {
    fn probe<'a>(&'a self, host: &'a str, probe: &'a HttpProbe) -> ProbeFuture<'a> {
        Box::pin(async move {
            let timeout = Duration::from_secs(probe.timeout_secs.max(1));
            let status = tokio::time::timeout(timeout, get_status(&self.addr, host, &probe.path))
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

/// One `GET` over a fresh connection (`Connection: close`); returns the status of the response.
/// Redirects are not followed and the body is not read.
async fn get_status(addr: &str, host: &str, path: &str) -> Result<u16, String> {
    if !token_ok(host) || !token_ok(path) || !path.starts_with('/') {
        return Err("invalid host or path for a probe".into());
    }
    let mut stream = TcpStream::connect(addr)
        .await
        .map_err(|e| format!("cannot connect to {addr}: {e}"))?;
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
    use tokio::net::TcpListener;

    /// Serves one canned response; returns the address and the raw request it received.
    async fn serve_once(response: &'static str) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut req = vec![0u8; 2048];
            let n = s.read(&mut req).await.unwrap();
            s.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8_lossy(&req[..n]).into_owned()
        });
        (addr, task)
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
        let (addr, req) = serve_once("HTTP/1.1 204 No Content\r\n\r\n").await;
        NginxProber::new(addr)
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
        let (addr, _) = serve_once("HTTP/1.1 301 Moved\r\nLocation: /x\r\n\r\n").await;
        let err = NginxProber::new(addr)
            .probe("a.example.com", &probe("/", 200, 2))
            .await
            .unwrap_err();
        assert_eq!(err, "status 301, expected 200");
    }

    #[tokio::test]
    async fn connection_refused_and_timeouts_are_errors() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        drop(listener);
        assert!(
            NginxProber::new(addr)
                .probe("a.example.com", &probe("/", 200, 1))
                .await
                .is_err()
        );

        // Accepts but never answers.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let _hold = tokio::spawn(async move {
            let (_s, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let err = NginxProber::new(addr)
            .probe("a.example.com", &probe("/", 200, 1))
            .await
            .unwrap_err();
        assert!(err.contains("no answer"), "{err}");
    }

    #[tokio::test]
    async fn header_injection_is_refused() {
        let p = NginxProber::new("127.0.0.1:1");
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
