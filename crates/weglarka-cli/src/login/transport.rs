//! The CLI's [`weglarka_oidc::Transport`]: HTTP/1.1 over TCP, TLS through `rustls` (`ring`, bundled
//! roots), one connection per request, no redirects (docs/decisions/0060).
//!
//! It is deliberately small instead of `reqwest`: the CLI stays a lean binary and the dependency
//! guard keeps `reqwest` out of it. Plain `http://` is accepted for loopback addresses only (a
//! provider on the same machine, or a test).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::Request;
use hyper::header::{self, HeaderValue};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use weglarka_oidc::{Error, HttpResponse, Secret, Transport, Url};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// The whole exchange after connecting, headers and body included.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);
const USER_AGENT: &str = concat!("weglarka-cli/", env!("CARGO_PKG_VERSION"));

pub struct HyperTransport {
    tls: TlsConnector,
}

impl HyperTransport {
    pub fn new() -> Result<Self, rustls::Error> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::with_roots(roots)
    }

    /// A custom root store: tests with a self-signed certificate, or a private PKI.
    pub fn with_roots(roots: RootCertStore) -> Result<Self, rustls::Error> {
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots)
                .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            tls: TlsConnector::from(Arc::new(config)),
        })
    }

    async fn send(
        &self,
        url: &Url,
        method: &'static str,
        headers: Vec<(header::HeaderName, HeaderValue)>,
        body: Bytes,
        limit: usize,
    ) -> Result<HttpResponse, Error> {
        let mut request = Request::builder()
            .method(method)
            .uri(path_and_query(url))
            .header(header::HOST, host_header(url)?)
            .header(header::USER_AGENT, USER_AGENT)
            .header(header::ACCEPT, "application/json")
            .header(header::CONNECTION, "close");
        for (name, value) in headers {
            request = request.header(name, value);
        }
        let request = request
            .body(Full::new(body))
            .map_err(|_| network("the request is not valid"))?;
        tokio::time::timeout(EXCHANGE_TIMEOUT, self.exchange(url, request, limit))
            .await
            .map_err(|_| network("the provider took too long to answer"))?
    }

    async fn exchange(
        &self,
        url: &Url,
        request: Request<Full<Bytes>>,
        limit: usize,
    ) -> Result<HttpResponse, Error> {
        let stream = self.connect_origin(url).await?;
        round_trip(TokioIo::new(stream), request, limit).await
    }

    /// A connection to the origin of `url`: TLS for `https`, plain TCP for `http` on loopback only.
    pub async fn connect_origin(&self, url: &Url) -> Result<Stream, Error> {
        let host = bare_host(url).ok_or_else(|| network("the URL has no host"))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| network("the URL has no port"))?;
        match url.scheme() {
            "https" => {
                let tcp = connect(&host, port).await?;
                let name = ServerName::try_from(host.clone())
                    .map_err(|_| network("the host is not a valid TLS name"))?;
                let tls = self
                    .tls
                    .connect(name, tcp)
                    .await
                    .map_err(|e| network(&format!("TLS handshake failed: {e}")))?;
                Ok(Stream::Tls(Box::new(tls)))
            }
            "http" if is_loopback(&host) => Ok(Stream::Plain(connect(&host, port).await?)),
            _ => Err(network("refusing a non-https URL")),
        }
    }
}

/// A connected socket, with or without TLS.
pub enum Stream {
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    Plain(TcpStream),
}

impl tokio::io::AsyncRead for Stream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            Self::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for Stream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Tls(s) => std::pin::Pin::new(s).poll_write(cx, data),
            Self::Plain(s) => std::pin::Pin::new(s).poll_write(cx, data),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tls(s) => std::pin::Pin::new(s).poll_flush(cx),
            Self::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tls(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            Self::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl Transport for HyperTransport {
    async fn get(&self, url: &Url, limit: usize) -> Result<HttpResponse, Error> {
        self.send(url, "GET", Vec::new(), Bytes::new(), limit).await
    }

    async fn post_form(
        &self,
        url: &Url,
        authorization: Option<&Secret>,
        body: String,
        limit: usize,
    ) -> Result<HttpResponse, Error> {
        let mut headers = vec![(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        )];
        if let Some(value) = authorization {
            let mut value = HeaderValue::from_str(value.expose())
                .map_err(|_| network("the credentials are not a header value"))?;
            value.set_sensitive(true);
            headers.push((header::AUTHORIZATION, value));
        }
        self.send(url, "POST", headers, Bytes::from(body), limit)
            .await
    }
}

fn network(reason: &str) -> Error {
    Error::Network(reason.to_owned())
}

async fn connect(host: &str, port: u16) -> Result<TcpStream, Error> {
    tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port)))
        .await
        .map_err(|_| network("connecting timed out"))?
        .map_err(|e| network(&format!("cannot connect to {host}:{port}: {e}")))
}

async fn round_trip<I>(
    io: I,
    request: Request<Full<Bytes>>,
    limit: usize,
) -> Result<HttpResponse, Error>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| network(&format!("HTTP handshake failed: {e}")))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let response = sender
        .send_request(request)
        .await
        .map_err(|e| network(&format!("the request failed: {e}")))?;
    let status = response.status().as_u16();
    // `Limited` stops reading at the cap, so a lying `Content-Length` (or a endless chunked
    // stream) cannot make the CLI allocate more.
    let body = Limited::new(response.into_body(), limit)
        .collect()
        .await
        .map_err(|_| network("the answer is larger than the allowed size or was cut short"))?
        .to_bytes();
    Ok(HttpResponse {
        status,
        body: body.to_vec(),
    })
}

fn path_and_query(url: &Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_owned(),
    }
}

fn bare_host(url: &Url) -> Option<String> {
    url.host_str()
        .map(|h| h.trim_matches(['[', ']']).to_owned())
}

fn is_loopback(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

pub(super) fn host_header(url: &Url) -> Result<HeaderValue, Error> {
    let host = url
        .host_str()
        .ok_or_else(|| network("the URL has no host"))?;
    let value = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    HeaderValue::from_str(&value).map_err(|_| network("the host is not a header value"))
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    /// Answers one request with `response`, and hands back what it received.
    async fn serve_once(response: &'static str) -> (Url, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!(
            "http://{}/token?x=1",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut seen = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = socket.read(&mut buf).await.unwrap();
                seen.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&seen);
                if let Some(head_end) = text.find("\r\n\r\n") {
                    let length = text
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .map(str::to_owned)
                        })
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if seen.len() >= head_end + 4 + length {
                        break;
                    }
                }
            }
            socket.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8_lossy(&seen).into_owned()
        });
        (url, task)
    }

    #[tokio::test]
    async fn posts_a_form_with_the_credentials_and_returns_an_error_body() {
        let (url, seen) = serve_once(
            "HTTP/1.1 400 Bad Request\r\nContent-Length: 33\r\nConnection: close\r\n\r\n{\"error\":\"authorization_pending\"}",
        )
        .await;
        let transport = HyperTransport::new().unwrap();
        let basic = Secret::new("Basic abc");
        let response = transport
            .post_form(&url, Some(&basic), "a=b".into(), 1024)
            .await
            .unwrap();
        assert_eq!(response.status, 400);
        assert_eq!(response.body, br#"{"error":"authorization_pending"}"#);
        let request = seen.await.unwrap();
        assert!(request.starts_with("POST /token?x=1 HTTP/1.1\r\n"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: basic abc\r\n")
        );
        assert!(request.ends_with("a=b"));
    }

    #[tokio::test]
    async fn an_answer_over_the_cap_is_refused() {
        let (url, _) = serve_once(
            "HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\n0123456789",
        )
        .await;
        let transport = HyperTransport::new().unwrap();
        assert!(matches!(
            transport.get(&url, 4).await,
            Err(Error::Network(_))
        ));
    }

    #[tokio::test]
    async fn plain_http_is_for_loopback_only() {
        let transport = HyperTransport::new().unwrap();
        let url = Url::parse("http://provider.example.com/x").unwrap();
        assert!(matches!(
            transport.get(&url, 1024).await,
            Err(Error::Network(m)) if m.contains("non-https")
        ));
    }
}
