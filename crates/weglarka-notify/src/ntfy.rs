//! ntfy channel: publishes through ntfy's JSON API (`POST <base>/`).
//!
//! The JSON form is used instead of ntfy's header form (`Title:`, `Priority:` …) because header values
//! must be ASCII and would need escaping for a UTF-8 title; the token, which *is* a header, is validated
//! by the settings (printable ASCII only).

use std::time::Duration;

use serde::Serialize;
use weglarka_http::reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HOST, HeaderValue};
use weglarka_http::{HttpError, Purpose};

use crate::channel::{Channel, ChannelError, SendFuture};
use crate::endpoint::Endpoint;
use crate::message::Message;

/// A single delivery attempt must not hold the worker longer than this (the HTTP client's total
/// timeout for [`Purpose::Notify`] is the same value).
pub const SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// ntfy publish body (`POST <base>/`).
#[derive(Debug, Serialize)]
struct Publish<'a> {
    topic: &'a str,
    title: &'a str,
    message: &'a str,
    priority: u8,
    #[serde(skip_serializing_if = "is_empty")]
    tags: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    click: Option<&'a str>,
}

fn is_empty(tags: &&[String]) -> bool {
    tags.is_empty()
}

/// ntfy channel. `Debug` prints whether a token is set, never the token.
pub struct NtfyChannel {
    client: weglarka_http::reqwest::Client,
    endpoint: Endpoint,
    topic: String,
    token: Option<String>,
}

impl std::fmt::Debug for NtfyChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NtfyChannel")
            .field("endpoint", &self.endpoint)
            .field("topic", &self.topic)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl NtfyChannel {
    pub fn new(
        endpoint: Endpoint,
        topic: impl Into<String>,
        token: Option<String>,
    ) -> Result<Self, HttpError> {
        Ok(Self::with_client(
            weglarka_http::client(Purpose::Notify)?,
            endpoint,
            topic,
            token,
        ))
    }

    /// Channel over a prepared client (the tests trust a self-signed certificate).
    pub fn with_client(
        client: weglarka_http::reqwest::Client,
        endpoint: Endpoint,
        topic: impl Into<String>,
        token: Option<String>,
    ) -> Self {
        Self {
            client,
            endpoint,
            topic: topic.into(),
            token,
        }
    }

    /// `POST <base>/` with the JSON body; the token becomes a *sensitive* `Authorization` header
    /// (redacted in `Debug`, never indexed by HTTP/2 header compression).
    async fn post(&self, body: Vec<u8>) -> Result<u16, ChannelError> {
        let mut request = self
            .client
            .post(self.endpoint.url())
            .header(HOST, self.endpoint.host.as_str())
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json")
            .body(body);
        if let Some(token) = &self.token {
            let mut value = HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| {
                ChannelError::Permanent("the ntfy token is not a valid header value".into())
            })?;
            value.set_sensitive(true);
            request = request.header(AUTHORIZATION, value);
        }
        let response = request.send().await.map_err(classify)?;
        Ok(response.status().as_u16())
    }
}

impl Channel for NtfyChannel {
    fn name(&self) -> &'static str {
        "ntfy"
    }

    fn send<'a>(&'a self, message: &'a Message) -> SendFuture<'a> {
        Box::pin(async move {
            let publish = Publish {
                topic: &self.topic,
                title: &message.title,
                message: &message.body,
                priority: message.priority,
                tags: &message.tags,
                click: message.click.as_deref(),
            };
            let body = serde_json::to_vec(&publish).map_err(|e| {
                ChannelError::Permanent(format!("cannot encode the ntfy request: {e}"))
            })?;
            verdict(self.post(body).await?)
        })
    }
}

/// Network-level errors are retryable: the daemon may be behind a proxy that is being restarted, and
/// the process has no way to tell a permanent DNS/TLS failure from a transient one.
fn classify(error: weglarka_http::reqwest::Error) -> ChannelError {
    ChannelError::Retryable(weglarka_http::error_chain(&error.without_url()))
}

fn verdict(status: u16) -> Result<(), ChannelError> {
    match status {
        200..=299 => Ok(()),
        401 | 403 => Err(ChannelError::Permanent(format!(
            "ntfy refused the access token (status {status}); check the `token_file` value"
        ))),
        408 | 429 | 500..=599 => Err(ChannelError::Retryable(format!("ntfy answered {status}"))),
        300..=399 => Err(ChannelError::Permanent(format!(
            "ntfy answered a redirect (status {status}); point `url` at the ntfy server itself"
        ))),
        other => Err(ChannelError::Permanent(format!(
            "ntfy rejected the notification (status {other}); check the topic and the URL"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use weglarka_model::events::Severity;

    fn message() -> Message {
        Message {
            severity: Severity::Warning,
            key: "deploy-failed:ntfy".into(),
            title: "deploy failed: ntfy".into(),
            body: "health gate failed after 10 attempts".into(),
            priority: 4,
            tags: vec!["warning".into()],
            click: Some("https://nz.example.com".into()),
        }
    }

    fn channel(addr: &str, token: Option<&str>) -> NtfyChannel {
        let (connect_host, port) = addr.rsplit_once(':').unwrap();
        let endpoint = Endpoint {
            tls: false,
            connect_host: connect_host.to_owned(),
            connect_port: port.parse().unwrap(),
            host: "ntfy.example.com".into(),
            path: "/".into(),
        };
        NtfyChannel::new(endpoint, "weglarka", token.map(ToString::to_string)).unwrap()
    }

    async fn serve_once(response: &'static str) -> (String, tokio::task::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = stream.read(&mut buf).await.unwrap();
            stream.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        (addr, task)
    }

    /// The JSON body of a captured request (everything after the blank line).
    fn body_of(request: &str) -> serde_json::Value {
        let (_, body) = request.split_once("\r\n\r\n").unwrap();
        serde_json::from_str(body).unwrap()
    }

    #[tokio::test]
    async fn publishes_the_json_body_and_reports_success() {
        let (addr, request) = serve_once("HTTP/1.1 200 OK\r\n\r\n").await;
        channel(&addr, Some("tk_secret"))
            .send(&message())
            .await
            .unwrap();
        let request = request.await.unwrap();
        // hyper lower-cases header names on the wire.
        let lower = request.to_ascii_lowercase();
        assert!(request.starts_with("POST / HTTP/1.1\r\n"), "{request}");
        assert!(
            lower.contains("\r\nauthorization: bearer tk_secret\r\n"),
            "{request}"
        );
        assert!(
            lower.contains("\r\nhost: ntfy.example.com\r\n"),
            "{request}"
        );
        insta::assert_json_snapshot!("ntfy_publish_body", body_of(&request));
    }

    #[tokio::test]
    async fn optional_fields_are_omitted() {
        let (addr, request) = serve_once("HTTP/1.1 200 OK\r\n\r\n").await;
        let mut message = message();
        message.tags.clear();
        message.click = None;
        channel(&addr, None).send(&message).await.unwrap();
        let body = body_of(&request.await.unwrap());
        assert!(body.get("tags").is_none(), "{body}");
        assert!(body.get("click").is_none(), "{body}");
        assert!(body.get("topic").is_some(), "{body}");
    }

    #[tokio::test]
    async fn a_rejected_token_is_permanent_and_a_server_error_is_retryable() {
        let (addr, _) = serve_once("HTTP/1.1 401 Unauthorized\r\n\r\n").await;
        let err = channel(&addr, Some("tk_wrong"))
            .send(&message())
            .await
            .unwrap_err();
        assert!(err.is_permanent(), "{err}");

        let (addr, _) = serve_once("HTTP/1.1 503 Service Unavailable\r\n\r\n").await;
        let err = channel(&addr, None).send(&message()).await.unwrap_err();
        assert!(!err.is_permanent(), "{err}");
    }

    #[tokio::test]
    async fn without_a_token_there_is_no_authorization_header() {
        let (addr, request) = serve_once("HTTP/1.1 204 No Content\r\n\r\n").await;
        channel(&addr, None).send(&message()).await.unwrap();
        let request = request.await.unwrap();
        assert!(
            !request.to_ascii_lowercase().contains("authorization"),
            "{request}"
        );
    }

    #[tokio::test]
    async fn a_redirect_is_not_followed_and_is_permanent() {
        let (addr, request) = serve_once(
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/x\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        let err = channel(&addr, Some("tk_secret"))
            .send(&message())
            .await
            .unwrap_err();
        assert!(err.is_permanent(), "{err}");
        request.await.unwrap();
    }

    #[tokio::test]
    async fn garbage_and_oversized_heads_are_retryable_errors() {
        let (addr, _) = serve_once("garbage\r\n\r\n").await;
        let err = channel(&addr, None).send(&message()).await.unwrap_err();
        assert!(!err.is_permanent(), "{err}");

        // A peer that never ends the head must not make the daemon read without bound.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let hold = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let chunk = vec![b'x'; 2 * 1024 * 1024];
            let _ = stream.write_all(&chunk).await;
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        let started = std::time::Instant::now();
        let err = channel(&addr, None).send(&message()).await.unwrap_err();
        assert!(!err.is_permanent(), "{err}");
        assert!(started.elapsed() < SEND_TIMEOUT, "gave up only on timeout");
        hold.abort();
    }

    #[tokio::test]
    async fn connection_refused_is_retryable() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        drop(listener);
        let err = channel(&addr, None).send(&message()).await.unwrap_err();
        assert!(!err.is_permanent(), "{err}");
    }

    #[tokio::test]
    async fn a_silent_server_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let hold = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        // A short total timeout keeps the suite fast; the test proves the client gives up by itself.
        let client = weglarka_http::builder_with_roots(
            Purpose::Notify,
            tokio_rustls::rustls::RootCertStore::empty(),
        )
        .unwrap()
        .timeout(Duration::from_millis(50))
        .build()
        .unwrap();
        let endpoint = channel(&addr, None).endpoint;
        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            NtfyChannel::with_client(client, endpoint, "wg", None).send(&message()),
        )
        .await
        .expect("the client must give up on its own");
        assert!(!outcome.unwrap_err().is_permanent());
        hold.abort();
    }

    mod tls {
        use super::*;
        use std::sync::Arc;
        use tokio_rustls::TlsAcceptor;
        use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio_rustls::rustls::{RootCertStore, ServerConfig};

        /// The throwaway self-signed certificate from `tests/fixtures` (see its README).
        fn fixtures() -> (
            CertificateDer<'static>,
            PrivateKeyDer<'static>,
            RootCertStore,
        ) {
            let cert =
                CertificateDer::from(include_bytes!("../tests/fixtures/test-cert.der").to_vec());
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                include_bytes!("../tests/fixtures/test-key.der").to_vec(),
            ));
            let mut roots = RootCertStore::empty();
            roots.add(cert.clone()).unwrap();
            (cert, key, roots)
        }

        /// Serves one TLS request; a failed handshake ends the task quietly (the client is asserted).
        async fn serve_tls_once(
            response: &'static str,
        ) -> (String, tokio::task::JoinHandle<String>) {
            let (cert, key, _) = fixtures();
            let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
            let config = Arc::new(
                ServerConfig::builder_with_provider(provider)
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_no_client_auth()
                    .with_single_cert(vec![cert], key)
                    .unwrap(),
            );
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap().to_string();
            let acceptor = TlsAcceptor::from(config);
            let task = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.unwrap();
                let Ok(mut stream) = acceptor.accept(tcp).await else {
                    return String::new();
                };
                let mut buf = vec![0u8; 8192];
                let n = stream.read(&mut buf).await.unwrap();
                stream.write_all(response.as_bytes()).await.unwrap();
                String::from_utf8_lossy(&buf[..n]).into_owned()
            });
            (addr, task)
        }

        fn endpoint(addr: &str, host: &str) -> Endpoint {
            Endpoint::parse(
                &format!("https://{host}:{}", addr.rsplit_once(':').unwrap().1),
                None,
            )
            .unwrap()
        }

        fn trusting(roots: RootCertStore, endpoint: Endpoint) -> NtfyChannel {
            let client = weglarka_http::client_with_roots(Purpose::Notify, roots).unwrap();
            NtfyChannel::with_client(client, endpoint, "weglarka", Some("tk_secret".into()))
        }

        #[tokio::test]
        async fn https_is_verified_against_the_configured_roots() {
            let (addr, request) = serve_tls_once("HTTP/1.1 200 OK\r\n\r\n").await;
            let (_, _, roots) = fixtures();
            // `localhost` resolves to the loopback listener and matches the fixture's SAN.
            trusting(roots, endpoint(&addr, "localhost"))
                .send(&message())
                .await
                .unwrap();
            let request = request.await.unwrap();
            assert!(
                request.contains("\r\nauthorization: Bearer tk_secret\r\n"),
                "{request}"
            );
        }

        #[tokio::test]
        async fn a_hostname_that_does_not_match_the_certificate_is_rejected() {
            let (addr, _) = serve_tls_once("HTTP/1.1 200 OK\r\n\r\n").await;
            let (_, _, roots) = fixtures();
            // The certificate is for `localhost`; reach the listener under a name it does not cover.
            let endpoint = Endpoint::parse(
                &format!(
                    "https://ntfy.example.com:{}",
                    addr.rsplit_once(':').unwrap().1
                ),
                None,
            )
            .unwrap();
            let client = weglarka_http::builder_with_roots(Purpose::Notify, roots)
                .unwrap()
                .resolve("ntfy.example.com", addr.parse().unwrap())
                .build()
                .unwrap();
            let channel = NtfyChannel::with_client(client, endpoint, "weglarka", None);
            let err = channel.send(&message()).await.unwrap_err();
            assert!(!err.is_permanent(), "{err}");
            assert!(err.to_string().to_lowercase().contains("cert"), "{err}");
        }

        #[tokio::test]
        async fn an_untrusted_certificate_is_rejected() {
            let (addr, _) = serve_tls_once("HTTP/1.1 200 OK\r\n\r\n").await;
            // The bundled webpki roots do not contain the self-signed test certificate.
            let err = NtfyChannel::new(endpoint(&addr, "localhost"), "weglarka", None)
                .unwrap()
                .send(&message())
                .await
                .unwrap_err();
            assert!(err.to_string().to_lowercase().contains("cert"), "{err}");
        }
    }

    #[test]
    fn status_verdicts() {
        for ok in [200, 201, 202, 204] {
            assert!(verdict(ok).is_ok(), "{ok}");
        }
        for permanent in [300, 400, 401, 403, 404, 413, 422] {
            assert!(
                verdict(permanent).unwrap_err().is_permanent(),
                "{permanent}"
            );
        }
        for retryable in [408, 429, 500, 502, 503, 504] {
            assert!(
                !verdict(retryable).unwrap_err().is_permanent(),
                "{retryable}"
            );
        }
    }

    #[test]
    fn debug_never_shows_the_token() {
        let channel = NtfyChannel::new(
            Endpoint::parse("https://ntfy.example.com", None).unwrap(),
            "weglarka",
            Some("tk_super_secret".into()),
        )
        .unwrap();
        let debug = format!("{channel:?}");
        assert!(!debug.contains("tk_super_secret"), "{debug}");
        assert!(debug.contains("redacted"), "{debug}");
        assert!(debug.contains("weglarka"), "{debug}");
    }
}
