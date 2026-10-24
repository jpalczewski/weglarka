//! ntfy channel: publishes through ntfy's JSON API (`POST <base>/`).
//!
//! The JSON form is used instead of ntfy's header form (`Title:`, `Priority:` …) because header values
//! must be ASCII and would need escaping for a UTF-8 title; the token, which *is* a header, is validated
//! by the settings (printable ASCII only).

use std::time::Duration;

use serde::Serialize;

use crate::channel::{Channel, ChannelError, SendFuture};
use crate::http::{Client, Endpoint, HttpError};
use crate::message::Message;

/// A single delivery attempt must not hold the worker longer than this.
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
    client: Client,
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
        Ok(Self {
            client: Client::new()?,
            endpoint,
            topic: topic.into(),
            token,
        })
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
            let status = self
                .client
                .post_json(&self.endpoint, self.token.as_deref(), &body, SEND_TIMEOUT)
                .await
                .map_err(classify)?;
            verdict(status)
        })
    }
}

/// Network-level errors are retryable: the daemon may be behind a proxy that is being restarted, and
/// the process has no way to tell a permanent DNS/TLS failure from a transient one.
fn classify(error: HttpError) -> ChannelError {
    ChannelError::Retryable(error.to_string())
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
    use weglarka_core::events::Severity;

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
        assert!(request.starts_with("POST / HTTP/1.1\r\n"), "{request}");
        assert!(
            request.contains("\r\nAuthorization: Bearer tk_secret\r\n"),
            "{request}"
        );
        assert!(
            request.contains("\r\nHost: ntfy.example.com\r\n"),
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
