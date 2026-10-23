//! HTTP/1.1 over a unix socket: one connection per call, responses read whole (`call`)
//! or as a stream of JSON lines (`Lines`).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::client::conn::http1;
use hyper::header::{CONTENT_TYPE, HOST};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use tokio::net::UnixStream;
use weglarka_core::podman::{PodmanError, Result};

/// API version in the path — forces v6 semantics regardless of the server's default version.
pub(crate) const API_PREFIX: &str = "/v6.0.0/libpod";

/// Limit for responses read whole (inspect, list) — a defense against RAM blowup.
const MAX_BODY: usize = 16 << 20;
/// Limit for a single stream line (pull, events).
const MAX_LINE: usize = 1 << 20;
/// How much of the error body we read.
const MAX_ERROR_BODY: usize = 64 << 10;

#[derive(Debug, Clone)]
pub(crate) struct Transport {
    socket: Arc<Path>,
}

impl Transport {
    pub(crate) fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into().into(),
        }
    }

    async fn open(
        &self,
        method: Method,
        path: &str,
        body: Option<(&'static str, Bytes)>,
    ) -> Result<(StatusCode, Incoming)> {
        let unreachable = |what: &str, e: &dyn std::fmt::Display| {
            PodmanError::Unreachable(format!("{}: {what}: {e}", self.socket.display()))
        };
        let stream = UnixStream::connect(&*self.socket)
            .await
            .map_err(|e| unreachable("connect", &e))?;
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|e| unreachable("handshake", &e))?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!(%error, "podman connection closed with error");
            }
        });

        let mut request = Request::builder()
            .method(method)
            .uri(format!("{API_PREFIX}{path}"))
            .header(HOST, "podman");
        let payload = match body {
            Some((content_type, bytes)) => {
                request = request.header(CONTENT_TYPE, content_type);
                bytes
            }
            None => Bytes::new(),
        };
        let request = request
            .body(Full::new(payload))
            .map_err(|e| PodmanError::Protocol(format!("building request: {e}")))?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|e| unreachable("request", &e))?;
        Ok((response.status(), response.into_body()))
    }

    /// Call with a response read whole. 2xx and 304 (already started/stopped) count as success.
    pub(crate) async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<(&'static str, Bytes)>,
    ) -> Result<Bytes> {
        let (status, incoming) = self.open(method, path, body).await?;
        if is_success(status) {
            read_limited(incoming, MAX_BODY).await
        } else {
            Err(error_from_response(status, incoming).await)
        }
    }

    pub(crate) async fn call_json(
        &self,
        method: Method,
        path: &str,
        body: &impl serde::Serialize,
    ) -> Result<Bytes> {
        let json = serde_json::to_vec(body)
            .map_err(|e| PodmanError::Protocol(format!("encoding request: {e}")))?;
        self.call(method, path, Some(("application/json", json.into())))
            .await
    }

    /// Call with a streamed response (JSON lines).
    pub(crate) async fn lines(&self, method: Method, path: &str) -> Result<Lines> {
        let (status, incoming) = self.open(method, path, None).await?;
        if is_success(status) {
            Ok(Lines::new(incoming))
        } else {
            Err(error_from_response(status, incoming).await)
        }
    }
}

fn is_success(status: StatusCode) -> bool {
    status.is_success() || status == StatusCode::NOT_MODIFIED
}

async fn read_limited(body: Incoming, limit: usize) -> Result<Bytes> {
    Limited::new(body, limit)
        .collect()
        .await
        .map(|collected| collected.to_bytes())
        .map_err(|e| PodmanError::Unreachable(format!("reading response: {e}")))
}

async fn error_from_response(status: StatusCode, body: Incoming) -> PodmanError {
    // An error while reading the error body does not matter — the status says what happened anyway.
    let bytes = read_limited(body, MAX_ERROR_BODY).await.unwrap_or_default();
    error_from_status(status.as_u16(), &bytes)
}

/// Maps a libpod error response (`{"cause","message","response"}`) to [`PodmanError`].
/// 409 stays `Api`; create calls turn it into `Conflict` via [`name_conflict`].
pub(crate) fn error_from_status(status: u16, body: &[u8]) -> PodmanError {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct ErrorBody {
        message: String,
        cause: String,
    }
    let parsed: ErrorBody = serde_json::from_slice(body).unwrap_or_default();
    let message = if !parsed.message.is_empty() {
        parsed.message
    } else if !parsed.cause.is_empty() {
        parsed.cause
    } else {
        String::from_utf8_lossy(body)
            .trim()
            .chars()
            .take(512)
            .collect()
    };
    match status {
        404 => PodmanError::NotFound(message),
        _ => PodmanError::Api { status, message },
    }
}

/// For create operations: name already taken. The docs promise 409, but libpod returns 409 only
/// for networks; a container with a taken name gets 500 with the message "… is already in use"
/// (measured on Podman 6.1.3 in CI), so we recognize that message too.
pub(crate) fn name_conflict(error: PodmanError) -> PodmanError {
    match error {
        PodmanError::Api { status, message }
            if status == 409
                || (status == 500
                    && ["already in use", "already exists"]
                        .iter()
                        .any(|needle| message.contains(needle))) =>
        {
            PodmanError::Conflict(message)
        }
        other => other,
    }
}

/// Reader of a JSON-lines stream (`\n`-separated objects: pull, events).
pub(crate) struct Lines {
    body: Incoming,
    buf: Vec<u8>,
    eof: bool,
}

impl Lines {
    fn new(body: Incoming) -> Self {
        Self {
            body,
            buf: Vec::new(),
            eof: false,
        }
    }

    /// Next non-empty line; `None` at the end of the stream.
    pub(crate) async fn next_line(&mut self) -> Result<Option<Vec<u8>>> {
        loop {
            if let Some(line) = take_line(&mut self.buf) {
                if line.iter().all(u8::is_ascii_whitespace) {
                    continue;
                }
                return Ok(Some(line));
            }
            if self.eof {
                let rest = std::mem::take(&mut self.buf);
                return Ok((!rest.iter().all(u8::is_ascii_whitespace)).then_some(rest));
            }
            if self.buf.len() > MAX_LINE {
                return Err(PodmanError::Protocol("stream line too long".into()));
            }
            match self.body.frame().await {
                None => self.eof = true,
                Some(Err(e)) => {
                    return Err(PodmanError::Unreachable(format!("stream interrupted: {e}")));
                }
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        self.buf.extend_from_slice(&data);
                    }
                }
            }
        }
    }
}

/// Cuts the first complete line out of the buffer (without `\n`/`\r\n`).
pub(crate) fn take_line(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    let end = buf.iter().position(|&b| b == b'\n')?;
    let mut line: Vec<u8> = buf.drain(..=end).collect();
    line.pop();
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    Some(line)
}

/// Percent-encoding of a query component (RFC 3986 unreserved characters are kept).
pub(crate) fn encode_component(input: &str) -> String {
    encode(input, |b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
}

/// Path segment(s): like a component, but `/`, `:` and `@` (image references) are kept.
pub(crate) fn encode_path(input: &str) -> String {
    encode(input, |b| {
        b.is_ascii_alphanumeric() || b"-._~/:@".contains(&b)
    })
}

fn encode(input: &str, keep: impl Fn(u8) -> bool) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        if keep(b) {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// Name/reference inserted into the path: non-empty, without `.` and `..` segments.
pub(crate) fn path_name(name: &str) -> Result<String> {
    if name.is_empty() || name.split('/').any(|s| s == "." || s == "..") {
        return Err(PodmanError::Api {
            status: 400,
            message: format!("invalid object name {name:?}"),
        });
    }
    Ok(encode_path(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn libpod_error_body_maps_to_not_found_and_api() {
        let body = br#"{"cause":"no such container","message":"no container with name or ID \"x\" found: no such container","response":404}"#;
        assert!(matches!(
            error_from_status(404, body),
            PodmanError::NotFound(m) if m.contains("no container")
        ));
        let err = error_from_status(500, b"plain text boom\n");
        assert!(
            matches!(&err, PodmanError::Api { status: 500, message } if message == "plain text boom")
        );
    }

    #[test]
    fn conflict_only_for_creating_calls() {
        let api409 = || error_from_status(409, br#"{"message":"name in use"}"#);
        assert!(matches!(api409(), PodmanError::Api { status: 409, .. }));
        assert!(matches!(name_conflict(api409()), PodmanError::Conflict(m) if m == "name in use"));
        let api500 = error_from_status(
            500,
            br#"{"message":"creating container storage: the container name \"x\" is already in use by abc"}"#,
        );
        assert!(matches!(name_conflict(api500), PodmanError::Conflict(_)));
        assert!(matches!(
            name_conflict(error_from_status(500, br#"{"message":"boom"}"#)),
            PodmanError::Api { status: 500, .. }
        ));
        assert!(matches!(
            name_conflict(PodmanError::NotFound("x".into())),
            PodmanError::NotFound(_)
        ));
    }

    #[test]
    fn splits_lines_across_chunks() {
        let mut buf = b"{\"a\":1}\r\n{\"b\"".to_vec();
        assert_eq!(take_line(&mut buf).unwrap(), b"{\"a\":1}");
        assert!(take_line(&mut buf).is_none());
        buf.extend_from_slice(b":2}\n");
        assert_eq!(take_line(&mut buf).unwrap(), b"{\"b\":2}");
        assert!(buf.is_empty());
    }

    #[test]
    fn encoding_escapes_query_and_keeps_image_refs() {
        assert_eq!(
            encode_component(r#"{"label":["a=b c"]}"#),
            "%7B%22label%22%3A%5B%22a%3Db%20c%22%5D%7D"
        );
        assert_eq!(
            encode_path("ghcr.io/x/y:latest@sha256:ab"),
            "ghcr.io/x/y:latest@sha256:ab"
        );
        assert_eq!(encode_path("a?b#c d"), "a%3Fb%23c%20d");
    }

    #[test]
    fn path_name_rejects_traversal() {
        assert!(path_name("").is_err());
        assert!(path_name("../x").is_err());
        assert!(path_name("a/./b").is_err());
        assert_eq!(path_name("my-app").unwrap(), "my-app");
    }
}
