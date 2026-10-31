//! `GET /v1/apps/{name}/access`: an app's access log as a framed stream (query:
//! [`AccessQuery`](crate::AccessQuery), docs/decisions/0062).
//!
//! The daemon reads the ingress nginx's JSON log, keeps the lines of one app and sends each as an
//! [`AccessEntry`]. The entry has no `app` field (the client named it and the daemon checked it) and
//! only the fields below, so anything else nginx logs never leaves the daemon.

use serde::{Deserialize, Serialize};

use crate::frame::{FrameDecoder, FrameError, FrameKind, encode_frame};

/// `Content-Type` of an access response stream.
pub const ACCESS_STREAM_CONTENT_TYPE: &str = "application/vnd.weglarka.access-stream";

/// One request, as nginx logged it (`weglarka-ingress` `LOG_FORMAT`). Unknown fields of a log line are
/// ignored when reading it, and missing ones take their default.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AccessEntry {
    /// RFC 3339 time nginx finished the request.
    pub time: String,
    pub host: String,
    /// The client (behind a CDN: the visitor).
    pub remote_addr: String,
    /// The TCP peer, only when it differs from the client (behind a CDN).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
    pub method: String,
    /// `$uri`: no query string.
    pub path: String,
    pub status: u16,
    pub bytes_sent: u64,
    /// Seconds.
    pub request_time: f64,
    /// `-` or a list on retry, as nginx prints it.
    pub upstream_response_time: String,
    pub request_id: String,
    pub user_agent: String,
}

/// One piece of an access response stream.
// Frames are short-lived and moved one at a time; boxing the entry would only add an allocation per request.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum AccessFrame {
    Entry(AccessEntry),
    /// A non-follow read reached its end; the last frame.
    End,
    /// The token that opened the stream expired; the last frame. The client reconnects with a fresh
    /// token and `since`.
    TokenExpired,
    /// The stream failed after it had started; the last frame.
    Error(String),
}

const ENTRY: u8 = 1;
const END: u8 = 3;
const TOKEN_EXPIRED: u8 = 4;
const ERROR: u8 = 5;

impl AccessFrame {
    /// `kind (1 byte) | payload length (u32, big endian) | payload`.
    pub fn encode(&self) -> Vec<u8> {
        let (kind, payload) = self.parts();
        encode_frame(kind, &payload)
    }
}

impl FrameKind for AccessFrame {
    fn parts(&self) -> (u8, Vec<u8>) {
        match self {
            Self::Entry(entry) => (
                ENTRY,
                serde_json::to_vec(entry).expect("an AccessEntry serialises"),
            ),
            Self::End => (END, Vec::new()),
            Self::TokenExpired => (TOKEN_EXPIRED, Vec::new()),
            Self::Error(message) => (ERROR, message.clone().into_bytes()),
        }
    }

    fn decode(kind: u8, payload: Vec<u8>) -> Result<Self, FrameError> {
        Ok(match kind {
            ENTRY => Self::Entry(
                serde_json::from_slice(&payload).map_err(|_| FrameError::Malformed("entry"))?,
            ),
            END => Self::End,
            TOKEN_EXPIRED => Self::TokenExpired,
            ERROR => Self::Error(String::from_utf8_lossy(&payload).into_owned()),
            other => return Err(FrameError::UnknownKind(other)),
        })
    }
}

/// Reassembles [`AccessFrame`]s from a byte stream cut anywhere.
pub type AccessFrameDecoder = FrameDecoder<AccessFrame>;

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> AccessEntry {
        AccessEntry {
            time: "2026-10-31T12:00:00+00:00".into(),
            host: "app.example.com".into(),
            remote_addr: "203.0.113.7".into(),
            peer: Some("198.51.100.1".into()),
            method: "GET".into(),
            path: "/a b/é".into(),
            status: 404,
            bytes_sent: 12,
            request_time: 0.25,
            upstream_response_time: "0.001".into(),
            request_id: "abc".into(),
            user_agent: "curl/8 \"quoted\"".into(),
        }
    }

    #[test]
    fn frames_roundtrip_whole_and_byte_by_byte() {
        let frames = vec![
            AccessFrame::Entry(entry()),
            AccessFrame::Entry(AccessEntry::default()),
            AccessFrame::End,
            AccessFrame::TokenExpired,
            AccessFrame::Error("podman went away".into()),
        ];
        let bytes: Vec<u8> = frames.iter().flat_map(AccessFrame::encode).collect();
        let mut whole = AccessFrameDecoder::default();
        assert_eq!(whole.push(&bytes).unwrap(), frames);
        assert!(whole.is_clean());
        let mut slow = AccessFrameDecoder::default();
        let mut got = Vec::new();
        for byte in &bytes {
            got.extend(slow.push(&[*byte]).unwrap());
        }
        assert_eq!(got, frames);
    }

    #[test]
    fn garbage_is_refused() {
        assert_eq!(
            AccessFrameDecoder::default().push(&[9, 0, 0, 0, 0]),
            Err(FrameError::UnknownKind(9))
        );
        assert_eq!(
            AccessFrameDecoder::default().push(&[1, 0, 0, 0, 2, b'{', b'}']),
            Ok(vec![AccessFrame::Entry(AccessEntry::default())])
        );
        assert_eq!(
            AccessFrameDecoder::default().push(&[1, 0, 0, 0, 1, b'x']),
            Err(FrameError::Malformed("entry"))
        );
    }

    #[test]
    fn unknown_fields_are_ignored_and_app_is_not_part_of_an_entry() {
        let got: AccessEntry =
            serde_json::from_str(r#"{"app":"web","status":200,"extra":1,"path":"/"}"#).unwrap();
        assert_eq!((got.status, got.path.as_str()), (200, "/"));
        assert!(!serde_json::to_string(&got).unwrap().contains("\"app\""));
    }
}
