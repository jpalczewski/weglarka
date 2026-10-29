//! `POST /v1/apps/{name}/forward` (issue #108, ADR 0041): the request and the framed response stream.
//!
//! Same framing as a run stream ([`crate::frame`]) with its own kinds. Errors that
//! happen before the relay starts are ordinary JSON [`ApiError`](crate::ApiError)s with an HTTP status;
//! once the stream has begun the status is already sent, so the end is always a final frame — or the
//! client hanging up, which is how a forward normally ends.

use serde::{Deserialize, Serialize};

use crate::frame::{FrameDecoder, FrameError, FrameKind, encode_frame};

/// `Content-Type` of a forward response stream.
pub const FORWARD_STREAM_CONTENT_TYPE: &str = "application/vnd.weglarka.forward-stream";

/// `POST /v1/apps/{name}/forward`: relay a port of the app to a loopback port of the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardRequest {
    /// Port inside the app's container (1–65535).
    pub port: u16,
    /// End the forward after this many seconds (default and maximum: 24 hours).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u32>,
}

/// One piece of a forward response stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardFrame {
    /// The relay is up and listens on `127.0.0.1:<host_port>` of the host; always the first frame.
    Ready { host_port: u16 },
    /// Sent now and then so that a dead connection is noticed on both sides.
    Keepalive,
    /// The forward ended after `timeout_secs`; the last frame.
    TimedOut,
    /// The token that opened the stream expired and the relay was removed; the last frame (only on the
    /// token listener).
    TokenExpired,
    /// The relay failed after the stream had started; the last frame.
    Error(String),
}

const READY: u8 = 1;
const KEEPALIVE: u8 = 2;
const TIMED_OUT: u8 = 3;
const ERROR: u8 = 4;
const TOKEN_EXPIRED: u8 = 5;

impl ForwardFrame {
    /// `kind (1 byte) | payload length (u32, big endian) | payload`.
    pub fn encode(&self) -> Vec<u8> {
        let (kind, payload) = self.parts();
        encode_frame(kind, &payload)
    }
}

impl FrameKind for ForwardFrame {
    fn parts(&self) -> (u8, Vec<u8>) {
        match self {
            Self::Ready { host_port } => (READY, host_port.to_be_bytes().to_vec()),
            Self::Keepalive => (KEEPALIVE, Vec::new()),
            Self::TimedOut => (TIMED_OUT, Vec::new()),
            Self::TokenExpired => (TOKEN_EXPIRED, Vec::new()),
            Self::Error(message) => (ERROR, message.clone().into_bytes()),
        }
    }

    fn decode(kind: u8, payload: Vec<u8>) -> Result<Self, FrameError> {
        Ok(match kind {
            READY => Self::Ready {
                host_port: u16::from_be_bytes(
                    payload
                        .try_into()
                        .map_err(|_| FrameError::Malformed("ready"))?,
                ),
            },
            KEEPALIVE => Self::Keepalive,
            TIMED_OUT => Self::TimedOut,
            TOKEN_EXPIRED => Self::TokenExpired,
            ERROR => Self::Error(String::from_utf8_lossy(&payload).into_owned()),
            other => return Err(FrameError::UnknownKind(other)),
        })
    }
}

/// Reassembles [`ForwardFrame`]s from a byte stream cut anywhere.
pub type ForwardFrameDecoder = FrameDecoder<ForwardFrame>;

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<ForwardFrame> {
        vec![
            ForwardFrame::Ready { host_port: 43211 },
            ForwardFrame::Keepalive,
            ForwardFrame::TimedOut,
            ForwardFrame::TokenExpired,
            ForwardFrame::Error("cannot start relay".into()),
        ]
    }

    #[test]
    fn frames_roundtrip_byte_by_byte_and_all_at_once() {
        let bytes: Vec<u8> = sample().iter().flat_map(ForwardFrame::encode).collect();
        let mut whole = ForwardFrameDecoder::default();
        assert_eq!(whole.push(&bytes).unwrap(), sample());
        assert!(whole.is_clean());
        let mut slow = ForwardFrameDecoder::default();
        let mut got = Vec::new();
        for byte in &bytes {
            got.extend(slow.push(&[*byte]).unwrap());
        }
        assert_eq!(got, sample());
    }

    #[test]
    fn garbage_and_truncation_are_refused() {
        assert_eq!(
            ForwardFrameDecoder::default().push(&[9, 0, 0, 0, 0]),
            Err(FrameError::UnknownKind(9))
        );
        assert_eq!(
            ForwardFrameDecoder::default().push(&[1, 0, 0, 0, 1, 7]),
            Err(FrameError::Malformed("ready"))
        );
        let mut d = ForwardFrameDecoder::default();
        let bytes = ForwardFrame::Ready { host_port: 1 }.encode();
        assert!(d.push(&bytes[..bytes.len() - 1]).unwrap().is_empty());
        assert!(!d.is_clean());
    }

    #[test]
    fn the_request_needs_a_port_and_rejects_unknown_fields() {
        let ok: ForwardRequest = serde_json::from_str(r#"{"port":5432}"#).unwrap();
        assert_eq!(ok.port, 5432);
        assert!(serde_json::from_str::<ForwardRequest>("{}").is_err());
        assert!(serde_json::from_str::<ForwardRequest>(r#"{"port":1,"x":1}"#).is_err());
    }
}
