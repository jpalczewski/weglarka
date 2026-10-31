//! `GET /v1/apps/{name}/logs`: the framed response stream (query: [`LogsQuery`](crate::LogsQuery)).
//!
//! Output of a container is arbitrary bytes, so the stream is length-prefixed frames
//! ([`crate::frame`]). Errors before the stream starts (unknown app, no container, bad query) are
//! ordinary JSON [`ApiError`](crate::ApiError)s; after that the status is sent, so the end is always
//! a final frame — or the client hanging up.

use crate::frame::{FrameDecoder, FrameError, FrameKind, encode_frame};
use std::borrow::Cow;

/// `Content-Type` of a logs response stream.
pub const LOGS_STREAM_CONTENT_TYPE: &str = "application/vnd.weglarka.logs-stream";

/// One piece of a logs response stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogFrame {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    /// The log has ended (the container exited, or a non-follow read reached its end); the last frame.
    End,
    /// The token that opened the stream expired; the last frame. The client reconnects with a fresh
    /// token and `since` = the time of the last output it saw.
    TokenExpired,
    /// The stream failed after it had started; the last frame.
    Error(String),
}

const STDOUT: u8 = 1;
const STDERR: u8 = 2;
const END: u8 = 3;
const TOKEN_EXPIRED: u8 = 4;
const ERROR: u8 = 5;

impl LogFrame {
    /// `kind (1 byte) | payload length (u32, big endian) | payload`.
    pub fn encode(&self) -> Vec<u8> {
        let (kind, payload) = self.parts();
        encode_frame(kind, &payload)
    }
}

impl FrameKind for LogFrame {
    fn parts(&self) -> (u8, Cow<'_, [u8]>) {
        match self {
            Self::Stdout(data) => (STDOUT, Cow::Borrowed(data)),
            Self::Stderr(data) => (STDERR, Cow::Borrowed(data)),
            Self::End => (END, Cow::Borrowed(&[])),
            Self::TokenExpired => (TOKEN_EXPIRED, Cow::Borrowed(&[])),
            Self::Error(message) => (ERROR, Cow::Borrowed(message.as_bytes())),
        }
    }

    fn decode(kind: u8, payload: Vec<u8>) -> Result<Self, FrameError> {
        Ok(match kind {
            STDOUT => Self::Stdout(payload),
            STDERR => Self::Stderr(payload),
            END => Self::End,
            TOKEN_EXPIRED => Self::TokenExpired,
            ERROR => Self::Error(String::from_utf8_lossy(&payload).into_owned()),
            other => return Err(FrameError::UnknownKind(other)),
        })
    }
}

/// Reassembles [`LogFrame`]s from a byte stream cut anywhere.
pub type LogFrameDecoder = FrameDecoder<LogFrame>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_roundtrip_whole_and_byte_by_byte() {
        let frames = vec![
            LogFrame::Stdout(b"hello \xff not utf-8\n".to_vec()),
            LogFrame::Stderr(Vec::new()),
            LogFrame::End,
            LogFrame::TokenExpired,
            LogFrame::Error("podman went away".into()),
        ];
        let bytes: Vec<u8> = frames.iter().flat_map(LogFrame::encode).collect();
        let mut whole = LogFrameDecoder::default();
        assert_eq!(whole.push(&bytes).unwrap(), frames);
        assert!(whole.is_clean());
        let mut slow = LogFrameDecoder::default();
        let mut got = Vec::new();
        for byte in &bytes {
            got.extend(slow.push(&[*byte]).unwrap());
        }
        assert_eq!(got, frames);
    }

    #[test]
    fn garbage_and_truncation_are_refused() {
        assert_eq!(
            LogFrameDecoder::default().push(&[9, 0, 0, 0, 0]),
            Err(FrameError::UnknownKind(9))
        );
        let mut d = LogFrameDecoder::default();
        let bytes = LogFrame::Stdout(b"abc".to_vec()).encode();
        assert!(d.push(&bytes[..bytes.len() - 1]).unwrap().is_empty());
        assert!(!d.is_clean());
    }
}
