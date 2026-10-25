//! `POST /v1/apps/{name}/run` (issue #106): the request and the framed response stream.
//!
//! Output of a process is arbitrary bytes, so the stream is length-prefixed frames, not JSON lines
//! (which would have to re-encode — and could split — multi-byte characters). Errors that happen
//! before the container starts are ordinary JSON [`ApiError`](crate::ApiError)s with an HTTP status;
//! once the stream has begun the status is already sent, so the end is always a final frame.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// `Content-Type` of a run response stream.
pub const RUN_STREAM_CONTENT_TYPE: &str = "application/vnd.weglarka.run-stream";

/// Longest payload of one frame the decoder accepts; the daemon sends far smaller ones.
pub const MAX_FRAME_PAYLOAD: usize = 16 * 1024 * 1024;

/// `POST /v1/apps/{name}/run`: run a command once in a fresh container of the app.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunRequest {
    /// Arguments to the image's entrypoint, or the whole command when `entrypoint` replaces it.
    #[serde(default)]
    pub command: Vec<String>,
    /// Replaces the image's `ENTRYPOINT` for this run only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<Vec<String>>,
    /// Added to the app's `env` for this run only; wins over a key the app sets.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Kill the process after this many seconds (default and maximum: 24 hours).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u32>,
}

/// One piece of a run response stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunFrame {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    /// The process exited with this code; always the last frame of a run that finished by itself.
    Exit(i32),
    /// The process was killed after `timeout_secs`; the last frame.
    TimedOut,
    /// The run failed after the stream had started (for example the container could not be
    /// started); the last frame.
    Error(String),
}

const STDOUT: u8 = 1;
const STDERR: u8 = 2;
const EXIT: u8 = 3;
const TIMED_OUT: u8 = 4;
const ERROR: u8 = 5;

impl RunFrame {
    /// `kind (1 byte) | payload length (u32, big endian) | payload`.
    pub fn encode(&self) -> Vec<u8> {
        let (kind, payload): (u8, Vec<u8>) = match self {
            Self::Stdout(data) => (STDOUT, data.clone()),
            Self::Stderr(data) => (STDERR, data.clone()),
            Self::Exit(code) => (EXIT, code.to_be_bytes().to_vec()),
            Self::TimedOut => (TIMED_OUT, Vec::new()),
            Self::Error(message) => (ERROR, message.clone().into_bytes()),
        };
        let mut out = Vec::with_capacity(5 + payload.len());
        out.push(kind);
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&payload);
        out
    }
}

/// A run stream that cannot be decoded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("run stream frame of {0} bytes exceeds the limit")]
    TooLarge(usize),
    #[error("run stream has an unknown frame kind {0}")]
    UnknownKind(u8),
    #[error("run stream has a malformed {0} frame")]
    Malformed(&'static str),
}

/// Reassembles [`RunFrame`]s from a byte stream cut anywhere.
#[derive(Debug, Default)]
pub struct RunFrameDecoder {
    buf: Vec<u8>,
}

impl RunFrameDecoder {
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<RunFrame>, FrameError> {
        self.buf.extend_from_slice(data);
        let mut frames = Vec::new();
        while let Some(&[kind, a, b, c, d]) = self.buf.first_chunk::<5>() {
            let len = u32::from_be_bytes([a, b, c, d]) as usize;
            if len > MAX_FRAME_PAYLOAD {
                return Err(FrameError::TooLarge(len));
            }
            if self.buf.len() < 5 + len {
                break;
            }
            let payload = self.buf[5..5 + len].to_vec();
            self.buf.drain(..5 + len);
            frames.push(match kind {
                STDOUT => RunFrame::Stdout(payload),
                STDERR => RunFrame::Stderr(payload),
                EXIT => RunFrame::Exit(i32::from_be_bytes(
                    payload
                        .try_into()
                        .map_err(|_| FrameError::Malformed("exit"))?,
                )),
                TIMED_OUT => RunFrame::TimedOut,
                ERROR => RunFrame::Error(String::from_utf8_lossy(&payload).into_owned()),
                other => return Err(FrameError::UnknownKind(other)),
            });
        }
        Ok(frames)
    }

    /// The stream ended inside a frame.
    pub fn is_clean(&self) -> bool {
        self.buf.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<RunFrame> {
        vec![
            RunFrame::Stdout(b"hello \xff not utf-8\n".to_vec()),
            RunFrame::Stderr(Vec::new()),
            RunFrame::Stderr(b"warn".to_vec()),
            RunFrame::Exit(-9),
            RunFrame::TimedOut,
            RunFrame::Error("cannot start container".into()),
        ]
    }

    #[test]
    fn frames_roundtrip_byte_by_byte_and_all_at_once() {
        let bytes: Vec<u8> = sample().iter().flat_map(RunFrame::encode).collect();
        let mut whole = RunFrameDecoder::default();
        assert_eq!(whole.push(&bytes).unwrap(), sample());
        assert!(whole.is_clean());
        let mut slow = RunFrameDecoder::default();
        let mut got = Vec::new();
        for byte in &bytes {
            got.extend(slow.push(&[*byte]).unwrap());
        }
        assert_eq!(got, sample());
    }

    #[test]
    fn a_truncated_stream_is_not_clean_and_garbage_is_refused() {
        let mut d = RunFrameDecoder::default();
        let bytes = RunFrame::Stdout(b"abc".to_vec()).encode();
        assert!(d.push(&bytes[..bytes.len() - 1]).unwrap().is_empty());
        assert!(!d.is_clean());
        assert_eq!(
            RunFrameDecoder::default().push(&[9, 0, 0, 0, 0]),
            Err(FrameError::UnknownKind(9))
        );
        assert_eq!(
            RunFrameDecoder::default().push(&[3, 0, 0, 0, 2, 0, 0]),
            Err(FrameError::Malformed("exit"))
        );
        assert_eq!(
            RunFrameDecoder::default().push(&[1, 0xff, 0xff, 0xff, 0xff]),
            Err(FrameError::TooLarge(u32::MAX as usize))
        );
    }

    #[test]
    fn the_request_rejects_unknown_fields_and_takes_an_empty_object() {
        let empty: RunRequest = serde_json::from_str("{}").unwrap();
        assert_eq!(empty, RunRequest::default());
        assert!(serde_json::from_str::<RunRequest>(r#"{"cmd":["x"]}"#).is_err());
    }
}
