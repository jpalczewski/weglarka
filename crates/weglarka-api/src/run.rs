//! `POST /v1/apps/{name}/run` (issue #106): the request and the framed response stream.
//!
//! Output of a process is arbitrary bytes, so the stream is length-prefixed frames, not JSON lines
//! (which would have to re-encode — and could split — multi-byte characters). Errors that happen
//! before the container starts are ordinary JSON [`ApiError`](crate::ApiError)s with an HTTP status;
//! once the stream has begun the status is already sent, so the end is always a final frame.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::frame::{Control, ControlFrame, FrameDecoder, FrameError, FrameKind, encode_frame};
use std::borrow::Cow;

/// `Content-Type` of a run response stream.
pub const RUN_STREAM_CONTENT_TYPE: &str = "application/vnd.weglarka.run-stream";

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
    /// Stored secrets for this run only, as `VARIABLE -> secret name`: the daemon reads each
    /// secret of the app from its store and passes it to the one-off container as an environment
    /// variable (a Podman secret, never a command line or the spec). Wins over `env` and over a
    /// binding of the app on the same variable; the app's spec is not touched (issue #297).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub secrets: BTreeMap<String, String>,
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
        let (kind, payload) = self.parts();
        encode_frame(kind, &payload)
    }

    /// The encoding of `Stdout`/`Stderr` carrying `data`, without building the frame (and so
    /// without copying a chunk into a `Vec` first); byte-identical to `encode()` of the frame.
    pub fn encode_output(stderr: bool, data: &[u8]) -> Vec<u8> {
        encode_frame(if stderr { STDERR } else { STDOUT }, data)
    }
}

impl FrameKind for RunFrame {
    fn parts(&self) -> (u8, Cow<'_, [u8]>) {
        match self {
            Self::Stdout(data) => (STDOUT, Cow::Borrowed(data)),
            Self::Stderr(data) => (STDERR, Cow::Borrowed(data)),
            Self::Exit(code) => (EXIT, Cow::Owned(code.to_be_bytes().to_vec())),
            Self::TimedOut => (TIMED_OUT, Cow::Borrowed(&[])),
            Self::Error(message) => (ERROR, Cow::Borrowed(message.as_bytes())),
        }
    }

    fn decode(kind: u8, payload: Vec<u8>) -> Result<Self, FrameError> {
        Ok(match kind {
            STDOUT => Self::Stdout(payload),
            STDERR => Self::Stderr(payload),
            EXIT => Self::Exit(i32::from_be_bytes(
                payload
                    .try_into()
                    .map_err(|_| FrameError::Malformed("exit"))?,
            )),
            TIMED_OUT => Self::TimedOut,
            ERROR => Self::Error(String::from_utf8_lossy(&payload).into_owned()),
            other => return Err(FrameError::UnknownKind(other)),
        })
    }
}

impl ControlFrame for RunFrame {
    fn control(&self) -> Option<Control> {
        match self {
            Self::Error(message) => Some(Control::Error(message.clone())),
            Self::Stdout(_) | Self::Stderr(_) | Self::Exit(_) | Self::TimedOut => None,
        }
    }
}

/// Reassembles [`RunFrame`]s from a byte stream cut anywhere.
pub type RunFrameDecoder = FrameDecoder<RunFrame>;

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
    fn encode_output_is_byte_identical_to_encoding_the_frame() {
        let data = b"out \xff\n";
        assert_eq!(
            RunFrame::encode_output(false, data),
            RunFrame::Stdout(data.to_vec()).encode()
        );
        assert_eq!(
            RunFrame::encode_output(true, data),
            RunFrame::Stderr(data.to_vec()).encode()
        );
        assert_eq!(RunFrame::encode_output(false, data)[..5], [1, 0, 0, 0, 6]);
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

    #[test]
    fn control_frames_map_and_data_frames_do_not() {
        assert_eq!(
            RunFrame::Error("x".into()).control(),
            Some(Control::Error("x".into()))
        );
        assert_eq!(RunFrame::Stdout(b"x".to_vec()).control(), None);
        assert_eq!(RunFrame::Stderr(Vec::new()).control(), None);
        // The exit code and the timeout are results the client reports, not a bare end.
        assert_eq!(RunFrame::Exit(0).control(), None);
        assert_eq!(RunFrame::TimedOut.control(), None);
    }
}
