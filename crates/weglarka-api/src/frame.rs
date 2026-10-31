//! The framing shared by every streamed response (`run`, `forward`, `logs`):
//! `kind (u8) | payload length (u32, big endian) | payload`.
//!
//! A stream carries arbitrary bytes (process output), so it is length-prefixed frames, not JSON
//! lines. Each endpoint defines its own frame enum and implements [`FrameKind`]; encoding and the
//! chunk-tolerant decoding live here once.

use std::borrow::Cow;
use std::marker::PhantomData;

/// Longest payload of one frame the decoder accepts; the daemon sends far smaller ones.
pub const MAX_FRAME_PAYLOAD: usize = 16 * 1024 * 1024;

/// A stream that cannot be decoded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("stream frame of {0} bytes exceeds the limit")]
    TooLarge(usize),
    #[error("stream has an unknown frame kind {0}")]
    UnknownKind(u8),
    #[error("stream has a malformed {0} frame")]
    Malformed(&'static str),
}

/// `kind | payload length | payload` as bytes.
pub fn encode_frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(kind);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// A frame enum of one stream: how it maps to and from `(kind, payload)`.
pub trait FrameKind: Sized {
    /// The kind byte and the payload of this frame; borrowed from the frame where it can be, so
    /// encoding a log chunk copies it once, into the output buffer.
    fn parts(&self) -> (u8, Cow<'_, [u8]>);

    /// The frame for a kind byte and payload, or [`FrameError`] for an unknown kind or a bad payload.
    fn decode(kind: u8, payload: Vec<u8>) -> Result<Self, FrameError>;
}

/// What a client does about a control frame, whichever stream it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Control {
    /// The stream finished normally; the last frame.
    End,
    /// The token that opened the stream expired; the last frame. Reconnect with a fresh token.
    TokenExpired,
    /// The stream failed after it had started; the last frame.
    Error(String),
}

/// A frame enum that can carry [`Control`] frames. Only frames that mean the same thing on every
/// stream map to a control: a frame with a payload of its own (`Exit`, `TimedOut`, `Keepalive`)
/// is data to the client, and so is anything the stream delivers (`Stdout`, `Entry`, `Ready`).
pub trait ControlFrame {
    /// The control this frame stands for, or `None` for a data frame.
    fn control(&self) -> Option<Control>;
}

/// Reassembles frames of one stream from a byte stream cut anywhere.
#[derive(Debug)]
pub struct FrameDecoder<F> {
    buf: Vec<u8>,
    frames: PhantomData<fn() -> F>,
}

// Not derived: `derive(Default)` would demand `F: Default`.
impl<F> Default for FrameDecoder<F> {
    fn default() -> Self {
        Self {
            buf: Vec::new(),
            frames: PhantomData,
        }
    }
}

impl<F: FrameKind> FrameDecoder<F> {
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<F>, FrameError> {
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
            frames.push(F::decode(kind, payload)?);
        }
        Ok(frames)
    }

    /// The stream did not end inside a frame.
    pub fn is_clean(&self) -> bool {
        self.buf.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    struct Raw(u8, Vec<u8>);

    // Deliberately not `Default`: the decoder must not ask for it.
    impl FrameKind for Raw {
        fn parts(&self) -> (u8, Cow<'_, [u8]>) {
            (self.0, Cow::Borrowed(&self.1))
        }
        fn decode(kind: u8, payload: Vec<u8>) -> Result<Self, FrameError> {
            Ok(Self(kind, payload))
        }
    }

    #[test]
    fn parts_borrow_the_payload_and_the_wire_bytes_are_unchanged() {
        let frame = Raw(9, b"payload".to_vec());
        assert!(matches!(frame.parts().1, Cow::Borrowed(_)));
        let (kind, payload) = frame.parts();
        assert_eq!(
            encode_frame(kind, &payload),
            [&[9, 0, 0, 0, 7][..], b"payload"].concat()
        );
    }

    #[test]
    fn encoding_is_kind_length_payload() {
        assert_eq!(encode_frame(7, b"ab"), [7, 0, 0, 0, 2, b'a', b'b']);
    }

    #[test]
    fn a_frame_cut_anywhere_is_reassembled_and_an_oversized_one_refused() {
        let bytes = encode_frame(1, b"hello");
        for cut in 0..=bytes.len() {
            let mut d = FrameDecoder::<Raw>::default();
            let mut got = d.push(&bytes[..cut]).unwrap();
            got.extend(d.push(&bytes[cut..]).unwrap());
            assert_eq!(got, [Raw(1, b"hello".to_vec())], "cut at {cut}");
            assert!(d.is_clean());
        }
        assert_eq!(
            FrameDecoder::<Raw>::default().push(&[1, 0xff, 0xff, 0xff, 0xff]),
            Err(FrameError::TooLarge(u32::MAX as usize))
        );
    }
}
