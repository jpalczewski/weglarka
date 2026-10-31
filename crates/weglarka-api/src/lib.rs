//! Węglarka admin API contract: request/response types, endpoint list and version.
//! Shared by the daemon (server) and the CLI (client). No HTTP server or client included.
//!
//! The admin API listens only on a unix socket (`admin.socket`); bodies are JSON.
//! Errors: [`ApiError`] with the matching HTTP status (see [`ErrorCode::http_status`]).

pub mod access;
pub mod certificates;
pub mod config_view;
pub mod doctor;
pub mod endpoints;
pub mod forward;
pub mod frame;
pub mod logs;
pub mod logtime;
pub mod run;
pub mod types;

pub use access::{ACCESS_STREAM_CONTENT_TYPE, AccessEntry, AccessFrame, AccessFrameDecoder};
pub use certificates::{CertStatus, CertificateRecord, CertificatesResponse};
pub use config_view::*;
pub use doctor::{CheckStatus, DoctorCheck, DoctorReport};
pub use endpoints::{Body, ENDPOINTS, Endpoint, Method};
pub use forward::{FORWARD_STREAM_CONTENT_TYPE, ForwardFrame, ForwardFrameDecoder, ForwardRequest};
pub use frame::{FrameDecoder, FrameError, FrameKind, MAX_FRAME_PAYLOAD, encode_frame};
pub use logs::{LOGS_STREAM_CONTENT_TYPE, LogFrame, LogFrameDecoder};
pub use logtime::{MAX_STAMP, parse_rfc3339, stamp_len};
pub use run::{RUN_STREAM_CONTENT_TYPE, RunFrame, RunFrameDecoder, RunRequest};
pub use types::*;

/// Contract version; path prefix (`/v1/...`). A breaking change means a new prefix.
pub const API_VERSION: &str = "v1";
