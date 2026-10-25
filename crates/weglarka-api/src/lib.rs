//! Węglarka admin API contract: request/response types, endpoint list and version.
//! Shared by the daemon (server) and the CLI (client). No HTTP server or client included.
//!
//! The admin API listens only on a unix socket (`admin.socket`); bodies are JSON.
//! Errors: [`ApiError`] with the matching HTTP status (see [`ErrorCode::http_status`]).

pub mod doctor;
pub mod endpoints;
pub mod forward;
pub mod run;
pub mod types;

pub use doctor::{CheckStatus, DoctorCheck, DoctorReport};
pub use endpoints::{ENDPOINTS, Endpoint, Method};
pub use forward::{FORWARD_STREAM_CONTENT_TYPE, ForwardFrame, ForwardFrameDecoder, ForwardRequest};
pub use run::{
    FrameError, MAX_FRAME_PAYLOAD, RUN_STREAM_CONTENT_TYPE, RunFrame, RunFrameDecoder, RunRequest,
};
pub use types::*;

/// Contract version; path prefix (`/v1/...`). A breaking change means a new prefix.
pub const API_VERSION: &str = "v1";
