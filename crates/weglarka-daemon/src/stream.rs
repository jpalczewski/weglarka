//! What the streamed responses (`run`, `forward`, `logs`) have in common: the body that drains a
//! frame channel, and the point in time a token-authenticated stream must end.

use std::convert::Infallible;
use std::time::{Duration, SystemTime};

use axum::body::{Body, Bytes};
use axum::extract::FromRequestParts;
use axum::http::header::CONTENT_TYPE;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use tokio::sync::mpsc;
use weglarka_model::admin_auth::Principal;

/// A `200` response whose body is whatever arrives on `frames` until the sender side is dropped.
/// Dropping the response (the client hung up) drops `frames`, which is how the task that feeds it
/// learns that nobody listens any more (`Sender::closed`).
pub(crate) fn stream_response(
    content_type: &'static str,
    frames: mpsc::Receiver<Bytes>,
) -> Response {
    let stream = futures_util::stream::unfold(frames, |mut rx| async move {
        rx.recv()
            .await
            .map(|frame| (Ok::<_, Infallible>(frame), rx))
    });
    ([(CONTENT_TYPE, content_type)], Body::from_stream(stream)).into_response()
}

/// When the token behind a request expires (`Principal.exp`), so a stream can end with it instead of
/// outliving the authorization that opened it. The unix socket carries no principal, hence no
/// deadline: its streams end by themselves or when the client hangs up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StreamDeadline(pub Option<SystemTime>);

impl StreamDeadline {
    /// Resolves at the deadline; never when there is none.
    pub(crate) async fn reached(self) {
        match self.0 {
            Some(at) => {
                // Wall clock to a monotonic wait: a clock step during the wait moves the end by
                // at most that step, and the token is verified again by the next request anyway.
                tokio::time::sleep(
                    at.duration_since(SystemTime::now())
                        .unwrap_or(Duration::ZERO),
                )
                .await;
            }
            None => std::future::pending().await,
        }
    }
}

impl<S: Send + Sync> FromRequestParts<S> for StreamDeadline {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Infallible> {
        Ok(Self(parts.extensions.get::<Principal>().map(|p| p.exp)))
    }
}

/// Who opened the stream, for the audit line at its end: the token's `sub`, `None` on the socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallerSub(pub Option<String>);

impl<S: Send + Sync> FromRequestParts<S> for CallerSub {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Infallible> {
        Ok(Self(
            parts.extensions.get::<Principal>().map(|p| p.sub.clone()),
        ))
    }
}
