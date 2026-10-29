//! `GET /v1/apps/{name}/logs` (`admin` scope, docs/decisions/0057): the output of an app's running
//! container as a stream of [`LogFrame`]s.
//!
//! `admin` although it only reads: logs can hold anything the app printed, secrets included, and
//! unlike a spec they cannot be redacted. The query is validated by [`LogsQuery::parse`] before any
//! of it reaches the libpod request. Everything that can be refused (bad query, unknown app, no
//! container) is an ordinary JSON error *before* the stream starts.
//!
//! The stream lives in its own task (the pump), so it ends the same way whether the client reads on
//! or hangs up: a dropped response body closes the frame channel and the pump drops the Podman
//! stream. Over the token listener it also ends *at* the token's expiry with a `TokenExpired` frame;
//! the client reconnects with a fresh token and `since`.
//!
//! Audit: `authenticate` logs the request when the headers go out (status, route template). The pump
//! adds one line when the stream ends — who, which app, the query's shape, how much, how long and why
//! it ended. Never the content, and never the raw query string.

use std::sync::Arc;
use std::time::SystemTime;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::response::Response;
use axum::routing::get;
use futures_util::StreamExt;
use tokio::sync::mpsc;
use tokio::time::Instant;
use weglarka_api::{LOGS_STREAM_CONTENT_TYPE, LogFrame, LogsQuery, endpoints};
use weglarka_model::app::InstanceName;
use weglarka_model::labels;
use weglarka_model::podman::{LogOptions, LogSource, LogStream, PodmanClient, PodmanError};
use weglarka_model::state;

use crate::admin::{Fail, parse_name};
use crate::app::Daemon;
use crate::stream::{CallerSub, StreamDeadline, stream_response};

/// Frames queued between the pump and the response body: small, so a slow client holds back the
/// reading of the Podman stream instead of buffering the log in memory.
const FRAME_QUEUE: usize = 8;

pub fn routes<P: PodmanClient + 'static>() -> Router<Arc<Daemon<P>>> {
    Router::new().route(endpoints::APPS_LOGS.path, get(app_logs::<P>))
}

async fn app_logs<P: PodmanClient + 'static>(
    State(d): State<Arc<Daemon<P>>>,
    Path(raw): Path<String>,
    RawQuery(raw_query): RawQuery,
    deadline: StreamDeadline,
    CallerSub(sub): CallerSub,
) -> Result<Response, Fail> {
    let name = parse_name(&raw)?;
    let query = LogsQuery::parse(raw_query.as_deref()).map_err(Fail::invalid)?;
    let known = state::load_apps(&d.paths.state.apps)
        .map_err(Fail::internal)?
        .apps
        .contains_key(&name);
    if !known {
        return Err(Fail::not_found(format!("unknown app: {name}")));
    }
    let container = labels::container_name(&name);
    let podman = d.engine.podman();
    podman
        .container_inspect(&container)
        .await
        .map_err(|e| podman_failure(&name, e))?;
    let options = LogOptions {
        follow: query.follow,
        tail: query.tail,
        since: query.since_time(),
        timestamps: query.timestamps,
    };
    let logs = podman
        .container_logs(&container, &options)
        .await
        .map_err(|e| podman_failure(&name, e))?;

    let (frames_tx, frames_rx) = mpsc::channel::<Bytes>(FRAME_QUEUE);
    tokio::spawn(pump(
        logs,
        frames_tx,
        deadline,
        Audit::new(sub, name, &query),
    ));
    Ok(stream_response(LOGS_STREAM_CONTENT_TYPE, frames_rx))
}

/// A missing container is a 404; any other Podman failure is logged and answered without its text.
fn podman_failure(name: &InstanceName, error: PodmanError) -> Fail {
    match error {
        PodmanError::NotFound(_) => Fail::not_found(format!("app {name} has no container")),
        other => {
            tracing::warn!(app = %name, error = %other, "reading container logs failed");
            Fail::internal("could not read the container's logs")
        }
    }
}

/// Why a stream ended (the `ended` field of the audit line).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ended {
    /// The client hung up (or stopped reading for good).
    ClientClosed,
    /// The token expired.
    TokenExpired,
    /// The log ended: a non-follow read reached its end, or the container exited.
    Eof,
    /// Podman failed mid-stream.
    Error,
}

impl Ended {
    fn as_str(self) -> &'static str {
        match self {
            Self::ClientClosed => "client_closed",
            Self::TokenExpired => "token_expired",
            Self::Eof => "eof",
            Self::Error => "error",
        }
    }
}

/// The facts of the audit line; none of them is log content.
#[derive(Debug)]
struct Audit {
    sub: Option<String>,
    app: InstanceName,
    follow: bool,
    tail: Option<u32>,
    since: Option<SystemTime>,
    started: Instant,
    frames: u64,
    bytes: u64,
}

impl Audit {
    fn new(sub: Option<String>, app: InstanceName, query: &LogsQuery) -> Self {
        Self {
            sub,
            app,
            follow: query.follow,
            tail: query.tail,
            since: query.since_time(),
            started: Instant::now(),
            frames: 0,
            bytes: 0,
        }
    }

    fn finish(&self, ended: Ended) {
        tracing::info!(
            sub = self.sub.as_deref().unwrap_or("unix socket"),
            app = %self.app,
            follow = self.follow,
            tail = self.tail,
            since = self.since.map(unix_secs),
            frames = self.frames,
            bytes = self.bytes,
            duration_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            ended = ended.as_str(),
            "admin logs stream ended"
        );
    }
}

fn unix_secs(at: SystemTime) -> u64 {
    at.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Copies `logs` into `frames_tx` as [`LogFrame`]s until the log ends, the client goes away or the
/// token expires — whichever is first — then writes the audit line. Returns by dropping `logs`, which
/// closes the Podman connection. The result is what the audit line says (for the tests).
async fn pump(
    mut logs: LogStream,
    frames_tx: mpsc::Sender<Bytes>,
    deadline: StreamDeadline,
    mut audit: Audit,
) -> (Ended, Audit) {
    let expiry = deadline.reached();
    tokio::pin!(expiry);
    let mut ended = loop {
        let next = tokio::select! {
            biased;
            // At the expiry itself, not a leeway later: the token's authority is over.
            () = &mut expiry => break Ended::TokenExpired,
            () = frames_tx.closed() => break Ended::ClientClosed,
            next = logs.next() => next,
        };
        let sent_bytes;
        let frame = match next {
            None => break Ended::Eof,
            Some(Ok(chunk)) => {
                sent_bytes = chunk.data.len() as u64;
                match chunk.source {
                    LogSource::Stdout => LogFrame::Stdout(chunk.data.to_vec()),
                    LogSource::Stderr => LogFrame::Stderr(chunk.data.to_vec()),
                }
            }
            Some(Err(error)) => {
                tracing::warn!(app = %audit.app, %error, "the container log stream failed");
                break Ended::Error;
            }
        };
        // A client that does not read must not outlive the token either.
        let sent = tokio::select! {
            biased;
            () = &mut expiry => break Ended::TokenExpired,
            sent = frames_tx.send(Bytes::from(frame.encode())) => sent,
        };
        if sent.is_err() {
            break Ended::ClientClosed;
        }
        // Counted once delivered: a frame lost to a hang-up or the token is not output the client got.
        audit.frames += 1;
        audit.bytes += sent_bytes;
    };
    let last = match ended {
        Ended::Eof => Some(LogFrame::End),
        Ended::TokenExpired => Some(LogFrame::TokenExpired),
        Ended::Error => Some(LogFrame::Error("the container log stream failed".into())),
        Ended::ClientClosed => None,
    };
    if let Some(frame) = last {
        let bytes = Bytes::from(frame.encode());
        let delivered = match ended {
            // The log's own end must not be lost to a full queue (a slow client would take it for an
            // interruption and re-read the log from the start); wait for room, but not past the token.
            Ended::Eof | Ended::Error => tokio::select! {
                biased;
                () = &mut expiry => {
                    // The token ran out while the closing frame waited for room: that ended the stream.
                    ended = Ended::TokenExpired;
                    false
                }
                sent = frames_tx.send(bytes) => sent.is_ok(),
            },
            // Not awaited: a client that is not reading gets a stream that just ends, which it treats
            // as an interruption and reconnects from; waiting here would keep the stream past the token.
            Ended::TokenExpired | Ended::ClientClosed => frames_tx.try_send(bytes).is_ok(),
        };
        if delivered {
            audit.frames += 1;
        }
    }
    drop(logs);
    audit.finish(ended);
    (ended, audit)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes as B;
    use futures_util::stream;
    use weglarka_api::LogFrameDecoder;
    use weglarka_model::podman::LogChunk;

    use super::*;

    fn chunk(source: LogSource, data: &'static str) -> Result<LogChunk, PodmanError> {
        Ok(LogChunk {
            source,
            data: B::from_static(data.as_bytes()),
        })
    }

    fn audit() -> Audit {
        Audit::new(
            Some("alice".into()),
            InstanceName::new("web").unwrap(),
            &LogsQuery::default(),
        )
    }

    async fn drain(mut rx: mpsc::Receiver<Bytes>) -> Vec<LogFrame> {
        let mut decoder = LogFrameDecoder::default();
        let mut frames = Vec::new();
        while let Some(bytes) = rx.recv().await {
            frames.extend(decoder.push(&bytes).unwrap());
        }
        assert!(decoder.is_clean());
        frames
    }

    #[tokio::test]
    async fn a_finished_log_ends_with_end() {
        let logs = stream::iter(vec![
            chunk(LogSource::Stdout, "out\n"),
            chunk(LogSource::Stderr, "err\n"),
        ])
        .boxed();
        let (tx, rx) = mpsc::channel(FRAME_QUEUE);
        pump(logs, tx, StreamDeadline(None), audit()).await;
        assert_eq!(
            drain(rx).await,
            [
                LogFrame::Stdout(b"out\n".to_vec()),
                LogFrame::Stderr(b"err\n".to_vec()),
                LogFrame::End
            ]
        );
    }

    #[tokio::test]
    async fn the_end_of_the_log_is_not_lost_when_the_queue_is_full() {
        let logs = stream::iter(vec![
            chunk(LogSource::Stdout, "a\n"),
            chunk(LogSource::Stdout, "b\n"),
            chunk(LogSource::Stdout, "c\n"),
        ])
        .boxed();
        // A queue of one and a reader that arrives late: `End` has to wait for room.
        let (tx, rx) = mpsc::channel(1);
        let pump = tokio::spawn(pump(logs, tx, StreamDeadline(None), audit()));
        tokio::task::yield_now().await;
        let frames = drain(rx).await;
        pump.await.unwrap();
        assert_eq!(frames.len(), 4, "{frames:?}");
        assert_eq!(frames[3], LogFrame::End);
    }

    #[tokio::test]
    async fn a_podman_failure_mid_stream_is_an_error_frame_without_its_text() {
        let logs = stream::iter(vec![
            chunk(LogSource::Stdout, "out\n"),
            Err(PodmanError::Protocol(
                "/run/user/1000/podman.sock: secret".into(),
            )),
        ])
        .boxed();
        let (tx, rx) = mpsc::channel(FRAME_QUEUE);
        pump(logs, tx, StreamDeadline(None), audit()).await;
        let frames = drain(rx).await;
        assert_eq!(frames[0], LogFrame::Stdout(b"out\n".to_vec()));
        let LogFrame::Error(message) = &frames[1] else {
            panic!("{frames:?}")
        };
        assert!(!message.contains("podman.sock"), "{message}");
    }

    #[tokio::test(start_paused = true)]
    async fn the_token_expiring_ends_the_stream_at_exp_with_token_expired() {
        let started = Instant::now();
        let deadline = StreamDeadline(Some(SystemTime::now() + Duration::from_secs(30)));
        // One line, then silence: a followed log of a quiet app.
        let logs = stream::iter(vec![chunk(LogSource::Stdout, "hi\n")])
            .chain(stream::pending())
            .boxed();
        let (tx, rx) = mpsc::channel(FRAME_QUEUE);
        let pump = tokio::spawn(pump(logs, tx, deadline, audit()));
        let frames = drain(rx).await;
        pump.await.unwrap();
        assert_eq!(
            frames,
            [LogFrame::Stdout(b"hi\n".to_vec()), LogFrame::TokenExpired]
        );
        let elapsed = started.elapsed();
        // At exp: not before, and not a leeway after (paused time moves only as far as the sleep).
        assert!(
            elapsed >= Duration::from_secs(29) && elapsed < Duration::from_secs(31),
            "{elapsed:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_client_that_stops_reading_cannot_hold_the_stream_past_exp() {
        let deadline = StreamDeadline(Some(SystemTime::now() + Duration::from_secs(5)));
        // Plenty of output, and a receiver nobody reads: the queue fills and `send` blocks.
        let logs = stream::repeat_with(|| chunk(LogSource::Stdout, "x\n")).boxed();
        let (tx, _rx) = mpsc::channel(1);
        tokio::time::timeout(Duration::from_secs(10), pump(logs, tx, deadline, audit()))
            .await
            .expect("the pump must end at exp, not wait for the client");
    }

    #[tokio::test(start_paused = true)]
    async fn bytes_and_frames_count_only_what_was_delivered() {
        let deadline = StreamDeadline(Some(SystemTime::now() + Duration::from_secs(5)));
        let logs = stream::repeat_with(|| chunk(LogSource::Stdout, "x\n")).boxed();
        // Room for one frame and nobody reading: the second chunk blocks in `send` until exp.
        let (tx, _rx) = mpsc::channel(1);
        let (ended, got) = pump(logs, tx, deadline, audit()).await;
        assert_eq!(ended, Ended::TokenExpired);
        assert_eq!((got.frames, got.bytes), (1, 2));
    }

    #[tokio::test(start_paused = true)]
    async fn a_closing_frame_cut_off_by_the_token_is_audited_as_token_expired() {
        let deadline = StreamDeadline(Some(SystemTime::now() + Duration::from_secs(5)));
        // The log ends, but `End` finds the queue full and nobody reading.
        let logs = stream::iter(vec![chunk(LogSource::Stdout, "x\n")]).boxed();
        let (tx, _rx) = mpsc::channel(1);
        let (ended, got) = pump(logs, tx, deadline, audit()).await;
        assert_eq!(ended, Ended::TokenExpired);
        assert_eq!((got.frames, got.bytes), (1, 2));
    }

    #[tokio::test(start_paused = true)]
    async fn a_client_hanging_up_stops_the_pump_and_drops_the_podman_stream() {
        struct Flag(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Flag {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Flag(Arc::clone(&dropped));
        let logs = stream::pending::<Result<LogChunk, PodmanError>>()
            .inspect(move |_| {
                let _ = &flag;
            })
            .boxed();
        let (tx, rx) = mpsc::channel(FRAME_QUEUE);
        let pump = tokio::spawn(pump(logs, tx, StreamDeadline(None), audit()));
        tokio::task::yield_now().await;
        assert!(!pump.is_finished());
        drop(rx);
        pump.await.unwrap();
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn the_audit_vocabulary_is_fixed() {
        let all = [
            Ended::ClientClosed,
            Ended::TokenExpired,
            Ended::Eof,
            Ended::Error,
        ]
        .map(Ended::as_str);
        assert_eq!(all, ["client_closed", "token_expired", "eof", "error"]);
    }
}
