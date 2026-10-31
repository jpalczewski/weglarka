//! Live parts of the pages, as server-sent events for htmx's `sse` extension.
//!
//! - `GET /events/stream`: the daemon does not stream events, so the panel polls
//!   `GET /v1/events?since=` on the page's behalf and pushes the new rows. Every SSE event carries
//!   `id: <boot_id>:<seq>`, so a reconnecting browser (`Last-Event-ID`) resumes where it stopped.
//! - `GET /apps/{name}/logs/stream`: the daemon's log stream (`admin` only) decoded with the shared
//!   frame decoder. Log text is untrusted: lines are cut, stripped of control characters and
//!   escaped by the template.
//!
//! Every stream is a value owned by the response body: when the browser goes away hyper drops the
//! body, which drops the upstream connection with it. A stream also ends when its session does.
//! Stream activity does not count as session activity (only requests through `require_session`
//! do), so a tab that only watches a stream is signed out when the idle timeout passes.

use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::Path;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use futures_util::stream::{self, Stream};
use tokio::sync::watch;
use weglarka_api::endpoints::{APPS_LOGS, EVENTS_RECENT};
use weglarka_api::{EventsQuery, EventsResponse, LogFrame, LogFrameDecoder};

use crate::app::AppState;
use crate::auth::fresh_token;
use crate::daemon::{Call, DaemonError, Stream as Upstream};
use crate::pages::{ErrorPage, EventItem, LogLine, LogLines, fragment};
use crate::routes::Req;
use crate::session::Session;
use crate::views;

/// Concurrent live streams one session may hold (events + a few logs).
pub const MAX_STREAMS_PER_SESSION: usize = 4;
/// Lines of history a log stream starts with.
const LOG_TAIL: &str = "200";
/// A longer line is cut (characters).
const MAX_LINE_CHARS: usize = 2_000;
/// Lines kept from one chunk of daemon output; the rest are counted, not stored.
const MAX_LINES_PER_CHUNK: usize = 1_000;
/// Lines per SSE event.
const LINES_PER_EVENT: usize = 100;
/// Reconnects after `TokenExpired` or a dropped upstream before giving up (resets on data).
const MAX_RECONNECTS: u32 = 5;
/// Consecutive failed polls after which the events stream ends (the browser reconnects).
const MAX_POLL_FAILURES: u32 = 10;
const KEEP_ALIVE: Duration = Duration::from_secs(15);

/// How many live streams each session holds; keyed by the session's address, which cannot be
/// reused while a stream (holding an `Arc<Session>`) is alive.
#[derive(Debug, Default)]
pub struct StreamSlots(Mutex<HashMap<usize, usize>>);

impl StreamSlots {
    fn acquire(self: &Arc<Self>, session: &Arc<Session>) -> Option<StreamGuard> {
        let key = Arc::as_ptr(session) as usize;
        let mut map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let count = map.entry(key).or_insert(0);
        if *count >= MAX_STREAMS_PER_SESSION {
            return None;
        }
        *count += 1;
        Some(StreamGuard {
            slots: self.clone(),
            key,
            _session: session.clone(),
        })
    }

    pub fn open_streams(&self) -> usize {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .sum()
    }
}

struct StreamGuard {
    slots: Arc<StreamSlots>,
    key: usize,
    _session: Arc<Session>,
}

impl Drop for StreamGuard {
    fn drop(&mut self) {
        let mut map = self.slots.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = map.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                map.remove(&self.key);
            }
        }
    }
}

fn too_many() -> Response {
    ErrorPage {
        title: "Too many live views",
        message: "Close another tab with a live view and try again.",
        sign_in: None,
    }
    .respond(StatusCode::TOO_MANY_REQUESTS)
}

fn sse<S>(stream: S) -> Response
where
    S: Stream<Item = Result<Event, Infallible>> + Send + 'static,
{
    let mut response = Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(KEEP_ALIVE))
        .into_response();
    response
        .headers_mut()
        .insert("x-accel-buffering", HeaderValue::from_static("no"));
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Waits for `delay` or the end of the session; `false` = the session ended.
async fn pause(ended: &mut watch::Receiver<bool>, delay: Duration) -> bool {
    tokio::select! {
        () = tokio::time::sleep(delay) => !*ended.borrow(),
        changed = ended.changed() => changed.is_ok() && !*ended.borrow(),
    }
}

// ---- events ---------------------------------------------------------------------------------

/// Where an events stream continues from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Cursor {
    boot: Option<String>,
    since: Option<u64>,
}

/// `Last-Event-ID: <boot>:<seq>` (the browser's own resume) wins over the page's `since`/`boot`.
fn cursor_from(last_event_id: Option<&str>, query: Option<&str>) -> Cursor {
    if let Some((boot, seq)) = last_event_id.and_then(|v| v.split_once(':')) {
        let q = EventsQuery::parse(Some(&format!("since={seq}&boot={boot}")));
        if let Ok(q) = q {
            return Cursor {
                boot: q.boot,
                since: q.since,
            };
        }
    }
    match EventsQuery::parse(query) {
        Ok(q) => Cursor {
            boot: q.boot,
            since: q.since,
        },
        Err(_) => Cursor::default(),
    }
}

struct EventsState {
    app: AppState,
    session: Arc<Session>,
    ended: watch::Receiver<bool>,
    cursor: Cursor,
    first: bool,
    failures: u32,
    queue: VecDeque<Event>,
    _slot: StreamGuard,
}

/// `GET /events/stream`.
pub async fn events_stream(req: Req) -> Response {
    let Some(slot) = req.state.streams.acquire(&req.session) else {
        return too_many();
    };
    let last_id = req
        .headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok());
    let cursor = cursor_from(last_id, req.uri.query());
    let mut state = EventsState {
        ended: req.session.ended(),
        app: req.state.clone(),
        session: req.session.clone(),
        cursor,
        first: false,
        failures: 0,
        queue: VecDeque::new(),
        _slot: slot,
    };
    // The first poll happens before the response is committed, so a refusal is an HTTP status
    // (EventSource gives up on a non-200) rather than an endless reconnect loop.
    if let Err(e) = poll_events(&mut state).await {
        return req.problem(&e, EVENTS_RECENT.scope);
    }
    sse(stream::unfold(state, next_events))
}

/// One poll of the daemon's events with the session's current token; queues the new rows.
async fn poll_events(st: &mut EventsState) -> Result<(), DaemonError> {
    let token = fresh_token(&st.app, &st.session)
        .await
        .ok_or(DaemonError::Unauthorized)?;
    let mut call = Call::new(&EVENTS_RECENT);
    if let Some(since) = st.cursor.since {
        call = call.query("since", since.to_string());
    }
    if let Some(boot) = &st.cursor.boot {
        call = call.query("boot", boot.clone());
    }
    let answer = st.app.daemon.send::<EventsResponse>(&token, &call).await?;
    queue_events(st, &answer);
    Ok(())
}

async fn next_events(mut st: EventsState) -> Option<(Result<Event, Infallible>, EventsState)> {
    loop {
        if let Some(event) = st.queue.pop_front() {
            return Some((Ok(event), st));
        }
        if !st.first && !pause(&mut st.ended, st.app.stream_poll).await {
            return None;
        }
        st.first = false;
        if st.session.is_ended() {
            return None;
        }
        match poll_events(&mut st).await {
            Ok(()) => st.failures = 0,
            // The daemon gives this identity no access at all (events need only `read`): the
            // session is over, not just this stream. The headers are sent, so end it directly.
            Err(DaemonError::Unauthorized | DaemonError::Forbidden) => {
                st.session.end();
                return None;
            }
            Err(e) => {
                st.failures += 1;
                tracing::debug!(error = %e, "polling daemon events failed");
                if st.failures >= MAX_POLL_FAILURES {
                    return None;
                }
            }
        }
    }
}

fn queue_events(st: &mut EventsState, answer: &EventsResponse) {
    if answer.reset {
        let notice = r#"<li class="event notice">The daemon restarted; its event history started over.</li>"#;
        st.queue.push_back(Event::default().data(notice));
    }
    for record in &answer.events {
        let row = views::event_row(record);
        let Some(html) = fragment(&EventItem { e: &row }) else {
            continue;
        };
        let mut event = Event::default().data(html);
        if is_boot_id(&answer.boot_id) {
            event = event.id(format!("{}:{}", answer.boot_id, record.seq));
        }
        st.queue.push_back(event);
    }
    st.cursor = Cursor {
        boot: is_boot_id(&answer.boot_id).then(|| answer.boot_id.clone()),
        since: Some(answer.next_seq),
    };
}

fn is_boot_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
}

// ---- logs -----------------------------------------------------------------------------------

/// Escapes text for an HTML text node. For the few fragments built by hand; everything else goes
/// through the templates.
pub fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// One line of untrusted log output made fit to show: control characters (escape sequences
/// included) and bidirectional overrides are dropped, a tab becomes a space, and a long line is cut.
pub fn sanitize_line(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    let mut out = String::new();
    for (count, c) in text.trim_end_matches('\r').chars().enumerate() {
        if count >= MAX_LINE_CHARS {
            out.push('…');
            break;
        }
        match c {
            '\t' => out.push(' '),
            c if c.is_control() => {}
            '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{200e}' | '\u{200f}' => {}
            c => out.push(c),
        }
    }
    out
}

/// Cuts a byte stream into lines without keeping more than one capped partial line.
#[derive(Debug, Default)]
struct LineSplitter {
    partial: Vec<u8>,
    overflow: bool,
}

/// What a chunk produced.
#[derive(Debug, Default, PartialEq, Eq)]
struct Split {
    lines: Vec<String>,
    /// Lines dropped because the chunk had more than [`MAX_LINES_PER_CHUNK`].
    skipped: usize,
}

impl LineSplitter {
    fn push(&mut self, data: &[u8]) -> Split {
        // Bytes kept per line: enough for MAX_LINE_CHARS characters of any width, plus the cut mark.
        const MAX_BYTES: usize = MAX_LINE_CHARS * 4 + 8;
        let mut split = Split::default();
        for piece in data.split_inclusive(|b| *b == b'\n') {
            let (body, complete) = match piece.split_last() {
                Some((b'\n', rest)) => (rest, true),
                _ => (piece, false),
            };
            if !self.overflow {
                let room = MAX_BYTES.saturating_sub(self.partial.len());
                self.partial
                    .extend_from_slice(&body[..body.len().min(room)]);
                self.overflow = body.len() > room;
            }
            if complete {
                if split.lines.len() < MAX_LINES_PER_CHUNK {
                    let mut line = sanitize_line(&self.partial);
                    if self.overflow && !line.ends_with('…') {
                        line.push('…');
                    }
                    split.lines.push(line);
                } else {
                    split.skipped += 1;
                }
                self.partial.clear();
                self.overflow = false;
            }
        }
        split
    }
}

struct LogsState {
    app: AppState,
    session: Arc<Session>,
    ended: watch::Receiver<bool>,
    name: String,
    upstream: Option<Upstream>,
    decoder: LogFrameDecoder,
    stdout: LineSplitter,
    stderr: LineSplitter,
    /// When data last arrived: a reconnect asks for output since then.
    last_data: SystemTime,
    reconnects: u32,
    queue: VecDeque<Event>,
    done: bool,
    /// The terminal `done` event has been sent.
    closed: bool,
    _slot: StreamGuard,
}

fn log_call(name: &str, since: Option<SystemTime>) -> Call {
    let call = Call::new(&APPS_LOGS)
        .param("name", name)
        .query("follow", "true");
    match since.and_then(|t| t.duration_since(UNIX_EPOCH).ok()) {
        Some(d) => call.query("since", format!("{}.{:09}", d.as_secs(), d.subsec_nanos())),
        None => call.query("tail", LOG_TAIL),
    }
}

/// `GET /apps/{name}/logs/stream`. The daemon's answer to the first request is the answer to the
/// browser: a 403 for a user who is not an admin, a 404 for an app without a container.
pub async fn logs_stream(req: Req, Path(name): Path<String>) -> Response {
    let name = match req.app_name(&name) {
        Ok(name) => name,
        Err(r) => return *r,
    };
    let Some(slot) = req.state.streams.acquire(&req.session) else {
        return too_many();
    };
    let started = SystemTime::now();
    let upstream = match req
        .state
        .daemon
        .open(&req.view.token, &log_call(&name, None))
        .await
    {
        Ok(upstream) => upstream,
        Err(e) => return req.problem(&e, APPS_LOGS.scope),
    };
    let state = LogsState {
        ended: req.session.ended(),
        app: req.state.clone(),
        session: req.session.clone(),
        name,
        upstream: Some(upstream),
        decoder: LogFrameDecoder::default(),
        stdout: LineSplitter::default(),
        stderr: LineSplitter::default(),
        last_data: started,
        reconnects: 0,
        queue: VecDeque::new(),
        done: false,
        closed: false,
        _slot: slot,
    };
    sse(stream::unfold(state, next_logs))
}

/// A status line for the log view. Terminal ones (`done`) are followed by a `done` event, which
/// the page's `sse-close="done"` turns into a closed EventSource: no reconnect, no duplicated tail.
fn status_event(text: &str) -> Event {
    Event::default().event("status").data(escape_html(text))
}

fn done_event() -> Event {
    Event::default().event("done").data("")
}

async fn next_logs(mut st: LogsState) -> Option<(Result<Event, Infallible>, LogsState)> {
    loop {
        if let Some(event) = st.queue.pop_front() {
            return Some((Ok(event), st));
        }
        if st.session.is_ended() {
            return None;
        }
        if st.done {
            if st.closed {
                return None;
            }
            st.closed = true;
            return Some((Ok(done_event()), st));
        }
        if st.upstream.is_none() {
            reconnect(&mut st).await;
            continue;
        }
        let upstream = st.upstream.as_mut()?;
        let chunk = tokio::select! {
            chunk = upstream.chunk() => chunk,
            // Logout, expiry or a failed refresh: close without a word (the page is gone too).
            _ = st.ended.changed() => return None,
        };
        match chunk {
            Some(Ok(bytes)) => {
                st.last_data = SystemTime::now();
                match st.decoder.push(&bytes) {
                    Ok(frames) => {
                        for frame in frames {
                            handle_frame(&mut st, frame);
                        }
                    }
                    Err(_) => {
                        st.queue.push_back(status_event(
                            "The log stream from the daemon is corrupted.",
                        ));
                        st.done = true;
                    }
                }
            }
            // The daemon closed the connection or it broke: try once more from where we stopped.
            Some(Err(_)) | None => st.upstream = None,
        }
    }
}

fn handle_frame(st: &mut LogsState, frame: LogFrame) {
    match frame {
        LogFrame::Stdout(data) => queue_lines(st, false, &data),
        LogFrame::Stderr(data) => queue_lines(st, true, &data),
        LogFrame::End => {
            st.queue.push_back(status_event("The log ended."));
            st.done = true;
        }
        // The token this stream was opened with expired: drop the connection, then reconnect with
        // a refreshed one, since the last data.
        LogFrame::TokenExpired => st.upstream = None,
        LogFrame::Error(message) => {
            let message = sanitize_line(message.as_bytes());
            st.queue.push_back(status_event(&format!(
                "The daemon reported an error: {message}"
            )));
            st.done = true;
        }
    }
}

fn queue_lines(st: &mut LogsState, stderr: bool, data: &[u8]) {
    st.reconnects = 0;
    let split = if stderr {
        st.stderr.push(data)
    } else {
        st.stdout.push(data)
    };
    let mut lines: Vec<LogLine> = split
        .lines
        .into_iter()
        .map(|text| LogLine { stderr, text })
        .collect();
    if split.skipped > 0 {
        lines.push(LogLine {
            stderr: true,
            text: format!("… {} lines skipped (too fast to show)", split.skipped),
        });
    }
    for batch in lines.chunks(LINES_PER_EVENT) {
        if let Some(html) = fragment(&LogLines { lines: batch }) {
            st.queue
                .push_back(Event::default().event("lines").data(html));
        }
    }
}

async fn reconnect(st: &mut LogsState) {
    st.reconnects += 1;
    if st.reconnects > MAX_RECONNECTS {
        st.queue
            .push_back(status_event("The connection to the daemon was lost."));
        st.done = true;
        return;
    }
    if st.reconnects > 1 && !pause(&mut st.ended, Duration::from_secs(1)).await {
        st.done = true;
        return;
    }
    let Some(token) = fresh_token(&st.app, &st.session).await else {
        st.done = true;
        return;
    };
    let call = log_call(&st.name, Some(st.last_data));
    match st.app.daemon.open(&token, &call).await {
        Ok(upstream) => {
            st.upstream = Some(upstream);
            // A half line from the old connection must not be glued to the new one's output.
            st.decoder = LogFrameDecoder::default();
            st.stdout = LineSplitter::default();
            st.stderr = LineSplitter::default();
        }
        Err(DaemonError::Unauthorized) => {
            st.session.end();
            st.done = true;
        }
        Err(DaemonError::Forbidden) => {
            st.queue
                .push_back(status_event("Logs are only available to administrators."));
            st.done = true;
        }
        Err(DaemonError::NotFound(_)) => {
            st.queue
                .push_back(status_event("The application has no running container."));
            st.done = true;
        }
        // Anything else is transient: loop around and try again, up to the limit.
        Err(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_are_sanitized() {
        assert_eq!(sanitize_line(b"plain\r"), "plain");
        assert_eq!(sanitize_line(b"a\x1b[31mred\x1b[0m"), "a[31mred[0m");
        assert_eq!(sanitize_line(b"a\tb\x00c\x07"), "a bc");
        assert_eq!(sanitize_line("x\u{202e}y".as_bytes()), "xy");
        assert_eq!(sanitize_line(b"bad \xff utf8"), "bad \u{fffd} utf8");
        let long = "é".repeat(MAX_LINE_CHARS + 50);
        let cut = sanitize_line(long.as_bytes());
        assert_eq!(cut.chars().count(), MAX_LINE_CHARS + 1);
        assert!(cut.ends_with('…'));
    }

    #[test]
    fn splitter_joins_chunks_and_caps_memory() {
        let mut s = LineSplitter::default();
        assert!(s.push(b"hel").lines.is_empty());
        assert_eq!(s.push(b"lo\nwor").lines, ["hello"]);
        assert_eq!(s.push(b"ld\n\n").lines, ["world", ""]);

        // A line without a newline never grows the buffer past its cap.
        let mut s = LineSplitter::default();
        for _ in 0..100 {
            s.push(&vec![b'x'; 10_000]);
        }
        assert!(s.partial.len() <= MAX_LINE_CHARS * 4 + 8);
        let out = s.push(b"\n");
        assert!(out.lines[0].ends_with('…'), "{}", out.lines[0].len());
    }

    #[test]
    fn a_flood_of_lines_is_counted_not_kept() {
        let mut s = LineSplitter::default();
        let split = s.push(&b"x\n".repeat(MAX_LINES_PER_CHUNK + 25));
        assert_eq!(split.lines.len(), MAX_LINES_PER_CHUNK);
        assert_eq!(split.skipped, 25);
    }

    #[test]
    fn escape_covers_the_html_specials() {
        assert_eq!(
            escape_html(r#"<a href="x">&'"#),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
    }

    #[test]
    fn cursor_prefers_last_event_id_and_validates_it() {
        let c = cursor_from(Some("ab-12:7"), Some("since=3&boot=ff"));
        assert_eq!((c.boot.as_deref(), c.since), (Some("ab-12"), Some(7)));
        let c = cursor_from(None, Some("since=3&boot=ff"));
        assert_eq!((c.boot.as_deref(), c.since), (Some("ff"), Some(3)));
        // Garbage in the header falls back to the query, garbage in both to "from the start".
        assert_eq!(cursor_from(Some("x y:1"), Some("since=3")).since, Some(3));
        assert_eq!(
            cursor_from(Some("junk"), Some("since=zz")),
            Cursor::default()
        );
    }

    #[test]
    fn stream_slots_are_per_session_and_released() {
        use crate::session::{Session, Tokens, User};
        let session = |name: &str| {
            Arc::new(Session::new(
                User {
                    sub: name.into(),
                    name: name.into(),
                },
                Tokens {
                    access: Arc::new(crate::config::Secret::new("t")),
                    refresh: None,
                    access_expires: std::time::Instant::now(),
                    refresh_retry_at: None,
                },
                std::time::Instant::now(),
            ))
        };
        let slots = Arc::new(StreamSlots::default());
        let (a, b) = (session("a"), session("b"));
        let held: Vec<_> = (0..MAX_STREAMS_PER_SESSION)
            .map(|_| slots.acquire(&a).unwrap())
            .collect();
        assert!(slots.acquire(&a).is_none());
        assert!(slots.acquire(&b).is_some());
        drop(held);
        let again = slots.acquire(&a);
        assert!(again.is_some());
        assert_eq!(slots.open_streams(), 1);
    }
}
