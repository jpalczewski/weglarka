//! Live parts of the pages, as server-sent events for htmx's `sse` extension.
//!
//! - `GET /events/stream`: the daemon does not stream events, so the panel polls
//!   `GET /v1/events?since=` on the page's behalf and pushes the new rows. Every SSE event carries
//!   `id: <boot_id>:<seq>`, so a reconnecting browser (`Last-Event-ID`) resumes where it stopped.
//! - `GET /apps/{name}/logs/stream`: the daemon's log stream (`admin` only) decoded with the shared
//!   frame decoder. Log text is untrusted: lines are cut, stripped of control characters and
//!   escaped by the template.
//!
//! - `GET /apps/{name}/access/stream`: the daemon's access-log stream (`admin` only), the same driver
//!   over an `AccessFeed`. The browser's filter is parsed with `AccessQuery::parse` and only the
//!   parsed value is forwarded; every entry field is untrusted and is cut, cleaned and escaped.
//! - `GET /apps/{name}/logs` and `GET /apps/{name}/access`: the fragments the app page's "Start"
//!   buttons load. They hold the `sse-connect`, so a page opens no stream until it is asked to.
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
use weglarka_api::endpoints::{APPS_ACCESS, APPS_LOGS, APPS_SHOW, EVENTS_RECENT};
use weglarka_api::{
    AccessEntry, AccessFrame, AccessQuery, Control, ControlFrame, EventsQuery, EventsResponse,
    FrameDecoder, FrameKind, LogFrame, ShowAppResponse, parse_rfc3339,
};
use weglarka_model::admin_auth::Scope;
use weglarka_unix_http::Bytes;

use crate::app::AppState;
use crate::auth::fresh_token;
use crate::daemon::{Call, DaemonError, Stream as Upstream};
use crate::pages::{
    AccessLive, AccessRow, AccessRows, ErrorPage, EventItem, FilterError, LogLine, LogLines,
    LogsLive, fragment, respond,
};
use crate::routes::Req;
use crate::session::Session;
use crate::views;

/// Concurrent live streams one session may hold (events + a few logs).
pub const MAX_STREAMS_PER_SESSION: usize = 4;
/// Lines of history a log stream starts with.
const LOG_TAIL: &str = "200";
/// Entries of history an access-log stream starts with when the filter names no `tail`.
const ACCESS_TAIL: u32 = 100;
/// Longest filter query string accepted from the browser (bytes, before decoding).
const MAX_FILTER_QUERY: usize = 1024;
/// Rows waiting in one stream's queue; a faster daemon is counted, not stored.
const MAX_QUEUED_ROWS: usize = 500;
/// Characters of each access-log field shown (a longer one is cut).
const MAX_TIME_CHARS: usize = 40;
const MAX_METHOD_CHARS: usize = 16;
const MAX_PATH_CHARS: usize = 300;
const MAX_ADDR_CHARS: usize = 64;
const MAX_AGENT_CHARS: usize = 200;
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
/// Wait before the second and later reconnects in a row.
const RECONNECT_DELAY: Duration = Duration::from_secs(1);
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
    clean_text(
        String::from_utf8_lossy(raw).trim_end_matches('\r'),
        MAX_LINE_CHARS,
    )
}

/// Untrusted text made fit to show: unsafe characters ([`weglarka_api::is_unsafe_char`]) are
/// dropped, a tab becomes a space, and at most `max` characters of the input are looked at (the
/// rest is replaced by `…`), so the work and the output are bounded whatever the input size.
fn clean_text(text: &str, max: usize) -> String {
    let mut out = String::new();
    for (count, c) in text.chars().enumerate() {
        if count >= max {
            out.push('…');
            break;
        }
        match c {
            '\t' => out.push(' '),
            c if weglarka_api::is_unsafe_char(c) => {}
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

/// The log stream as a feed: cuts the output into sanitized lines, one splitter per channel.
struct LogsFeed {
    name: String,
    stdout: LineSplitter,
    stderr: LineSplitter,
}

impl LogsFeed {
    fn new(name: String) -> Self {
        Self {
            name,
            stdout: LineSplitter::default(),
            stderr: LineSplitter::default(),
        }
    }

    fn lines(&mut self, stderr: bool, data: &[u8], out: &mut VecDeque<Event>) {
        let split = if stderr {
            self.stderr.push(data)
        } else {
            self.stdout.push(data)
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
                out.push_back(Event::default().event("lines").data(html));
            }
        }
    }
}

impl UpstreamFeed for LogsFeed {
    type Frame = LogFrame;

    const NOTICES: Notices = Notices {
        ended: "The log ended.",
        corrupted: "The log stream from the daemon is corrupted.",
        forbidden: "Logs are only available to administrators.",
        not_found: "The application has no running container.",
    };

    fn call(&self, resume_from: Option<SystemTime>) -> Call {
        log_call(&self.name, resume_from)
    }

    fn on_data(&mut self, frame: LogFrame, out: &mut VecDeque<Event>) -> bool {
        match frame {
            LogFrame::Stdout(data) => self.lines(false, &data, out),
            LogFrame::Stderr(data) => self.lines(true, &data, out),
            // Control frames are the driver's.
            LogFrame::End | LogFrame::TokenExpired | LogFrame::Error(_) => return false,
        }
        true
    }

    fn reset(&mut self) {
        // A half line from the old connection must not be glued to the new one's output.
        self.stdout = LineSplitter::default();
        self.stderr = LineSplitter::default();
    }
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
    serve(req, LogsFeed::new(name), APPS_LOGS.scope).await
}

/// Takes a stream slot, opens the feed's first request with the user's token and hands the
/// connection to a [`Driver`]. A refusal from the daemon is the answer to the browser.
async fn serve<F: UpstreamFeed>(req: Req, feed: F, scope: Option<Scope>) -> Response {
    let Some(slot) = req.state.streams.acquire(&req.session) else {
        return too_many();
    };
    let started = SystemTime::now();
    let upstream = match req
        .state
        .daemon
        .open(&req.view.token, &feed.call(None))
        .await
    {
        Ok(upstream) => upstream,
        Err(e) => return req.problem(&e, scope),
    };
    let link = PanelLink {
        app: req.state.clone(),
        session: req.session.clone(),
    };
    let driver = Driver::new(feed, link, req.session.clone(), upstream, started, slot);
    sse(stream::unfold(driver, Driver::next))
}

/// The section fragments are for administrators like the streams they start: the daemon marks the
/// app view `redacted` exactly for a token below `admin`. Nothing is opened here.
async fn require_admin(req: &Req, name: &str, scope: Option<Scope>) -> Result<(), Box<Response>> {
    let call = Call::new(&APPS_SHOW).param("name", name);
    let app = req.get::<ShowAppResponse>(call).await?;
    if app.redacted {
        return Err(Box::new(req.problem(&DaemonError::Forbidden, scope)));
    }
    Ok(())
}

/// `GET /apps/{name}/logs`: the live log element the "Start" button loads (docs/decisions/0065,
/// decision 7: a stream opens on demand, not on page load).
pub async fn logs_section(req: Req, Path(name): Path<String>) -> Response {
    let name = match req.app_name(&name) {
        Ok(name) => name,
        Err(r) => return *r,
    };
    if let Err(r) = require_admin(&req, &name, APPS_LOGS.scope).await {
        return *r;
    }
    respond(
        &LogsLive {
            stream: format!("/apps/{name}/logs/stream"),
        },
        StatusCode::OK,
    )
}

/// A status line for the log view. Terminal ones (`done`) are followed by a `done` event, which
/// the page's `sse-close="done"` turns into a closed EventSource: no reconnect, no duplicated tail.
fn status_event(text: &str) -> Event {
    Event::default().event("status").data(escape_html(text))
}

fn done_event() -> Event {
    Event::default().event("done").data("")
}

// ---- access log -----------------------------------------------------------------------------

/// The browser's filter was not acceptable. Carries no detail on purpose: nothing of the input is
/// echoed back.
#[derive(Debug)]
struct InvalidFilter;

fn invalid_filter() -> Response {
    respond(&FilterError, StatusCode::BAD_REQUEST)
}

/// Turns the browser's query string into the query the panel is willing to forward.
///
/// The form sends an empty value for every filter left blank, which counts as "no filter". Values
/// are percent-decoded first (a form encodes `/`), then checked by [`AccessQuery::parse`], which
/// accepts only the shapes the daemon accepts. What is returned is that parsed value: the raw string
/// never reaches the daemon. `follow` is always on and `since` is the panel's own (resume), so a
/// browser-supplied one is dropped.
fn access_filter(raw: Option<&str>) -> Result<AccessQuery, InvalidFilter> {
    let raw = raw.unwrap_or_default();
    if raw.len() > MAX_FILTER_QUERY {
        return Err(InvalidFilter);
    }
    let mut pairs = Vec::new();
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        if value.is_empty() {
            continue;
        }
        // A decoded `&` or `=` would turn into another parameter once the pairs are joined.
        if key.contains(['&', '=']) || value.contains(['&', '=']) {
            return Err(InvalidFilter);
        }
        pairs.push(format!("{key}={value}"));
    }
    let mut query = AccessQuery::parse(Some(&pairs.join("&"))).map_err(|_| InvalidFilter)?;
    query.follow = true;
    query.since = None;
    Ok(query)
}

/// The request for an access stream: `follow=true` always; the first connection starts from the
/// `tail` (default [`ACCESS_TAIL`]), a resume from `since`, then the filter.
fn access_call(name: &str, filter: &AccessQuery, since: Option<Duration>) -> Call {
    let mut call = Call::new(&APPS_ACCESS)
        .param("name", name)
        .query("follow", "true");
    call = match since {
        Some(d) => call.query("since", format!("{}.{:09}", d.as_secs(), d.subsec_nanos())),
        None => call.query("tail", filter.tail.unwrap_or(ACCESS_TAIL).to_string()),
    };
    if let Some(status) = filter.status {
        call = call.query("status", status.to_string());
    }
    if let Some(method) = &filter.method {
        call = call.query("method", method.clone());
    }
    if let Some(path) = &filter.path {
        call = call.query("path", path.clone());
    }
    if let Some(host) = &filter.host {
        call = call.query("host", host.clone());
    }
    call
}

/// One access-log entry made fit to show. Every text field is untrusted (a client chooses the
/// path and the user agent): cut, cleaned, and escaped later by the template.
fn access_row(entry: &AccessEntry) -> AccessRow {
    let request_time = if entry.request_time.is_finite() && entry.request_time >= 0.0 {
        format!("{:.3} s", entry.request_time)
    } else {
        "-".to_owned()
    };
    AccessRow {
        time: clean_text(&entry.time, MAX_TIME_CHARS),
        method: clean_text(&entry.method, MAX_METHOD_CHARS),
        path: clean_text(&entry.path, MAX_PATH_CHARS),
        status: entry.status,
        class: match entry.status / 100 {
            2 => "ok",
            3 => "info",
            4 => "warn",
            5 => "fail",
            _ => "muted",
        },
        bytes: entry.bytes_sent,
        request_time,
        remote: clean_text(&entry.remote_addr, MAX_ADDR_CHARS),
        user_agent: clean_text(&entry.user_agent, MAX_AGENT_CHARS),
    }
}

/// The access log as a feed: one row per entry; remembers the time of the newest entry so that a
/// reconnect asks for `since` it.
struct AccessFeed {
    name: String,
    filter: AccessQuery,
    /// The newest entry time seen (since the unix epoch); survives a reconnect.
    last_entry: Option<Duration>,
    /// Entries dropped because the queue was full, until the next row says so.
    skipped: usize,
}

impl AccessFeed {
    fn new(name: String, filter: AccessQuery) -> Self {
        Self {
            name,
            filter,
            last_entry: None,
            skipped: 0,
        }
    }
}

impl UpstreamFeed for AccessFeed {
    type Frame = AccessFrame;

    const NOTICES: Notices = Notices {
        ended: "The access log ended.",
        corrupted: "The access-log stream from the daemon is corrupted.",
        forbidden: "The access log is only available to administrators.",
        not_found: "The application was not found.",
    };

    fn call(&self, resume_from: Option<SystemTime>) -> Call {
        // A resume asks for entries since the newest one received (the daemon's `since` is
        // inclusive, so that one may come twice); with none yet, since data last arrived.
        let since = resume_from.map(|at| {
            self.last_entry
                .unwrap_or_else(|| at.duration_since(UNIX_EPOCH).unwrap_or_default())
        });
        access_call(&self.name, &self.filter, since)
    }

    fn on_data(&mut self, frame: AccessFrame, out: &mut VecDeque<Event>) -> bool {
        let AccessFrame::Entry(entry) = frame else {
            // Control frames are the driver's.
            return false;
        };
        if let Some(at) = parse_rfc3339(entry.time.as_bytes()) {
            self.last_entry = Some(self.last_entry.map_or(at, |old| old.max(at)));
        }
        if out.len() >= MAX_QUEUED_ROWS {
            self.skipped += 1;
            return true;
        }
        if self.skipped > 0 {
            let text = format!("… {} entries skipped (too fast to show)", self.skipped);
            out.push_back(status_event(&text));
            self.skipped = 0;
        }
        if let Some(html) = fragment(&AccessRows {
            rows: &[access_row(&entry)],
        }) {
            out.push_back(Event::default().event("rows").data(html));
        }
        true
    }

    fn reset(&mut self) {
        // Nothing is half-assembled: an entry is a whole frame. `last_entry` must survive.
    }
}

/// `GET /apps/{name}/access`: the live element the filter form's "Start" loads. The filter is
/// validated here (400 without echoing it) and the stream URL it carries is the re-encoded parsed
/// value.
pub async fn access_section(req: Req, Path(name): Path<String>) -> Response {
    let name = match req.app_name(&name) {
        Ok(name) => name,
        Err(r) => return *r,
    };
    if let Err(r) = require_admin(&req, &name, APPS_ACCESS.scope).await {
        return *r;
    }
    let Ok(filter) = access_filter(req.uri.query()) else {
        return invalid_filter();
    };
    respond(
        &AccessLive {
            stream: format!("/apps/{name}/access/stream?{}", filter.to_query_string()),
        },
        StatusCode::OK,
    )
}

/// `GET /apps/{name}/access/stream`. Like the logs, the daemon's answer to the first request is
/// the answer to the browser (403 for a user who is not an admin).
pub async fn access_stream(req: Req, Path(name): Path<String>) -> Response {
    let name = match req.app_name(&name) {
        Ok(name) => name,
        Err(r) => return *r,
    };
    let Ok(filter) = access_filter(req.uri.query()) else {
        return invalid_filter();
    };
    serve(req, AccessFeed::new(name, filter), APPS_ACCESS.scope).await
}

// ---- the resumable stream driver ------------------------------------------------------------

/// The texts a stream shows when it ends for a reason of its own.
struct Notices {
    /// The daemon sent `End`.
    ended: &'static str,
    /// The frames from the daemon could not be decoded.
    corrupted: &'static str,
    /// A reconnect was refused with 403.
    forbidden: &'static str,
    /// A reconnect found nothing to stream (404).
    not_found: &'static str,
}

/// What one daemon stream turns into on the page; the [`Driver`] does the rest (frames, control,
/// reconnect, end of the session).
trait UpstreamFeed: Send + 'static {
    type Frame: FrameKind + ControlFrame + Send + 'static;

    const NOTICES: Notices;

    /// The request that opens (or, with `resume_from` = when data last arrived, resumes) the stream.
    fn call(&self, resume_from: Option<SystemTime>) -> Call;

    /// Queues the events a data frame stands for. `true` = it was data, so the reconnect counter
    /// starts over. Control frames never get here.
    fn on_data(&mut self, frame: Self::Frame, out: &mut VecDeque<Event>) -> bool;

    /// A new connection starts: drop anything half-assembled from the old one.
    fn reset(&mut self);
}

/// Why a connection could not be made.
#[derive(Debug)]
enum Connect {
    /// No usable token (the session ended or its refresh was refused).
    NoToken,
    Daemon(DaemonError),
}

/// An open connection to the daemon, read chunk by chunk.
trait Conn: Send + 'static {
    /// The next chunk; `None` = the daemon closed the connection or it broke.
    fn chunk(&mut self) -> impl Future<Output = Option<Bytes>> + Send;
}

/// Opens connections with the session's current token.
trait Link: Send + 'static {
    type Conn: Conn;

    fn connect(&self, call: &Call) -> impl Future<Output = Result<Self::Conn, Connect>> + Send;
}

impl Conn for Upstream {
    async fn chunk(&mut self) -> Option<Bytes> {
        match Upstream::chunk(self).await {
            Some(Ok(bytes)) => Some(bytes),
            Some(Err(_)) | None => None,
        }
    }
}

struct PanelLink {
    app: AppState,
    session: Arc<Session>,
}

impl Link for PanelLink {
    type Conn = Upstream;

    async fn connect(&self, call: &Call) -> Result<Upstream, Connect> {
        let token = fresh_token(&self.app, &self.session)
            .await
            .ok_or(Connect::NoToken)?;
        self.app
            .daemon
            .open(&token, call)
            .await
            .map_err(Connect::Daemon)
    }
}

/// One resumable stream from the daemon as SSE events. Owns the connection, the decoder, the
/// stream slot, the queue and the reconnect counter, so that dropping it (the browser left) closes
/// everything. Reconnects after `TokenExpired` or a dropped connection, asking for output since
/// the last data; ends silently with the session; ends with a status and `done` otherwise.
struct Driver<F: UpstreamFeed, L: Link> {
    feed: F,
    link: L,
    session: Arc<Session>,
    ended: watch::Receiver<bool>,
    upstream: Option<L::Conn>,
    decoder: FrameDecoder<F::Frame>,
    /// When data last arrived: a reconnect asks for output since then.
    last_data: SystemTime,
    reconnects: u32,
    /// Wait before the second and later reconnects in a row.
    retry_delay: Duration,
    queue: VecDeque<Event>,
    done: bool,
    /// The terminal `done` event has been sent.
    closed: bool,
    _slot: StreamGuard,
}

impl<F: UpstreamFeed, L: Link> Driver<F, L> {
    fn new(
        feed: F,
        link: L,
        session: Arc<Session>,
        upstream: L::Conn,
        started: SystemTime,
        slot: StreamGuard,
    ) -> Self {
        Self {
            feed,
            link,
            ended: session.ended(),
            session,
            upstream: Some(upstream),
            decoder: FrameDecoder::default(),
            last_data: started,
            reconnects: 0,
            retry_delay: RECONNECT_DELAY,
            queue: VecDeque::new(),
            done: false,
            closed: false,
            _slot: slot,
        }
    }

    /// The next SSE event, or `None` when the stream is over.
    async fn next(mut self) -> Option<(Result<Event, Infallible>, Self)> {
        loop {
            if let Some(event) = self.queue.pop_front() {
                return Some((Ok(event), self));
            }
            if self.session.is_ended() {
                return None;
            }
            if self.done {
                if self.closed {
                    return None;
                }
                self.closed = true;
                return Some((Ok(done_event()), self));
            }
            if self.upstream.is_none() {
                self.reconnect().await;
                continue;
            }
            let upstream = self.upstream.as_mut()?;
            let chunk = tokio::select! {
                chunk = upstream.chunk() => chunk,
                // Logout, expiry or a failed refresh: close without a word (the page is gone too).
                _ = self.ended.changed() => return None,
            };
            match chunk {
                Some(bytes) => {
                    self.last_data = SystemTime::now();
                    match self.decoder.push(&bytes) {
                        Ok(frames) => {
                            for frame in frames {
                                self.handle(frame);
                            }
                        }
                        Err(_) => self.finish(F::NOTICES.corrupted),
                    }
                }
                // The daemon closed the connection or it broke: try once more from where we stopped.
                None => self.upstream = None,
            }
        }
    }

    /// A status line, then the end of the stream.
    fn finish(&mut self, notice: &str) {
        self.queue.push_back(status_event(notice));
        self.done = true;
    }

    fn handle(&mut self, frame: F::Frame) {
        match frame.control() {
            Some(Control::End) => self.finish(F::NOTICES.ended),
            // The token this stream was opened with expired: drop the connection, then reconnect
            // with a refreshed one, since the last data.
            Some(Control::TokenExpired) => self.upstream = None,
            Some(Control::Error(message)) => {
                let message = sanitize_line(message.as_bytes());
                self.finish(&format!("The daemon reported an error: {message}"));
            }
            None => {
                if self.feed.on_data(frame, &mut self.queue) {
                    self.reconnects = 0;
                }
            }
        }
    }

    async fn reconnect(&mut self) {
        self.reconnects += 1;
        if self.reconnects > MAX_RECONNECTS {
            self.finish("The connection to the daemon was lost.");
            return;
        }
        if self.reconnects > 1 && !pause(&mut self.ended, self.retry_delay).await {
            self.done = true;
            return;
        }
        let call = self.feed.call(Some(self.last_data));
        match self.link.connect(&call).await {
            Ok(upstream) => {
                self.upstream = Some(upstream);
                self.decoder = FrameDecoder::default();
                self.feed.reset();
            }
            Err(Connect::NoToken) => self.done = true,
            Err(Connect::Daemon(DaemonError::Unauthorized)) => {
                self.session.end();
                self.done = true;
            }
            Err(Connect::Daemon(DaemonError::Forbidden)) => self.finish(F::NOTICES.forbidden),
            Err(Connect::Daemon(DaemonError::NotFound(_))) => self.finish(F::NOTICES.not_found),
            // Anything else is transient: loop around and try again, up to the limit.
            Err(Connect::Daemon(_)) => {}
        }
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
    fn clean_text_drops_unsafe_characters_and_cuts() {
        assert_eq!(clean_text("a\tb\x1b[0m\u{202e}c\0", 40), "a b[0mc");
        assert_eq!(clean_text("abcdef", 3), "abc…");
        assert_eq!(clean_text("abc", 3), "abc");
        let huge = "é".repeat(1_000_000);
        assert_eq!(clean_text(&huge, 10).chars().count(), 11);
    }

    #[test]
    fn the_access_filter_is_parsed_not_passed_on() {
        let q = access_filter(Some("status=5xx&method=&path=%2Fapi&follow=false&since=3")).unwrap();
        assert!(q.follow && q.since.is_none());
        assert_eq!(q.to_query_string(), "follow=true&status=5xx&path=/api");
        assert_eq!(
            access_filter(None).unwrap().to_query_string(),
            "follow=true"
        );
        for bad in [
            "status=1",
            "path=%2Fa%26host%3Dx",
            "path=%2Fa%3Db",
            "path=%2Fa%25",
            "x=1",
            "host=A",
            "status=2xx&status=2xx",
        ] {
            assert!(access_filter(Some(bad)).is_err(), "{bad}");
        }
        assert!(access_filter(Some(&"a=b&".repeat(400))).is_err());
    }

    #[test]
    fn the_access_feed_counts_what_it_cannot_queue_and_remembers_the_newest_time() {
        let mut feed = AccessFeed::new("web".into(), AccessQuery::default());
        let entry = |time: &str| {
            AccessFrame::Entry(AccessEntry {
                time: time.into(),
                ..AccessEntry::default()
            })
        };
        let mut out = VecDeque::new();
        assert!(feed.on_data(entry("2026-10-31T12:00:05Z"), &mut out));
        assert!(feed.on_data(entry("2026-10-31T12:00:01Z"), &mut out));
        assert!(feed.on_data(entry("not a time"), &mut out));
        let newest = parse_rfc3339(b"2026-10-31T12:00:05Z");
        assert_eq!(feed.last_entry, newest);
        assert_eq!(out.len(), 3);
        // A full queue drops the entry, and the next row that fits says how many.
        let mut full: VecDeque<Event> = (0..MAX_QUEUED_ROWS).map(|_| Event::default()).collect();
        assert!(feed.on_data(entry("x"), &mut full));
        assert_eq!((full.len(), feed.skipped), (MAX_QUEUED_ROWS, 1));
        full.clear();
        assert!(feed.on_data(entry("x"), &mut full));
        assert_eq!((full.len(), feed.skipped), (2, 0));
        // Control frames are not data.
        assert!(!feed.on_data(AccessFrame::End, &mut out));
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

    // ---- the driver, against a fake feed and a scripted link -------------------------------

    use std::sync::atomic::{AtomicUsize, Ordering};

    /// What a scripted connection does.
    enum Step {
        Frames(Vec<TestFrame>),
        /// Frames, then the connection breaks.
        Broken(Vec<TestFrame>),
        /// Garbage that is not a frame.
        Garbage,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum TestFrame {
        Data(String),
        End,
        TokenExpired,
        Error(String),
    }

    impl FrameKind for TestFrame {
        fn parts(&self) -> (u8, std::borrow::Cow<'_, [u8]>) {
            use std::borrow::Cow;
            match self {
                Self::Data(t) => (1, Cow::Borrowed(t.as_bytes())),
                Self::End => (3, Cow::Borrowed(&[])),
                Self::TokenExpired => (4, Cow::Borrowed(&[])),
                Self::Error(m) => (5, Cow::Borrowed(m.as_bytes())),
            }
        }
        fn decode(kind: u8, payload: Vec<u8>) -> Result<Self, weglarka_api::FrameError> {
            let text = String::from_utf8_lossy(&payload).into_owned();
            Ok(match kind {
                1 => Self::Data(text),
                3 => Self::End,
                4 => Self::TokenExpired,
                5 => Self::Error(text),
                other => return Err(weglarka_api::FrameError::UnknownKind(other)),
            })
        }
    }

    impl ControlFrame for TestFrame {
        fn control(&self) -> Option<Control> {
            match self {
                Self::Data(_) => None,
                Self::End => Some(Control::End),
                Self::TokenExpired => Some(Control::TokenExpired),
                Self::Error(m) => Some(Control::Error(m.clone())),
            }
        }
    }

    struct TestFeed {
        resets: Arc<AtomicUsize>,
        /// The `resume_from` of every `call`.
        calls: Arc<Mutex<Vec<Option<SystemTime>>>>,
    }

    impl UpstreamFeed for TestFeed {
        type Frame = TestFrame;
        const NOTICES: Notices = Notices {
            ended: "ended",
            corrupted: "corrupted",
            forbidden: "forbidden",
            not_found: "not found",
        };
        fn call(&self, resume_from: Option<SystemTime>) -> Call {
            self.calls.lock().unwrap().push(resume_from);
            Call::new(&APPS_LOGS).param("name", "web")
        }
        fn on_data(&mut self, frame: TestFrame, out: &mut VecDeque<Event>) -> bool {
            let TestFrame::Data(text) = frame else {
                return false;
            };
            out.push_back(Event::default().data(text));
            true
        }
        fn reset(&mut self) {
            self.resets.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct TestConn(VecDeque<Option<Bytes>>);

    impl Conn for TestConn {
        async fn chunk(&mut self) -> Option<Bytes> {
            match self.0.pop_front() {
                Some(chunk) => chunk,
                // Held open, like a quiet daemon.
                None => std::future::pending().await,
            }
        }
    }

    /// Connections the driver asks for after the first, in order; a missing script = refused.
    struct TestLink {
        script: Mutex<VecDeque<Result<Step, DaemonError>>>,
        /// The `resume_from` of every reconnect is recorded by the feed's caller, so count here.
        connects: Arc<AtomicUsize>,
    }

    impl Link for TestLink {
        type Conn = TestConn;
        async fn connect(&self, _call: &Call) -> Result<TestConn, Connect> {
            self.connects.fetch_add(1, Ordering::SeqCst);
            let next = self.script.lock().unwrap().pop_front();
            match next {
                Some(Ok(step)) => Ok(conn(step)),
                Some(Err(e)) => Err(Connect::Daemon(e)),
                None => Err(Connect::Daemon(DaemonError::Timeout)),
            }
        }
    }

    fn conn(step: Step) -> TestConn {
        let (frames, broken) = match step {
            Step::Frames(f) => (f, false),
            Step::Broken(f) => (f, true),
            Step::Garbage => {
                return TestConn(VecDeque::from([Some(Bytes::from_static(&[9, 0, 0, 0, 0]))]));
            }
        };
        let mut chunks: VecDeque<Option<Bytes>> = frames
            .iter()
            .map(|f| {
                let (kind, payload) = f.parts();
                Some(Bytes::from(weglarka_api::encode_frame(kind, &payload)))
            })
            .collect();
        if broken {
            chunks.push_back(None);
        }
        TestConn(chunks)
    }

    struct Rig {
        driver: Driver<TestFeed, TestLink>,
        connects: Arc<AtomicUsize>,
        resets: Arc<AtomicUsize>,
        calls: Arc<Mutex<Vec<Option<SystemTime>>>>,
        session: Arc<Session>,
    }

    fn rig(first: Step, later: Vec<Result<Step, DaemonError>>) -> Rig {
        use crate::session::{Tokens, User};
        let session = Arc::new(Session::new(
            User {
                sub: "u".into(),
                name: "u".into(),
            },
            Tokens {
                access: Arc::new(crate::config::Secret::new("t")),
                refresh: None,
                access_expires: std::time::Instant::now(),
                refresh_retry_at: None,
            },
            std::time::Instant::now(),
        ));
        let slots = Arc::new(StreamSlots::default());
        let connects = Arc::new(AtomicUsize::new(0));
        let resets = Arc::new(AtomicUsize::new(0));
        let link = TestLink {
            script: Mutex::new(later.into()),
            connects: connects.clone(),
        };
        let calls = Arc::new(Mutex::new(Vec::new()));
        let feed = TestFeed {
            resets: resets.clone(),
            calls: calls.clone(),
        };
        let mut driver = Driver::new(
            feed,
            link,
            session.clone(),
            conn(first),
            SystemTime::now(),
            slots.acquire(&session).unwrap(),
        );
        driver.retry_delay = Duration::ZERO;
        Rig {
            driver,
            connects,
            resets,
            calls,
            session,
        }
    }

    /// Drains the stream: every event as text (`event: name|data`), until it ends or `limit`.
    async fn drain(driver: Driver<TestFeed, TestLink>, limit: usize) -> Vec<String> {
        use futures_util::StreamExt;
        let stream = stream::unfold(driver, Driver::next);
        futures_util::pin_mut!(stream);
        let mut out = Vec::new();
        while out.len() < limit {
            let next = tokio::time::timeout(Duration::from_millis(300), stream.next()).await;
            match next {
                Ok(Some(Ok(event))) => out.push(format!("{event:?}")),
                Ok(Some(Err(never))) => match never {},
                Ok(None) => break,
                Err(_) => {
                    out.push("<quiet>".into());
                    break;
                }
            }
        }
        out
    }

    fn data(t: &str) -> TestFrame {
        TestFrame::Data(t.into())
    }

    #[tokio::test]
    async fn token_expiry_reconnects_since_the_last_data_and_resets_the_feed() {
        let r = rig(
            Step::Frames(vec![data("one"), TestFrame::TokenExpired]),
            vec![Ok(Step::Frames(vec![data("two")]))],
        );
        let started = r.driver.last_data;
        let (connects, resets, calls) = (r.connects.clone(), r.resets.clone(), r.calls.clone());
        let events = drain(r.driver, 3).await;
        assert!(
            events[0].contains("one") && events[1].contains("two"),
            "{events:?}"
        );
        assert_eq!(events[2], "<quiet>");
        assert_eq!(connects.load(Ordering::SeqCst), 1);
        assert_eq!(resets.load(Ordering::SeqCst), 1);
        // The reconnect asked for output since the chunk that carried `one` arrived.
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let since = calls[0].expect("a reconnect resumes");
        assert!(since >= started && since <= SystemTime::now());
    }

    #[tokio::test]
    async fn more_than_max_reconnects_gives_up_with_a_status_and_done() {
        let r = rig(
            Step::Broken(vec![]),
            (0..MAX_RECONNECTS + 3)
                .map(|_| Err(DaemonError::Timeout))
                .collect(),
        );
        let connects = r.connects.clone();
        let events = drain(r.driver, 10).await;
        assert_eq!(events.len(), 2, "{events:?}");
        assert!(
            events[0].contains("status") && events[0].contains("connection to the daemon was lost")
        );
        assert!(events[1].contains("done"));
        assert_eq!(connects.load(Ordering::SeqCst) as u32, MAX_RECONNECTS);
    }

    #[tokio::test]
    async fn data_starts_the_reconnect_count_over() {
        // Each connection delivers data and then breaks: far more reconnects than the limit are fine.
        let rounds = MAX_RECONNECTS as usize * 2;
        let later = (0..rounds)
            .map(|i| Ok(Step::Broken(vec![data(&format!("n{i}"))])))
            .collect();
        let r = rig(Step::Broken(vec![data("n")]), later);
        let events = drain(r.driver, rounds + 1).await;
        assert_eq!(events.len(), rounds + 1, "{events:?}");
        assert!(events.iter().all(|e| !e.contains("lost")));
    }

    #[tokio::test]
    async fn end_shows_a_status_then_done() {
        let r = rig(Step::Frames(vec![data("last"), TestFrame::End]), vec![]);
        let events = drain(r.driver, 10).await;
        assert_eq!(events.len(), 3, "{events:?}");
        assert!(events[0].contains("last"));
        assert!(events[1].contains("status") && events[1].contains("ended"));
        assert!(events[2].contains("done"));
    }

    #[tokio::test]
    async fn a_daemon_error_is_shown_sanitized_and_ends_the_stream() {
        let r = rig(
            Step::Frames(vec![TestFrame::Error("bad\x1b[31m <b>".into())]),
            vec![],
        );
        let events = drain(r.driver, 10).await;
        assert!(
            events[0].contains("The daemon reported an error: bad[31m &lt;b&gt;"),
            "{events:?}"
        );
        assert!(events[1].contains("done"));
    }

    #[tokio::test]
    async fn a_corrupted_stream_ends_with_a_notice() {
        let r = rig(Step::Garbage, vec![]);
        let events = drain(r.driver, 10).await;
        assert!(
            events[0].contains("corrupted") && events[1].contains("done"),
            "{events:?}"
        );
    }

    #[tokio::test]
    async fn a_refused_reconnect_says_why() {
        for (error, text) in [
            (DaemonError::Forbidden, "forbidden"),
            (DaemonError::NotFound("x".into()), "not found"),
        ] {
            let r = rig(Step::Broken(vec![]), vec![Err(error)]);
            let events = drain(r.driver, 10).await;
            assert!(
                events[0].contains(text) && events[1].contains("done"),
                "{events:?}"
            );
        }
        // Unauthorized ends the session and the stream without a word.
        let r = rig(Step::Broken(vec![]), vec![Err(DaemonError::Unauthorized)]);
        let session = r.session.clone();
        assert!(drain(r.driver, 10).await.is_empty());
        assert!(session.is_ended());
    }

    #[tokio::test]
    async fn the_end_of_the_session_ends_the_stream_silently() {
        let r = rig(Step::Frames(vec![data("one")]), vec![]);
        let session = r.session.clone();
        let mut events = Vec::new();
        {
            use futures_util::StreamExt;
            let stream = stream::unfold(r.driver, Driver::next);
            futures_util::pin_mut!(stream);
            events.push(format!("{:?}", stream.next().await.unwrap().unwrap()));
            session.end();
            assert!(stream.next().await.is_none());
        }
        assert!(events[0].contains("one"));
    }
}
