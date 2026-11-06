//! `GET /v1/apps/{name}/access` (`admin` scope, docs/decisions/0063): the requests that reached an app
//! through its domains, as a stream of [`AccessFrame`]s.
//!
//! nginx writes one JSON line per request into **one file shared by all apps** (ADR 0070):
//! `<state dir>/ingress-logs/access.log`, rotated daily by the daemon. The daemon is the boundary
//! between the apps: it parses every line, keeps the lines whose `app` is the requested one and sends
//! each as an [`AccessEntry`] (an allowlist of fields, serialised anew). Nothing is decided by
//! searching the raw line for text: a user agent may well contain `"app":"x"`.
//!
//! History is read from the completed daily files whose date is inside `since`, then from the current
//! `access.log`. Follow starts at the byte offset and inode where history stopped, so a line is sent
//! exactly once within one stream; a rotation during history is handled by draining the old file first
//! and only then switching to the new one.
//!
//! The stream lives in its own task (the pump): it ends when the client hangs up, when the token
//! expires or when the log ends, also during a long scan that sends nothing.
//!
//! Audit: one line when the stream ends, with counts and the shape of the query; never a filter value
//! and never log content.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path as StdPath, PathBuf};
use std::pin::pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use axum::response::Response;
use axum::routing::get;
use serde::Deserialize;
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;
use tokio::time::Instant;
use weglarka_api::{
    ACCESS_STREAM_CONTENT_TYPE, AccessEntry, AccessFrame, AccessQuery, StatusFilter, endpoints,
    parse_rfc3339,
};
use weglarka_model::app::InstanceName;
use weglarka_model::podman::PodmanClient;
use weglarka_model::state;

use crate::admin::{Fail, parse_name};
use crate::app::Daemon;
use crate::stream::{CallerSub, Ended, StreamDeadline, stream_response, unix_secs};
use weglarka_model::ingress_logs::{self, LogKind};

/// Frames queued between the pump and the response body: small, so a slow client holds back the
/// reading of the Podman stream instead of buffering the log in memory.
const FRAME_QUEUE: usize = 8;
/// How far back a request without `since` looks.
const DEFAULT_ACCESS_WINDOW: Duration = Duration::from_secs(3600);
/// Bytes of encoded entries the `tail` ring may hold, whatever `tail` says.
const MAX_RING_BYTES: usize = 1024 * 1024;
/// A longer log line is skipped (and counted) without being buffered whole.
const MAX_LINE: usize = 16 * 1024;

pub fn routes<P: PodmanClient + 'static>() -> Router<Arc<Daemon<P>>> {
    Router::new().route(endpoints::APPS_ACCESS.path, get(app_access::<P>))
}

async fn app_access<P: PodmanClient + 'static>(
    State(d): State<Arc<Daemon<P>>>,
    Path(raw): Path<String>,
    RawQuery(raw_query): RawQuery,
    deadline: StreamDeadline,
    CallerSub(sub): CallerSub,
) -> Result<Response, Fail> {
    let name = parse_name(&raw)?;
    let query = AccessQuery::parse(raw_query.as_deref()).map_err(Fail::invalid)?;
    let known = state::load_apps(&d.paths.state.apps)
        .map_err(Fail::internal)?
        .apps
        .contains_key(&name);
    if !known {
        return Err(Fail::not_found(format!("unknown app: {name}")));
    }
    let now = SystemTime::now();
    let since = query.since_time().unwrap_or_else(|| {
        now.checked_sub(DEFAULT_ACCESS_WINDOW)
            .unwrap_or(SystemTime::UNIX_EPOCH)
    });
    let dir = d.ingress.logs_dir().to_path_buf();
    let history = Reader::History(History::new(dir.clone(), since));
    let follow = query.follow.then_some(FollowPlan::Files(dir));

    let (frames_tx, frames_rx) = mpsc::channel::<Bytes>(FRAME_QUEUE);
    let audit = Audit::new(sub, name.clone(), &query, since);
    tokio::spawn(pump(
        history,
        follow,
        Scan::new(name, &query, since),
        query.tail,
        frames_tx,
        deadline,
        audit,
    ));
    Ok(stream_response(ACCESS_STREAM_CONTENT_TYPE, frames_rx))
}

// ---- Parsing and filtering: pure, no I/O (the same lines can be shipped to Loki later, #82) ----

/// A log line as nginx wrote it: the app it belongs to and the entry. Anything else on the line is
/// dropped by the entry's own deserialisation.
#[derive(Deserialize)]
struct Logged {
    #[serde(default)]
    app: String,
    #[serde(flatten)]
    entry: AccessEntry,
}

/// What a log line is.
#[derive(Debug, PartialEq)]
// Short-lived: one per log line, consumed at once.
#[allow(clippy::large_enum_variant)]
pub(crate) enum Parsed {
    Entry {
        app: String,
        entry: AccessEntry,
    },
    /// Not a JSON object of the expected shape.
    Invalid,
}

/// Parses one line without its newline. Invalid UTF-8 (a `$uri` can hold any bytes) is replaced, not
/// refused.
pub(crate) fn parse_line(line: &[u8]) -> Parsed {
    match serde_json::from_str::<Logged>(&String::from_utf8_lossy(line)) {
        Ok(Logged { app, entry }) => Parsed::Entry { app, entry },
        Err(_) => Parsed::Invalid,
    }
}

/// The `status`/`method`/`path`/`host` conditions of a query.
#[derive(Debug, Clone, Default)]
pub(crate) struct Filter {
    status: Option<StatusFilter>,
    method: Option<String>,
    path: Option<String>,
    host: Option<String>,
}

impl Filter {
    pub(crate) fn new(query: &AccessQuery) -> Self {
        Self {
            status: query.status,
            method: query.method.clone(),
            path: query.path.clone(),
            host: query.host.clone(),
        }
    }

    pub(crate) fn matches(&self, entry: &AccessEntry) -> bool {
        self.status.is_none_or(|s| s.matches(entry.status))
            && self.method.as_ref().is_none_or(|m| *m == entry.method)
            && self.path.as_ref().is_none_or(|p| entry.path.starts_with(p))
            && self.host.as_ref().is_none_or(|h| *h == entry.host)
    }
}

/// Whether the entry is inside the time window. `None` means `$time_iso8601` is missing or does not
/// parse: the line is skipped (and counted) instead of being shown out of window.
fn time_window(entry: &AccessEntry, since: Duration) -> Option<bool> {
    parse_rfc3339(entry.time.as_bytes()).map(|time| time >= since)
}

/// A complete line of the log, or the mark of one that was too long to keep.
#[derive(Debug, PartialEq, Eq)]
enum Line<'a> {
    Complete(&'a [u8]),
    TooLong,
}

/// Cuts a byte stream into lines, however the chunks fall. A line over [`MAX_LINE`] is dropped as it
/// grows and reported once, at its newline.
#[derive(Debug, Default)]
struct LineBuffer {
    buf: Vec<u8>,
    overlong: bool,
}

impl LineBuffer {
    fn push(&mut self, data: &[u8], mut on_line: impl FnMut(Line<'_>)) {
        let mut rest = data;
        while !rest.is_empty() {
            let (part, newline) = match rest.iter().position(|&b| b == b'\n') {
                Some(i) => (&rest[..i], true),
                None => (rest, false),
            };
            rest = &rest[part.len() + usize::from(newline)..];
            if !self.overlong {
                if self.buf.len() + part.len() > MAX_LINE {
                    self.overlong = true;
                    self.buf.clear();
                } else {
                    self.buf.extend_from_slice(part);
                }
            }
            if newline {
                if self.overlong {
                    on_line(Line::TooLong);
                } else {
                    on_line(Line::Complete(&self.buf));
                }
                self.buf.clear();
                self.overlong = false;
            }
        }
    }
}

/// The line-level state of a stream: what is kept and what was counted.
struct Scan {
    app: InstanceName,
    filter: Filter,
    lines: LineBuffer,
    /// `since` as seconds/nanoseconds since the unix epoch, compared with `AccessEntry::time`.
    since: Duration,
    /// Lines seen, whatever they were.
    scanned: u64,
    /// Lines that were not valid entries (too long, not JSON, no usable time).
    skipped: u64,
}

impl Scan {
    fn new(app: InstanceName, query: &AccessQuery, since: SystemTime) -> Self {
        Self {
            app,
            filter: Filter::new(query),
            lines: LineBuffer::default(),
            since: since.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO),
            scanned: 0,
            skipped: 0,
        }
    }

    /// The entries of this app that pass the filter in `data` (a chunk of the access log).
    fn chunk(&mut self, data: &[u8]) -> Vec<AccessEntry> {
        let mut kept = Vec::new();
        let Self {
            app,
            filter,
            lines,
            since,
            scanned,
            skipped,
        } = self;
        lines.push(data, |line| {
            *scanned += 1;
            let Line::Complete(line) = line else {
                *skipped += 1;
                return;
            };
            match parse_line(line) {
                Parsed::Invalid => *skipped += 1,
                Parsed::Entry { app: of, entry } => {
                    if of != app.as_str() {
                        return;
                    }
                    match time_window(&entry, *since) {
                        Some(true) if filter.matches(&entry) => kept.push(entry),
                        Some(_) => {}
                        None => *skipped += 1,
                    }
                }
            }
        });
        kept
    }
}

// ---- File sources (ADR 0070) ----

/// How much a single file read returns; the pump turns it into lines.
const CHUNK: usize = 64 * 1024;
/// Poll interval of a followed file. A log stream may be up to this late; that is cheaper than an
/// inotify dependency and matches the previous libpod stream's latency closely enough.
const POLL: Duration = Duration::from_millis(250);

/// A reader of one `access.log` (follow) or of the daily files selected by `since` (history).
enum Reader {
    History(History),
    Follow(Follow),
    #[cfg(test)]
    TestStream(futures_util::stream::BoxStream<'static, io::Result<Bytes>>),
}

/// What to follow after history. Production points at the directory (the history reader knows the
/// exact offset and inode); unit tests provide a prepared reader instead.
enum FollowPlan {
    Files(PathBuf),
    #[cfg(test)]
    Reader(Box<Reader>),
}

impl Reader {
    async fn next_chunk(&mut self) -> Option<io::Result<Bytes>> {
        match self {
            Self::History(history) => history.next_chunk().await,
            Self::Follow(follow) => follow.next_chunk().await,
            #[cfg(test)]
            Self::TestStream(stream) => futures_util::StreamExt::next(stream).await,
        }
    }
}

struct History {
    files: VecDeque<PathBuf>,
    file: Option<File>,
    path: Option<PathBuf>,
    position: u64,
    id: Option<(u64, u64)>,
    buf: Vec<u8>,
}

impl History {
    fn new(dir: PathBuf, since: SystemTime) -> Self {
        Self {
            files: select_files(&dir, since),
            file: None,
            path: None,
            position: 0,
            id: None,
            buf: vec![0; CHUNK],
        }
    }

    async fn next_chunk(&mut self) -> Option<io::Result<Bytes>> {
        loop {
            let Some(file) = self.file.as_mut() else {
                let path = self.files.pop_front()?;
                match File::open(&path).await {
                    Ok(file) => {
                        self.id = file.metadata().await.ok().map(|m| (m.dev(), m.ino()));
                        self.file = Some(file);
                        self.path = Some(path);
                        self.position = 0;
                        continue;
                    }
                    // Pruned between the listing and the open: the rest of the history is still valid.
                    Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                    Err(e) => return Some(Err(e)),
                }
            };
            match file.read(&mut self.buf).await {
                Ok(0) => {
                    // Keep the last descriptor open at EOF for follow: it carries the exact byte
                    // offset and inode where history stopped, so the first live line is not
                    // repeated. A non-final file is closed and the loop opens the next one.
                    if self.files.is_empty() {
                        return None;
                    }
                    self.file = None;
                }
                Ok(n) => {
                    self.position += n as u64;
                    return Some(Ok(Bytes::copy_from_slice(&self.buf[..n])));
                }
                Err(e) => return Some(Err(e)),
            }
        }
    }

    /// Build the follow reader at the exact byte where history stopped. When history ended on a
    /// rotated file (or on no file at all), the new current file starts at zero; when it ended on
    /// `access.log`, the open descriptor is reused, so no line written during history is lost.
    fn into_follow(self, dir: PathBuf) -> (Follow, bool) {
        let current = dir.join(ingress_logs::shared().current(LogKind::Access));
        let same = self.path.as_deref() == Some(current.as_path());
        (
            Follow {
                path: current,
                file: same.then_some(self.file).flatten(),
                position: if same { self.position } else { 0 },
                id: if same { self.id } else { None },
                buf: vec![0; CHUNK],
            },
            same,
        )
    }
}

struct Follow {
    path: PathBuf,
    file: Option<File>,
    position: u64,
    id: Option<(u64, u64)>,
    buf: Vec<u8>,
}

impl Follow {
    async fn next_chunk(&mut self) -> Option<io::Result<Bytes>> {
        loop {
            if self.file.is_none() {
                match File::open(&self.path).await {
                    Ok(file) => {
                        self.id = file.metadata().await.ok().map(|m| (m.dev(), m.ino()));
                        self.file = Some(file);
                        self.position = 0;
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        tokio::time::sleep(POLL).await;
                        continue;
                    }
                    Err(e) => return Some(Err(e)),
                }
            }
            let file = self.file.as_mut()?;
            match file.read(&mut self.buf).await {
                Ok(0) => {
                    // At EOF: a different inode at the path means the daemon rotated the file. The
                    // old descriptor is drained (we are at EOF), so switch only after this check.
                    match tokio::fs::metadata(&self.path).await {
                        Ok(meta) => {
                            let current = (meta.dev(), meta.ino());
                            if self.id.is_some_and(|id| id != current) {
                                // Old workers can still append to the old inode after HUP (a long
                                // request, a streaming response). Drain it once more before switching,
                                // or those lines are lost with the dropped descriptor.
                                match file.read(&mut self.buf).await {
                                    Ok(0) => {}
                                    Ok(n) => {
                                        self.position += n as u64;
                                        return Some(Ok(Bytes::copy_from_slice(&self.buf[..n])));
                                    }
                                    Err(e) => return Some(Err(e)),
                                }
                                self.file = None;
                                continue;
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::NotFound => {
                            // Between rename and HUP nginx has not created the new file yet.
                        }
                        Err(e) => return Some(Err(e)),
                    }
                    tokio::time::sleep(POLL).await;
                }
                Ok(n) => {
                    self.position += n as u64;
                    return Some(Ok(Bytes::copy_from_slice(&self.buf[..n])));
                }
                Err(e) => return Some(Err(e)),
            }
        }
    }
}

/// Completed daily files that were still being written at `since`, in write order, followed by the
/// current file. The current file is last; it may contain lines older than `since`, which `Scan`
/// filters out.
///
/// The name of a completed file is the UTC day the current file *started* on, and rotation runs at
/// most an hour after midnight. Its last write can therefore be on the next day, after `since`; a
/// date-based selection would drop those lines. `mtime` is the time of the last write (also when an
/// old worker kept appending after the rename), which is the right lower bound. A file whose mtime
/// cannot be read is kept: the timestamp filter in `Scan` still decides per line.
fn select_files(dir: &StdPath, since: SystemTime) -> VecDeque<PathBuf> {
    let layout = ingress_logs::shared();
    let Ok(found) = layout.completed(dir) else {
        return VecDeque::new();
    };
    let mut completed = Vec::new();
    for (kind, _, path) in found {
        if kind != LogKind::Access {
            continue;
        }
        let modified = std::fs::metadata(&path)
            .ok()
            .and_then(|m| m.modified().ok());
        if modified.is_none_or(|m| m >= since) {
            completed.push((modified, path));
        }
    }
    let current = Some(dir.join(layout.current(LogKind::Access))).filter(|p| p.exists());
    completed.sort_by_key(|(modified, _)| *modified);
    completed
        .into_iter()
        .map(|(_, path)| path)
        .chain(current)
        .collect()
}

// ---- The pump ----

/// The last matching entries, encoded, bounded by count and by bytes.
struct Ring {
    cap: usize,
    bytes: usize,
    frames: VecDeque<Bytes>,
}

impl Ring {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            bytes: 0,
            frames: VecDeque::new(),
        }
    }

    fn push(&mut self, frame: Bytes) {
        self.bytes += frame.len();
        self.frames.push_back(frame);
        while self.frames.len() > self.cap || self.bytes > MAX_RING_BYTES {
            let Some(old) = self.frames.pop_front() else {
                break;
            };
            self.bytes -= old.len();
        }
    }
}

/// The facts of the audit line; none of them is a filter value or log content.
#[derive(Debug)]
struct Audit {
    sub: Option<String>,
    app: InstanceName,
    follow: bool,
    tail: Option<u32>,
    since: SystemTime,
    filtered: bool,
    started: Instant,
    /// Entry frames delivered.
    frames: u64,
    scanned: u64,
    skipped: u64,
}

impl Audit {
    fn new(sub: Option<String>, app: InstanceName, query: &AccessQuery, since: SystemTime) -> Self {
        Self {
            sub,
            app,
            follow: query.follow,
            tail: query.tail,
            since,
            filtered: query.is_filtered(),
            started: Instant::now(),
            frames: 0,
            scanned: 0,
            skipped: 0,
        }
    }

    /// Lines were skipped, some were scanned and none was sent.
    fn format_may_have_drifted(&self) -> bool {
        self.skipped > 0 && self.scanned > 0 && self.frames == 0
    }

    fn finish(&self, ended: Ended) {
        tracing::info!(
            sub = self.sub.as_deref().unwrap_or("unix socket"),
            app = %self.app,
            follow = self.follow,
            tail = self.tail,
            since = unix_secs(self.since),
            filtered = self.filtered,
            scanned = self.scanned,
            frames = self.frames,
            skipped = self.skipped,
            duration_ms = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            ended = ended.as_str(),
            "admin access stream ended"
        );
        if self.format_may_have_drifted() {
            // No content on purpose: this only says the format may have drifted from `AccessEntry`.
            tracing::warn!(
                app = %self.app,
                scanned = self.scanned,
                skipped = self.skipped,
                "access log lines were skipped and none was sent; has the nginx log format changed?"
            );
        }
    }
}

/// Sends `bytes` unless the token expires first or the client is gone.
async fn send(
    tx: &mpsc::Sender<Bytes>,
    expiry: &mut (impl Future<Output = ()> + Unpin),
    bytes: Bytes,
) -> Result<(), Ended> {
    tokio::select! {
        biased;
        () = expiry => Err(Ended::TokenExpired),
        sent = tx.send(bytes) => sent.map_err(|_| Ended::ClientClosed),
    }
}

/// Reads `logs` to its end. Matching entries go into `ring` when there is one, else straight to the
/// client. `Ok` means the log ended; `Err` says why the stream has to.
async fn read_phase(
    reader: &mut Reader,
    scan: &mut Scan,
    mut ring: Option<&mut Ring>,
    tx: &mpsc::Sender<Bytes>,
    expiry: &mut (impl Future<Output = ()> + Unpin),
    audit: &mut Audit,
) -> Result<(), Ended> {
    loop {
        // Token expiry and a hang-up win over a log that keeps delivering lines nobody wants.
        let next = tokio::select! {
            biased;
            () = &mut *expiry => return Err(Ended::TokenExpired),
            () = tx.closed() => return Err(Ended::ClientClosed),
            next = reader.next_chunk() => next,
        };
        match next {
            None => return Ok(()),
            Some(Err(error)) => {
                tracing::warn!(app = %scan.app, %error, "the ingress access log could not be read");
                return Err(Ended::Error);
            }
            Some(Ok(data)) => {
                let entries = scan.chunk(&data);
                audit.scanned = scan.scanned;
                audit.skipped = scan.skipped;
                for entry in entries {
                    let frame = Bytes::from(AccessFrame::Entry(entry).encode());
                    match ring.as_deref_mut() {
                        Some(ring) => ring.push(frame),
                        None => {
                            send(tx, expiry, frame).await?;
                            audit.frames += 1;
                        }
                    }
                }
            }
        }
        // Let other tasks (and the clock) run even when the log is all ready data.
        tokio::task::yield_now().await;
    }
}

/// The whole stream; the error is why it ended early.
async fn run(
    mut history: Reader,
    follow: Option<FollowPlan>,
    scan: &mut Scan,
    tail: Option<u32>,
    tx: &mpsc::Sender<Bytes>,
    expiry: &mut (impl Future<Output = ()> + Unpin),
    audit: &mut Audit,
) -> Result<(), Ended> {
    match tail {
        Some(tail) => {
            let mut ring = Ring::new(tail as usize);
            read_phase(&mut history, scan, Some(&mut ring), tx, expiry, audit).await?;
            for frame in ring.frames {
                send(tx, expiry, frame).await?;
                audit.frames += 1;
            }
        }
        None => read_phase(&mut history, scan, None, tx, expiry, audit).await?,
    }
    let Some(plan) = follow else {
        return Ok(());
    };
    let mut follow = match plan {
        FollowPlan::Files(dir) => {
            let Reader::History(history) = history else {
                return Ok(());
            };
            let (follow, same_file) = history.into_follow(dir);
            // A fragment the history ended in belongs to the file it was reading. When history ended
            // on a rotated file, follow switches to the (new) current file and drops the fragment.
            if !same_file {
                scan.lines = LineBuffer::default();
            }
            Reader::Follow(follow)
        }
        #[cfg(test)]
        FollowPlan::Reader(reader) => *reader,
    };
    read_phase(&mut follow, scan, None, tx, expiry, audit).await
}

/// Copies the app's access log into `frames_tx` until it ends, the client goes away or the token
/// expires, then writes the audit line. The result is what the audit line says (for the tests).
async fn pump(
    history: Reader,
    follow: Option<FollowPlan>,
    mut scan: Scan,
    tail: Option<u32>,
    frames_tx: mpsc::Sender<Bytes>,
    deadline: StreamDeadline,
    mut audit: Audit,
) -> (Ended, Audit) {
    let mut expiry = pin!(deadline.reached());
    let result = run(
        history,
        follow,
        &mut scan,
        tail,
        &frames_tx,
        &mut expiry,
        &mut audit,
    )
    .await;
    audit.scanned = scan.scanned;
    audit.skipped = scan.skipped;
    let mut ended = result.err().unwrap_or(Ended::Eof);
    let last = match ended {
        Ended::Eof => Some(AccessFrame::End),
        Ended::TokenExpired => Some(AccessFrame::TokenExpired),
        Ended::Error => Some(AccessFrame::Error("the nginx log stream failed".into())),
        Ended::ClientClosed => None,
    };
    if let Some(frame) = last {
        let bytes = Bytes::from(frame.encode());
        match ended {
            // The log's own end must not be lost to a full queue (the client would take it for an
            // interruption and read the window again); wait for room, but not past the token.
            Ended::Eof | Ended::Error => {
                if send(&frames_tx, &mut expiry, bytes).await == Err(Ended::TokenExpired) {
                    ended = Ended::TokenExpired;
                }
            }
            // Not awaited: a client that is not reading just gets a stream that ends.
            Ended::TokenExpired | Ended::ClientClosed => {
                let _ = frames_tx.try_send(bytes);
            }
        }
    }
    audit.finish(ended);
    (ended, audit)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use futures_util::StreamExt as _;
    use futures_util::stream;

    use super::*;

    fn line(app: &str, status: u16, path: &str) -> String {
        format!(
            "{{\"time\":\"2026-10-31T12:00:00+00:00\",\"app\":\"{app}\",\"host\":\"web.example.com\",\
             \"remote_addr\":\"203.0.113.7\",\"method\":\"GET\",\"path\":\"{path}\",\"status\":{status},\
             \"bytes_sent\":5,\"request_time\":0.001,\"upstream_response_time\":\"0.001\",\
             \"request_id\":\"r\",\"user_agent\":\"curl\"}}\n"
        )
    }

    fn out(data: impl Into<Vec<u8>>) -> io::Result<Bytes> {
        Ok(Bytes::from(data.into()))
    }

    fn name() -> InstanceName {
        InstanceName::new("web").unwrap()
    }

    fn query(raw: &str) -> AccessQuery {
        AccessQuery::parse(Some(raw)).unwrap()
    }

    fn scan(raw: &str) -> Scan {
        Scan::new(name(), &query(raw), UNIX_EPOCH)
    }

    #[cfg(test)]
    fn stream_reader(
        chunks: impl futures_util::Stream<Item = io::Result<Bytes>> + Send + 'static,
    ) -> Reader {
        Reader::TestStream(Box::pin(chunks))
    }

    fn audit(q: &AccessQuery) -> Audit {
        Audit::new(Some("alice".into()), name(), q, SystemTime::UNIX_EPOCH)
    }

    async fn drain(mut rx: mpsc::Receiver<Bytes>) -> Vec<AccessFrame> {
        let mut decoder = weglarka_api::AccessFrameDecoder::default();
        let mut frames = Vec::new();
        while let Some(bytes) = rx.recv().await {
            frames.extend(decoder.push(&bytes).unwrap());
        }
        assert!(decoder.is_clean());
        frames
    }

    /// Runs the pump over `chunks` as the history and returns what the client gets.
    async fn history_of(raw: &str, chunks: Vec<io::Result<Bytes>>) -> (Vec<AccessFrame>, Audit) {
        let q = query(raw);
        let (tx, rx) = mpsc::channel(FRAME_QUEUE);
        let task = tokio::spawn(pump(
            stream_reader(stream::iter(chunks)),
            None,
            Scan::new(name(), &q, UNIX_EPOCH),
            q.tail,
            tx,
            StreamDeadline(None),
            audit(&q),
        ));
        let frames = drain(rx).await;
        (frames, task.await.unwrap().1)
    }

    fn paths(frames: &[AccessFrame]) -> Vec<String> {
        frames
            .iter()
            .filter_map(|f| match f {
                AccessFrame::Entry(e) => Some(e.path.clone()),
                _ => None,
            })
            .collect()
    }

    // ---- nginx compatibility ----

    /// Sample values for the variables of the format, as nginx would print them after `escape=json`.
    fn render(format: &str) -> String {
        [
            ("$time_iso8601", "2026-10-31T12:00:00+00:00"),
            ("$app", "web"),
            ("$host", "web.example.com"),
            ("$weglarka_client", "203.0.113.7"),
            ("$weglarka_peer", "198.51.100.1"),
            ("$remote_addr", "203.0.113.7"),
            ("$request_method", "GET"),
            ("$uri", "/index.html"),
            ("$status", "200"),
            ("$body_bytes_sent", "1234"),
            ("$request_time", "0.005"),
            ("$upstream_response_time", "0.004"),
            ("$upstream_status", "200"),
            ("$upstream_addr", "10.89.0.5:8080"),
            ("$upstream_header_time", "0.003"),
            ("$request_length", "321"),
            ("$server_protocol", "HTTP/1.1"),
            ("$request_id", "0123456789abcdef"),
            ("$http_user_agent", "curl/8.0"),
        ]
        .iter()
        .fold(format.to_owned(), |acc, (var, value)| {
            acc.replace(var, value)
        })
    }

    #[test]
    fn every_rendering_of_the_nginx_log_format_parses_into_an_entry() {
        let formats = weglarka_ingress::nginx::rendered_log_formats();
        assert_eq!(formats.len(), 4);
        for format in formats {
            let line = render(&format);
            assert!(
                !line.contains('$'),
                "a variable was not substituted: {line}"
            );
            let Parsed::Entry { app, entry } = parse_line(line.as_bytes()) else {
                panic!("does not parse: {line}")
            };
            assert_eq!(app, "web", "{line}");
            assert_eq!(
                (
                    entry.status,
                    entry.bytes_sent,
                    entry.request_time,
                    entry.request_length
                ),
                (200, 1234, 0.005, Some(321)),
                "{line}"
            );
            for (got, want) in [
                (&entry.time, "2026-10-31T12:00:00+00:00"),
                (&entry.host, "web.example.com"),
                (&entry.method, "GET"),
                (&entry.path, "/index.html"),
                (&entry.upstream_response_time, "0.004"),
                (&entry.upstream_status, "200"),
                (&entry.upstream_header_time, "0.003"),
                (&entry.server_protocol, "HTTP/1.1"),
                (&entry.request_id, "0123456789abcdef"),
                (&entry.user_agent, "curl/8.0"),
            ] {
                assert_eq!(got, want, "{line}");
            }
            if format.contains("\"peer\"") {
                // Behind a CDN the client and the TCP peer are different fields.
                assert_eq!(entry.remote_addr, "203.0.113.7", "{line}");
                assert!(
                    entry.peer.as_deref().is_some_and(|p| !p.is_empty()),
                    "{line}"
                );
            } else {
                assert!(
                    ["203.0.113.7", "198.51.100.1"].contains(&entry.remote_addr.as_str()),
                    "{line}"
                );
                assert_eq!(entry.peer, None, "{line}");
            }
            // The peer is logged as its own field exactly behind a CDN.
            assert_eq!(entry.peer.is_some(), format.contains("\"peer\""), "{line}");
        }
    }

    #[test]
    fn the_format_has_a_field_for_every_entry_field() {
        // A rename in the format would leave the entry field at its default; this catches it.
        let line = render(weglarka_ingress::nginx::LOG_FORMAT);
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        let entry = serde_json::to_value(AccessEntry::default()).unwrap();
        for key in entry.as_object().unwrap().keys() {
            assert!(value.get(key).is_some(), "the nginx format has no `{key}`");
        }
    }

    // ---- parsing ----

    #[test]
    fn a_forged_user_agent_cannot_change_the_app() {
        let forged = r#"{"time":"2026-10-31T12:00:00+00:00","app":"web","host":"h","remote_addr":"a","method":"GET","path":"/","status":200,"bytes_sent":1,"request_time":0.1,"upstream_response_time":"-","request_id":"r","user_agent":"x\",\"app\":\"other"}"#;
        let Parsed::Entry { app, entry } = parse_line(forged.as_bytes()) else {
            panic!()
        };
        assert_eq!(app, "web");
        assert!(entry.user_agent.contains("\"app\":\"other"));
        // The other way round: an entry of another app whose user agent names ours.
        let other = forged
            .replace("\"app\":\"web\"", "\"app\":\"other\"")
            .replace("\\\"app\\\":\\\"other", "\\\"app\\\":\\\"web");
        let mut s = scan("");
        assert!(s.chunk(format!("{other}\n").as_bytes()).is_empty());
        assert_eq!(s.chunk(format!("{forged}\n").as_bytes()).len(), 1);
    }

    #[test]
    fn invalid_utf8_in_a_path_is_replaced_not_refused() {
        let mut raw = br#"{"app":"web","path":"/a"#.to_vec();
        raw.extend_from_slice(&[0xff, 0xfe]);
        raw.extend_from_slice(br#"b","status":200}"#);
        let Parsed::Entry { entry, .. } = parse_line(&raw) else {
            panic!()
        };
        assert_eq!(entry.path, "/a\u{fffd}\u{fffd}b");
    }

    #[test]
    fn unknown_and_missing_fields_and_garbage() {
        let Parsed::Entry { app, entry } = parse_line(br#"{"app":"web","new_field":[1,2]}"#) else {
            panic!()
        };
        assert_eq!((app.as_str(), entry.status), ("web", 0));
        assert_eq!(parse_line(b"not json"), Parsed::Invalid);
        assert_eq!(parse_line(b"[1]"), Parsed::Invalid);
        assert_eq!(parse_line(b""), Parsed::Invalid);
        // A line without `app` belongs to nobody.
        let mut s = scan("");
        assert!(s.chunk(b"{\"status\":200}\n").is_empty());
    }

    #[test]
    fn lines_are_cut_across_chunks_and_long_lines_skipped() {
        let mut s = scan("");
        let l = line("web", 200, "/a");
        let (a, b) = l.as_bytes().split_at(30);
        assert!(s.chunk(a).is_empty());
        assert_eq!(s.chunk(b).len(), 1);
        // Over the limit, with the newline in a later chunk: skipped, counted once, the next line fine.
        let long = vec![b'x'; MAX_LINE + 1];
        assert!(s.chunk(&long).is_empty());
        assert!(s.chunk(&long).is_empty());
        let mut next = b"\n".to_vec();
        next.extend_from_slice(l.as_bytes());
        assert_eq!(s.chunk(&next).len(), 1);
        assert_eq!((s.scanned, s.skipped), (3, 1));
        // A line of exactly the limit is still parsed (and is invalid JSON here).
        let mut s = scan("");
        let mut exact = vec![b'y'; MAX_LINE];
        exact.push(b'\n');
        assert!(s.chunk(&exact).is_empty());
        assert_eq!((s.scanned, s.skipped), (1, 1));
        assert!(s.lines.buf.is_empty() && !s.lines.overlong);
    }

    // ---- filters ----

    fn entry(status: u16, method: &str, path: &str, host: &str) -> AccessEntry {
        AccessEntry {
            status,
            method: method.into(),
            path: path.into(),
            host: host.into(),
            ..Default::default()
        }
    }

    #[test]
    fn a_completed_file_is_selected_by_its_last_write_not_its_name() {
        // Rotation may run after midnight, so `access-D.log` can contain lines from D+1. Selecting by
        // the date in the name would drop them from a window that starts after midnight.
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join("access-2026-11-02.log");
        let recent = dir.path().join("access-2026-11-03.log");
        let current = dir
            .path()
            .join(ingress_logs::shared().current(LogKind::Access));
        std::fs::write(&old, b"old\n").unwrap();
        std::fs::write(&recent, b"recent\n").unwrap();
        std::fs::write(&current, b"current\n").unwrap();
        let at = |path: &std::path::Path, secs: u64| {
            std::fs::File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_modified(UNIX_EPOCH + Duration::from_secs(secs))
                .unwrap();
        };
        // 2026-11-04 00:00 UTC plus a few minutes.
        let midnight = 1_793_750_400;
        at(&old, midnight - 600);
        at(&recent, midnight + 600);
        at(&current, midnight + 900);

        let files = select_files(dir.path(), UNIX_EPOCH + Duration::from_secs(midnight + 300));
        let names: Vec<String> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["access-2026-11-03.log", "access.log"]);
    }

    #[test]
    fn filters_match_as_documented() {
        let e = entry(503, "POST", "/api/v1/x", "web.example.com");
        for (raw, want) in [
            ("", true),
            ("status=5xx", true),
            ("status=503", true),
            ("status=502", false),
            ("status=4xx", false),
            ("method=POST", true),
            ("method=GET", false),
            ("path=/api", true),
            ("path=/api/v1/x", true),
            ("path=/ap/", false),
            ("path=/", true),
            ("host=web.example.com", true),
            ("host=example.com", false),
            (
                "status=5xx&method=POST&path=/api&host=web.example.com",
                true,
            ),
            ("status=5xx&method=GET", false),
        ] {
            assert_eq!(Filter::new(&query(raw)).matches(&e), want, "{raw}");
        }
    }

    #[tokio::test]
    async fn only_this_apps_matching_lines_are_sent_and_the_stream_ends() {
        let data = [
            line("web", 200, "/a"),
            line("other", 200, "/secret"),
            line("-", 200, "/dash"),
            line("web", 503, "/b"),
            "garbage\n".to_owned(),
        ]
        .concat();
        let (frames, audit) = history_of("status=5xx", vec![out(data.clone())]).await;
        assert_eq!(paths(&frames), ["/b"]);
        assert_eq!(frames.last(), Some(&AccessFrame::End));
        assert_eq!((audit.scanned, audit.skipped, audit.frames), (5, 1, 1));
        let (frames, _) = history_of("", vec![out(data)]).await;
        assert_eq!(paths(&frames), ["/a", "/b"]);
    }

    #[tokio::test]
    async fn a_line_without_a_parseable_time_is_skipped() {
        let bad = line("web", 200, "/bad-time").replace("2026-10-31T12:00:00+00:00", "not-a-time");
        let (frames, audit) = history_of("", vec![out(bad), out(line("web", 200, "/ok"))]).await;
        assert_eq!(paths(&frames), ["/ok"]);
        assert_eq!(audit.scanned, 2);
        assert_eq!(audit.skipped, 1);
    }

    // ---- the ring ----

    #[tokio::test]
    async fn tail_keeps_the_last_matches_in_order() {
        let data: String = (1..=5)
            .map(|i| line("web", 200, &format!("/{i}")))
            .collect();
        let (frames, _) = history_of("tail=2", vec![out(data.clone())]).await;
        assert_eq!(paths(&frames), ["/4", "/5"]);
        let (frames, audit) = history_of("tail=0", vec![out(data.clone())]).await;
        assert!(paths(&frames).is_empty());
        assert_eq!(frames, [AccessFrame::End]);
        assert_eq!(audit.scanned, 5);
        let (frames, _) = history_of("tail=1000", vec![out(data)]).await;
        assert_eq!(paths(&frames).len(), 5);
    }

    #[tokio::test]
    async fn tail_counts_matches_not_lines_of_the_whole_log() {
        let mut data = String::new();
        for i in 0..20 {
            data += &line("web", 200, &format!("/mine{i}"));
            data += &line("other", 200, "/theirs");
            data += &line("other", 200, "/theirs");
        }
        let (frames, _) = history_of("tail=3", vec![out(data)]).await;
        assert_eq!(paths(&frames), ["/mine17", "/mine18", "/mine19"]);
    }

    #[test]
    fn the_ring_is_bounded_by_bytes_too() {
        let mut ring = Ring::new(1000);
        let big = Bytes::from(vec![0u8; MAX_RING_BYTES / 4 + 1]);
        for _ in 0..10 {
            ring.push(big.clone());
        }
        assert_eq!(ring.frames.len(), 3);
        assert!(ring.bytes <= MAX_RING_BYTES);
        let mut ring = Ring::new(0);
        ring.push(Bytes::from_static(b"x"));
        assert!(ring.frames.is_empty() && ring.bytes == 0);
    }

    #[tokio::test]
    async fn follow_drains_the_old_file_after_a_rename() {
        use std::io::Write as _;
        let d = tempfile::tempdir().unwrap();
        let path = d
            .path()
            .join(ingress_logs::shared().current(LogKind::Access));
        std::fs::write(
            &path, b"a
",
        )
        .unwrap();
        let file = File::open(&path).await.unwrap();
        let meta = file.metadata().await.unwrap();
        let mut follow = Follow {
            path: path.clone(),
            file: Some(file),
            position: 0,
            id: Some((meta.dev(), meta.ino())),
            buf: vec![0; CHUNK],
        };
        assert_eq!(
            follow.next_chunk().await.unwrap().unwrap(),
            Bytes::from_static(
                b"a
"
            )
        );

        // The daemon renames the file, an old worker appends to the renamed inode, and nginx
        // creates the new current file.
        let old = d.path().join("access-2026-11-03.log");
        std::fs::rename(&path, &old).unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&old)
            .unwrap()
            .write_all(b"a2\n")
            .unwrap();
        std::fs::write(&path, b"b\n").unwrap();

        assert_eq!(
            follow.next_chunk().await.unwrap().unwrap(),
            Bytes::from_static(b"a2\n")
        );
        assert_eq!(
            follow.next_chunk().await.unwrap().unwrap(),
            Bytes::from_static(b"b\n")
        );
    }

    // ---- two phases ----

    #[tokio::test]
    async fn follow_reads_a_second_stream_after_the_history_without_waiting_for_a_ring() {
        let q = query("follow=true&tail=1");
        let (tx, rx) = mpsc::channel(FRAME_QUEUE);
        let history = stream_reader(stream::iter(vec![out(
            line("web", 200, "/h1") + &line("web", 200, "/h2")
        )]));
        let live = stream_reader(stream::iter(vec![out(
            line("web", 200, "/l1") + &line("web", 200, "/l2")
        )]));
        let task = tokio::spawn(pump(
            history,
            Some(FollowPlan::Reader(Box::new(live))),
            Scan::new(name(), &q, UNIX_EPOCH),
            q.tail,
            tx,
            StreamDeadline(None),
            audit(&q),
        ));
        let frames = drain(rx).await;
        task.await.unwrap();
        // The ring bounds the history only; the followed lines all come.
        assert_eq!(paths(&frames), ["/h2", "/l1", "/l2"]);
    }

    #[tokio::test]
    async fn an_unterminated_history_fragment_is_completed_by_follow() {
        let q = query("follow=true");
        let (tx, rx) = mpsc::channel(FRAME_QUEUE);
        let full = line("web", 200, "/live");
        let cut = full.len() - 10;
        let history = stream_reader(stream::iter(vec![out(
            line("web", 200, "/h") + &full[..cut]
        )]));
        let live = stream_reader(stream::iter(vec![out(full[cut..].to_owned())]));
        let task = tokio::spawn(pump(
            history,
            Some(FollowPlan::Reader(Box::new(live))),
            Scan::new(name(), &q, UNIX_EPOCH),
            None,
            tx,
            StreamDeadline(None),
            audit(&q),
        ));
        let frames = drain(rx).await;
        task.await.unwrap();
        assert_eq!(paths(&frames), ["/h", "/live"]);
    }

    #[tokio::test]
    async fn a_follow_that_cannot_be_read_is_an_error_frame_without_its_text() {
        let q = query("follow=true");
        let (tx, rx) = mpsc::channel(FRAME_QUEUE);
        let live = stream_reader(stream::iter(vec![Err(io::Error::other(
            "/run/user/1000/podman.sock: secret",
        ))]));
        let task = tokio::spawn(pump(
            stream_reader(stream::iter(Vec::new())),
            Some(FollowPlan::Reader(Box::new(live))),
            Scan::new(name(), &q, UNIX_EPOCH),
            None,
            tx,
            StreamDeadline(None),
            audit(&q),
        ));
        let frames = drain(rx).await;
        let (ended, _) = task.await.unwrap();
        assert_eq!(ended, Ended::Error);
        let [AccessFrame::Error(message)] = frames.as_slice() else {
            panic!("{frames:?}")
        };
        assert!(!message.contains("podman.sock"));
    }

    // ---- ending ----

    #[tokio::test(start_paused = true)]
    async fn the_token_expiring_during_a_scan_of_only_foreign_lines_ends_at_exp() {
        let started = Instant::now();
        let deadline = StreamDeadline(Some(SystemTime::now() + Duration::from_secs(30)));
        // Foreign traffic once a second, forever: nothing is ever sent.
        let foreign = stream::unfold((), |()| async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Some((out(line("other", 200, "/x")), ()))
        })
        .boxed();
        let q = query("");
        let (tx, rx) = mpsc::channel(FRAME_QUEUE);
        let task = tokio::spawn(pump(
            stream_reader(foreign),
            None,
            Scan::new(name(), &q, UNIX_EPOCH),
            None,
            tx,
            deadline,
            audit(&q),
        ));
        let frames = drain(rx).await;
        let (ended, got) = task.await.unwrap();
        assert_eq!(
            (ended, frames),
            (Ended::TokenExpired, vec![AccessFrame::TokenExpired])
        );
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_secs(29) && elapsed < Duration::from_secs(31),
            "{elapsed:?}"
        );
        assert!(got.scanned >= 28 && got.frames == 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_client_that_stops_reading_cannot_hold_the_stream_past_exp() {
        let deadline = StreamDeadline(Some(SystemTime::now() + Duration::from_secs(5)));
        let all = stream::repeat_with(|| out(line("web", 200, "/x"))).boxed();
        let q = query("");
        let (tx, _rx) = mpsc::channel(1);
        let (ended, got) = tokio::time::timeout(
            Duration::from_secs(10),
            pump(
                stream_reader(all),
                None,
                Scan::new(name(), &q, UNIX_EPOCH),
                None,
                tx,
                deadline,
                audit(&q),
            ),
        )
        .await
        .expect("the pump must end at exp, not wait for the client");
        assert_eq!((ended, got.frames), (Ended::TokenExpired, 1));
    }

    #[tokio::test(start_paused = true)]
    async fn a_client_hanging_up_during_a_silent_scan_releases_the_podman_stream() {
        struct Flag(Arc<AtomicBool>);
        impl Drop for Flag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicBool::new(false));
        let flag = Flag(Arc::clone(&dropped));
        // Foreign lines, then silence, and the stream holds the flag.
        let logs = stream::iter(vec![out(line("other", 200, "/x"))])
            .chain(stream::pending())
            .inspect(move |_| {
                let _ = &flag;
            })
            .boxed();
        let q = query("");
        let (tx, rx) = mpsc::channel(FRAME_QUEUE);
        let task = tokio::spawn(pump(
            stream_reader(logs),
            None,
            Scan::new(name(), &q, UNIX_EPOCH),
            None,
            tx,
            StreamDeadline(None),
            audit(&q),
        ));
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(!task.is_finished());
        drop(rx);
        let (ended, _) = task.await.unwrap();
        assert_eq!(ended, Ended::ClientClosed);
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn a_file_error_mid_stream_is_an_error_frame_without_its_text() {
        let (frames, _) = history_of(
            "",
            vec![
                out(line("web", 200, "/a")),
                Err(io::Error::other("/run/user/1000/podman.sock: secret")),
            ],
        )
        .await;
        assert_eq!(paths(&frames), ["/a"]);
        let Some(AccessFrame::Error(message)) = frames.last() else {
            panic!("{frames:?}")
        };
        assert!(!message.contains("podman.sock"));
    }

    // ---- the audit ----

    #[tokio::test]
    async fn the_audit_holds_no_filter_value_and_flags_a_drifted_format() {
        let raw = "status=418&method=BREW&path=/teapot-secret&host=tea.example.com&tail=3";
        let (frames, got) = history_of(raw, vec![out("SECRET-LOG-CONTENT\n")]).await;
        assert_eq!(frames, [AccessFrame::End]);
        // The audit line is built from these fields only, so none of them may hold a value. No `..`:
        // a new field is a conscious decision. `started` only yields the duration, and its `Debug`
        // output is clock digits that may well contain `418`.
        let Audit {
            sub,
            app,
            follow,
            tail,
            since,
            filtered,
            started: _,
            frames: sent,
            scanned,
            skipped,
        } = &got;
        let fields = format!(
            "{sub:?} {app} {follow} {tail:?} {} {filtered} {sent} {scanned} {skipped}",
            unix_secs(*since)
        );
        for secret in [
            "418",
            "BREW",
            "teapot-secret",
            "tea.example.com",
            "SECRET-LOG-CONTENT",
        ] {
            assert!(
                !fields.contains(secret),
                "{secret} is in the audit: {fields}"
            );
        }
        assert!(got.filtered && got.format_may_have_drifted());
        // Unparseable lines next to real entries are not a drift.
        let (_, got) = history_of("", vec![out("junk\n"), out(line("web", 200, "/"))]).await;
        assert!(!got.format_may_have_drifted());
        // A quiet log is not one either.
        let (_, got) = history_of("", vec![out(line("other", 200, "/"))]).await;
        assert!(!got.format_may_have_drifted());
    }
}
