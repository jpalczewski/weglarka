//! `weglarka logs <app>... | --all` (issue #345): what the containers of one or many apps printed,
//! optionally followed. One task polls the per-app streams with `select_all`, so there are no
//! spawned tasks, and a slow terminal or pipe holds back every stream (backpressure) instead of
//! growing a queue.

use std::borrow::Cow;
use std::io::IsTerminal;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::Args;
use futures_util::StreamExt;
use futures_util::stream::{self, select_all};
use tokio::io::{AsyncWrite, AsyncWriteExt};
pub(crate) use weglarka_api::parse_rfc3339;
use weglarka_api::{
    ListAppsResponse, LogFrame, LogsQuery, MAX_LOGS_TAIL, MAX_STAMP, RuntimeState, endpoints,
};

use crate::client::{ApiClient, LogStream};
use crate::commands::{client, instance};
use crate::error::{CliError, Kind, exit};
use crate::run::parse_timeout;
use crate::settings::Overrides;

/// Most apps one invocation follows. Every app is a connection; the panel relay allows 64 in total
/// (`MAX_CONCURRENT`), so one command must not be able to exhaust it.
pub(crate) const MAX_APP_STREAMS: usize = 32;
/// `--tail` when neither `--tail` nor `--since` is given.
const DEFAULT_TAIL: u32 = 100;
/// A line longer than this is written in parts, so memory stays bounded.
const MAX_LINE: usize = 64 * 1024;
/// Reopens in a row, with no output in between, after which a stream is given up.
pub(crate) const MAX_QUIET_REOPENS: u32 = 5;
/// A reopen starts this much before the last delivered line's timestamp, so a line that was in
/// flight when the connection ended is not lost (at the price of a repeat).
const REOPEN_OVERLAP: Duration = Duration::from_secs(2);
/// A connection that stayed open at least this long was not a tight loop, however quiet: it does
/// not count towards [`MAX_QUIET_REOPENS`] (an idle app followed for hours expires many tokens).
pub(crate) const STABLE_FOR: Duration = Duration::from_secs(60);

/// The count of quick reopens after one more, given how long the connection being replaced lived;
/// `None` when the stream expires in a tight loop and should be given up.
pub(crate) fn count_reopen(quick_reopens: u32, lived: Duration) -> Option<u32> {
    let before = if lived >= STABLE_FOR {
        0
    } else {
        quick_reopens
    };
    (before < MAX_QUIET_REOPENS).then_some(before + 1)
}

/// `--tail`: a number of lines, or `all`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tail {
    All,
    Lines(u32),
}

fn parse_tail(raw: &str) -> Result<Tail, String> {
    if raw == "all" {
        return Ok(Tail::All);
    }
    raw.parse::<u32>()
        .ok()
        .filter(|n| *n <= MAX_LOGS_TAIL)
        .map(Tail::Lines)
        .ok_or_else(|| format!("expected `all` or a number from 0 to {MAX_LOGS_TAIL}, got {raw:?}"))
}

/// Flags of `logs`.
#[derive(Debug, Args)]
#[command(after_long_help = "\
Several apps (or --all) are printed as `app | line`, in the order lines arrive; there is no merge by
time. To order them, add --timestamps and sort: `weglarka logs --all --timestamps | sort -t'|' -k2`.
--all follows the apps that have a running container (at most 32 in one command).

With --follow, a long-lived connection is renewed when its token expires, continuing from the
timestamp of the last printed line (so a long --since or --tail all read is not cut short). Lines
around the renewal can be printed twice (delivery is at-least-once).

A stream that fails is reported on stderr while the others go on; the exit code is then 70.
Log content is untrusted: on a terminal, control characters are replaced with U+FFFD.

Examples:
  weglarka logs ntfy -f
  weglarka logs web api --since 10m --timestamps
  weglarka logs --all -n 20
  weglarka --json logs ntfy -n 1000 | jq -r .line")]
pub struct LogsArgs {
    /// Instance names (at most 32).
    #[arg(value_name = "APP", conflicts_with = "all")]
    pub apps: Vec<String>,
    /// Every app with a running container.
    #[arg(long)]
    pub all: bool,
    /// Keep the stream open and print new output as it arrives.
    #[arg(short = 'f', long)]
    pub follow: bool,
    /// Only the last N lines per app (`all` = the whole log). Default 100; with --since, no limit.
    #[arg(short = 'n', long, value_name = "N|all", value_parser = parse_tail)]
    pub tail: Option<Tail>,
    /// Only output newer than this: seconds, or a number with `s`, `m` or `h` (`90`, `10m`, `2h`).
    #[arg(long, value_name = "DURATION", value_parser = parse_timeout)]
    pub since: Option<Duration>,
    /// Prefix every line with its timestamp.
    #[arg(long)]
    pub timestamps: bool,
}

/// Which apps the command was asked for.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Selection {
    All,
    Apps(Vec<String>),
}

impl LogsArgs {
    pub(crate) fn selection(&self) -> Result<Selection, CliError> {
        if self.all {
            return Ok(Selection::All);
        }
        if self.apps.is_empty() {
            return Err(CliError::usage("no app given")
                .with_hint("name the apps (`weglarka logs ntfy`) or use --all"));
        }
        let mut names: Vec<String> = Vec::new();
        for raw in &self.apps {
            let name = instance(raw)?.as_str().to_owned();
            if !names.contains(&name) {
                names.push(name);
            }
        }
        check_limit(names.len())?;
        Ok(Selection::Apps(names))
    }

    /// The query of the first request; `now` anchors `--since`.
    pub(crate) fn query(&self, now: SystemTime) -> LogsQuery {
        let tail = match (self.tail, self.since) {
            (Some(Tail::All), _) => None,
            (Some(Tail::Lines(n)), _) => Some(n),
            (None, Some(_)) => None,
            (None, None) => Some(DEFAULT_TAIL),
        };
        LogsQuery {
            follow: self.follow,
            tail,
            since: self.since.map(|ago| since_epoch(now.checked_sub(ago))),
            timestamps: self.timestamps,
        }
    }
}

pub(crate) fn since_epoch(t: Option<SystemTime>) -> Duration {
    t.and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .unwrap_or_default()
}

fn check_limit(count: usize) -> Result<(), CliError> {
    if count > MAX_APP_STREAMS {
        return Err(CliError::usage(format!(
            "{count} apps is more than one command follows (at most {MAX_APP_STREAMS})"
        ))
        .with_hint("name fewer apps, or run several commands"));
    }
    Ok(())
}

/// Control characters (escape sequences, `\r` overwriting a line, …) and bidirectional overrides in
/// untrusted text are replaced with U+FFFD when `terminal` is set; `\t` and `\n` stay. Not a
/// terminal: the bytes are returned unchanged.
pub(crate) fn sanitize_for_terminal(bytes: &[u8], terminal: bool) -> Cow<'_, [u8]> {
    if !terminal {
        return Cow::Borrowed(bytes);
    }
    let text = String::from_utf8_lossy(bytes);
    let clean: String = text
        .chars()
        .map(|c| match c {
            '\t' | '\n' => c,
            c if c.is_control() => '\u{FFFD}',
            '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{200e}' | '\u{200f}' => {
                '\u{FFFD}'
            }
            c => c,
        })
        .collect();
    Cow::Owned(clean.into_bytes())
}

/// A line, or a part of an over-long one.
#[derive(Debug, PartialEq, Eq)]
struct Piece {
    bytes: Vec<u8>,
    /// False for a part cut at [`MAX_LINE`]: the line goes on in the next piece.
    newline: bool,
}

/// Cuts one stream (one app, stdout or stderr) into lines; a chunk need not end at a newline.
#[derive(Debug, Default)]
struct LineBuf {
    pending: Vec<u8>,
}

impl LineBuf {
    fn push(&mut self, data: &[u8], out: &mut Vec<Piece>) {
        for (n, segment) in data.split(|&b| b == b'\n').enumerate() {
            // Every segment but the first follows a newline, so the pending line is complete.
            if n > 0 {
                out.push(Piece {
                    bytes: std::mem::take(&mut self.pending),
                    newline: true,
                });
            }
            let mut rest = segment;
            while self.pending.len() + rest.len() > MAX_LINE {
                let room = MAX_LINE - self.pending.len();
                self.pending.extend_from_slice(&rest[..room]);
                rest = &rest[room..];
                out.push(Piece {
                    bytes: std::mem::take(&mut self.pending),
                    newline: false,
                });
            }
            self.pending.extend_from_slice(rest);
        }
    }

    /// The stream ended: a trailing fragment becomes a line of its own.
    fn finish(&mut self) -> Option<Piece> {
        (!self.pending.is_empty()).then(|| Piece {
            bytes: std::mem::take(&mut self.pending),
            newline: true,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// One app: the bytes as they are.
    Raw,
    /// Several apps: `app | line`.
    Prefixed,
    /// JSON Lines `{"app","stream","line"}`.
    Json,
}

/// Writes log lines to stdout and stderr (or JSON Lines to stdout) and tracks failures.
pub(crate) struct Printer<O, E> {
    mode: Mode,
    out: O,
    err: E,
    /// Whether each output is a terminal, i.e. whether untrusted text must be sanitised.
    out_tty: bool,
    err_tty: bool,
    names: Vec<String>,
    /// Per app: stdout and stderr.
    bufs: Vec<[LineBuf; 2]>,
    width: usize,
    failed: bool,
}

impl<O: AsyncWrite + Unpin, E: AsyncWrite + Unpin> Printer<O, E> {
    pub(crate) fn new(
        mode: Mode,
        names: Vec<String>,
        (out, out_tty): (O, bool),
        (err, err_tty): (E, bool),
    ) -> Self {
        Self {
            mode,
            out,
            err,
            out_tty,
            err_tty,
            width: names.iter().map(String::len).max().unwrap_or(0),
            bufs: names.iter().map(|_| Default::default()).collect(),
            names,
            failed: false,
        }
    }

    pub(crate) async fn data(
        &mut self,
        app: usize,
        stderr: bool,
        chunk: &[u8],
    ) -> std::io::Result<()> {
        let mut pieces = Vec::new();
        self.bufs[app][usize::from(stderr)].push(chunk, &mut pieces);
        for piece in pieces {
            self.piece(app, stderr, piece).await?;
        }
        self.flush().await
    }

    /// The app's stream is over: write what is left of its lines.
    pub(crate) async fn end(&mut self, app: usize) -> std::io::Result<()> {
        for stderr in [false, true] {
            if let Some(piece) = self.bufs[app][usize::from(stderr)].finish() {
                self.piece(app, stderr, piece).await?;
            }
        }
        self.flush().await
    }

    /// A stream failed: say so on stderr (the others go on) and remember it for the exit code.
    pub(crate) async fn fail(&mut self, app: usize, message: &str) -> std::io::Result<()> {
        self.end(app).await?;
        self.failed = true;
        self.note(&self.names[app].clone(), message).await
    }

    pub(crate) async fn note(&mut self, app: &str, message: &str) -> std::io::Result<()> {
        let message = sanitize_for_terminal(message.as_bytes(), self.err_tty);
        let mut line = format!("weglarka: {app}: ").into_bytes();
        line.extend_from_slice(&message);
        line.push(b'\n');
        self.err.write_all(&line).await?;
        self.err.flush().await
    }

    pub(crate) fn exit_code(&self) -> i32 {
        if self.failed {
            exit::INTERNAL
        } else {
            exit::OK
        }
    }

    async fn piece(&mut self, app: usize, stderr: bool, piece: Piece) -> std::io::Result<()> {
        let mut line = Vec::new();
        match self.mode {
            Mode::Json => {
                let value = serde_json::json!({
                    "app": self.names[app],
                    "stream": if stderr { "stderr" } else { "stdout" },
                    // JSON escapes C0 only; C1 (U+009B is CSI) and bidi would still reach a terminal.
                    "line": String::from_utf8_lossy(&sanitize_for_terminal(&piece.bytes, self.out_tty)),
                });
                line.extend_from_slice(value.to_string().as_bytes());
                line.push(b'\n');
                return self.out.write_all(&line).await;
            }
            Mode::Prefixed => {
                line.extend_from_slice(
                    format!("{:<width$} | ", self.names[app], width = self.width).as_bytes(),
                );
            }
            Mode::Raw => {}
        }
        let tty = if stderr { self.err_tty } else { self.out_tty };
        line.extend_from_slice(&sanitize_for_terminal(&piece.bytes, tty));
        if piece.newline || self.mode == Mode::Prefixed {
            line.push(b'\n');
        }
        if stderr {
            self.err.write_all(&line).await
        } else {
            self.out.write_all(&line).await
        }
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        self.out.flush().await?;
        self.err.flush().await
    }
}

/// What one app's stream produced.
#[derive(Debug)]
enum Event {
    Data {
        app: usize,
        stderr: bool,
        bytes: Vec<u8>,
    },
    End(usize),
    Failed(usize, String),
}

/// One app's stream, with what it takes to reopen it.
struct AppStream<'a> {
    app: usize,
    name: String,
    client: &'a ApiClient,
    query: LogsQuery,
    stream: LogStream,
    /// When the first request was made: where a reopen of a `--tail 0` follow starts from.
    started: SystemTime,
    /// The timestamp of the last delivered line (since the epoch): a reopen asks for output since
    /// then. Never the local clock, which is far ahead of the lines while history is being read.
    last_line: Option<Duration>,
    /// Drop the timestamp prefix from lines (the user did not ask for `--timestamps`).
    strip: bool,
    /// Per stream (stdout, stderr): the prefix splitter.
    stamps: [Stamps; 2],
    /// Bytes held back by `stamps` when the stream ended, still to be delivered.
    leftovers: Vec<(bool, Vec<u8>)>,
    /// The event that ends the stream, once `leftovers` are out.
    ended: Option<Event>,
    quiet_reopens: u32,
    /// When the current connection was opened.
    opened: Instant,
}

impl AppStream<'_> {
    /// The next event, or `None` once the stream has ended.
    async fn next(mut self) -> Option<(Event, Option<Self>)> {
        let app = self.app;
        loop {
            if let Some((stderr, bytes)) = self.leftovers.pop() {
                return Some((Event::Data { app, stderr, bytes }, Some(self)));
            }
            if let Some(event) = self.ended.take() {
                return Some((event, None));
            }
            match self.stream.next().await {
                Ok(Some(LogFrame::Stdout(bytes))) => {
                    return Some(self.data(false, bytes));
                }
                Ok(Some(LogFrame::Stderr(bytes))) => return Some(self.data(true, bytes)),
                Ok(Some(LogFrame::End)) => self.stop(Event::End(app)),
                Ok(Some(LogFrame::TokenExpired)) => {
                    if let Err(message) = self.reopen().await {
                        self.stop(Event::Failed(app, message));
                    }
                }
                Ok(Some(LogFrame::Error(message))) => self.stop(Event::Failed(
                    app,
                    format!("the daemon reported: {message}"),
                )),
                Ok(None) => self.stop(Event::Failed(
                    app,
                    "the stream ended without a final frame".into(),
                )),
                Err(e) => self.stop(Event::Failed(app, e.message)),
            }
        }
    }

    /// The stream is over: deliver what the prefix splitters held back, then `last`.
    fn stop(&mut self, last: Event) {
        for stderr in [false, true] {
            let held = self.stamps[usize::from(stderr)].finish();
            if !held.is_empty() {
                self.leftovers.push((stderr, held));
            }
        }
        self.ended = Some(last);
    }

    fn data(mut self, stderr: bool, bytes: Vec<u8>) -> (Event, Option<Self>) {
        let bytes = self.stamps[usize::from(stderr)].feed(&bytes, self.strip, &mut self.last_line);
        self.quiet_reopens = 0;
        (
            Event::Data {
                app: self.app,
                stderr,
                bytes,
            },
            Some(self),
        )
    }

    /// The token expired: continue from the last output with a fresh connection (a remote host
    /// refreshes its token when a connection opens).
    async fn reopen(&mut self) -> Result<(), String> {
        self.quiet_reopens = count_reopen(self.quiet_reopens, self.opened.elapsed())
            .ok_or("the stream keeps expiring without output")?;
        let query = reopen_query(&self.query, self.last_line, self.started);
        // A prefix cut by the old connection is read again from the new one.
        self.stamps = Default::default();
        self.stream = self
            .client
            .open_logs(&self.name, &query)
            .await
            .map_err(|e| format!("cannot reopen the stream: {}", e.message))?;
        self.opened = Instant::now();
        Ok(())
    }
}

/// The query that continues a stream whose token expired. It never moves `since` past output that
/// was not delivered: with no line yet, the first query is repeated unchanged (the tail included);
/// afterwards it resumes at the last delivered line, without a tail.
fn reopen_query(first: &LogsQuery, last_line: Option<Duration>, started: SystemTime) -> LogsQuery {
    match (last_line, first.tail) {
        (Some(at), _) => LogsQuery {
            tail: None,
            since: Some(at.saturating_sub(REOPEN_OVERLAP)),
            ..*first
        },
        // `--tail 0` asks for nothing old, so output since the start is all there can be.
        (None, Some(0)) => LogsQuery {
            tail: None,
            since: Some(
                first
                    .since
                    .unwrap_or_default()
                    .max(since_epoch(started.checked_sub(REOPEN_OVERLAP))),
            ),
            ..*first
        },
        (None, _) => *first,
    }
}

/// Splits the RFC 3339 prefix off the lines of one stream. The daemon is always asked for
/// `timestamps=true`, because the time of the last line is what a reopen resumes from; the prefix
/// is dropped again unless the user asked for it. Everything after the prefix passes byte for byte,
/// and a prefix that does not parse is left in place.
#[derive(Debug, Default)]
struct Stamps {
    /// The start of the current line, held back until its first space or newline.
    head: Vec<u8>,
    /// Past the prefix of the current line.
    in_line: bool,
}

impl Stamps {
    /// `chunk` through the splitter; the time of every line seen goes to `last`.
    fn feed(&mut self, chunk: &[u8], strip: bool, last: &mut Option<Duration>) -> Vec<u8> {
        let mut out = Vec::with_capacity(chunk.len());
        let mut rest = chunk;
        while let Some(&b) = rest.first() {
            if self.in_line {
                let end = rest.iter().position(|&c| c == b'\n').map(|i| i + 1);
                out.extend_from_slice(&rest[..end.unwrap_or(rest.len())]);
                rest = &rest[end.unwrap_or(rest.len())..];
                self.in_line = end.is_none();
                continue;
            }
            rest = &rest[1..];
            match b {
                b' ' => {
                    match parse_rfc3339(&self.head) {
                        Some(at) => {
                            *last = Some(at);
                            if !strip {
                                out.extend_from_slice(&self.head);
                                out.push(b);
                            }
                        }
                        None => {
                            out.extend_from_slice(&self.head);
                            out.push(b);
                        }
                    }
                    self.head.clear();
                    self.in_line = true;
                }
                b'\n' => {
                    out.append(&mut self.head);
                    out.push(b);
                }
                _ => {
                    self.head.push(b);
                    if self.head.len() > MAX_STAMP {
                        out.append(&mut self.head);
                        self.in_line = true;
                    }
                }
            }
        }
        out
    }

    /// The stream ended inside the start of a line: what was held back.
    fn finish(&mut self) -> Vec<u8> {
        self.in_line = false;
        std::mem::take(&mut self.head)
    }
}

/// Prints the streams of `names` until all have ended. Everything is opened before anything is
/// printed; with `tolerate_missing` an app the daemon does not know (it may have just been
/// removed) is noted and skipped instead of failing the command.
pub(crate) async fn stream_logs<O, E>(
    client: &ApiClient,
    names: Vec<String>,
    query: LogsQuery,
    tolerate_missing: bool,
    mode: Mode,
    outputs: ((O, bool), (E, bool)),
) -> Result<i32, CliError>
where
    O: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    // The timestamps are needed to resume after a token renewal, whatever the user asked for.
    let strip = !query.timestamps;
    let query = LogsQuery {
        timestamps: true,
        ..query
    };
    let opened =
        futures_util::future::join_all(names.iter().map(|name| client.open_logs(name, &query)))
            .await;
    let started = SystemTime::now();
    let mut kept = Vec::new();
    let mut streams = Vec::new();
    let mut skipped = Vec::new();
    for (name, result) in names.into_iter().zip(opened) {
        match result {
            Ok(stream) => {
                streams.push((kept.len(), stream));
                kept.push(name);
            }
            Err(e) if tolerate_missing && e.kind == Kind::NotFound => skipped.push((name, e)),
            Err(e) => return Err(e),
        }
    }
    let (out, err) = outputs;
    let mut printer = Printer::new(mode, kept.clone(), out, err);
    let io = |e: std::io::Error| CliError::internal(format!("cannot write the output: {e}"));
    for (name, e) in skipped {
        printer
            .note(&name, &format!("skipped: {}", e.message))
            .await
            .map_err(io)?;
    }
    if streams.is_empty() {
        // Nothing left to follow (every app was skipped); an empty `select_all` would never end.
        return Ok(exit::OK);
    }
    let mut all = select_all(streams.into_iter().map(|(app, stream)| {
        let state = AppStream {
            app,
            name: kept[app].clone(),
            client,
            query,
            stream,
            started,
            last_line: None,
            strip,
            stamps: Default::default(),
            leftovers: Vec::new(),
            ended: None,
            quiet_reopens: 0,
            opened: Instant::now(),
        };
        Box::pin(stream::unfold(Some(state), |state| async move {
            state?.next().await
        }))
    }));
    while let Some(event) = all.next().await {
        let written = match event {
            Event::Data { app, stderr, bytes } => printer.data(app, stderr, &bytes).await,
            Event::End(app) => printer.end(app).await,
            Event::Failed(app, message) => printer.fail(app, &message).await,
        };
        match written {
            Ok(()) => {}
            // `| head`: the reader is gone, which is how this command is meant to end.
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => return Ok(exit::OK),
            Err(e) => return Err(io(e)),
        }
    }
    Ok(printer.exit_code())
}

pub async fn run(json: bool, o: &Overrides, a: LogsArgs) -> Result<i32, CliError> {
    let selection = a.selection()?;
    let query = a.query(SystemTime::now());
    let client = client(o)?;
    let (names, all) = match selection {
        Selection::Apps(names) => (names, false),
        Selection::All => {
            let list: ListAppsResponse =
                client.call(endpoints::APPS_LIST, &[], None::<&()>).await?;
            let names: Vec<String> = list
                .apps
                .iter()
                .filter(|app| {
                    matches!(app.runtime, RuntimeState::Running | RuntimeState::Unhealthy)
                })
                .map(|app| app.name.as_str().to_owned())
                .collect();
            check_limit(names.len())?;
            if names.is_empty() {
                eprintln!("weglarka: no app has a running container");
                return Ok(exit::OK);
            }
            (names, true)
        }
    };
    let mode = if json {
        Mode::Json
    } else if all || names.len() > 1 {
        Mode::Prefixed
    } else {
        Mode::Raw
    };
    let out = (tokio::io::stdout(), std::io::stdout().is_terminal());
    let err = (tokio::io::stderr(), std::io::stderr().is_terminal());
    stream_logs(&client, names, query, all, mode, (out, err)).await
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use clap::Parser as _;
    use hyper::body::Bytes;
    use weglarka_api::LOGS_STREAM_CONTENT_TYPE;
    use weglarka_unix_http::testing::{Reply, mock_seen};

    use super::*;

    #[derive(Debug, clap::Parser)]
    struct W {
        #[command(flatten)]
        a: LogsArgs,
    }

    fn parse(argv: &[&str]) -> LogsArgs {
        W::try_parse_from(std::iter::once("logs").chain(argv.iter().copied()))
            .unwrap()
            .a
    }

    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_000_000)
    }

    // ---- arguments

    #[test]
    fn tail_defaults_to_100_and_since_alone_means_no_limit() {
        assert_eq!(parse(&["web"]).query(now()).tail, Some(100));
        let q = parse(&["web", "--since", "10m"]).query(now());
        assert_eq!(q.tail, None);
        assert_eq!(q.since, Some(Duration::from_secs(1_000_000 - 600)));
        assert_eq!(
            parse(&["web", "-n", "5", "--since", "90"])
                .query(now())
                .tail,
            Some(5)
        );
        assert_eq!(parse(&["web", "--tail", "all"]).query(now()).tail, None);
        assert_eq!(parse(&["web", "-n", "0"]).query(now()).tail, Some(0));
        let q = parse(&["web", "-f", "--timestamps"]).query(now());
        assert!(q.follow && q.timestamps);
    }

    #[test]
    fn bad_flags_are_usage_errors() {
        for argv in [
            &["web", "-n", "10001"][..],
            &["web", "-n", "-1"],
            &["web", "-n", "many"],
            &["web", "--since", "0"],
            &["web", "--since", "soon"],
            &["web", "--all"],
        ] {
            assert!(
                W::try_parse_from(std::iter::once("logs").chain(argv.iter().copied())).is_err(),
                "{argv:?}"
            );
        }
        assert!(parse(&["web", "-n", "10000"]).tail == Some(Tail::Lines(10_000)));
        let err = parse(&[]).selection().unwrap_err();
        assert_eq!(err.kind, Kind::Usage);
        assert_eq!(parse(&["--all"]).selection().unwrap(), Selection::All);
    }

    #[test]
    fn names_are_checked_and_deduplicated() {
        assert_eq!(
            parse(&["web", "api", "web"]).selection().unwrap(),
            Selection::Apps(vec!["web".into(), "api".into()])
        );
        assert_eq!(parse(&["Web!"]).selection().unwrap_err().kind, Kind::Usage);
    }

    #[test]
    fn more_than_32_apps_is_a_usage_error() {
        let names: Vec<String> = (0..33).map(|i| format!("app{i}")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let err = parse(&refs).selection().unwrap_err();
        assert_eq!(err.kind, Kind::Usage);
        assert!(err.hint.is_some());
        assert!(parse(&refs[..32]).selection().is_ok());
        assert!(check_limit(33).is_err() && check_limit(32).is_ok());
    }

    // ---- line buffer and sanitising

    fn lines(buf: &mut LineBuf, chunks: &[&[u8]]) -> Vec<(String, bool)> {
        let mut pieces = Vec::new();
        for c in chunks {
            buf.push(c, &mut pieces);
        }
        pieces
            .into_iter()
            .map(|p| (String::from_utf8_lossy(&p.bytes).into_owned(), p.newline))
            .collect()
    }

    #[test]
    fn a_chunk_cutting_a_line_is_joined_and_a_fragment_is_finished() {
        let mut buf = LineBuf::default();
        assert_eq!(
            lines(&mut buf, &[b"hel", b"lo\nwor", b"ld\n\npar"]),
            [
                ("hello".into(), true),
                ("world".into(), true),
                (String::new(), true)
            ]
        );
        let tail = buf.finish().unwrap();
        assert_eq!((tail.bytes.as_slice(), tail.newline), (&b"par"[..], true));
        assert!(buf.finish().is_none());
    }

    #[test]
    fn a_line_over_64_kib_is_written_in_parts() {
        let mut buf = LineBuf::default();
        let long = vec![b'x'; MAX_LINE * 2 + 10];
        let mut pieces = Vec::new();
        buf.push(&long, &mut pieces);
        assert_eq!(pieces.len(), 2);
        assert!(
            pieces
                .iter()
                .all(|p| p.bytes.len() == MAX_LINE && !p.newline)
        );
        assert_eq!(buf.pending.len(), 10);
        buf.push(b"\n", &mut pieces);
        assert_eq!(pieces.last().unwrap().bytes.len(), 10);
        assert!(pieces.last().unwrap().newline);
        // Exactly at the limit is still one line.
        let mut pieces = Vec::new();
        buf.push(&vec![b'y'; MAX_LINE], &mut pieces);
        buf.push(b"\n", &mut pieces);
        assert_eq!(pieces.len(), 1);
    }

    #[test]
    fn control_characters_are_replaced_only_for_a_terminal() {
        let raw = b"ok\t\x1b[31mred\x07\r\xc2\x9b\xe2\x80\xae end\n\xff";
        assert_eq!(sanitize_for_terminal(raw, false).as_ref(), raw);
        let clean = sanitize_for_terminal(raw, true);
        assert_eq!(
            String::from_utf8(clean.into_owned()).unwrap(),
            "ok\t\u{FFFD}[31mred\u{FFFD}\u{FFFD}\u{FFFD}\u{FFFD} end\n\u{FFFD}"
        );
    }

    // ---- printer

    type Out = Vec<u8>;

    fn printer(mode: Mode, names: &[&str], tty: bool) -> Printer<Out, Out> {
        Printer::new(
            mode,
            names.iter().map(|n| (*n).to_owned()).collect(),
            (Vec::new(), tty),
            (Vec::new(), tty),
        )
    }

    fn text(v: &[u8]) -> String {
        String::from_utf8_lossy(v).into_owned()
    }

    #[tokio::test]
    async fn raw_mode_keeps_bytes_and_splits_the_streams() {
        let mut p = printer(Mode::Raw, &["web"], false);
        p.data(0, false, b"a\xff").await.unwrap();
        p.data(0, true, b"warn\n").await.unwrap();
        p.data(0, false, b"b\npart").await.unwrap();
        p.end(0).await.unwrap();
        assert_eq!(p.out, b"a\xffb\npart\n");
        assert_eq!(p.err, b"warn\n");
        assert_eq!(p.exit_code(), 0);
    }

    #[tokio::test]
    async fn stdout_and_stderr_have_separate_line_buffers() {
        let mut p = printer(Mode::Prefixed, &["web"], false);
        p.data(0, false, b"out-").await.unwrap();
        p.data(0, true, b"err-").await.unwrap();
        p.data(0, false, b"1\n").await.unwrap();
        p.data(0, true, b"2\n").await.unwrap();
        assert_eq!(
            (text(&p.out), text(&p.err)),
            ("web | out-1\n".into(), "web | err-2\n".into())
        );
    }

    #[tokio::test]
    async fn several_apps_are_prefixed_and_padded() {
        let mut p = printer(Mode::Prefixed, &["web", "gateway"], false);
        p.data(0, false, b"one\n").await.unwrap();
        p.data(1, false, b"two\nthr").await.unwrap();
        p.end(1).await.unwrap();
        assert_eq!(
            text(&p.out),
            "web     | one\ngateway | two\ngateway | thr\n"
        );
    }

    #[tokio::test]
    async fn json_is_lossy_utf8_one_object_per_line_even_for_one_app() {
        let mut p = printer(Mode::Json, &["web"], false);
        p.data(0, false, b"caf\xe9\n").await.unwrap();
        p.data(0, true, b"x").await.unwrap();
        p.end(0).await.unwrap();
        let got: Vec<serde_json::Value> = text(&p.out)
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(
            got,
            [
                serde_json::json!({"app": "web", "stream": "stdout", "line": "caf\u{FFFD}"}),
                serde_json::json!({"app": "web", "stream": "stderr", "line": "x"}),
            ]
        );
        assert!(p.err.is_empty());
    }

    #[tokio::test]
    async fn json_on_a_terminal_is_sanitised_too() {
        let mut p = printer(Mode::Json, &["web"], true);
        p.data(0, false, b"a\xc2\x9b[0m\xe2\x80\xaeb\x1bc\n")
            .await
            .unwrap();
        let got: serde_json::Value = serde_json::from_str(text(&p.out).trim()).unwrap();
        assert_eq!(got["line"], "a\u{FFFD}[0m\u{FFFD}b\u{FFFD}c");
    }

    #[tokio::test]
    async fn a_terminal_gets_sanitised_lines_a_pipe_does_not() {
        for (tty, expected) in [
            (true, "web | a\u{FFFD}[0mb\n"),
            (false, "web | a\x1b[0mb\n"),
        ] {
            let mut p = printer(Mode::Prefixed, &["web"], tty);
            p.data(0, false, b"a\x1b[0mb\n").await.unwrap();
            assert_eq!(text(&p.out), expected);
        }
    }

    // ---- against a mock daemon

    fn frames(frames: &[LogFrame]) -> Vec<Bytes> {
        frames.iter().map(|f| Bytes::from(f.encode())).collect()
    }

    fn logs_reply(frames_: &[LogFrame]) -> Reply {
        Reply::chunks(200, frames(frames_)).content_type(LOGS_STREAM_CONTENT_TYPE)
    }

    fn not_found() -> Reply {
        Reply::new(404, r#"{"code":"not_found","message":"no such app"}"#)
            .content_type("application/json")
    }

    fn query() -> LogsQuery {
        LogsQuery {
            tail: Some(100),
            ..Default::default()
        }
    }

    async fn drive(
        socket: &std::path::Path,
        names: &[&str],
        tolerate: bool,
        mode: Mode,
    ) -> (Result<i32, CliError>, String, String) {
        let (out, err) = (
            Arc::new(std::sync::Mutex::new(Vec::new())),
            Arc::new(std::sync::Mutex::new(Vec::new())),
        );
        let result = stream_logs(
            &ApiClient::new(socket),
            names.iter().map(|n| (*n).to_owned()).collect(),
            query(),
            tolerate,
            mode,
            ((Sink(out.clone()), false), (Sink(err.clone()), false)),
        )
        .await;
        let (o, e) = (text(&out.lock().unwrap()), text(&err.lock().unwrap()));
        (result, o, e)
    }

    /// A writer whose bytes outlive the printer.
    struct Sink(Arc<std::sync::Mutex<Vec<u8>>>);

    impl AsyncWrite for Sink {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.0.lock().unwrap().extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    fn app_of(path: &str) -> &str {
        path.trim_start_matches("/v1/apps/")
            .trim_end_matches("/logs")
    }

    #[tokio::test]
    async fn two_apps_are_prefixed_and_the_request_carries_the_query() {
        let mock = mock_seen(|seen| {
            let line = format!("hi from {}\n", app_of(&seen.path));
            logs_reply(&[LogFrame::Stdout(line.into_bytes()), LogFrame::End])
        })
        .await;
        let (code, out, err) = drive(&mock, &["web", "api"], false, Mode::Prefixed).await;
        assert_eq!(code.unwrap(), 0);
        assert!(err.is_empty(), "{err}");
        let mut got: Vec<&str> = out.lines().collect();
        got.sort_unstable();
        assert_eq!(got, ["api | hi from api", "web | hi from web"]);
        let seen = mock.seen.lock().unwrap();
        assert!(
            seen.iter()
                .all(|s| s.uri().ends_with("/logs?tail=100&timestamps=true")),
            "{seen:?}"
        );
    }

    #[tokio::test]
    async fn a_quiet_app_does_not_block_the_other() {
        let mock = mock_seen(|seen| {
            if app_of(&seen.path) == "quiet" {
                Reply::chunks(200, [])
                    .content_type(LOGS_STREAM_CONTENT_TYPE)
                    .hold_open()
            } else {
                logs_reply(&[LogFrame::Stdout(b"busy line\n".to_vec()), LogFrame::End])
            }
        })
        .await;
        let (out, err) = (
            Arc::new(std::sync::Mutex::new(Vec::new())),
            Arc::new(std::sync::Mutex::new(Vec::new())),
        );
        let client = ApiClient::new(&*mock);
        let run = stream_logs(
            &client,
            vec!["quiet".into(), "busy".into()],
            query(),
            false,
            Mode::Prefixed,
            ((Sink(out.clone()), false), (Sink(err), false)),
        );
        // The quiet stream never ends, so the command does not either; the busy line still arrives.
        let _ = tokio::time::timeout(Duration::from_millis(500), run).await;
        assert_eq!(text(&out.lock().unwrap()), "busy  | busy line\n");
    }

    #[tokio::test]
    async fn a_missing_app_fails_the_command_before_any_output() {
        let mock = mock_seen(|seen| {
            if app_of(&seen.path) == "gone" {
                not_found()
            } else {
                logs_reply(&[LogFrame::Stdout(b"line\n".to_vec()), LogFrame::End])
            }
        })
        .await;
        let (code, out, _) = drive(&mock, &["web", "gone"], false, Mode::Prefixed).await;
        assert_eq!(code.unwrap_err().kind, Kind::NotFound);
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn with_all_a_missing_app_is_noted_and_the_others_go_on() {
        let mock = mock_seen(|seen| {
            if app_of(&seen.path) == "gone" {
                not_found()
            } else {
                logs_reply(&[LogFrame::Stdout(b"line\n".to_vec()), LogFrame::End])
            }
        })
        .await;
        let (code, out, err) = drive(&mock, &["web", "gone"], true, Mode::Prefixed).await;
        assert_eq!(code.unwrap(), 0);
        assert_eq!(out, "web | line\n");
        assert!(err.contains("gone") && err.contains("skipped"), "{err}");
    }

    #[tokio::test]
    async fn with_all_nothing_left_after_skipping_ends_at_once() {
        let mock = mock_seen(|_| not_found()).await;
        let (code, out, err) = drive(&mock, &["gone"], true, Mode::Prefixed).await;
        assert_eq!(code.unwrap(), 0);
        assert!(out.is_empty() && err.contains("skipped"), "{err}");
    }

    #[tokio::test]
    async fn one_failing_stream_does_not_stop_the_other_but_fails_the_exit_code() {
        let mock = mock_seen(|seen| match app_of(&seen.path) {
            "bad" => logs_reply(&[
                LogFrame::Stdout(b"half".to_vec()),
                LogFrame::Error("podman went away".into()),
            ]),
            "cut" => Reply::chunks(200, frames(&[LogFrame::Stdout(b"x\n".to_vec())]))
                .content_type(LOGS_STREAM_CONTENT_TYPE)
                .fail_body(),
            _ => logs_reply(&[LogFrame::Stdout(b"fine\n".to_vec()), LogFrame::End]),
        })
        .await;
        let (code, out, err) = drive(&mock, &["good", "bad", "cut"], false, Mode::Prefixed).await;
        assert_eq!(code.unwrap(), exit::INTERNAL);
        assert!(
            out.contains("good | fine\n") && out.contains("bad  | half\n"),
            "{out}"
        );
        assert!(
            err.contains("bad: the daemon reported: podman went away"),
            "{err}"
        );
        assert!(err.contains("cut:"), "{err}");
    }

    #[tokio::test]
    async fn an_end_without_a_final_frame_is_a_failure() {
        let mock = mock_seen(|_| logs_reply(&[LogFrame::Stdout(b"x\n".to_vec())])).await;
        let (code, out, err) = drive(&mock, &["web"], false, Mode::Raw).await;
        assert_eq!(code.unwrap(), exit::INTERNAL);
        assert_eq!(out, "x\n");
        assert!(err.contains("without a final frame"), "{err}");
    }

    #[tokio::test]
    async fn token_expiry_reopens_with_since_and_no_tail() {
        let mock = mock_seen(|seen| {
            if seen.query.as_deref().is_some_and(|q| q.contains("since=")) {
                logs_reply(&[LogFrame::Stdout(b"after\n".to_vec()), LogFrame::End])
            } else {
                logs_reply(&[
                    LogFrame::Stdout(b"2026-10-31T10:00:00Z before\n".to_vec()),
                    LogFrame::TokenExpired,
                ])
            }
        })
        .await;
        let (code, out, _) = drive(&mock, &["web"], false, Mode::Raw).await;
        assert_eq!(code.unwrap(), 0);
        assert_eq!(out, "before\nafter\n");
        let seen = mock.seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].uri(), "/v1/apps/web/logs?tail=100&timestamps=true");
        let second = seen[1].uri();
        assert!(second.starts_with("/v1/apps/web/logs?since="), "{second}");
        assert!(!second.contains("tail"), "{second}");
    }

    #[tokio::test]
    async fn a_stream_that_only_expires_is_given_up() {
        let mock = mock_seen(|_| logs_reply(&[LogFrame::TokenExpired])).await;
        let (code, _, err) = drive(&mock, &["web"], false, Mode::Raw).await;
        assert_eq!(code.unwrap(), exit::INTERNAL);
        assert!(err.contains("keeps expiring"), "{err}");
        assert_eq!(
            mock.seen.lock().unwrap().len(),
            1 + MAX_QUIET_REOPENS as usize
        );
    }

    /// A mock whose first connection gives `first` and whose reopens give `after`; the requests are
    /// kept in `seen`.
    async fn expiring(
        first: Vec<LogFrame>,
        after: Vec<LogFrame>,
    ) -> weglarka_unix_http::testing::Mock {
        mock_seen(move |seen| {
            if seen.query.as_deref().is_some_and(|q| q.contains("since=")) {
                logs_reply(&after)
            } else {
                logs_reply(&first)
            }
        })
        .await
    }

    fn since_of(uri: &str) -> f64 {
        let q = uri.split_once('?').unwrap().1;
        let v = q
            .split('&')
            .find_map(|kv| kv.strip_prefix("since="))
            .unwrap();
        v.parse().unwrap()
    }

    #[tokio::test]
    async fn expiry_mid_history_resumes_at_the_last_line_not_at_the_clock() {
        let mock = expiring(
            vec![
                LogFrame::Stdout(b"2026-10-31T10:00:00Z old one\n".to_vec()),
                LogFrame::Stdout(b"2026-10-31T10:00:05.5+01:00 old two\n".to_vec()),
                LogFrame::TokenExpired,
            ],
            vec![LogFrame::End],
        )
        .await;
        let (code, out, _) = drive(&mock, &["web"], false, Mode::Raw).await;
        assert_eq!(code.unwrap(), 0);
        assert_eq!(out, "old one\nold two\n");
        let seen = mock.seen.lock().unwrap();
        // 09:00:05.5Z minus the overlap.
        let want = 1_793_437_205.5 - REOPEN_OVERLAP.as_secs_f64();
        assert!(
            (since_of(&seen[1].uri()) - want).abs() < 1e-6,
            "{}",
            seen[1].uri()
        );
        assert!(!seen[1].uri().contains("tail"));
    }

    #[tokio::test]
    async fn expiry_before_any_line_repeats_the_exact_query() {
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let mock = mock_seen(move |_| {
            if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                logs_reply(&[LogFrame::TokenExpired])
            } else {
                logs_reply(&[LogFrame::End])
            }
        })
        .await;
        let (code, _, _) = drive(&mock, &["web"], false, Mode::Raw).await;
        assert_eq!(code.unwrap(), 0);
        let seen = mock.seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].uri(), seen[1].uri());
        assert_eq!(seen[1].uri(), "/v1/apps/web/logs?tail=100&timestamps=true");
    }

    #[tokio::test]
    async fn the_prefix_is_stripped_unless_timestamps_were_asked_for() {
        let frames = vec![
            LogFrame::Stdout(b"2026-10-31T10:00:00Z hello wor".to_vec()),
            LogFrame::Stdout(b"ld\n2026-10-31T10:00:01".to_vec()),
            LogFrame::Stdout(b"Z second\n".to_vec()),
            LogFrame::End,
        ];
        let mock = mock_seen(move |_| logs_reply(&frames)).await;
        let (_, out, _) = drive(&mock, &["web"], false, Mode::Raw).await;
        assert_eq!(out, "hello world\nsecond\n");

        let frames = vec![
            LogFrame::Stdout(b"2026-10-31T10:00:00Z hello\n".to_vec()),
            LogFrame::End,
        ];
        let mock = mock_seen(move |_| logs_reply(&frames)).await;
        let out = Arc::new(std::sync::Mutex::new(Vec::new()));
        let q = LogsQuery {
            timestamps: true,
            ..query()
        };
        stream_logs(
            &ApiClient::new(&*mock),
            vec!["web".into()],
            q,
            false,
            Mode::Raw,
            (
                (Sink(out.clone()), false),
                (Sink(Default::default()), false),
            ),
        )
        .await
        .unwrap();
        assert_eq!(text(&out.lock().unwrap()), "2026-10-31T10:00:00Z hello\n");
    }

    #[tokio::test]
    async fn an_unparseable_timestamp_never_moves_since_forward() {
        let mock = expiring(
            vec![
                LogFrame::Stdout(b"2026-10-31T10:00:00Z good\n".to_vec()),
                LogFrame::Stdout(b"2099-13-45T99:00:00Z bad\n".to_vec()),
                LogFrame::Stdout(b"no stamp at all\n".to_vec()),
                LogFrame::TokenExpired,
            ],
            vec![LogFrame::End],
        )
        .await;
        let (_, out, _) = drive(&mock, &["web"], false, Mode::Raw).await;
        assert_eq!(out, "good\n2099-13-45T99:00:00Z bad\nno stamp at all\n");
        let seen = mock.seen.lock().unwrap();
        let want = 1_793_440_800.0 - REOPEN_OVERLAP.as_secs_f64();
        assert!(
            (since_of(&seen[1].uri()) - want).abs() < 1e-6,
            "{}",
            seen[1].uri()
        );
    }

    struct Broken;

    impl AsyncWrite for Broken {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn a_closed_stdout_ends_the_command_quietly() {
        let mock =
            mock_seen(|_| logs_reply(&[LogFrame::Stdout(b"x\n".to_vec()), LogFrame::End])).await;
        let err = Arc::new(std::sync::Mutex::new(Vec::new()));
        let code = stream_logs(
            &ApiClient::new(&*mock),
            vec!["web".into()],
            query(),
            false,
            Mode::Raw,
            ((Broken, false), (Sink(err.clone()), false)),
        )
        .await;
        assert_eq!(code.unwrap(), 0);
        assert!(err.lock().unwrap().is_empty());
    }

    #[test]
    fn only_quick_expiries_count_towards_giving_up() {
        let quick = Duration::from_millis(5);
        let mut n = 0;
        for _ in 0..MAX_QUIET_REOPENS {
            n = count_reopen(n, quick).unwrap();
        }
        assert_eq!(count_reopen(n, quick), None);
        // A quiet stream that lives past the threshold each time is reopened without end.
        let mut n = 0;
        for _ in 0..MAX_QUIET_REOPENS * 10 {
            n = count_reopen(n, STABLE_FOR).unwrap();
        }
        assert_eq!(n, 1);
        // A stable stretch resets an earlier run of quick ones.
        let n = count_reopen(MAX_QUIET_REOPENS, STABLE_FOR).unwrap();
        assert_eq!(n, 1);
    }

    #[tokio::test]
    async fn a_success_that_is_not_a_logs_stream_is_refused() {
        let mock = mock_seen(|_| Reply::new(200, "{}").content_type("application/json")).await;
        let err = ApiClient::new(&*mock)
            .open_logs("web", &query())
            .await
            .err()
            .unwrap();
        assert_eq!(err.kind, Kind::Internal);
    }
}
