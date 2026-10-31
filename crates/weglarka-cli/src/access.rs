//! `weglarka access <app>`: the requests that reached an app through its domains
//! (`GET /v1/apps/{name}/access`, docs/decisions/0063), the second view next to `weglarka logs`.
//!
//! The daemon filters the ingress log down to one app; this side only prints. A request's path, host
//! and user agent are chosen by whoever made the request, so on a terminal they go through the same
//! sanitising as log lines, and in the text form they can never start a line of their own.

use std::io::IsTerminal;
use std::time::{Duration, Instant, SystemTime};

use clap::Args;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use weglarka_api::{AccessEntry, AccessFrame, AccessQuery, MAX_ACCESS_TAIL};

use crate::client::ApiClient;
use crate::commands::{client, instance};
use crate::error::{CliError, exit};
use crate::logs::{count_reopen, parse_rfc3339, sanitize_for_terminal, since_epoch};
use crate::run::parse_timeout;
use crate::settings::Overrides;

/// `--tail` when neither `--tail` nor `--since` is given.
const DEFAULT_TAIL: u32 = 100;

#[derive(Debug, Args)]
#[command(after_help = "\
Examples:
  weglarka access ntfy -f
  weglarka access web --since 10m --status 5xx
  weglarka access web -n 20 --path /api --method POST
  weglarka --json access web -f | jq -r .remote_addr")]
pub struct AccessArgs {
    /// Instance name.
    #[arg(value_name = "APP")]
    pub app: String,
    /// Keep the stream open and print new requests as they arrive.
    #[arg(short = 'f', long)]
    pub follow: bool,
    /// Only the last N matching requests (at most 1000). Default 100; with --since, no limit.
    #[arg(short = 'n', long, value_name = "N", value_parser = clap::value_parser!(u32).range(0..=i64::from(MAX_ACCESS_TAIL)))]
    pub tail: Option<u32>,
    /// Only requests newer than this: seconds, or a number with `s`, `m` or `h`. Default: the last hour.
    #[arg(long, value_name = "DURATION", value_parser = parse_timeout)]
    pub since: Option<Duration>,
    /// Only this status (`404`) or class (`5xx`).
    #[arg(long, value_name = "404|5xx", value_parser = |v: &str| filter("status", v))]
    pub status: Option<String>,
    /// Only this method (`GET`, `POST`, …).
    #[arg(long, value_name = "METHOD", value_parser = |v: &str| filter("method", &v.to_ascii_uppercase()))]
    pub method: Option<String>,
    /// Only paths starting with this prefix (letters, digits and `_.-/`; no query string, no `%`).
    #[arg(long, value_name = "PREFIX", value_parser = |v: &str| filter("path", v))]
    pub path: Option<String>,
    /// Only requests to this domain. Not `--host`: that is the global flag naming the panel.
    #[arg(long, value_name = "DOMAIN", value_parser = |v: &str| filter("host", &v.to_ascii_lowercase()))]
    pub domain: Option<String>,
}

/// Checks one filter value with the daemon's own parser, so a bad value is a usage error here and not
/// a `400` later. A `&` would smuggle in a second parameter that the single-key parse then accepts.
fn filter(key: &str, value: &str) -> Result<String, String> {
    if value.contains('&') {
        return Err(format!("`{key}` must not contain `&`"));
    }
    AccessQuery::parse(Some(&format!("{key}={value}"))).map(|_| value.to_owned())
}

impl AccessArgs {
    /// The query of the first request; `now` anchors `--since`.
    pub(crate) fn query(&self, now: SystemTime) -> Result<AccessQuery, CliError> {
        let tail = match (self.tail, self.since) {
            (Some(n), _) => Some(n),
            (None, Some(_)) => None,
            (None, None) => Some(DEFAULT_TAIL),
        };
        let mut raw = AccessQuery {
            follow: self.follow,
            tail,
            since: self.since.map(|ago| since_epoch(now.checked_sub(ago))),
            ..Default::default()
        }
        .to_query_string();
        for (key, value) in [
            ("status", &self.status),
            ("method", &self.method),
            ("path", &self.path),
            ("host", &self.domain),
        ] {
            if let Some(value) = value {
                raw.push_str(&format!("&{key}={value}"));
            }
        }
        // The same parser the daemon applies: a value clap let through that it refuses is a bug here.
        AccessQuery::parse(Some(&raw)).map_err(CliError::usage)
    }
}

/// A field of untrusted text for the one-line form: sanitised for a terminal, and never able to end
/// the line (a decoded `%0a` in `$uri` is a real newline).
fn field(text: &str, terminal: bool) -> String {
    String::from_utf8_lossy(&sanitize_for_terminal(text.as_bytes(), terminal))
        .chars()
        .map(|c| {
            if matches!(c, '\n' | '\r' | '\t') {
                '\u{FFFD}'
            } else {
                c
            }
        })
        .collect()
}

/// `time status method host path request_time remote_addr request_id`
fn text_line(entry: &AccessEntry, terminal: bool) -> String {
    let f = |s: &str| field(s, terminal);
    format!(
        "{} {} {} {} {} {:.3}s {} {}\n",
        f(&entry.time),
        entry.status,
        f(&entry.method),
        f(&entry.host),
        f(&entry.path),
        entry.request_time,
        f(&entry.remote_addr),
        f(&entry.request_id),
    )
}

/// The entry as one JSON line; on a terminal every string goes through the sanitiser (JSON escapes C0
/// only, and C1 or bidi controls would still reach the terminal).
fn json_line(entry: &AccessEntry, terminal: bool) -> String {
    let clean = |s: &str| {
        String::from_utf8_lossy(&sanitize_for_terminal(s.as_bytes(), terminal)).into_owned()
    };
    let entry = AccessEntry {
        time: clean(&entry.time),
        host: clean(&entry.host),
        remote_addr: clean(&entry.remote_addr),
        peer: entry.peer.as_deref().map(clean),
        method: clean(&entry.method),
        path: clean(&entry.path),
        upstream_response_time: clean(&entry.upstream_response_time),
        request_id: clean(&entry.request_id),
        user_agent: clean(&entry.user_agent),
        ..entry.clone()
    };
    let mut line = serde_json::to_string(&entry).expect("an AccessEntry serialises");
    line.push('\n');
    line
}

/// The query that continues a stream whose token expired. Before any entry arrived nothing was
/// printed, so the original query is repeated whole (`tail` and `since` included: the history read, or
/// its ring, may still have been running). Afterwards: from the second of the last entry (`since` is
/// inclusive, so no overlap is needed) without `tail`. An entry time that does not parse leaves the
/// resume point where it was, so the failure is repeated lines, never a gap.
fn resume_query(query: &AccessQuery, resume: Option<Duration>, received_any: bool) -> AccessQuery {
    if !received_any {
        return query.clone();
    }
    AccessQuery {
        tail: None,
        since: resume.or(query.since),
        ..query.clone()
    }
}

/// Prints the app's access stream until it ends. A token that expires reopens the stream from the
/// last request; one that does so in a tight loop is given up.
pub(crate) async fn stream_access<O: AsyncWrite + Unpin>(
    client: &ApiClient,
    name: &str,
    query: AccessQuery,
    json: bool,
    (mut out, terminal): (O, bool),
) -> Result<i32, CliError> {
    let io = |e: std::io::Error| CliError::internal(format!("cannot write the output: {e}"));
    let mut stream = client.open_access(name, &query).await?;
    let mut resume: Option<Duration> = None;
    let mut received_any = false;
    let mut opened = Instant::now();
    let mut quiet_reopens = 0;
    loop {
        match stream.next().await? {
            Some(AccessFrame::Entry(entry)) => {
                received_any = true;
                // An nginx `$time_iso8601`, floored to the second; unparseable leaves `resume` alone.
                if let Some(at) = parse_rfc3339(entry.time.as_bytes()) {
                    resume = Some(Duration::from_secs(at.as_secs()));
                }
                quiet_reopens = 0;
                let line = if json {
                    json_line(&entry, terminal)
                } else {
                    text_line(&entry, terminal)
                };
                let written = async {
                    out.write_all(line.as_bytes()).await?;
                    out.flush().await
                }
                .await;
                match written {
                    Ok(()) => {}
                    // `| head`: the reader is gone, which is how this command is meant to end.
                    Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => return Ok(exit::OK),
                    Err(e) => return Err(io(e)),
                }
            }
            Some(AccessFrame::End) => return Ok(exit::OK),
            Some(AccessFrame::TokenExpired) => {
                quiet_reopens = count_reopen(quiet_reopens, opened.elapsed()).ok_or_else(|| {
                    CliError::internal("the stream keeps expiring without output")
                })?;
                let again = resume_query(&query, resume, received_any);
                stream = client.open_access(name, &again).await.map_err(|mut e| {
                    e.message = format!("cannot reopen the stream: {}", e.message);
                    e
                })?;
                opened = Instant::now();
            }
            Some(AccessFrame::Error(message)) => {
                return Err(CliError::internal(format!(
                    "the daemon reported: {}",
                    field(&message, true)
                )));
            }
            None => {
                return Err(CliError::internal("the stream ended without a final frame"));
            }
        }
    }
}

pub async fn run(json: bool, o: &Overrides, a: AccessArgs) -> Result<i32, CliError> {
    let name = instance(&a.app)?.as_str().to_owned();
    let query = a.query(SystemTime::now())?;
    let client = client(o)?;
    let out = (tokio::io::stdout(), std::io::stdout().is_terminal());
    stream_access(&client, &name, query, json, out).await
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use clap::Parser as _;
    use hyper::body::Bytes;
    use weglarka_api::{ACCESS_STREAM_CONTENT_TYPE, StatusFilter};
    use weglarka_unix_http::testing::{Reply, mock_seen};

    use super::*;
    use crate::cli::{Cli, Command};
    use crate::error::Kind;
    use crate::logs::MAX_QUIET_REOPENS;

    #[derive(Debug, clap::Parser)]
    struct W {
        #[command(flatten)]
        a: AccessArgs,
    }

    fn parse(argv: &[&str]) -> Result<AccessArgs, clap::Error> {
        W::try_parse_from(std::iter::once("access").chain(argv.iter().copied())).map(|w| w.a)
    }

    fn now() -> SystemTime {
        std::time::UNIX_EPOCH + Duration::from_secs(1_000_000)
    }

    fn entry(path: &str) -> AccessEntry {
        AccessEntry {
            time: "2026-10-31T12:00:00+00:00".into(),
            host: "web.example.com".into(),
            remote_addr: "203.0.113.7".into(),
            method: "GET".into(),
            path: path.into(),
            status: 404,
            request_time: 0.0125,
            request_id: "abc".into(),
            user_agent: "curl/8".into(),
            ..Default::default()
        }
    }

    // ---- arguments

    #[test]
    fn the_query_follows_from_the_flags() {
        let q = parse(&["web"]).unwrap().query(now()).unwrap();
        assert_eq!(q.to_query_string(), "tail=100");
        let q = parse(&["web", "--since", "10m"])
            .unwrap()
            .query(now())
            .unwrap();
        assert_eq!(q.tail, None);
        assert_eq!(q.since, Some(Duration::from_secs(1_000_000 - 600)));
        let q = parse(&[
            "web",
            "-f",
            "-n",
            "5",
            "--status",
            "5xx",
            "--method",
            "post",
            "--path",
            "/api",
            "--domain",
            "Web.Example.com",
        ])
        .unwrap()
        .query(now())
        .unwrap();
        assert_eq!(
            q.to_query_string(),
            "follow=true&tail=5&status=5xx&method=POST&path=/api&host=web.example.com"
        );
        assert_eq!(q.status, Some(StatusFilter::Class(5)));
    }

    #[test]
    fn bad_flags_are_usage_errors() {
        for argv in [
            &["web", "-n", "1001"][..],
            &["web", "-n", "-1"],
            &["web", "--since", "0"],
            &["web", "--status", "6xx"],
            &["web", "--status", "404&host=x"],
            &["web", "--path", "api"],
            &["web", "--path", "/a&host=other.example.com"],
            &["web", "--path", "/a%2fb"],
            &["web", "--method", "GE T"],
            &["web", "--domain", "a b"],
            &[],
            &["web", "api"],
        ] {
            assert!(parse(argv).is_err(), "{argv:?}");
        }
        assert!(parse(&["web", "-n", "1000", "--status", "404"]).is_ok());
        assert_eq!(instance("Web!").unwrap_err().kind, Kind::Usage);
    }

    /// The whole command line, with the global `--host` that names the panel next to the filter.
    #[test]
    fn the_panel_address_and_the_domain_filter_are_separate() {
        let panel = "https://panel.example.com";
        for argv in [
            &[
                "weglarka",
                "--host",
                panel,
                "access",
                "web",
                "--domain",
                "web.example.com",
            ][..],
            &[
                "weglarka",
                "access",
                "web",
                "--domain",
                "web.example.com",
                "--host",
                panel,
            ],
        ] {
            let cli = Cli::try_parse_from(argv).unwrap();
            assert_eq!(cli.host.as_deref(), Some(panel), "{argv:?}");
            let Command::Access(a) = cli.command else {
                panic!("{argv:?}")
            };
            let q = a.query(now()).unwrap();
            assert_eq!(q.host.as_deref(), Some("web.example.com"), "{argv:?}");
        }
        let Command::Access(a) =
            Cli::try_parse_from(["weglarka", "--host", panel, "access", "web"])
                .unwrap()
                .command
        else {
            panic!()
        };
        assert_eq!(a.query(now()).unwrap().host, None);
    }

    // ---- resuming

    #[test]
    fn log_times_are_parsed_with_their_offset() {
        let parse_log_time = |t: &str| parse_rfc3339(t.as_bytes()).map(|d| d.as_secs());
        assert_eq!(parse_log_time("1970-01-01T00:00:00+00:00"), Some(0));
        assert_eq!(
            parse_log_time("2026-10-31T12:00:00+00:00"),
            Some(1_793_448_000)
        );
        assert_eq!(parse_log_time("2026-10-31T12:00:00Z"), Some(1_793_448_000));
        assert_eq!(
            parse_log_time("2026-10-31T13:30:00+01:30"),
            Some(1_793_448_000)
        );
        assert_eq!(
            parse_log_time("2026-10-31T07:00:00-05:00"),
            Some(1_793_448_000)
        );
        // Leap day, and a date past the 2038 boundary.
        assert_eq!(
            parse_log_time("2024-02-29T00:00:00+00:00"),
            Some(1_709_164_800)
        );
        assert_eq!(
            parse_log_time("2100-03-01T00:00:00+00:00"),
            Some(4_107_542_400)
        );
        for bad in [
            "",
            "-",
            "2026-10-31",
            "2026-10-31 12:00:00+00:00",
            "2026-13-31T12:00:00+00:00",
            "2026-10-31T24:00:00+00:00",
            "2026-10-31T12:00:00",
            "2026-10-31T12:00:00+0000",
            "2026-10-31T12:00:00+25:00",
            "202a-10-31T12:00:00+00:00",
            "1969-12-31T00:00:00+00:00",
            "2026-10-31T12:00:00+00:00x",
        ] {
            assert_eq!(parse_log_time(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn resuming_never_leaves_a_gap() {
        let original =
            AccessQuery::parse(Some("follow=true&tail=100&since=1700000000&status=5xx")).unwrap();
        // Nothing received yet: exactly the original query, tail and since included.
        assert_eq!(resume_query(&original, None, false), original);
        // After entries: from the last entry's second, no tail, filters kept.
        let again = resume_query(&original, Some(Duration::from_secs(1_700_000_500)), true);
        assert_eq!(again.since, Some(Duration::from_secs(1_700_000_500)));
        assert_eq!(
            (again.tail, again.follow, again.status),
            (None, true, original.status)
        );
        // An unparseable time keeps the earlier resume point, or else the original since.
        assert_eq!(resume_query(&original, None, true).since, original.since);
        let open = AccessQuery::parse(Some("follow=true")).unwrap();
        assert_eq!(resume_query(&open, None, true).since, None);
    }

    // ---- output

    #[test]
    fn the_text_form_is_one_line_with_the_documented_fields() {
        assert_eq!(
            text_line(&entry("/missing"), false),
            "2026-10-31T12:00:00+00:00 404 GET web.example.com /missing 0.013s 203.0.113.7 abc\n"
        );
    }

    #[test]
    fn untrusted_fields_cannot_start_a_line_or_drive_a_terminal() {
        let evil = entry("/a\nFAKE 200 line\r\u{1b}[31m\u{202e}x\ty");
        for terminal in [false, true] {
            let line = text_line(&evil, terminal);
            assert_eq!(line.matches('\n').count(), 1, "{line:?}");
            assert!(!line.contains('\r') && !line.contains('\t'), "{line:?}");
        }
        let tty = text_line(&evil, true);
        assert!(
            !tty.contains('\u{1b}') && !tty.contains('\u{202e}'),
            "{tty:?}"
        );
        // Piped output keeps the bytes the operator may want to grep for, minus line breaks.
        assert!(text_line(&evil, false).contains('\u{1b}'));
    }

    #[test]
    fn json_lines_are_the_entry_and_sanitised_on_a_terminal() {
        let mut e = entry("/a\u{9b}31m\u{202e}");
        e.user_agent = "ua\u{1b}[2J".into();
        let piped: AccessEntry = serde_json::from_str(&json_line(&e, false)).unwrap();
        assert_eq!(piped, e);
        let line = json_line(&e, true);
        assert_eq!(line.matches('\n').count(), 1);
        let tty: AccessEntry = serde_json::from_str(&line).unwrap();
        assert_eq!(tty.path, "/a\u{fffd}31m\u{fffd}");
        assert_eq!(tty.user_agent, "ua\u{fffd}[2J");
        assert!(!line.contains("\"app\""));
    }

    // ---- against a mock daemon

    struct Sink(Arc<Mutex<Vec<u8>>>);

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

    fn reply(frames: &[AccessFrame]) -> Reply {
        Reply::chunks(
            200,
            frames
                .iter()
                .map(|f| Bytes::from(f.encode()))
                .collect::<Vec<_>>(),
        )
        .content_type(ACCESS_STREAM_CONTENT_TYPE)
    }

    fn q() -> AccessQuery {
        AccessQuery {
            tail: Some(100),
            ..Default::default()
        }
    }

    async fn drive(
        socket: &std::path::Path,
        query: AccessQuery,
        json: bool,
    ) -> (Result<i32, CliError>, String) {
        let out = Arc::new(Mutex::new(Vec::new()));
        let result = stream_access(
            &ApiClient::new(socket),
            "web",
            query,
            json,
            (Sink(out.clone()), false),
        )
        .await;
        (
            result,
            String::from_utf8_lossy(&out.lock().unwrap()).into_owned(),
        )
    }

    #[tokio::test]
    async fn entries_are_printed_and_the_request_carries_the_query() {
        let mock = mock_seen(|_| {
            reply(&[
                AccessFrame::Entry(entry("/a")),
                AccessFrame::Entry(entry("/b")),
                AccessFrame::End,
            ])
        })
        .await;
        let (code, out) = drive(&mock, q(), false).await;
        assert_eq!(code.unwrap(), 0);
        assert_eq!(out.lines().count(), 2);
        assert!(out.contains(" /a ") && out.contains(" /b "), "{out}");
        let (code, json) = drive(&mock, q(), true).await;
        assert_eq!(code.unwrap(), 0);
        let first: AccessEntry = serde_json::from_str(json.lines().next().unwrap()).unwrap();
        assert_eq!(first.path, "/a");
        assert_eq!(
            mock.seen.lock().unwrap()[0].uri(),
            "/v1/apps/web/access?tail=100"
        );
    }

    #[tokio::test]
    async fn token_expiry_reopens_with_since_and_no_tail_and_keeps_the_filters() {
        let mock = mock_seen(|seen| {
            if seen.query.as_deref().is_some_and(|q| q.contains("since=")) {
                reply(&[AccessFrame::Entry(entry("/after")), AccessFrame::End])
            } else {
                reply(&[
                    AccessFrame::Entry(entry("/before")),
                    AccessFrame::TokenExpired,
                ])
            }
        })
        .await;
        let query = AccessQuery::parse(Some("follow=true&tail=10&status=5xx")).unwrap();
        let (code, out) = drive(&mock, query, false).await;
        assert_eq!(code.unwrap(), 0);
        assert!(out.contains("/before") && out.contains("/after"), "{out}");
        let seen = mock.seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(
            seen[0].uri(),
            "/v1/apps/web/access?follow=true&tail=10&status=5xx"
        );
        let second = seen[1].uri();
        assert!(
            second.starts_with("/v1/apps/web/access?follow=true&since="),
            "{second}"
        );
        assert!(
            second.ends_with("&status=5xx") && !second.contains("tail"),
            "{second}"
        );
    }

    #[tokio::test]
    async fn a_stream_that_only_expires_is_given_up_but_a_quiet_stable_one_is_not() {
        let mock = mock_seen(|_| reply(&[AccessFrame::TokenExpired])).await;
        let (code, _) = drive(&mock, q(), false).await;
        let err = code.unwrap_err();
        assert!(err.message.contains("keeps expiring"), "{}", err.message);
        assert_eq!(
            mock.seen.lock().unwrap().len(),
            1 + MAX_QUIET_REOPENS as usize
        );
    }

    #[tokio::test]
    async fn daemon_errors_and_cut_streams_are_failures() {
        let mock = mock_seen(|_| {
            reply(&[
                AccessFrame::Entry(entry("/a")),
                AccessFrame::Error("podman went away".into()),
            ])
        })
        .await;
        let (code, out) = drive(&mock, q(), false).await;
        assert!(code.unwrap_err().message.contains("podman went away"));
        assert!(out.contains("/a"));
        let mock = mock_seen(|_| reply(&[AccessFrame::Entry(entry("/a"))])).await;
        let (code, _) = drive(&mock, q(), false).await;
        assert!(code.unwrap_err().message.contains("without a final frame"));
    }

    #[tokio::test]
    async fn an_api_error_before_the_stream_keeps_its_kind() {
        let mock = mock_seen(|_| {
            Reply::new(404, r#"{"code":"not_found","message":"unknown app: web"}"#)
                .content_type("application/json")
        })
        .await;
        let (code, out) = drive(&mock, q(), false).await;
        assert_eq!(code.unwrap_err().kind, Kind::NotFound);
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn an_older_daemon_without_the_route_gets_the_version_hint() {
        let mock = mock_seen(|_| Reply::new(404, "")).await;
        let (code, _) = drive(&mock, q(), false).await;
        let err = code.unwrap_err();
        assert!(
            err.hint
                .as_deref()
                .is_some_and(|h| h.contains("versions may differ")),
            "{err:?}"
        );
        let mock = mock_seen(|_| Reply::new(200, "{}").content_type("application/json")).await;
        let err = drive(&mock, q(), false).await.0.unwrap_err();
        assert!(
            err.hint
                .as_deref()
                .is_some_and(|h| h.contains("versions may differ"))
        );
    }

    #[tokio::test]
    async fn a_closed_stdout_ends_the_command_quietly() {
        let mock = mock_seen(|_| reply(&[AccessFrame::Entry(entry("/a")), AccessFrame::End])).await;
        let code = stream_access(&ApiClient::new(&*mock), "web", q(), false, (Broken, false)).await;
        assert_eq!(code.unwrap(), 0);
    }
}
