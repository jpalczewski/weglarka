//! `weglarka run <app> [flags] -- <command…>` (issue #106): a one-off container with the app's image,
//! env, secrets, volumes, configs and networks. Its output is streamed as it is produced, and the
//! command's exit code becomes the CLI's.

use std::collections::BTreeMap;
use std::time::Duration;

use clap::Args;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use weglarka_api::{RunFrame, RunRequest};

use crate::cli::parse_pair;
use crate::commands::{client, instance};
use crate::error::CliError;
use crate::settings::Overrides;

/// What `weglarka run` exits with when the daemon killed the command after `--timeout` (the code
/// `timeout(1)` uses).
pub const EXIT_TIMED_OUT: i32 = 124;

/// Flags of `run`. The command goes after `--`, so its own flags are never taken for ours.
#[derive(Debug, Args)]
#[command(after_long_help = "\
The exit code is the command's own, so it can collide with Węglarka's (3 = not found, 4 = conflict…):
errors before the command starts are printed on stderr; use --json to tell the two apart.
A command killed by --timeout exits with 124.

Examples:
  weglarka run ntfy -- ntfy user list
  weglarka run gitea --env LOG_LEVEL=debug -- gitea admin user list
  weglarka run gitea --entrypoint /bin/sh -- -c 'ls /data'")]
pub struct RunArgs {
    /// Instance name.
    pub name: String,
    /// Environment variable KEY=VALUE for this run only (repeatable); wins over the app's own.
    #[arg(short = 'e', long = "env", value_name = "K=V", value_parser = parse_pair)]
    pub env: Vec<(String, String)>,
    /// Replace the image's entrypoint with this executable; the words after `--` become its arguments.
    #[arg(long, value_name = "PATH")]
    pub entrypoint: Option<String>,
    /// Kill the command after this long: seconds, or a number with `s`, `m` or `h` (`90`, `10m`, `2h`).
    /// Default and maximum: 24 hours.
    #[arg(long, value_name = "DURATION", value_parser = parse_timeout)]
    pub timeout: Option<Duration>,
    /// The command: arguments to the image's entrypoint, or to --entrypoint.
    #[arg(last = true, value_name = "COMMAND")]
    pub command: Vec<String>,
}

/// `90`, `90s`, `10m`, `2h` → a duration of at least one second.
pub(crate) fn parse_timeout(raw: &str) -> Result<Duration, String> {
    let bad = || format!("expected a duration such as 90, 90s, 10m or 2h, got {raw:?}");
    let (digits, unit) = match raw.char_indices().last() {
        Some((i, c @ ('s' | 'm' | 'h'))) => (&raw[..i], c),
        Some(_) => (raw, 's'),
        None => return Err(bad()),
    };
    let n: u64 = digits.parse().map_err(|_| bad())?;
    let secs = n
        .checked_mul(match unit {
            'm' => 60,
            'h' => 3600,
            _ => 1,
        })
        .ok_or_else(bad)?;
    if secs == 0 {
        return Err("a timeout must be at least one second".into());
    }
    Ok(Duration::from_secs(secs))
}

impl RunArgs {
    pub(crate) fn request(&self) -> Result<RunRequest, CliError> {
        if self.command.is_empty() && self.entrypoint.is_none() {
            return Err(CliError::usage("nothing to run").with_hint(
                "put the command after `--`, e.g. `weglarka run ntfy -- ntfy user list`",
            ));
        }
        let timeout_secs = self
            .timeout
            .map(|t| {
                u32::try_from(t.as_secs())
                    .map_err(|_| CliError::usage("--timeout is longer than 24 hours"))
            })
            .transpose()?;
        Ok(RunRequest {
            command: self.command.clone(),
            entrypoint: self.entrypoint.clone().map(|e| vec![e]),
            env: self.env.iter().cloned().collect::<BTreeMap<_, _>>(),
            timeout_secs,
        })
    }
}

/// How a run ended, from the CLI's point of view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Ending {
    Exited(i32),
    TimedOut,
}

/// Writes frames as they arrive: the command's stdout and stderr to ours (or, with `--json`, as JSON
/// lines), and remembers how the run ended.
pub(crate) struct Printer<O, E> {
    json: bool,
    out: O,
    err: E,
    ending: Option<Ending>,
}

impl<O: AsyncWrite + Unpin, E: AsyncWrite + Unpin> Printer<O, E> {
    pub(crate) fn new(json: bool, out: O, err: E) -> Self {
        Self {
            json,
            out,
            err,
            ending: None,
        }
    }

    pub(crate) async fn frame(&mut self, frame: RunFrame) -> Result<(), CliError> {
        let io = |e: std::io::Error| CliError::internal(format!("cannot write the output: {e}"));
        match frame {
            RunFrame::Stdout(data) if self.json => self.line("stdout", &data).await?,
            RunFrame::Stderr(data) if self.json => self.line("stderr", &data).await?,
            RunFrame::Stdout(data) => {
                self.out.write_all(&data).await.map_err(io)?;
                self.out.flush().await.map_err(io)?;
            }
            RunFrame::Stderr(data) => {
                self.err.write_all(&data).await.map_err(io)?;
                self.err.flush().await.map_err(io)?;
            }
            RunFrame::Exit(code) => {
                if self.json {
                    self.json_line(&serde_json::json!({ "exit_code": code }))
                        .await?;
                }
                self.ending = Some(Ending::Exited(code));
            }
            RunFrame::TimedOut => {
                if self.json {
                    self.json_line(&serde_json::json!({ "timed_out": true }))
                        .await?;
                }
                self.ending = Some(Ending::TimedOut);
            }
            RunFrame::Error(message) => {
                return Err(CliError::internal(format!("run failed: {message}")));
            }
        }
        Ok(())
    }

    /// Output is bytes; JSON strings are text, so non-UTF-8 is replaced (use the plain mode for
    /// binary output).
    async fn line(&mut self, stream: &str, data: &[u8]) -> Result<(), CliError> {
        self.json_line(&serde_json::json!({
            "stream": stream,
            "data": String::from_utf8_lossy(data),
        }))
        .await
    }

    async fn json_line(&mut self, value: &serde_json::Value) -> Result<(), CliError> {
        let io = |e: std::io::Error| CliError::internal(format!("cannot write the output: {e}"));
        let mut line = value.to_string();
        line.push('\n');
        self.out.write_all(line.as_bytes()).await.map_err(io)?;
        self.out.flush().await.map_err(io)
    }

    /// The stream is over: the ending, or an error when it stopped before the final frame.
    pub(crate) fn finish(self) -> Result<i32, CliError> {
        match self.ending {
            Some(Ending::Exited(code)) => Ok(code),
            Some(Ending::TimedOut) => Ok(EXIT_TIMED_OUT),
            None => Err(CliError::internal(
                "the daemon closed the connection before the command finished",
            )
            .with_hint("the one-off container was removed; check the daemon's log")),
        }
    }
}

pub async fn run(json: bool, o: &Overrides, a: RunArgs) -> Result<i32, CliError> {
    let name = instance(&a.name)?;
    let request = a.request()?;
    let mut printer = Printer::new(json, tokio::io::stdout(), tokio::io::stderr());
    let mut stream = client(o)?.open_run(name.as_str(), &request).await?;
    while let Some(frame) = stream.next().await? {
        printer.frame(frame).await?;
    }
    let code = printer.finish()?;
    // A process killed by a signal reports 128 + n; anything else fits a byte already, but `exit`
    // truncates to 8 bits, so keep what the shell will see.
    Ok(code & 0xff)
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    use clap::Parser as _;
    use http_body_util::BodyExt;
    use hyper::body::{Bytes, Incoming};
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;
    use weglarka_api::{ApiError, ErrorCode, RUN_STREAM_CONTENT_TYPE};

    use super::*;
    use crate::client::ApiClient;
    use crate::error::Kind;

    #[derive(Debug, clap::Parser)]
    struct W {
        #[command(flatten)]
        a: RunArgs,
    }

    fn parse(argv: &[&str]) -> RunArgs {
        W::try_parse_from(argv).unwrap().a
    }

    #[test]
    fn timeouts_take_seconds_or_a_unit_and_reject_nonsense() {
        assert_eq!(parse_timeout("90"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_timeout("90s"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_timeout("10m"), Ok(Duration::from_secs(600)));
        assert_eq!(parse_timeout("2h"), Ok(Duration::from_secs(7200)));
        for bad in [
            "",
            "m",
            "-5",
            "1.5h",
            "10d",
            "0",
            "0m",
            "99999999999999999999h",
        ] {
            assert!(parse_timeout(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn everything_after_the_double_dash_is_the_command() {
        let a = parse(&[
            "run",
            "gitea",
            "-e",
            "A=1",
            "--env",
            "B=",
            "--entrypoint",
            "/bin/sh",
            "--timeout",
            "10m",
            "--",
            "-c",
            "ls --all",
            "--env=not-ours",
        ]);
        let req = a.request().unwrap();
        assert_eq!(a.name, "gitea");
        assert_eq!(req.command, ["-c", "ls --all", "--env=not-ours"]);
        assert_eq!(req.entrypoint, Some(vec!["/bin/sh".to_owned()]));
        assert_eq!(
            req.env,
            BTreeMap::from([("A".into(), "1".into()), ("B".into(), String::new())])
        );
        assert_eq!(req.timeout_secs, Some(600));
        // Without `--`, nothing to run (unless an entrypoint is given).
        let err = parse(&["run", "gitea"]).request().unwrap_err();
        assert_eq!(err.kind, Kind::Usage);
        assert!(
            parse(&["run", "gitea", "--entrypoint", "/bin/true"])
                .request()
                .is_ok()
        );
        assert!(W::try_parse_from(["run", "gitea", "-e", "NOEQUALS", "--", "x"]).is_err());
    }

    async fn drive(json: bool, frames: Vec<RunFrame>) -> (Result<i32, CliError>, String, String) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut printer = Printer::new(json, &mut out, &mut err);
        for frame in frames {
            if let Err(e) = printer.frame(frame).await {
                return (Err(e), String::new(), String::new());
            }
        }
        let code = printer.finish();
        (
            code,
            String::from_utf8_lossy(&out).into_owned(),
            String::from_utf8_lossy(&err).into_owned(),
        )
    }

    #[tokio::test]
    async fn output_goes_to_the_matching_stream_and_the_exit_code_is_the_commands() {
        let (code, out, err) = drive(
            false,
            vec![
                RunFrame::Stdout(b"rows: 3\n".to_vec()),
                RunFrame::Stderr(b"warn\n".to_vec()),
                RunFrame::Exit(7),
            ],
        )
        .await;
        assert_eq!(
            (code.unwrap(), out.as_str(), err.as_str()),
            (7, "rows: 3\n", "warn\n")
        );

        let (code, ..) = drive(false, vec![RunFrame::TimedOut]).await;
        assert_eq!(code.unwrap(), EXIT_TIMED_OUT);
    }

    #[tokio::test]
    async fn a_stream_without_an_ending_or_with_an_error_frame_is_an_error() {
        let (code, ..) = drive(false, vec![RunFrame::Stdout(b"partial".to_vec())]).await;
        assert_eq!(code.unwrap_err().kind, Kind::Internal);
        let (code, ..) = drive(
            false,
            vec![RunFrame::Error("cannot start container".into())],
        )
        .await;
        let err = code.unwrap_err();
        assert!(err.to_string().contains("cannot start container"), "{err}");
    }

    #[tokio::test]
    async fn json_mode_prints_one_object_per_line_and_never_raw_output() {
        let (code, out, err) = drive(
            true,
            vec![
                RunFrame::Stdout(b"hi\n".to_vec()),
                RunFrame::Stderr(b"oops".to_vec()),
                RunFrame::Exit(0),
            ],
        )
        .await;
        assert_eq!(code.unwrap(), 0);
        assert!(err.is_empty());
        let lines: Vec<serde_json::Value> = out
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(
            lines,
            [
                serde_json::json!({"stream": "stdout", "data": "hi\n"}),
                serde_json::json!({"stream": "stderr", "data": "oops"}),
                serde_json::json!({"exit_code": 0}),
            ]
        );
    }

    /// A one-route server: answers `POST /v1/apps/*/run` with `status`, `content_type` and the
    /// `chunks` as separate body frames (so the client must reassemble frames cut anywhere).
    async fn serve(status: u16, content_type: &'static str, chunks: Vec<Vec<u8>>) -> PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let socket = std::env::temp_dir().join(format!(
            "wgl-run-{}-{}.sock",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&socket);
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let svc = service_fn(move |req: Request<Incoming>| {
                let chunks = chunks.clone();
                async move {
                    assert_eq!(req.method(), "POST");
                    assert_eq!(req.uri().path(), "/v1/apps/ntfy/run");
                    let sent = req.into_body().collect().await.unwrap().to_bytes();
                    assert!(serde_json::from_slice::<RunRequest>(&sent).is_ok());
                    let frames = chunks
                        .into_iter()
                        .map(|c| Ok::<_, Infallible>(hyper::body::Frame::data(Bytes::from(c))));
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(status)
                            .header("content-type", content_type)
                            .body(http_body_util::StreamBody::new(futures_util::stream::iter(
                                frames,
                            )))
                            .unwrap(),
                    )
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), svc)
                .await;
        });
        socket
    }

    fn request() -> RunRequest {
        RunRequest {
            command: vec!["true".into()],
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn the_client_reassembles_frames_the_network_cut_in_pieces() {
        let bytes: Vec<u8> = [RunFrame::Stdout(b"hello\n".to_vec()), RunFrame::Exit(3)]
            .iter()
            .flat_map(RunFrame::encode)
            .collect();
        let pieces = bytes.chunks(4).map(<[u8]>::to_vec).collect();
        let socket = serve(200, RUN_STREAM_CONTENT_TYPE, pieces).await;
        let mut stream = ApiClient::new(&socket)
            .open_run("ntfy", &request())
            .await
            .unwrap();
        assert_eq!(
            stream.next().await.unwrap(),
            Some(RunFrame::Stdout(b"hello\n".to_vec()))
        );
        assert_eq!(stream.next().await.unwrap(), Some(RunFrame::Exit(3)));
        assert_eq!(stream.next().await.unwrap(), None);
        let _ = std::fs::remove_file(&socket);
    }

    #[tokio::test]
    async fn a_stream_cut_inside_a_frame_is_an_error() {
        let mut bytes = RunFrame::Stdout(b"hello".to_vec()).encode();
        bytes.truncate(bytes.len() - 2);
        let socket = serve(200, RUN_STREAM_CONTENT_TYPE, vec![bytes]).await;
        let mut stream = ApiClient::new(&socket)
            .open_run("ntfy", &request())
            .await
            .unwrap();
        assert_eq!(stream.next().await.unwrap_err().kind, Kind::Internal);
        let _ = std::fs::remove_file(&socket);
    }

    #[tokio::test]
    async fn an_error_before_the_stream_keeps_its_api_kind() {
        let body = serde_json::to_vec(&ApiError {
            code: ErrorCode::Conflict,
            message: "app ntfy has no deployed image yet".into(),
        })
        .unwrap();
        let socket = serve(409, "application/json", vec![body]).await;
        let err = ApiClient::new(&socket)
            .open_run("ntfy", &request())
            .await
            .err()
            .unwrap();
        assert_eq!(err.kind, Kind::Conflict);
        let _ = std::fs::remove_file(&socket);
    }

    #[tokio::test]
    async fn a_success_that_is_not_a_run_stream_is_refused() {
        let socket = serve(200, "application/json", vec![b"{}".to_vec()]).await;
        let err = ApiClient::new(&socket)
            .open_run("ntfy", &request())
            .await
            .err()
            .unwrap();
        assert_eq!(err.kind, Kind::Internal);
        let _ = std::fs::remove_file(&socket);
    }
}
