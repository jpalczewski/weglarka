//! `weglarka forward <app> <port>` (issue #108, ADR 0041): a temporary relay to a port of an app.
//!
//! The daemon starts a relay container published on a loopback port of the host and keeps it for as
//! long as this process holds the request open. With an SSH destination configured the CLI also runs
//! `ssh -L` to that port, so the app's port shows up on the laptop; Ctrl-C (or ssh dying) ends both.

use std::collections::VecDeque;
use std::process::Stdio;
use std::time::Duration;

use clap::Args;
use http_body_util::Full;
use hyper::Request;
use hyper::body::Bytes;
use hyper::header::CONTENT_TYPE;
use weglarka_api::{
    FORWARD_STREAM_CONTENT_TYPE, ForwardFrame, ForwardFrameDecoder, ForwardRequest, endpoints,
};
use weglarka_unix_http::StreamingResponse;

use crate::client::{ApiClient, method_str, request_path};
use crate::commands::{client, instance};
use crate::error::CliError;
use crate::run::parse_timeout;
use crate::settings::Overrides;
use crate::user_config::UserConfig;

/// Flags of `forward`.
#[derive(Debug, Args)]
#[command(after_long_help = "\
The SSH destination of the host comes from --ssh, else $WEGLARKA_SSH, else `ssh_host` in
$XDG_CONFIG_HOME/weglarka/cli.toml (default ~/.config/weglarka/cli.toml). Without one nothing is
tunnelled: the relay's loopback address on the host is printed and kept open until Ctrl-C.
Anyone who can log in to the host can reach that loopback port while the forward lives.

Examples:
  weglarka forward gitea 3000                  # localhost:3000 -> gitea's port 3000
  weglarka forward db 5432 --local-port 15432 --timeout 2h")]
pub struct ForwardArgs {
    /// Instance name.
    pub name: String,
    /// Port inside the app's container.
    #[arg(value_parser = clap::value_parser!(u16).range(1..))]
    pub port: u16,
    /// Port on this machine's loopback (default: the same as the app's port).
    #[arg(long, value_name = "PORT", value_parser = clap::value_parser!(u16).range(1..))]
    pub local_port: Option<u16>,
    /// SSH destination of the Węglarka host (`host`, `user@host` or an ssh_config alias).
    #[arg(long, value_name = "DESTINATION", env = "WEGLARKA_SSH")]
    pub ssh: Option<String>,
    /// End the forward after this long: seconds, or a number with `s`, `m` or `h`. Default and
    /// maximum: 24 hours.
    #[arg(long, value_name = "DURATION", value_parser = parse_timeout)]
    pub timeout: Option<Duration>,
}

impl ForwardArgs {
    fn request(&self) -> Result<ForwardRequest, CliError> {
        let timeout_secs = self
            .timeout
            .map(|t| {
                u32::try_from(t.as_secs())
                    .map_err(|_| CliError::usage("--timeout is longer than 24 hours"))
            })
            .transpose()?;
        Ok(ForwardRequest {
            port: self.port,
            timeout_secs,
        })
    }
}

/// An SSH destination ends up on a command line: no option lookalikes, no whitespace.
pub(crate) fn validate_ssh_destination(dest: &str) -> Result<(), CliError> {
    if dest.is_empty()
        || dest.starts_with('-')
        || dest.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(CliError::usage(format!("invalid SSH destination {dest:?}"))
            .with_hint("use `host`, `user@host` or a name from ~/.ssh/config"));
    }
    Ok(())
}

/// The arguments of the `ssh` process that carries `127.0.0.1:<local>` to the relay's host port.
pub(crate) fn ssh_args(destination: &str, local_port: u16, host_port: u16) -> Vec<String> {
    [
        "-N",
        "-T",
        "-o",
        "ExitOnForwardFailure=yes",
        "-o",
        "ServerAliveInterval=15",
        "-L",
    ]
    .into_iter()
    .map(str::to_owned)
    .chain([
        format!("127.0.0.1:{local_port}:127.0.0.1:{host_port}"),
        "--".to_owned(),
        destination.to_owned(),
    ])
    .collect()
}

/// The frames of a forward response, as they arrive.
pub(crate) struct ForwardStream {
    /// Keeps the connection's request side open for as long as the response is read.
    response: StreamingResponse<Full<Bytes>>,
    decoder: ForwardFrameDecoder,
    ready: VecDeque<ForwardFrame>,
}

impl ForwardStream {
    /// The next frame, or `None` when the daemon closed the stream.
    pub(crate) async fn next(&mut self) -> Result<Option<ForwardFrame>, CliError> {
        loop {
            if let Some(frame) = self.ready.pop_front() {
                return Ok(Some(frame));
            }
            let Some(chunk) = self.response.chunk().await else {
                return if self.decoder.is_clean() {
                    Ok(None)
                } else {
                    Err(CliError::internal("forward stream ended inside a frame"))
                };
            };
            let data = chunk
                .map_err(|e| CliError::internal(format!("forward stream interrupted: {e}")))?;
            self.ready.extend(
                self.decoder
                    .push(&data)
                    .map_err(|e| CliError::internal(e.to_string()))?,
            );
        }
    }
}

impl ApiClient {
    /// `POST /v1/apps/{name}/forward`: opens the response stream of a forward. No overall timeout
    /// and no busy retry (the request has side effects once the stream starts); an error before the
    /// stream is an ordinary API error. Dropping the stream closes the connection, which makes the
    /// daemon remove the relay.
    pub(crate) async fn open_forward(
        &self,
        name: &str,
        request: &ForwardRequest,
    ) -> Result<ForwardStream, CliError> {
        let payload = serde_json::to_vec(request)
            .map_err(|e| CliError::internal(format!("cannot encode request: {e}")))?;
        let req = Request::builder()
            .method(method_str(endpoints::APPS_FORWARD.method))
            .uri(request_path(endpoints::APPS_FORWARD, &[("name", name)], ""))
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(payload)))
            .map_err(|e| CliError::internal(format!("cannot build request: {e}")))?;
        let response = self
            .open_stream(req, FORWARD_STREAM_CONTENT_TYPE, "forward")
            .await?;
        Ok(ForwardStream {
            response,
            decoder: ForwardFrameDecoder::default(),
            ready: VecDeque::new(),
        })
    }
}

/// Waits for the first frame, which names the host port.
async fn wait_ready(stream: &mut ForwardStream) -> Result<u16, CliError> {
    match stream.next().await? {
        Some(ForwardFrame::Ready { host_port }) => Ok(host_port),
        Some(ForwardFrame::Error(message)) => {
            Err(CliError::internal(format!("forward failed: {message}")))
        }
        Some(other) => Err(CliError::internal(format!(
            "unexpected first frame of the forward stream: {other:?}"
        ))),
        None => Err(CliError::internal(
            "the daemon closed the connection before the forward was ready",
        )),
    }
}

pub async fn run(json: bool, o: &Overrides, a: ForwardArgs) -> Result<i32, CliError> {
    let name = instance(&a.name)?;
    let request = a.request()?;
    let destination = match a.ssh.clone() {
        Some(dest) => Some(dest),
        None => UserConfig::load_default()?.ssh_host,
    };
    if let Some(dest) = &destination {
        validate_ssh_destination(dest)?;
    }
    let local_port = a.local_port.unwrap_or(a.port);

    let mut stream = client(o)?.open_forward(name.as_str(), &request).await?;
    let host_port = wait_ready(&mut stream).await?;

    let mut ssh = match &destination {
        Some(dest) => Some(
            tokio::process::Command::new("ssh")
                .args(ssh_args(dest, local_port, host_port))
                .stdin(Stdio::null())
                // Dropping the child (any exit path below) ends the tunnel.
                .kill_on_drop(true)
                .spawn()
                .map_err(|e| CliError::internal(format!("cannot start ssh: {e}")))?,
        ),
        None => None,
    };

    if json {
        println!(
            "{}",
            serde_json::json!({
                "ready": true,
                "app": name.as_str(),
                "port": a.port,
                "host_port": host_port,
                "local_port": ssh.as_ref().map(|_| local_port),
            })
        );
    } else if ssh.is_some() {
        eprintln!(
            "Forwarding 127.0.0.1:{local_port} -> {name}:{} (relay on the host's 127.0.0.1:{host_port}). Ctrl-C to stop.",
            a.port
        );
    } else {
        eprintln!(
            "Relay for {name}:{} listens on 127.0.0.1:{host_port} of the host; nothing is tunnelled \
             (no SSH destination: --ssh, WEGLARKA_SSH or `ssh_host` in cli.toml). Ctrl-C to stop.",
            a.port
        );
    }

    let ssh_exit = async {
        match ssh.as_mut() {
            Some(child) => child.wait().await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(ssh_exit);
    loop {
        tokio::select! {
            frame = stream.next() => match frame? {
                Some(ForwardFrame::Keepalive | ForwardFrame::Ready { .. }) => {}
                Some(ForwardFrame::TimedOut) => {
                    eprintln!("The forward reached its timeout and was closed.");
                    return Ok(0);
                }
                Some(ForwardFrame::Error(message)) => {
                    return Err(CliError::internal(format!("forward failed: {message}")));
                }
                None => {
                    return Err(CliError::internal(
                        "the daemon closed the connection; the relay was removed",
                    ));
                }
            },
            status = &mut ssh_exit => {
                let status = status
                    .map_err(|e| CliError::internal(format!("waiting for ssh failed: {e}")))?;
                return Err(CliError::internal(format!("ssh exited ({status}); the forward was closed"))
                    .with_hint("check the destination, your key and that the local port is free"));
            }
            _ = tokio::signal::ctrl_c() => return Ok(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_carries_loopback_to_loopback_and_takes_the_destination_last() {
        assert_eq!(
            ssh_args("me@deploy", 15432, 43211),
            [
                "-N",
                "-T",
                "-o",
                "ExitOnForwardFailure=yes",
                "-o",
                "ServerAliveInterval=15",
                "-L",
                "127.0.0.1:15432:127.0.0.1:43211",
                "--",
                "me@deploy",
            ]
        );
    }

    #[test]
    fn destinations_that_look_like_options_or_contain_whitespace_are_refused() {
        for ok in ["deploy", "me@deploy", "me@10.0.0.2", "my-alias"] {
            assert!(validate_ssh_destination(ok).is_ok(), "{ok}");
        }
        for bad in ["", "-oProxyCommand=x", "a b", "a\nb", "a\tb"] {
            assert!(validate_ssh_destination(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_timeout_is_capped_by_the_wire_type() {
        let args = ForwardArgs {
            name: "x".into(),
            port: 80,
            local_port: None,
            ssh: None,
            timeout: Some(Duration::from_secs(u64::from(u32::MAX) + 1)),
        };
        assert!(args.request().is_err());
        let ok = ForwardArgs {
            timeout: Some(Duration::from_secs(90)),
            ..args
        };
        assert_eq!(ok.request().unwrap().timeout_secs, Some(90));
    }

    #[derive(Debug, clap::Parser)]
    struct W {
        #[command(flatten)]
        a: ForwardArgs,
    }

    #[test]
    fn ports_are_1_to_65535_and_the_local_port_is_optional() {
        use clap::Parser as _;
        let a = W::try_parse_from(["forward", "db", "5432", "--local-port", "15432"])
            .unwrap()
            .a;
        assert_eq!((a.port, a.local_port), (5432, Some(15432)));
        assert!(W::try_parse_from(["forward", "db", "0"]).is_err());
        assert!(W::try_parse_from(["forward", "db", "70000"]).is_err());
        assert!(W::try_parse_from(["forward", "db", "1", "--local-port", "0"]).is_err());
    }

    #[tokio::test]
    async fn the_stream_reassembles_frames_and_ends_when_the_daemon_closes() {
        use weglarka_unix_http::testing::{Reply, mock_with};
        let bytes: Vec<u8> = [
            ForwardFrame::Ready { host_port: 43211 },
            ForwardFrame::TimedOut,
        ]
        .iter()
        .flat_map(ForwardFrame::encode)
        .collect();
        // Cut inside the first frame.
        let pieces = [bytes[..3].to_vec(), bytes[3..].to_vec()].map(Bytes::from);
        let socket = mock_with(move |_, _| {
            Reply::chunks(200, pieces.clone()).content_type(FORWARD_STREAM_CONTENT_TYPE)
        })
        .await;
        let mut stream = ApiClient::new(socket.socket.clone())
            .open_forward(
                "db",
                &ForwardRequest {
                    port: 5432,
                    timeout_secs: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(wait_ready(&mut stream).await.unwrap(), 43211);
        assert_eq!(stream.next().await.unwrap(), Some(ForwardFrame::TimedOut));
        assert_eq!(stream.next().await.unwrap(), None);
        let seen = socket.seen.lock().unwrap();
        assert_eq!(seen[0].path, "/v1/apps/db/forward");
        let sent: ForwardRequest = serde_json::from_str(&seen[0].body).unwrap();
        assert_eq!(sent.port, 5432);
    }
}
