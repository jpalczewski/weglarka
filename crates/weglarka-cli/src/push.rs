//! `weglarka push <app> (ARCHIVE | --image REF)` (issue #109, docs/decisions/0042): deploy an image
//! that did not come through the webhook.
//!
//! An archive (`podman save`/`docker save`, a file or `-` for stdin) is streamed to the daemon, which
//! loads it, tags it into the app's image repository and deploys it with the usual health gate and
//! rollback. `--image` deploys another tag or digest of that repository instead, pulled by the host.
//! Either way the digest is pinned in the state and `apps.toml` keeps its tag.

use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use clap::Args;
use futures_util::stream::BoxStream;
use hyper::body::Bytes;
use weglarka_api::{DeployResponse, endpoints};

use crate::cli::DeployArgs;
use crate::commands::{DryRun, client, deploy, instance, report_deploy};
use crate::error::CliError;
use crate::settings::Overrides;
use crate::volumes::chunks;

/// Flags of `push`. Exactly one of the archive and `--image`.
#[derive(Debug, Args)]
#[command(after_long_help = "\
The new digest replaces the app's current one in the state, but `image` in the spec keeps its tag:
the next webhook (or `apps deploy`) for that tag deploys the tag's image again.

Examples:
  podman save --format oci-archive ghcr.io/me/app:dev | weglarka push app -
  weglarka push app ./app.tar
  weglarka push app --image ghcr.io/me/app:sha-1f2e3d4")]
pub struct PushArgs {
    /// Instance name.
    pub app: String,
    /// Image archive from `podman save` or `docker save`: a file, or `-` for stdin. Plain tar, not
    /// .tar.gz. Streamed, never held in memory.
    #[arg(value_name = "ARCHIVE", conflicts_with = "image")]
    pub archive: Option<PathBuf>,
    /// Deploy this tag or digest of the app's image repository (it must be the same repository as
    /// the spec's `image`), pulled by the host with the app's registry credentials.
    #[arg(long, value_name = "REF")]
    pub image: Option<String>,
    /// Push a static site (not available yet).
    #[arg(long = "static", hide = true)]
    pub static_site: bool,
    /// Send nothing; check that the app exists and show the request.
    #[arg(long)]
    pub dry_run: bool,
}

pub async fn run(json: bool, o: &Overrides, a: PushArgs) -> Result<i32, CliError> {
    if a.static_site {
        return Err(
            CliError::usage("pushing a static site is not available yet (issue #48)")
                .with_hint("push an image: an archive or --image REF"),
        );
    }
    match (&a.archive, &a.image) {
        (Some(path), None) => archive(json, o, &a, path).await,
        (None, Some(reference)) => {
            // A reference is an ordinary deploy of another tag of the same repository.
            deploy(
                json,
                o,
                DeployArgs {
                    app: a.app.clone(),
                    image: Some(reference.clone()),
                    dry_run: a.dry_run,
                },
            )
            .await
        }
        _ => Err(CliError::usage("give an image archive or --image REF")
            .with_hint("`podman save <image> | weglarka push <app> -`, or `weglarka push <app> --image <ref>`")),
    }
}

async fn archive(json: bool, o: &Overrides, a: &PushArgs, path: &PathBuf) -> Result<i32, CliError> {
    let name = instance(&a.app)?;
    let params = [("name", name.as_str())];
    if a.dry_run {
        DryRun::new(endpoints::APPS_PUSH_IMAGE, &params, None).print(json);
        return Ok(crate::error::exit::OK);
    }
    let client = client(o)?;
    let counter = Arc::new(AtomicU64::new(0));
    let body: BoxStream<'static, std::io::Result<Bytes>> = if path.as_os_str() == "-" {
        if std::io::stdin().is_terminal() {
            return Err(
                CliError::usage("refusing to read an image archive from the terminal")
                    .with_hint("pipe it in (`podman save <image> | weglarka push <app> -`)"),
            );
        }
        chunks(tokio::io::stdin(), counter)
    } else {
        let file = tokio::fs::File::open(path)
            .await
            .map_err(|e| CliError::usage(format!("cannot open {}: {e}", path.display())))?;
        chunks(file, counter)
    };
    let resp: DeployResponse = client
        .upload_json(endpoints::APPS_PUSH_IMAGE, &params, body)
        .await?;
    Ok(report_deploy(json, &name, &resp))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use clap::Parser;

    use super::*;
    use crate::cli::{Cli, Command};
    use crate::error::exit;

    fn parse(args: &[&str]) -> Result<PushArgs, clap::Error> {
        let argv = std::iter::once("weglarka").chain(args.iter().copied());
        Cli::try_parse_from(argv).map(|cli| match cli.command {
            Command::Push(a) => a,
            other => panic!("not push: {other:?}"),
        })
    }

    type Seen = Arc<Mutex<Vec<weglarka_unix_http::testing::Seen>>>;

    /// Unix-socket daemon answering every request with `status` and `reply`. The returned guard
    /// derefs to the socket path and removes the socket on drop.
    async fn mock(
        _tag: &str,
        status: u16,
        reply: &'static [u8],
    ) -> (weglarka_unix_http::testing::Mock, Seen) {
        let m = weglarka_unix_http::testing::mock_with(move |_, _| {
            weglarka_unix_http::testing::Reply::new(status, Bytes::from_static(reply))
        })
        .await;
        let seen = m.seen.clone();
        (m, seen)
    }

    fn overrides(socket: &std::path::Path) -> Overrides {
        Overrides {
            config: None,
            socket: Some(socket.to_owned()),
        }
    }

    const DEPLOYED: &[u8] = br#"{"outcome":"deployed","generation":2,"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
    const ROLLED_BACK: &[u8] = br#"{"outcome":"rolled_back","generation":3,"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}"#;

    #[test]
    fn parsing_takes_an_archive_or_an_image_but_not_both() {
        let a = parse(&["push", "app", "./app.tar"]).unwrap();
        assert_eq!(a.archive, Some(PathBuf::from("./app.tar")));
        assert!(a.image.is_none());
        let a = parse(&["push", "app", "-"]).unwrap();
        assert_eq!(a.archive, Some(PathBuf::from("-")));
        let a = parse(&["push", "app", "--image", "ghcr.io/me/app:sha-1"]).unwrap();
        assert_eq!(a.image.as_deref(), Some("ghcr.io/me/app:sha-1"));
        assert!(parse(&["push", "app", "x.tar", "--image", "r"]).is_err());
        assert!(parse(&["push"]).is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn an_archive_is_streamed_intact_and_the_outcome_reported() {
        let (socket, seen) = mock("arc", 200, DEPLOYED).await;
        let file = std::env::temp_dir().join(format!("wgp-{}-in.tar", std::process::id()));
        let payload: Vec<u8> = (0..crate::volumes::CHUNK * 2 + 5)
            .map(|i| (i % 249) as u8)
            .collect();
        std::fs::write(&file, &payload).unwrap();

        let code = run(
            true,
            &overrides(&socket),
            parse(&["push", "app", file.to_str().unwrap()]).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(code, exit::OK);
        let seen = seen.lock().unwrap();
        assert_eq!(seen[0].method, "PUT");
        assert_eq!(seen[0].uri(), "/v1/apps/app/image");
        assert_eq!(seen[0].raw_body, payload, "the archive arrives intact");
        let _ = std::fs::remove_file(file);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_rolled_back_push_exits_with_the_rollback_code() {
        let (socket, _) = mock("rb", 200, ROLLED_BACK).await;
        let file = std::env::temp_dir().join(format!("wgp-{}-rb.tar", std::process::id()));
        std::fs::write(&file, b"x").unwrap();
        let code = run(
            true,
            &overrides(&socket),
            parse(&["push", "app", file.to_str().unwrap()]).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(code, exit::ROLLED_BACK);
        let _ = std::fs::remove_file(file);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_daemon_error_is_reported_and_a_missing_file_is_a_usage_error() {
        let body: &'static [u8] =
            br#"{"code":"invalid_request","message":"cannot load the image archive: x"}"#;
        let (socket, _) = mock("bad", 400, body).await;
        let file = std::env::temp_dir().join(format!("wgp-{}-bad.tar", std::process::id()));
        std::fs::write(&file, b"junk").unwrap();
        let args = || parse(&["push", "app", file.to_str().unwrap()]).unwrap();
        let err = run(true, &overrides(&socket), args()).await.unwrap_err();
        assert!(err.to_string().contains("cannot load the image archive"));
        let _ = std::fs::remove_file(&file);

        let err = run(
            true,
            &overrides(&socket),
            parse(&["push", "app", "/nonexistent/app.tar"]).unwrap(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.exit_code(), exit::USAGE);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn an_image_reference_goes_through_deploy_and_static_is_refused() {
        let (socket, seen) = mock("img", 200, DEPLOYED).await;
        run(
            true,
            &overrides(&socket),
            parse(&["push", "app", "--image", "ghcr.io/me/app:sha-1"]).unwrap(),
        )
        .await
        .unwrap();
        {
            let seen = seen.lock().unwrap();
            assert_eq!(seen[0].method, "POST");
            assert_eq!(seen[0].uri(), "/v1/apps/app/deploy");
            let body: serde_json::Value = serde_json::from_slice(&seen[0].raw_body).unwrap();
            assert_eq!(body["image_ref"], "ghcr.io/me/app:sha-1");
        }

        let err = run(
            true,
            &overrides(&socket),
            parse(&["push", "app", "--static"]).unwrap(),
        )
        .await
        .unwrap_err();
        assert_eq!(err.exit_code(), exit::USAGE);
        assert!(err.to_string().contains("static"));
        let err = run(true, &overrides(&socket), parse(&["push", "app"]).unwrap())
            .await
            .unwrap_err();
        assert_eq!(err.exit_code(), exit::USAGE);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dry_run_sends_nothing() {
        let (socket, seen) = mock("dry", 200, DEPLOYED).await;
        let code = run(
            true,
            &overrides(&socket),
            parse(&["push", "app", "x.tar", "--dry-run"]).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(code, exit::OK);
        assert!(seen.lock().unwrap().is_empty());
    }
}
