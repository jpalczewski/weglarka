//! `weglarka volumes list|export|import` (API: `VOLUMES_*`). Tars are streamed — file or
//! stdin/stdout on this side, request/response bodies on the wire — so a volume never sits in RAM.

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use clap::{Args, Subcommand};
use futures_util::stream;
use hyper::body::Bytes;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt};
use weglarka_api::{ListVolumesResponse, endpoints};

use crate::commands::{DryRun, client, instance};
use crate::error::{CliError, exit};
use crate::output::{emit, table};
use crate::settings::Overrides;

const CHUNK: usize = 256 * 1024;

#[derive(Debug, Subcommand)]
pub enum VolumesCommand {
    /// List the volumes an app declares and whether they exist yet.
    List { app: String },
    /// Write a volume as a tar to a file or stdout (Węglarka's own backup format).
    Export(ExportArgs),
    /// Extract a tar into a volume. The app is stopped for the import and started again.
    Import(ImportArgs),
}

#[derive(Debug, Args)]
pub struct ExportArgs {
    pub app: String,
    /// Volume name within the app (as in `volumes list`).
    pub volume: String,
    /// Output file (default: stdout, which must not be a terminal).
    #[arg(long, short, value_name = "FILE")]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ImportArgs {
    pub app: String,
    /// Volume name within the app (as in `volumes list`).
    pub volume: String,
    /// Input tar file (default: stdin, which must not be a terminal). Plain tar, not .tar.gz.
    #[arg(long, short, value_name = "FILE")]
    pub from: Option<PathBuf>,
    /// The tar is a `weglarka volumes export` of THIS app. Restores it byte for byte, ids included.
    /// Do NOT use it for tars from Coolify, docker or tar(1): their uids would silently land on the
    /// wrong users. Without --own the tar is treated as foreign: every extracted file is owned by the app's user
    /// whatever the tar says (a Węglarka export imported that way loses its owners).
    #[arg(long)]
    pub own: bool,
    /// Empty the volume first (it is removed and created again), so files missing from the tar do
    /// not survive — e.g. a stale SQLite `-wal`/`-shm` that would otherwise be replayed onto the
    /// imported database. The app's container is recreated. Without it, only the tar's paths are
    /// overwritten and everything else in the volume stays.
    #[arg(long)]
    pub replace: bool,
    /// Send nothing; show the request.
    #[arg(long)]
    pub dry_run: bool,
}

pub async fn run(json: bool, o: &Overrides, cmd: VolumesCommand) -> Result<i32, CliError> {
    match cmd {
        VolumesCommand::List { app } => list(json, o, &app).await,
        VolumesCommand::Export(a) => export(o, a).await,
        VolumesCommand::Import(a) => import(json, o, a).await,
    }
}

async fn list(json: bool, o: &Overrides, app: &str) -> Result<i32, CliError> {
    let app = instance(app)?;
    let resp: ListVolumesResponse = client(o)?
        .call(
            endpoints::VOLUMES_LIST,
            &[("name", app.as_str())],
            None::<&()>,
        )
        .await?;
    emit(json, &resp, || {
        if resp.volumes.is_empty() {
            return format!("{app} declares no volumes\n");
        }
        let rows: Vec<Vec<String>> = resp
            .volumes
            .iter()
            .map(|v| {
                vec![
                    v.name.clone(),
                    v.target.clone(),
                    v.podman_name.clone(),
                    if v.exists { "yes" } else { "not yet" }.to_owned(),
                ]
            })
            .collect();
        table(&["VOLUME", "TARGET", "PODMAN NAME", "EXISTS"], &rows)
    });
    Ok(exit::OK)
}

async fn export(o: &Overrides, a: ExportArgs) -> Result<i32, CliError> {
    let app = instance(&a.app)?;
    let params = [("name", app.as_str()), ("volume", a.volume.as_str())];
    let client = client(o)?;
    let io = |what: &str, e: std::io::Error| CliError::internal(format!("{what}: {e}"));
    let written = match &a.out {
        Some(path) => {
            let mut file = tokio::fs::File::create(path)
                .await
                .map_err(|e| io(&format!("cannot create {}", path.display()), e))?;
            let n = client
                .download(endpoints::VOLUMES_EXPORT, &params, &mut file)
                .await;
            if n.is_err() {
                drop(file);
                let _ = tokio::fs::remove_file(path).await; // no half-written backup left behind
            }
            n?
        }
        None => {
            if std::io::stdout().is_terminal() {
                return Err(CliError::usage("refusing to write a tar to the terminal")
                    .with_hint("redirect the output (`> backup.tar`) or use --out FILE"));
            }
            client
                .download(endpoints::VOLUMES_EXPORT, &params, &mut tokio::io::stdout())
                .await?
        }
    };
    // Stdout may carry the tar, so the note goes to stderr.
    let _ = writeln!(
        std::io::stderr(),
        "exported {}/{}: {written} bytes",
        app,
        a.volume
    );
    Ok(exit::OK)
}

#[derive(Debug, Serialize)]
struct Imported {
    app: String,
    volume: String,
    mode: &'static str,
    bytes: u64,
}

async fn import(json: bool, o: &Overrides, a: ImportArgs) -> Result<i32, CliError> {
    let app = instance(&a.app)?;
    let params = [("name", app.as_str()), ("volume", a.volume.as_str())];
    let (mut query, mode) = if a.own {
        (String::new(), "own")
    } else {
        ("foreign=true".to_owned(), "foreign")
    };
    if a.replace {
        if !query.is_empty() {
            query.push('&');
        }
        query.push_str("replace=true");
    }
    if a.dry_run {
        let mut dry = DryRun::new(endpoints::VOLUMES_IMPORT, &params, None);
        if !query.is_empty() {
            dry.path.push('?');
            dry.path.push_str(&query);
        }
        dry.print(json);
        return Ok(exit::OK);
    }
    let client = client(o)?;
    let counter = Arc::new(AtomicU64::new(0));
    let body: stream::BoxStream<'static, std::io::Result<Bytes>> = match &a.from {
        Some(path) => {
            let file = tokio::fs::File::open(path)
                .await
                .map_err(|e| CliError::usage(format!("cannot open {}: {e}", path.display())))?;
            chunks(file, counter.clone())
        }
        None => {
            if std::io::stdin().is_terminal() {
                return Err(CliError::usage("refusing to read a tar from the terminal")
                    .with_hint("pass a file (--from FILE) or redirect stdin (`< backup.tar`)"));
            }
            chunks(tokio::io::stdin(), counter.clone())
        }
    };
    client
        .upload(endpoints::VOLUMES_IMPORT, &params, &query, body)
        .await?;
    let out = Imported {
        app: app.to_string(),
        volume: a.volume,
        mode,
        bytes: counter.load(Ordering::Relaxed),
    };
    emit(json, &out, || {
        format!(
            "imported {} bytes into {}/{} ({} mode); the app was restarted if it was running\n",
            out.bytes, out.app, out.volume, out.mode
        )
    });
    Ok(exit::OK)
}

/// Reads `reader` in [`CHUNK`]-sized pieces, counting the bytes.
fn chunks(
    reader: impl AsyncRead + Send + Unpin + 'static,
    counter: Arc<AtomicU64>,
) -> stream::BoxStream<'static, std::io::Result<Bytes>> {
    Box::pin(stream::unfold((reader, counter), |(mut r, c)| async move {
        let mut buf = vec![0u8; CHUNK];
        match r.read(&mut buf).await {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                c.fetch_add(n as u64, Ordering::Relaxed);
                Some((Ok(Bytes::from(buf)), (r, c)))
            }
            Err(e) => Some((Err(e), (r, c))),
        }
    }))
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::sync::Mutex;

    use http_body_util::{BodyExt, Full};
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;

    use super::*;
    use crate::client::ApiClient;

    /// What the mock daemon saw: `(method, path?query, body)`.
    type Seen = Arc<Mutex<Vec<(String, String, Vec<u8>)>>>;

    /// Unix-socket server answering every request with `status` and `reply`.
    async fn mock(tag: &str, status: u16, reply: &'static [u8]) -> (PathBuf, Seen) {
        let socket = std::env::temp_dir().join(format!("wgv-{}-{tag}.sock", std::process::id()));
        let _ = std::fs::remove_file(&socket);
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let seen: Seen = Arc::default();
        let seen2 = seen.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let seen = seen2.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let seen = seen.clone();
                        async move {
                            let method = req.method().to_string();
                            let uri = req.uri().to_string();
                            let body = req.into_body().collect().await.unwrap().to_bytes();
                            seen.lock().unwrap().push((method, uri, body.to_vec()));
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(status)
                                    .body(Full::new(Bytes::from_static(reply)))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        (socket, seen)
    }

    fn overrides(socket: &std::path::Path) -> Overrides {
        Overrides {
            config: None,
            socket: Some(socket.to_owned()),
        }
    }

    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("wgv-{}-{name}", std::process::id()))
    }

    #[tokio::test(flavor = "current_thread")]
    async fn import_streams_a_file_in_foreign_mode_by_default() {
        let (socket, seen) = mock("imp", 204, b"").await;
        let file = scratch("in.tar");
        let payload: Vec<u8> = (0..CHUNK * 2 + 17).map(|i| (i % 251) as u8).collect();
        std::fs::write(&file, &payload).unwrap();

        let args = |own, replace| ImportArgs {
            app: "szklana".into(),
            volume: "data".into(),
            from: Some(file.clone()),
            own,
            replace,
            dry_run: false,
        };
        import(true, &overrides(&socket), args(false, false))
            .await
            .unwrap();
        import(true, &overrides(&socket), args(true, false))
            .await
            .unwrap();
        import(true, &overrides(&socket), args(false, true))
            .await
            .unwrap();

        let seen = seen.lock().unwrap();
        assert_eq!(seen[0].0, "PUT");
        assert_eq!(
            seen[0].1,
            "/v1/apps/szklana/volumes/data/import?foreign=true"
        );
        assert_eq!(seen[0].2, payload, "body arrives intact");
        assert_eq!(
            seen[1].1, "/v1/apps/szklana/volumes/data/import",
            "--own sends no foreign flag"
        );
        assert_eq!(
            seen[2].1,
            "/v1/apps/szklana/volumes/data/import?foreign=true&replace=true"
        );
        let _ = std::fs::remove_file(file);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn export_writes_the_response_body_to_a_file_and_leaves_none_on_error() {
        let (socket, seen) = mock("exp", 200, b"TAR-BYTES").await;
        let out = scratch("out.tar");
        let args = || ExportArgs {
            app: "szklana".into(),
            volume: "data".into(),
            out: Some(out.clone()),
        };
        export(&overrides(&socket), args()).await.unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"TAR-BYTES");
        assert_eq!(
            seen.lock().unwrap()[0].1,
            "/v1/apps/szklana/volumes/data/export"
        );
        let _ = std::fs::remove_file(&out);

        let body: &'static [u8] = br#"{"code":"not_found","message":"no such volume"}"#;
        let (socket, _) = mock("exp404", 404, body).await;
        assert!(export(&overrides(&socket), args()).await.is_err());
        assert!(!out.exists(), "no half-written backup");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn purge_flag_goes_into_the_query() {
        let (socket, seen) = mock("purge", 204, b"").await;
        ApiClient::new(&socket)
            .call_empty_query(
                endpoints::APPS_REMOVE,
                &[("name", "x")],
                "purge_volumes=true",
            )
            .await
            .unwrap();
        assert_eq!(seen.lock().unwrap()[0].1, "/v1/apps/x?purge_volumes=true");
    }

    #[test]
    fn invalid_app_names_are_usage_errors() {
        assert!(instance("Not Valid").is_err());
    }
}
