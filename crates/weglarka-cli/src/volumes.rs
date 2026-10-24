//! `weglarka volumes list|add|remove|export|import` (API: `VOLUMES_*`, `SHARED_VOLUMES_*`). Tars
//! are streamed — file or stdin/stdout on this side, request/response bodies on the wire — so a
//! volume never sits in RAM.

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use clap::{Args, Subcommand};
use futures_util::stream;
use hyper::body::Bytes;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt};
use weglarka_api::{ListSharedVolumesResponse, ListVolumesResponse, endpoints};
use weglarka_core::app::{InstanceName, SharedVolumeName};

use crate::commands::{DryRun, client, instance};
use crate::error::{CliError, Kind, exit};
use crate::output::{emit, table};
use crate::settings::Overrides;

const CHUNK: usize = 256 * 1024;

#[derive(Debug, Subcommand)]
pub enum VolumesCommand {
    /// List the volumes an app declares and whether they exist yet; without an app, list the shared
    /// volumes declared in apps.toml.
    List {
        /// Instance name. Without it, declared shared volumes are listed.
        app: Option<String>,
    },
    /// Declare a shared volume. Apps mount it with `apps add/update --shared-volume NAME=/PATH[:ro]`
    /// or `shared_volumes` in the spec.
    Add(DeclareArgs),
    /// Remove a declared shared volume. Refused while an app still mounts it; without --purge it is
    /// also refused while the volume still holds data.
    Remove(SharedRemoveArgs),
    /// Write a volume as a tar to a file or stdout (Węglarka's own backup format).
    Export(ExportArgs),
    /// Extract a tar into a volume. The app is stopped for the import and started again.
    Import(ImportArgs),
}

#[derive(Debug, Args)]
pub struct DeclareArgs {
    /// Shared volume name ([a-z0-9-], 1–63 characters).
    pub name: String,
    /// Send nothing; show the request.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct SharedRemoveArgs {
    /// Shared volume name ([a-z0-9-], 1–63 characters).
    pub name: String,
    /// Also delete the Podman volume (its data!) and release its uid range. Without it only the
    /// declaration of an empty volume can be removed.
    #[arg(long)]
    pub purge: bool,
    /// Send nothing; show the request.
    #[arg(long)]
    pub dry_run: bool,
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
        VolumesCommand::List { app } => list(json, o, app.as_deref()).await,
        VolumesCommand::Add(a) => declare(json, o, a).await,
        VolumesCommand::Remove(a) => remove(json, o, a).await,
        VolumesCommand::Export(a) => export(o, a).await,
        VolumesCommand::Import(a) => import(json, o, a).await,
    }
}

async fn list(json: bool, o: &Overrides, app: Option<&str>) -> Result<i32, CliError> {
    match app {
        Some(app) => list_app(json, o, app).await,
        None => list_shared(json, o).await,
    }
}

async fn list_app(json: bool, o: &Overrides, app: &str) -> Result<i32, CliError> {
    let app = instance(app)?;
    let resp: ListVolumesResponse = client(o)?
        .call(
            endpoints::VOLUMES_LIST,
            &[("name", app.as_str())],
            None::<&()>,
        )
        .await?;
    emit(json, &resp, || app_volumes_table(&app, &resp));
    Ok(exit::OK)
}

/// Table of one app's volumes; the `SHARED` column marks volumes shared with other instances.
fn app_volumes_table(app: &InstanceName, resp: &ListVolumesResponse) -> String {
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
                if v.shared {
                    "yes".to_owned()
                } else {
                    String::new()
                },
            ]
        })
        .collect();
    table(
        &["VOLUME", "TARGET", "PODMAN NAME", "EXISTS", "SHARED"],
        &rows,
    )
}

async fn list_shared(json: bool, o: &Overrides) -> Result<i32, CliError> {
    let resp: ListSharedVolumesResponse = client(o)?
        .call(endpoints::SHARED_VOLUMES_LIST, &[], None::<&()>)
        .await?;
    emit(json, &resp, || shared_volumes_table(&resp));
    Ok(exit::OK)
}

/// Table of the declared shared volumes: range as `<start>+<size>`, `-` for "not allocated yet".
fn shared_volumes_table(resp: &ListSharedVolumesResponse) -> String {
    if resp.volumes.is_empty() {
        return "no shared volumes declared (add one with `weglarka volumes add <name>`)\n"
            .to_owned();
    }
    let rows: Vec<Vec<String>> = resp
        .volumes
        .iter()
        .map(|v| {
            vec![
                v.name.to_string(),
                v.podman_name.clone(),
                if v.members.is_empty() {
                    "-".to_owned()
                } else {
                    v.members
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                },
                v.uid_range
                    .map_or_else(|| "-".to_owned(), |r| format!("{}+{}", r.start, r.size)),
                if v.exists { "yes" } else { "not yet" }.to_owned(),
            ]
        })
        .collect();
    table(
        &["NAME", "PODMAN NAME", "MEMBERS", "RANGE", "EXISTS"],
        &rows,
    )
}

/// A shared volume name is also a URL path segment here, so validation is mandatory.
fn shared_volume_name(name: &str) -> Result<SharedVolumeName, CliError> {
    SharedVolumeName::new(name).map_err(|e| {
        CliError::usage(e.to_string()).with_hint(
            "shared volume names: lowercase letters, digits and hyphens, e.g. `kajet-data`",
        )
    })
}

#[derive(Debug, Serialize)]
struct Declared {
    declared: String,
}

async fn declare(json: bool, o: &Overrides, a: DeclareArgs) -> Result<i32, CliError> {
    let name = shared_volume_name(&a.name)?;
    let params = [("volume", name.as_str())];
    if a.dry_run {
        DryRun::new(endpoints::SHARED_VOLUMES_DECLARE, &params, None).print(json);
        return Ok(exit::OK);
    }
    client(o)?
        .call_empty(endpoints::SHARED_VOLUMES_DECLARE, &params)
        .await?;
    let out = Declared {
        declared: name.to_string(),
    };
    emit(json, &out, || {
        format!(
            "declared shared volume {name}; mount it with `weglarka apps add/update <app> \
             --shared-volume {name}=/PATH`\n"
        )
    });
    Ok(exit::OK)
}

#[derive(Debug, Serialize)]
struct RemovedShared {
    removed: String,
    purged: bool,
}

/// The request `volumes remove --dry-run` shows; `--purge` is a query parameter, so it is part of
/// the printed path.
fn remove_dry_run(name: &str, purge: bool) -> DryRun {
    let params = [("volume", name)];
    let mut dry = DryRun::new(endpoints::SHARED_VOLUMES_REMOVE, &params, None);
    if purge {
        dry.path.push_str("?purge=true");
    }
    dry
}

async fn remove(json: bool, o: &Overrides, a: SharedRemoveArgs) -> Result<i32, CliError> {
    let name = shared_volume_name(&a.name)?;
    if a.dry_run {
        remove_dry_run(name.as_str(), a.purge).print(json);
        return Ok(exit::OK);
    }
    let params = [("volume", name.as_str())];
    let client = client(o)?;
    let result = if a.purge {
        client
            .call_empty_query(endpoints::SHARED_VOLUMES_REMOVE, &params, "purge=true")
            .await
    } else {
        client
            .call_empty(endpoints::SHARED_VOLUMES_REMOVE, &params)
            .await
    };
    result.map_err(|e| shared_volume_error(e, a.purge))?;
    let out = RemovedShared {
        removed: name.to_string(),
        purged: a.purge,
    };
    emit(json, &out, || {
        if out.purged {
            format!("removed shared volume {} and its data\n", out.removed)
        } else {
            format!(
                "removed the declaration of shared volume {} (the data was already gone)\n",
                out.removed
            )
        }
    });
    Ok(exit::OK)
}

/// Hints for the two expected refusals; the daemon message names the remaining members.
fn shared_volume_error(e: CliError, purge: bool) -> CliError {
    match e.kind {
        Kind::NotFound => e.with_hint("declared shared volumes: `weglarka volumes list`"),
        Kind::Conflict if purge => e.with_hint(
            "apps still mount it: remove the mount from their specs first \
             (`weglarka apps update <app> --spec FILE`)",
        ),
        Kind::Conflict => e.with_hint(
            "the volume still holds data: `weglarka volumes remove <name> --purge` deletes it \
             (after every member is stopped)",
        ),
        _ => e,
    }
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

    // ---------- shared volumes (issue #33) ----------

    use weglarka_api::{ApiError, ErrorCode, SharedVolumeSummary, VolumeSummary};
    use weglarka_core::uid_range::UidRange;

    fn leaked(s: String) -> &'static [u8] {
        Box::leak(s.into_bytes().into_boxed_slice())
    }

    fn shared_resp() -> ListSharedVolumesResponse {
        let name = |s: &str| SharedVolumeName::new(s).unwrap();
        ListSharedVolumesResponse {
            volumes: vec![
                SharedVolumeSummary {
                    name: name("kajet-data"),
                    podman_name: "wg-shared-kajet-data".into(),
                    members: vec![
                        InstanceName::new("kajet-api").unwrap(),
                        InstanceName::new("kajet-mcp").unwrap(),
                    ],
                    uid_range: Some(UidRange {
                        start: 100_000,
                        size: 65_536,
                    }),
                    exists: true,
                },
                SharedVolumeSummary {
                    name: name("future"),
                    podman_name: "wg-shared-future".into(),
                    members: vec![],
                    uid_range: None,
                    exists: false,
                },
            ],
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn list_without_an_app_requests_the_shared_volumes() {
        let body = leaked(serde_json::to_string(&shared_resp()).unwrap());
        let (socket, seen) = mock("slist", 200, body).await;
        assert_eq!(
            list(true, &overrides(&socket), None).await.unwrap(),
            exit::OK
        );
        let seen = seen.lock().unwrap();
        assert_eq!(
            (seen[0].0.as_str(), seen[0].1.as_str()),
            ("GET", "/v1/volumes")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn list_with_an_app_requests_its_volumes() {
        let body = leaked(serde_json::to_string(&ListVolumesResponse { volumes: vec![] }).unwrap());
        let (socket, seen) = mock("alist", 200, body).await;
        assert_eq!(
            list(true, &overrides(&socket), Some("kajet-api"))
                .await
                .unwrap(),
            exit::OK
        );
        assert_eq!(seen.lock().unwrap()[0].1, "/v1/apps/kajet-api/volumes");
    }

    #[test]
    fn shared_volumes_table_renders_members_range_and_exists() {
        let t = shared_volumes_table(&shared_resp());
        assert!(t.starts_with("NAME"), "{t}");
        assert!(t.contains("wg-shared-kajet-data"), "{t}");
        assert!(t.contains("kajet-api, kajet-mcp"), "{t}");
        assert!(t.contains("100000+65536"), "{t}");
        let unused: Vec<&str> = t
            .lines()
            .find(|l| l.starts_with("future"))
            .unwrap()
            .split_whitespace()
            .collect();
        assert_eq!(
            unused,
            ["future", "wg-shared-future", "-", "-", "not", "yet"],
            "no members, no range, not created yet"
        );
        assert!(
            shared_volumes_table(&ListSharedVolumesResponse::default())
                .contains("no shared volumes declared")
        );
    }

    #[test]
    fn app_volumes_table_marks_shared_volumes() {
        let resp = ListVolumesResponse {
            volumes: vec![
                VolumeSummary {
                    name: "cache".into(),
                    target: "/cache".into(),
                    podman_name: "kajet-api.cache".into(),
                    exists: false,
                    shared: false,
                },
                VolumeSummary {
                    name: "kajet-data".into(),
                    target: "/data".into(),
                    podman_name: "wg-shared-kajet-data".into(),
                    exists: true,
                    shared: true,
                },
            ],
        };
        let t = app_volumes_table(&InstanceName::new("kajet-api").unwrap(), &resp);
        assert!(t.contains("SHARED"), "{t}");
        let shared_row = t
            .lines()
            .find(|l| l.contains("wg-shared-kajet-data"))
            .unwrap();
        assert!(shared_row.trim_end().ends_with("yes"), "{shared_row}");
        let private_row = t.lines().find(|l| l.contains("kajet-api.cache")).unwrap();
        assert!(!private_row.trim_end().ends_with("yes"), "{private_row}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn add_declares_a_shared_volume_and_dry_run_sends_nothing() {
        let (socket, seen) = mock("sadd", 204, b"").await;
        let o = overrides(&socket);
        declare(
            true,
            &o,
            DeclareArgs {
                name: "kajet-data".into(),
                dry_run: true,
            },
        )
        .await
        .unwrap();
        assert!(seen.lock().unwrap().is_empty(), "--dry-run sends nothing");
        assert_eq!(
            declare(
                true,
                &o,
                DeclareArgs {
                    name: "kajet-data".into(),
                    dry_run: false,
                },
            )
            .await
            .unwrap(),
            exit::OK
        );
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            (seen[0].0.as_str(), seen[0].1.as_str()),
            ("PUT", "/v1/volumes/kajet-data")
        );
        assert!(seen[0].2.is_empty(), "the declaration has no body");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn remove_sends_purge_only_when_asked() {
        let (socket, seen) = mock("srm", 204, b"").await;
        let o = overrides(&socket);
        for purge in [false, true] {
            remove(
                true,
                &o,
                SharedRemoveArgs {
                    name: "kajet-data".into(),
                    purge,
                    dry_run: false,
                },
            )
            .await
            .unwrap();
        }
        let seen = seen.lock().unwrap();
        assert_eq!(
            (seen[0].0.as_str(), seen[0].1.as_str()),
            ("DELETE", "/v1/volumes/kajet-data")
        );
        assert_eq!(
            (seen[1].0.as_str(), seen[1].1.as_str()),
            ("DELETE", "/v1/volumes/kajet-data?purge=true")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn remove_dry_run_shows_the_query_and_sends_nothing() {
        let (socket, seen) = mock("srmdry", 204, b"").await;
        remove(
            true,
            &overrides(&socket),
            SharedRemoveArgs {
                name: "kajet-data".into(),
                purge: true,
                dry_run: true,
            },
        )
        .await
        .unwrap();
        assert!(seen.lock().unwrap().is_empty(), "--dry-run sends nothing");
        assert_eq!(
            remove_dry_run("kajet-data", false).path,
            "/v1/volumes/kajet-data"
        );
        assert_eq!(
            remove_dry_run("kajet-data", true).path,
            "/v1/volumes/kajet-data?purge=true"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn invalid_shared_volume_names_are_usage_errors() {
        let (socket, seen) = mock("sbad", 204, b"").await;
        let o = overrides(&socket);
        let err = declare(
            true,
            &o,
            DeclareArgs {
                name: "Kajet_Data".into(),
                dry_run: false,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.exit_code(), exit::USAGE);
        let err = remove(
            true,
            &o,
            SharedRemoveArgs {
                name: "kajet/data".into(),
                purge: false,
                dry_run: false,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.exit_code(), exit::USAGE);
        assert!(
            seen.lock().unwrap().is_empty(),
            "invalid names never reach the daemon"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refusals_keep_the_daemon_message_and_the_exit_code() {
        let conflict = leaked(
            serde_json::to_string(&ApiError {
                code: ErrorCode::Conflict,
                message: "shared volume \"kajet-data\" is still mounted by: kajet-mcp".into(),
            })
            .unwrap(),
        );
        let (socket, _) = mock("srm409", 409, conflict).await;
        let err = remove(
            true,
            &overrides(&socket),
            SharedRemoveArgs {
                name: "kajet-data".into(),
                purge: true,
                dry_run: false,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.exit_code(), exit::CONFLICT);
        assert!(err.message.contains("kajet-mcp"), "{}", err.message);
        assert!(err.hint.is_some(), "the refusal carries a hint");

        let missing = leaked(
            serde_json::to_string(&ApiError {
                code: ErrorCode::NotFound,
                message: "no such shared volume".into(),
            })
            .unwrap(),
        );
        let (socket, _) = mock("srm404", 404, missing).await;
        let err = remove(
            true,
            &overrides(&socket),
            SharedRemoveArgs {
                name: "kajet-data".into(),
                purge: false,
                dry_run: false,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(err.exit_code(), exit::NOT_FOUND);
        assert!(
            err.hint
                .as_deref()
                .is_some_and(|h| h.contains("volumes list")),
            "{:?}",
            err.hint
        );
    }
}
