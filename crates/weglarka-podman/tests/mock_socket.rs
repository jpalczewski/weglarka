//! Full client against a mock unix-socket server (no Podman): request paths, error
//! mapping, a pull stream with an error mid-way, a missing socket.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use weglarka_core::podman::{
    ContainerFilter, ContainerState, EventFilter, HealthStatus, NetworkSpec, PodmanClient,
    PodmanError, PullEvent, RegistryAuth,
};
use weglarka_podman::LibpodClient;

macro_rules! fixture {
    ($name:literal) => {
        include_str!(concat!("fixtures/", $name))
    };
}

/// Route: (prefix "METHOD /path", status, body). The first match wins.
type Route = (&'static str, u16, &'static str);

struct Mock {
    socket: PathBuf,
    requests: Arc<Mutex<Vec<String>>>,
}

impl Mock {
    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket);
    }
}

fn serve(routes: Vec<Route>) -> Mock {
    static N: AtomicU32 = AtomicU32::new(0);
    let socket = std::env::temp_dir().join(format!(
        "weglarka-mock-{}-{}.sock",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket).unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let log = requests.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut conn, _)) = listener.accept().await else {
                return;
            };
            let routes = routes.clone();
            let log = log.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let (head, body_start) = loop {
                    let n = conn.read(&mut chunk).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break (String::from_utf8_lossy(&buf[..i]).into_owned(), i + 4);
                    }
                };
                let len = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                while buf.len() < body_start + len {
                    let n = conn.read(&mut chunk).await.unwrap();
                    buf.extend_from_slice(&chunk[..n]);
                }
                let request_line = head.lines().next().unwrap().to_owned();
                let body = String::from_utf8_lossy(&buf[body_start..body_start + len]);
                // Only the registry-auth header is of interest to the tests; absent → the entry is unchanged.
                let auth = head
                    .lines()
                    .find_map(|l| l.strip_prefix("x-registry-auth: "))
                    .map(|v| format!(" [x-registry-auth: {v}]"))
                    .unwrap_or_default();
                log.lock()
                    .unwrap()
                    .push(format!("{request_line} {body}{auth}").trim_end().to_owned());
                let target = request_line.rsplit_once(' ').unwrap().0;
                let (status, payload) = routes
                    .iter()
                    .find(|(prefix, _, _)| target.starts_with(prefix))
                    .map(|&(_, s, b)| (s, b))
                    .unwrap_or((500, r#"{"message":"unmocked"}"#));
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                    payload.len()
                );
                let _ = conn.write_all(response.as_bytes()).await;
            });
        }
    });
    Mock { socket, requests }
}

#[tokio::test]
async fn missing_socket_is_unreachable() {
    let client = LibpodClient::new("/nonexistent/podman.sock");
    let err = client.version().await.unwrap_err();
    assert!(matches!(err, PodmanError::Unreachable(m) if m.contains("/nonexistent/podman.sock")));
}

#[tokio::test]
async fn version_uses_v6_libpod_prefix() {
    let mock = serve(vec![(
        "GET /v6.0.0/libpod/version",
        200,
        fixture!("version.json"),
    )]);
    let v = LibpodClient::new(&mock.socket).version().await.unwrap();
    assert_eq!(
        (v.version.as_str(), v.api_version.as_str()),
        ("6.1.0", "6.1.0")
    );
}

#[tokio::test]
async fn not_found_and_name_conflict() {
    let mock = serve(vec![
        (
            "GET /v6.0.0/libpod/containers/nope/json",
            404,
            fixture!("error_404.json"),
        ),
        (
            "POST /v6.0.0/libpod/containers/create",
            500,
            fixture!("error_create_name_in_use.json"),
        ),
        ("POST /v6.0.0/libpod/containers/x/healthcheck", 409, "{}"),
    ]);
    let client = LibpodClient::new(&mock.socket);
    assert!(
        matches!(client.container_inspect("nope").await, Err(PodmanError::NotFound(m)) if m.contains("no container"))
    );
    let spec = weglarka_core::podman::ContainerSpec {
        name: "x".into(),
        image: "i".into(),
        command: vec![],
        entrypoint: None,
        labels: Default::default(),
        env: Default::default(),
        networks: vec![],
        network_aliases: Default::default(),
        secrets: vec![],
        publish: vec![],
        restart: weglarka_core::podman::RestartPolicy::No,
        userns_auto: false,
        mounts: vec![],
        volumes: vec![],
        resources: Default::default(),
        healthcheck: None,
        id_mapping: None,
        security: Default::default(),
    };
    assert!(
        matches!(client.container_create(&spec).await, Err(PodmanError::Conflict(m)) if m.contains("already in use"))
    );
    assert!(client.container_inspect("../etc").await.is_err());
}

#[tokio::test]
async fn list_filters_by_label_and_inspects_each() {
    let mock = serve(vec![
        (
            "GET /v6.0.0/libpod/containers/json",
            200,
            fixture!("list_containers.json"),
        ),
        (
            "GET /v6.0.0/libpod/containers/3f2a9c1d/json",
            200,
            fixture!("inspect_container_running.json"),
        ),
        (
            "GET /v6.0.0/libpod/containers/aa/json",
            404,
            fixture!("error_404.json"),
        ),
    ]);
    let filter = ContainerFilter {
        labels: [("weglarka.instance".to_owned(), "ntfy".to_owned())].into(),
    };
    let list = LibpodClient::new(&mock.socket)
        .container_list(&filter)
        .await
        .unwrap();
    assert_eq!(list.len(), 1, "usunięty w trakcie jest pomijany");
    assert_eq!(list[0].state, ContainerState::Running);
    assert!(
        mock.requests()[0]
            .contains("all=true&filters=%7B%22label%22%3A%5B%22weglarka.instance%3Dntfy%22%5D%7D")
    );
}

#[tokio::test]
async fn image_list_reads_the_collection_and_keeps_names() {
    let mock = serve(vec![(
        "GET /v6.0.0/libpod/images/json",
        200,
        fixture!("list_images.json"),
    )]);
    let images = LibpodClient::new(&mock.socket).image_list().await.unwrap();
    assert_eq!(images.len(), 2);
    assert_eq!(
        images[0].repo_tags,
        ["ghcr.io/jpalczewski/ntfy.zig:latest".to_owned()]
    );
    assert_eq!(images[0].size_bytes, 41_943_040);
    assert!(mock.requests()[0].contains("/images/json"));
}

#[tokio::test]
async fn pull_streams_progress_then_complete_with_digest() {
    let mock = serve(vec![
        (
            "POST /v6.0.0/libpod/images/pull?reference=ghcr.io%2Fjpalczewski%2Fntfy.zig%3Alatest",
            200,
            fixture!("pull_ok.ndjson"),
        ),
        (
            "GET /v6.0.0/libpod/images/ghcr.io/jpalczewski/ntfy.zig:latest/json",
            200,
            fixture!("inspect_image.json"),
        ),
    ]);
    let events: Vec<_> = LibpodClient::new(&mock.socket)
        .image_pull("ghcr.io/jpalczewski/ntfy.zig:latest")
        .collect()
        .await;
    assert_eq!(events.len(), 3, "{events:?}");
    assert!(matches!(&events[0], Ok(PullEvent::Progress { .. })));
    let Ok(PullEvent::Complete { image_id, digest }) = &events[2] else {
        panic!("{events:?}")
    };
    assert!(image_id.starts_with("9b8a"));
    assert_eq!(
        digest.as_ref().unwrap().as_str(),
        format!("sha256:{}", "2".repeat(64))
    );
}

#[tokio::test]
async fn pull_error_in_stream_body_is_err_item_then_ends() {
    let mock = serve(vec![(
        "POST /v6.0.0/libpod/images/pull",
        200,
        fixture!("pull_error.ndjson"),
    )]);
    let events: Vec<_> = LibpodClient::new(&mock.socket)
        .image_pull("ghcr.io/x/bad:latest")
        .collect()
        .await;
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], Ok(PullEvent::Progress { .. })));
    assert!(matches!(&events[1], Err(PodmanError::Pull(m)) if m.contains("unauthorized")));
}

/// `image_pull_with` sends `X-Registry-Auth` (base64url JSON); a plain `image_pull` sends none.
#[tokio::test]
async fn pull_with_credentials_sends_registry_auth_header_and_plain_pull_does_not() {
    let routes = || {
        vec![
            (
                "POST /v6.0.0/libpod/images/pull",
                200,
                fixture!("pull_ok.ndjson"),
            ),
            (
                "GET /v6.0.0/libpod/images/",
                200,
                fixture!("inspect_image.json"),
            ),
        ]
    };
    let image = "ghcr.io/jpalczewski/ntfy.zig:latest";

    let mock = serve(routes());
    let auth = RegistryAuth::new("ci", "s3cr3t:with-colon");
    let events: Vec<_> = LibpodClient::new(&mock.socket)
        .image_pull_with(image, Some(&auth))
        .collect()
        .await;
    assert!(
        matches!(events.last(), Some(Ok(PullEvent::Complete { .. }))),
        "{events:?}"
    );
    let pull = mock.requests().remove(0);
    // {"username":"ci","password":"s3cr3t:with-colon","serveraddress":"ghcr.io"}
    assert!(
        pull.ends_with(
            " [x-registry-auth: eyJ1c2VybmFtZSI6ImNpIiwicGFzc3dvcmQiOiJzM2NyM3Q6d2l0aC1jb2xvbiIsInNlcnZlcmFkZHJlc3MiOiJnaGNyLmlvIn0=]"
        ),
        "{pull}"
    );
    assert!(
        !format!("{auth:?}").contains("s3cr3t"),
        "Debug redacts the password"
    );

    let mock = serve(routes());
    LibpodClient::new(&mock.socket)
        .image_pull(image)
        .collect::<Vec<_>>()
        .await;
    assert!(!mock.requests()[0].contains("x-registry-auth"));
}

/// 401/403 from libpod (before the stream starts) and the `unauthorized` error inside the stream
/// are both registry-auth failures.
#[tokio::test]
async fn pull_auth_failures_are_recognized_in_status_and_in_stream() {
    let mock = serve(vec![(
        "POST /v6.0.0/libpod/images/pull",
        401,
        r#"{"message":"denied"}"#,
    )]);
    let events: Vec<_> = LibpodClient::new(&mock.socket)
        .image_pull("ghcr.io/x/priv:latest")
        .collect()
        .await;
    assert!(
        matches!(events.as_slice(), [Err(e)] if e.is_registry_auth_failure()),
        "{events:?}"
    );

    let mock = serve(vec![(
        "POST /v6.0.0/libpod/images/pull",
        200,
        fixture!("pull_error.ndjson"),
    )]);
    let events: Vec<_> = LibpodClient::new(&mock.socket)
        .image_pull("ghcr.io/x/bad:latest")
        .collect()
        .await;
    assert!(matches!(&events[1], Err(e) if e.is_registry_auth_failure()));
}

#[tokio::test]
async fn pull_http_error_is_not_found() {
    let mock = serve(vec![(
        "POST /v6.0.0/libpod/images/pull",
        404,
        r#"{"message":"manifest unknown"}"#,
    )]);
    let events: Vec<_> = LibpodClient::new(&mock.socket)
        .image_pull("x/y")
        .collect()
        .await;
    assert!(matches!(events.as_slice(), [Err(PodmanError::NotFound(_))]));
}

#[tokio::test]
async fn network_create_is_idempotent_and_secret_replaces() {
    let mock = serve(vec![
        (
            "POST /v6.0.0/libpod/networks/create",
            409,
            r#"{"message":"network already exists"}"#,
        ),
        ("POST /v6.0.0/libpod/secrets/create", 200, r#"{"ID":"s"}"#),
        ("POST /v6.0.0/libpod/networks/net/connect", 200, "{}"),
        ("POST /v6.0.0/libpod/containers/c/start", 304, ""),
        (
            "GET /v6.0.0/libpod/containers/c/healthcheck",
            200,
            r#"{"Status":"unhealthy","FailingStreak":3}"#,
        ),
    ]);
    let client = LibpodClient::new(&mock.socket);
    client
        .network_create(&NetworkSpec {
            name: "net".into(),
            internal: false,
            labels: Default::default(),
        })
        .await
        .unwrap();
    client.secret_create("s", b"top secret").await.unwrap();
    client.network_connect("net", "c").await.unwrap();
    client.container_start("c").await.unwrap();
    assert_eq!(
        client.healthcheck_run("c").await.unwrap(),
        HealthStatus::Unhealthy
    );
    let requests = mock.requests();
    assert!(requests.iter().any(
        |r| r.contains("secrets/create?name=s&driver=file&replace=true")
            && r.ends_with("top secret")
    ));
    assert!(requests.iter().any(|r| r.contains(r#"{"container":"c"}"#)));
}

#[tokio::test]
async fn events_stream_yields_domain_events_and_reports_close() {
    let mock = serve(vec![(
        "GET /v6.0.0/libpod/events?stream=true&since=5",
        200,
        fixture!("events.ndjson"),
    )]);
    let events: Vec<_> = LibpodClient::new(&mock.socket)
        .events(&EventFilter {
            labels: Default::default(),
            since: Some(5),
        })
        .collect()
        .await;
    assert_eq!(events.len(), 5);
    assert_eq!(events[0].as_ref().unwrap().action, "start");
    assert!(
        matches!(events[4], Err(PodmanError::Unreachable(_))),
        "koniec strumienia = utrata połączenia"
    );
}

#[tokio::test]
async fn exec_runs_detached_and_returns_exit_code_and_disconnect_is_idempotent() {
    let mock = serve(vec![
        (
            "POST /v6.0.0/libpod/containers/c/exec",
            201,
            r#"{"Id":"abc123"}"#,
        ),
        ("POST /v6.0.0/libpod/exec/abc123/start", 200, ""),
        (
            "GET /v6.0.0/libpod/exec/abc123/json",
            200,
            r#"{"Running":false,"ExitCode":1}"#,
        ),
        (
            "POST /v6.0.0/libpod/networks/net/disconnect",
            500,
            r#"{"message":"container c is not connected to network net"}"#,
        ),
    ]);
    let client = LibpodClient::new(&mock.socket);
    let cmd = ["nginx".to_owned(), "-t".to_owned()];
    assert_eq!(client.container_exec("c", &cmd).await.unwrap(), 1);
    client.network_disconnect("net", "c").await.unwrap();
    let requests = mock.requests();
    assert!(
        requests
            .iter()
            .any(|r| r.contains(r#"{"Cmd":["nginx","-t"]}"#))
    );
    assert!(requests.iter().any(|r| r.contains(r#"{"Detach":true}"#)));
}

#[tokio::test]
async fn volume_calls_use_libpod_paths_and_map_results() {
    use weglarka_core::podman::{VolumeFilter, VolumeSpec};
    let mock = serve(vec![
        (
            "POST /v6.0.0/libpod/volumes/create",
            201,
            r#"{"Name":"app.data"}"#,
        ),
        (
            "GET /v6.0.0/libpod/volumes/app.data/json",
            200,
            r#"{"Name":"app.data","Mountpoint":"/v/app.data/_data","Labels":{"weglarka.instance":"app"},"Extra":1}"#,
        ),
        (
            "GET /v6.0.0/libpod/volumes/json?filters=",
            200,
            r#"[{"Name":"app.data","Labels":null,"Mountpoint":""}]"#,
        ),
        (
            "GET /v6.0.0/libpod/volumes/app.data/export",
            200,
            "TARBYTES",
        ),
        (
            "GET /v6.0.0/libpod/volumes/gone/json",
            404,
            fixture!("error_404.json"),
        ),
        ("DELETE /v6.0.0/libpod/volumes/app.data?force=true", 204, ""),
    ]);
    let client = LibpodClient::new(&mock.socket);
    let labels =
        std::collections::BTreeMap::from([("weglarka.instance".to_owned(), "app".to_owned())]);
    client
        .volume_create(&VolumeSpec {
            name: "app.data".into(),
            labels: labels.clone(),
        })
        .await
        .unwrap();
    let info = client.volume_inspect("app.data").await.unwrap();
    assert_eq!(info.labels, labels);
    assert_eq!(info.mountpoint.as_deref(), Some("/v/app.data/_data"));
    assert!(matches!(
        client.volume_inspect("gone").await,
        Err(PodmanError::NotFound(_))
    ));
    let listed = client.volume_list(&VolumeFilter { labels }).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert!(listed[0].labels.is_empty() && listed[0].mountpoint.is_none());
    let mut chunks = Vec::new();
    let mut tar = client.volume_export("app.data").await.unwrap();
    while let Some(chunk) = tar.next().await {
        chunks.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(chunks, b"TARBYTES");
    client.volume_remove("app.data", true).await.unwrap();
    assert!(client.volume_export("../x").await.is_err());
    assert!(mock.requests()[0].contains(r#""Name":"app.data""#));
}

/// One-off containers (issue #106): the log stream is demultiplexed into stdout/stderr and `wait`
/// returns the exit code, whichever of libpod's two shapes it answers in.
#[tokio::test]
async fn logs_are_demultiplexed_and_wait_returns_the_exit_code() {
    use weglarka_core::podman::LogSource;
    let mock = serve(vec![
        (
            "GET /v6.0.0/libpod/containers/job/logs",
            200,
            "\x01\0\0\0\0\0\0\x06hello\n\x02\0\0\0\0\0\0\x04bad\n",
        ),
        ("POST /v6.0.0/libpod/containers/job/wait", 200, "7"),
        (
            "POST /v6.0.0/libpod/containers/gone/wait",
            404,
            r#"{"message":"no such container gone"}"#,
        ),
    ]);
    let client = LibpodClient::new(&mock.socket);
    let mut logs = client.container_logs("job", true).await.unwrap();
    let mut got = Vec::new();
    while let Some(chunk) = logs.next().await {
        let chunk = chunk.unwrap();
        got.push((
            chunk.source,
            String::from_utf8(chunk.data.to_vec()).unwrap(),
        ));
    }
    assert_eq!(
        got,
        [
            (LogSource::Stdout, "hello\n".to_owned()),
            (LogSource::Stderr, "bad\n".to_owned())
        ]
    );
    assert_eq!(client.container_wait("job").await.unwrap(), 7);
    assert!(matches!(
        client.container_wait("gone").await,
        Err(PodmanError::NotFound(_))
    ));
    let requests = mock.requests();
    assert!(
        requests
            .iter()
            .any(|r| r.contains("logs?stdout=true&stderr=true&follow=true")),
        "{requests:?}"
    );
    assert!(
        requests
            .iter()
            .any(|r| r.contains("wait?condition=stopped&condition=exited")),
        "{requests:?}"
    );
}
