use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;

/// A loopback "panel": answers one request with `response` and returns what it received.
async fn serve_once(response: &'static str) -> (String, tokio::task::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let host = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut seen = Vec::new();
        let mut buf = [0u8; 4096];
        while !String::from_utf8_lossy(&seen).contains("\r\n\r\n") {
            let n = socket.read(&mut buf).await.unwrap();
            seen.extend_from_slice(&buf[..n]);
        }
        socket.write_all(response.as_bytes()).await.unwrap();
        String::from_utf8_lossy(&seen).into_owned()
    });
    (host, task)
}

fn signed_in(host: &str) -> (tempfile::TempDir, Remote) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path().join("credentials.toml"));
    store
        .update(|c| {
            c.hosts.insert(
                normalize_host(host).unwrap(),
                super::super::credentials::HostEntry {
                    issuer: "https://auth.example.com".into(),
                    client_id: "weglarka-cli".into(),
                    audience: "https://admin.example.com/api/".into(),
                    access_token: "ACCESS1".into(),
                    access_expires: now_secs() + 3600,
                    refresh_token: None,
                },
            )
        })
        .unwrap();
    let remote = Remote::with_parts(host, HyperTransport::new(), store).unwrap();
    (dir, remote)
}

fn get(path: &str) -> Request<http_body_util::Empty<bytes::Bytes>> {
    Request::builder()
        .method("GET")
        .uri(path)
        .body(http_body_util::Empty::new())
        .unwrap()
}

#[tokio::test]
async fn a_request_goes_under_the_relay_prefix_with_the_bearer() {
    let (host, seen) =
        serve_once("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await;
    let (_dir, remote) = signed_in(&host);
    let response = remote
        .buffered(get("/v1/apps?x=1"), None, "request")
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    let request = seen.await.unwrap();
    assert!(request.starts_with("GET /_weglarka/api/v1/apps?x=1 HTTP/1.1\r\n"));
    let lower = request.to_ascii_lowercase();
    assert!(lower.contains("authorization: bearer access1\r\n"));
    assert!(lower.contains(&format!("host: {}\r\n", host.trim_start_matches("http://"))));
}

#[tokio::test]
async fn not_being_signed_in_is_reported_before_any_connection() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path().join("credentials.toml"));
    let remote = Remote::with_parts("http://127.0.0.1:9", HyperTransport::new(), store).unwrap();
    let err = remote
        .buffered(get("/v1/apps"), None, "request")
        .await
        .unwrap_err();
    assert_eq!(err.kind, Kind::NotFound);
    assert!(err.message.contains("not signed in"));
}

#[tokio::test]
async fn an_unreachable_host_is_unreachable_not_internal() {
    // Port 9 (discard) is closed on loopback in the test environment.
    let (_dir, remote) = signed_in("http://127.0.0.1:9");
    let err = remote
        .buffered(get("/v1/apps"), None, "request")
        .await
        .unwrap_err();
    assert_eq!(err.kind, Kind::Unreachable);
    assert!(!err.message.contains("ACCESS1"));
}
