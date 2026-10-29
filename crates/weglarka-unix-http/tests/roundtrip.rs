use std::time::Duration;

use http_body_util::Full;
use weglarka_unix_http::testing::{Reply, mock, mock_with};
use weglarka_unix_http::{Bytes, Error, HeaderValue, Request, UnixClient, bearer};

fn get(path: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .uri(path)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn buffered_sends_headers_and_host() {
    let m = mock(|_, _| (200, "hello".into())).await;
    let client = UnixClient::new(&m.socket);
    let mut req = get("/x?a=b");
    req.headers_mut()
        .insert("authorization", bearer("tok").unwrap());
    let resp = client
        .buffered(req, Some(Duration::from_secs(5)))
        .await
        .unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(&resp.body[..], b"hello");
    let seen = m.seen.lock().unwrap();
    assert_eq!(seen[0].path, "/x");
    assert_eq!(seen[0].query.as_deref(), Some("a=b"));
    assert_eq!(seen[0].host.as_deref(), Some("localhost"));
    assert_eq!(seen[0].header("Authorization"), Some("Bearer tok"));
}

#[tokio::test(flavor = "current_thread")]
async fn open_streams_the_body() {
    let m = mock(|_, _| (200, "streamed".into())).await;
    let client = UnixClient::new(&m.socket);
    let mut resp = client.open(get("/s")).await.unwrap();
    assert_eq!(resp.status, 200);
    let mut got = Vec::new();
    while let Some(chunk) = resp.chunk().await {
        got.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(got, b"streamed");
}

#[tokio::test(flavor = "current_thread")]
async fn missing_socket_is_a_connect_error() {
    let client = UnixClient::new("/nonexistent/wgl.sock");
    let err = client.buffered(get("/"), None).await.unwrap_err();
    assert!(err.is_connect(), "{err}");
    assert!(matches!(err, Error::Connect(_)));
}

#[test]
fn bearer_is_sensitive_and_validated() {
    assert!(bearer("a\nb").is_err());
    assert!(format!("{:?}", bearer("secret").unwrap()).contains("Sensitive"));
}

#[tokio::test(flavor = "current_thread")]
async fn host_defaults_to_localhost_and_can_be_overridden() {
    let m = mock(|_, _| (204, String::new())).await;
    UnixClient::new(&m.socket)
        .buffered(get("/a"), None)
        .await
        .unwrap();
    UnixClient::new(&m.socket)
        .with_host(HeaderValue::from_static("panel"))
        .buffered(get("/b"), None)
        .await
        .unwrap();
    // A Host the request already carries is left alone.
    let mut req = get("/c");
    req.headers_mut()
        .insert("host", HeaderValue::from_static("own"));
    UnixClient::new(&m.socket)
        .buffered(req, None)
        .await
        .unwrap();
    let hosts: Vec<_> = m
        .seen
        .lock()
        .unwrap()
        .iter()
        .map(|s| s.host.clone().unwrap())
        .collect();
    assert_eq!(hosts, ["localhost", "panel", "own"]);
}

fn stalled() -> Reply {
    Reply::new(200, "late").head_delay(Duration::from_secs(30))
}

#[tokio::test(flavor = "current_thread")]
async fn a_stalled_head_times_out_with_the_head_timeout() {
    let m = mock_with(|_, _| stalled()).await;
    let client = UnixClient::new(&m.socket).with_head_timeout(Some(Duration::from_millis(100)));
    assert!(matches!(
        client.open(get("/")).await.err(),
        Some(Error::Timeout)
    ));
    assert!(matches!(
        client.buffered(get("/"), None).await.unwrap_err(),
        Error::Timeout
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn the_exchange_timeout_bounds_a_buffered_request() {
    let m = mock_with(|_, _| stalled()).await;
    let err = UnixClient::new(&m.socket)
        .buffered(get("/"), Some(Duration::from_millis(100)))
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Timeout), "{err}");
    assert!(!err.is_connect());
}

#[tokio::test(flavor = "current_thread")]
async fn the_head_timeout_does_not_cap_the_body() {
    // The head arrives at once; the body is not limited by the head timeout.
    let m = mock_with(|_, _| Reply::chunks(200, [Bytes::from("a"), Bytes::from("b")])).await;
    let client = UnixClient::new(&m.socket).with_head_timeout(Some(Duration::from_millis(100)));
    let resp = client.open(get("/")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(&resp.collect().await.unwrap()[..], b"ab");
}

#[tokio::test(flavor = "current_thread")]
async fn a_body_that_breaks_mid_stream_is_a_request_error() {
    let m = mock_with(|_, _| Reply::chunks(200, [Bytes::from("partial")]).fail_body()).await;
    let mut resp = UnixClient::new(&m.socket).open(get("/")).await.unwrap();
    // Whether "partial" is delivered before the break depends on flushing; the stream must end in
    // an error, never in a clean end.
    let err = loop {
        match resp.chunk().await.expect("the stream must not end cleanly") {
            Ok(_) => continue,
            Err(e) => break e,
        }
    };
    assert!(matches!(err, Error::Request(_)), "{err}");
    assert!(!err.is_connect());
}

#[test]
fn a_connect_timeout_counts_as_a_connect_failure() {
    // Not provokable against a unix socket (connect completes at once), so only the contract:
    // callers map `is_connect()` errors to "cannot reach the daemon".
    assert!(Error::ConnectTimeout.is_connect());
    assert_eq!(Error::ConnectTimeout.to_string(), "connection timed out");
    assert!(!Error::Timeout.is_connect());
}
