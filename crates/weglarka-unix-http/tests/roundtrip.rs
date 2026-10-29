use std::time::Duration;

use http_body_util::Full;
use weglarka_unix_http::testing::mock;
use weglarka_unix_http::{Bytes, Error, Request, UnixClient, bearer};

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
    while let Some(frame) = resp.frame().await {
        if let Some(data) = frame.unwrap().data_ref() {
            got.extend_from_slice(data);
        }
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
