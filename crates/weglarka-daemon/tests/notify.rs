//! Notifications (issue #38) on `FakePodman`: engine events reach a mock ntfy server through the
//! durable outbox, and `notify test`/`notify status` answer over the admin API.

mod common;

use common::*;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper::StatusCode;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const IMAGE: &str = "ghcr.io/jpalczewski/ntfy.zig:latest";

// ── Mock ntfy ────────────────────────────────────────────────────────────────

/// A mock ntfy server: records every request and answers with a configurable status.
struct Ntfy {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
    status: Arc<Mutex<u16>>,
    task: tokio::task::JoinHandle<()>,
}

impl Ntfy {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let status = Arc::new(Mutex::new(200u16));
        let (recorded, reply) = (requests.clone(), status.clone());
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let request = read_request(&mut stream).await;
                recorded.lock().unwrap().push(request);
                let code = *reply.lock().unwrap();
                let response = format!("HTTP/1.1 {code} X\r\nContent-Length: 0\r\n\r\n");
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        Self {
            addr,
            requests,
            status,
            task,
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn set_status(&self, status: u16) {
        *self.status.lock().unwrap() = status;
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }

    /// The JSON bodies of the publish requests, in arrival order.
    fn published(&self) -> Vec<Value> {
        self.requests()
            .iter()
            .filter_map(|request| {
                let (_, body) = request.split_once("\r\n\r\n")?;
                serde_json::from_str(body).ok()
            })
            .collect()
    }
}

impl Drop for Ntfy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Reads one complete HTTP request (head + `Content-Length` body); clients send `Connection: close`.
async fn read_request(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        if request_complete(&buf) {
            break;
        }
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

fn request_complete(buf: &[u8]) -> bool {
    let text = String::from_utf8_lossy(buf);
    let Some((head, body)) = text.split_once("\r\n\r\n") else {
        return false;
    };
    let mut length = 0usize;
    for line in head.split("\r\n") {
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
            && let Ok(parsed) = value.trim().parse::<usize>()
        {
            length = parsed;
        }
    }
    body.len() >= length
}

// ── Daemon harness ───────────────────────────────────────────────────────────

/// Starts the daemon; `ntfy` adds `[notify.ntfy]` (without it notifications stay off). The
/// reconcile interval is short because the crash-loop test waits for a periodic pass.
async fn harness(ntfy: Option<&Ntfy>) -> Harness {
    let notify = match ntfy {
        Some(ntfy) => format!(
            "[notify.ntfy]\nurl = \"{}\"\ntopic = \"weglarka\"\n",
            ntfy.url()
        ),
        None => String::new(),
    };
    Builder::new()
        .sections(&format!(
            "[runtime]\nreconcile_interval_secs = 1\n\n{notify}"
        ))
        .build()
        .await
}

fn app_body(name: &str, domain: &str) -> Value {
    json!({
        "name": name,
        "spec": {
            "image": IMAGE,
            "domains": [domain],
            "port": 8085,
            "health": { "attempts": 1, "window_secs": 1 }
        }
    })
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn status_and_test_endpoint_reach_ntfy() {
    let ntfy = Ntfy::start().await;
    let h = harness(Some(&ntfy)).await;

    let (status, body) = admin(&h, "GET", "/v1/notifications", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["enabled"], json!(true), "{body}");
    assert_eq!(body["channels"][0]["name"], json!("ntfy"), "{body}");
    assert_eq!(body["pending"], json!(0), "{body}");

    let (status, body) = admin(&h, "POST", "/v1/notifications/test", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["delivered"], json!(true), "{body}");

    let published = ntfy.published();
    assert_eq!(published.len(), 1, "{published:?}");
    assert_eq!(published[0]["topic"], json!("weglarka"));
    assert_eq!(published[0]["title"], json!("Węglarka test notification"));
    assert!(
        published[0]["message"]
            .as_str()
            .unwrap()
            .contains("hooks.example.eu"),
        "{published:?}"
    );
}

#[tokio::test]
async fn notifications_are_off_without_a_notify_section() {
    let h = harness(None).await;
    let (status, body) = admin(&h, "GET", "/v1/notifications", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["enabled"], json!(false), "{body}");
    assert_eq!(body["pending"], json!(0), "{body}");

    let (status, body) = admin(&h, "POST", "/v1/notifications/test", None).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], json!("conflict"), "{body}");
    assert!(
        body["message"].as_str().unwrap().contains("[notify.ntfy]"),
        "{body}"
    );
}

#[tokio::test]
async fn a_successful_deploy_is_published_once() {
    let ntfy = Ntfy::start().await;
    let h = harness(Some(&ntfy)).await;

    let (status, body) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(app_body("demo", "demo.example.eu")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    eventually("the deploy notification", || async {
        ntfy.published()
            .iter()
            .any(|p| p["title"] == json!("deployed demo"))
    })
    .await;

    let published = ntfy.published();
    let deploy: Vec<&Value> = published
        .iter()
        .filter(|p| p["title"] == json!("deployed demo"))
        .collect();
    assert_eq!(deploy.len(), 1, "{published:?}");
    assert_eq!(deploy[0]["severity"], json!(null), "not part of the body");
    assert_eq!(deploy[0]["click"], json!("https://demo.example.eu"));
    assert_eq!(deploy[0]["priority"], json!(3));

    // Delivered: the durable outbox is empty and nothing was dropped.
    let (_, body) = admin(&h, "GET", "/v1/notifications", None).await;
    assert_eq!(body["pending"], json!(0), "{body}");
    assert_eq!(body["dropped"], json!(0), "{body}");
    assert!(body["last_delivered_at"].is_string(), "{body}");
    let _ = h.fake;
}

#[tokio::test]
async fn a_failed_delivery_stays_in_the_outbox() {
    let ntfy = Ntfy::start().await;
    ntfy.set_status(500);
    let h = harness(Some(&ntfy)).await;

    let (status, body) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(app_body("demo", "demo.example.eu")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The notification is queued and kept: a deploy is not lost because ntfy is being redeployed.
    let outbox = h.root.join("state/notifications.toml");
    eventually("the pending notification", || {
        let outbox = outbox.clone();
        async move {
            std::fs::read_to_string(&outbox)
                .map(|src| src.contains("deployed demo") && src.contains("attempts = 1"))
                .unwrap_or(false)
        }
    })
    .await;

    let (status, body) = admin(&h, "GET", "/v1/notifications", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["pending"], json!(1), "{body}");
    assert!(
        body["last_error"].as_str().unwrap().contains("500"),
        "{body}"
    );

    // The retry is scheduled, not spammed: exactly one attempt so far.
    let published = ntfy.published();
    assert_eq!(published.len(), 1, "{published:?}");
    let src = std::fs::read_to_string(&outbox).unwrap();
    assert!(src.contains("title = \"deployed demo\""), "{src}");
    assert!(
        !src.contains("Authorization"),
        "no token in the outbox: {src}"
    );
}

/// Crash-loop detection (issue #112) rides the same pipeline: libpod's restart counter is observed by the
/// reconcile pass, becomes an engine event and reaches ntfy.
#[tokio::test]
async fn a_crash_loop_reaches_ntfy() {
    let ntfy = Ntfy::start().await;
    let h = harness(Some(&ntfy)).await;

    let (status, body) = admin(
        &h,
        "POST",
        "/v1/apps",
        Some(app_body("demo", "demo.example.eu")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    eventually("the deploy notification", || async {
        ntfy.published()
            .iter()
            .any(|p| p["title"] == json!("deployed demo"))
    })
    .await;

    // Below the default threshold (3 new restarts): no alert, the periodic pass must have seen it.
    h.fake.set_restarts("demo", 2);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(
        !ntfy
            .published()
            .iter()
            .any(|p| p["title"] == json!("crash loop: demo")),
        "two restarts are below the threshold"
    );

    h.fake.set_restarts("demo", 3);
    eventually("the crash-loop notification", || async {
        ntfy.published()
            .iter()
            .any(|p| p["title"] == json!("crash loop: demo"))
    })
    .await;

    let published = ntfy.published();
    let crash: Vec<&Value> = published
        .iter()
        .filter(|p| p["title"] == json!("crash loop: demo"))
        .collect();
    assert_eq!(crash.len(), 1, "{published:?}");
    assert_eq!(crash[0]["priority"], json!(5));
    assert_eq!(
        crash[0]["message"],
        json!("3 restarts; check the logs with `weglarka apps show demo`")
    );
}
