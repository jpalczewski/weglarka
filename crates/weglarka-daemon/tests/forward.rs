//! `POST /v1/apps/{name}/forward` (issue #108) over the real admin socket on `FakePodman`: the framed
//! response stream, errors before the stream starts, and that a hung-up client does not leave a relay
//! behind.

mod common;

use common::*;
use hyper::StatusCode;
use serde_json::json;
use weglarka_api::{ForwardFrame, ForwardFrameDecoder};
use weglarka_core::testing::{Call, RunScript};

fn frames(body: &[u8]) -> Vec<ForwardFrame> {
    let mut decoder = ForwardFrameDecoder::default();
    let frames = decoder.push(body).unwrap();
    assert!(decoder.is_clean(), "the stream ended inside a frame");
    frames
}

async fn deployed_app() -> Harness {
    let h = harness().await;
    add(&h, "ntfy", spec("ntfy.example.eu")).await;
    deployed(&h, "ntfy").await;
    h
}

fn relays(h: &Harness) -> Vec<String> {
    h.fake
        .containers()
        .into_iter()
        .map(|c| c.name)
        .filter(|n| n.starts_with("wg-fwd."))
        .collect()
}

fn hang() -> RunScript {
    RunScript {
        hang: true,
        ..Default::default()
    }
}

#[tokio::test]
async fn a_forward_announces_its_host_port_and_a_timeout_removes_the_relay() {
    let h = deployed_app().await;
    h.fake.script_next_run(hang());
    let (status, body) = raw(
        &h,
        "POST",
        "/v1/apps/ntfy/forward",
        json!({ "port": 8085, "timeout_secs": 1 })
            .to_string()
            .into_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let got = frames(&body);
    let [ForwardFrame::Ready { host_port }, ForwardFrame::TimedOut] = got.as_slice() else {
        panic!("{got:?}")
    };
    let relay = h
        .fake
        .created_specs()
        .into_iter()
        .find(|s| s.name.starts_with("wg-fwd."))
        .expect("a relay was created");
    assert_eq!(relay.publish[0].host_ip.as_deref(), Some("127.0.0.1"));
    assert_ne!(*host_port, 0);
    assert!(relays(&h).is_empty());
    assert!(h.fake.calls().iter().any(|c| matches!(
        c,
        Call::ContainerKill { name, signal } if name.starts_with("wg-fwd.") && signal == "KILL"
    )));
    assert!(
        h.fake.containers().iter().any(|c| c.name == "ntfy"),
        "the app itself is untouched"
    );
}

#[tokio::test]
async fn what_cannot_be_forwarded_is_refused_with_a_json_error_before_any_stream() {
    let h = deployed_app().await;
    for (path, body, expected) in [
        ("/v1/apps/ntfy/forward", json!({ "port": 0 }), 400),
        ("/v1/apps/ntfy/forward", json!({}), 400),
        ("/v1/apps/ntfy/forward", json!({ "port": 1, "x": 1 }), 400),
        ("/v1/apps/nope/forward", json!({ "port": 80 }), 404),
    ] {
        let (status, v) = admin(&h, "POST", path, Some(body.clone())).await;
        assert_eq!(status.as_u16(), expected, "{body}: {v}");
    }

    // Declared but not started: nothing to forward to.
    let mut idle = spec("idle.example.eu");
    idle["start"] = json!(false);
    add(&h, "idle", idle).await;
    deployed(&h, "idle").await;
    let (status, v) = admin(
        &h,
        "POST",
        "/v1/apps/idle/forward",
        Some(json!({ "port": 80 })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{v}");
    assert!(
        !h.fake
            .created_specs()
            .iter()
            .any(|s| s.name.starts_with("wg-fwd.")),
        "nothing was created"
    );
}

#[tokio::test]
async fn a_client_that_hangs_up_removes_the_relay() {
    let h = deployed_app().await;
    h.fake.script_next_run(hang());
    let stream = tokio::net::UnixStream::connect(&h.running.admin_socket)
        .await
        .unwrap();
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .unwrap();
    tokio::spawn(conn);
    let request = hyper::Request::builder()
        .method("POST")
        .uri("/v1/apps/ntfy/forward")
        .header("host", "weglarka")
        .body(http_body_util::Full::new(bytes::Bytes::from(
            json!({ "port": 8085 }).to_string(),
        )))
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    eventually("the relay exists", || async { relays(&h).len() == 1 }).await;
    drop(response);
    drop(sender);
    eventually("the relay is gone", || async { relays(&h).is_empty() }).await;
}
