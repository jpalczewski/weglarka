//! `GET /v1/apps/{name}/logs` (docs/decisions/0057) over the real admin sockets on `FakePodman`: the
//! framed stream, the `admin` scope, errors before the stream starts, and where a stream ends — at the
//! token's expiry on the token listener, never on the unix socket.

use crate::common::*;
use crate::token_api::{Setup, setup};

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use serde_json::json;
use tokio::net::UnixStream;
use weglarka_api::{
    ForwardFrame, ForwardFrameDecoder, LOGS_STREAM_CONTENT_TYPE, LogFrame, LogFrameDecoder,
    endpoints,
};
use weglarka_engine::testing::{Call, LogScript, RunScript};
use weglarka_model::admin_auth::testing::{AUDIENCE, ISSUER};
use weglarka_model::podman::{LogOptions, LogSource};

pub(crate) const STEP: Duration = Duration::from_secs(10);

fn logs_path(app: &str) -> String {
    endpoints::APPS_LOGS.path.replace("{name}", app)
}

pub(crate) fn script(output: &[(LogSource, &str)], hold_open: bool) -> LogScript {
    LogScript {
        output: output
            .iter()
            .map(|(source, text)| (*source, text.as_bytes().to_vec()))
            .collect(),
        hold_open,
    }
}

/// Opens a request on `socket` and returns the response as soon as its headers are there; the body
/// is read by the caller, a frame at a time.
pub(crate) async fn open(
    socket: &Path,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Vec<u8>,
) -> Response<Incoming> {
    let stream = UnixStream::connect(socket).await.unwrap();
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "weglarka");
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .unwrap();
    tokio::spawn(conn);
    tokio::time::timeout(
        STEP,
        sender.send_request(req.body(Full::new(Bytes::from(body))).unwrap()),
    )
    .await
    .expect("headers in time")
    .unwrap()
}

/// Reads `response` to its end and decodes it with `decode`; panics if it does not end within `within`.
pub(crate) async fn read_all<T>(
    mut response: Response<Incoming>,
    within: Duration,
    mut decode: impl FnMut(&[u8]) -> Vec<T>,
) -> Vec<T> {
    let mut frames = Vec::new();
    let read = async {
        while let Some(frame) = response.body_mut().frame().await {
            if let Ok(data) = frame.unwrap().into_data() {
                frames.extend(decode(&data));
            }
        }
    };
    tokio::time::timeout(within, read)
        .await
        .expect("the stream did not end in time");
    frames
}

async fn read_log_frames(response: Response<Incoming>, within: Duration) -> Vec<LogFrame> {
    let mut decoder = LogFrameDecoder::default();
    read_all(response, within, |data| decoder.push(data).unwrap()).await
}

pub(crate) fn log_calls(h: &Harness) -> Vec<(String, LogOptions)> {
    h.fake
        .calls()
        .into_iter()
        .filter_map(|c| match c {
            Call::ContainerLogs { name, options } => Some((name, options)),
            _ => None,
        })
        .collect()
}

/// A token with `groups` that expires `lifetime` from now.
pub(crate) fn token_for(s: &Setup, sub: &str, groups: &[&str], lifetime: Duration) -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    s.issuer.sign(&json!({
        "iss": ISSUER, "aud": [AUDIENCE], "sub": sub,
        "exp": (now + lifetime).as_secs_f64(), "nbf": now.as_secs() - 5, "groups": groups,
    }))
}

pub(crate) async fn deployed_app(h: &Harness) -> String {
    add(h, "web", spec("web.example.com")).await;
    deployed(h, "web").await;
    "wg-web".to_owned()
}

fn container_of(h: &Harness) -> String {
    h.fake
        .containers()
        .into_iter()
        .map(|c| c.name)
        .find(|n| !n.starts_with("wg-fwd.") && !n.contains("nginx") && !n.contains("forwarder"))
        .expect("the app's container")
}

#[tokio::test]
async fn an_admin_token_streams_the_log_and_the_query_reaches_podman() {
    let s = setup().await;
    deployed_app(&s.h).await;
    let container = container_of(&s.h);
    s.h.fake.script_logs(
        &container,
        script(
            &[
                (LogSource::Stdout, "starting\n"),
                (LogSource::Stderr, "warning\n"),
            ],
            false,
        ),
    );
    let admin_token = s.issuer.token("adam", &["admins"]);

    let response = open(
        &s.token_socket,
        "GET",
        &format!(
            "{}?tail=50&since=1700000000.5&timestamps=true",
            logs_path("web")
        ),
        Some(&admin_token),
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], LOGS_STREAM_CONTENT_TYPE);
    assert_eq!(
        read_log_frames(response, STEP).await,
        [
            LogFrame::Stdout(b"starting\n".to_vec()),
            LogFrame::Stderr(b"warning\n".to_vec()),
            LogFrame::End
        ]
    );
    assert_eq!(
        log_calls(&s.h),
        [(
            container,
            LogOptions {
                follow: false,
                tail: Some(50),
                since: Some(UNIX_EPOCH + Duration::new(1_700_000_000, 500_000_000)),
                timestamps: true,
            }
        )]
    );
}

#[tokio::test]
async fn a_line_split_into_records_has_one_timestamp_at_its_start() {
    let s = setup().await;
    deployed_app(&s.h).await;
    let container = container_of(&s.h);
    s.h.fake.script_logs(
        &container,
        script(
            &[
                (LogSource::Stdout, "2026-10-31T10:00:00.1Z long "),
                (LogSource::Stdout, "2026-10-31T10:00:00.1Z line"),
                (LogSource::Stdout, "2026-10-31T10:00:00.1Z  end\n"),
                (LogSource::Stdout, "2026-10-31T10:00:01Z next\n"),
            ],
            false,
        ),
    );
    let admin_token = s.issuer.token("adam", &["admins"]);
    let with = |query: &str| format!("{}?{query}", logs_path("web"));
    let response = open(
        &s.token_socket,
        "GET",
        &with("timestamps=true"),
        Some(&admin_token),
        Vec::new(),
    )
    .await;
    assert_eq!(
        read_log_frames(response, STEP).await,
        [
            LogFrame::Stdout(b"2026-10-31T10:00:00.1Z long ".to_vec()),
            LogFrame::Stdout(b"line".to_vec()),
            LogFrame::Stdout(b" end\n".to_vec()),
            LogFrame::Stdout(b"2026-10-31T10:00:01Z next\n".to_vec()),
            LogFrame::End
        ]
    );
}

#[tokio::test]
async fn a_read_token_is_refused_before_anything_is_read() {
    let s = setup().await;
    deployed_app(&s.h).await;
    let reader = s.issuer.token("rita", &["viewers"]);
    let (status, _, body) = crate::token_api::call(
        &s.token_socket,
        "GET",
        &logs_path("web"),
        Some(&reader),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(log_calls(&s.h).is_empty());
}

#[tokio::test]
async fn bad_requests_fail_with_json_before_the_stream_starts() {
    let s = setup().await;
    let admin_token = s.issuer.token("adam", &["admins"]);
    let mut stopped = spec("idle.example.com");
    stopped["start"] = json!(false);
    add(&s.h, "idle", stopped).await;
    deployed_app(&s.h).await;
    let get = |path: String| {
        let (socket, token) = (s.token_socket.clone(), admin_token.clone());
        async move {
            let (status, _, body) =
                crate::token_api::call(&socket, "GET", &path, Some(&token), None).await;
            (status, body)
        }
    };

    let (status, body) = get(logs_path("nope")).await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::NOT_FOUND, &json!("not_found"))
    );
    // Declared, but nothing runs: provisioned only.
    let (status, body) = get(logs_path("idle")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert!(body["message"].as_str().unwrap().contains("no container"));
    let (status, body) = get(logs_path("Not_A_Name")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    for bad in [
        "x=1",
        "tail=5%26until%3D1",
        "follow=yes",
        "since=1.",
        "tail=10001",
    ] {
        let (status, body) = get(format!("{}?{bad}", logs_path("web"))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {body}");
    }
    assert!(log_calls(&s.h).is_empty(), "nothing reached podman");
}

#[tokio::test]
async fn a_followed_stream_ends_at_the_token_expiry_and_lets_go_of_podman() {
    let s = setup().await;
    deployed_app(&s.h).await;
    let container = container_of(&s.h);
    s.h.fake
        .script_logs(&container, script(&[(LogSource::Stdout, "hi\n")], true));
    let token = token_for(&s, "adam", &["admins"], Duration::from_secs(3));

    let started = std::time::Instant::now();
    let response = open(
        &s.token_socket,
        "GET",
        &format!("{}?follow=true", logs_path("web")),
        Some(&token),
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let frames = read_log_frames(response, STEP).await;
    assert_eq!(
        frames,
        [LogFrame::Stdout(b"hi\n".to_vec()), LogFrame::TokenExpired]
    );
    // The token had at most 3 s (the claim is whole seconds, so up to a second less): the stream is
    // over then, not a verification leeway later.
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "{:?}",
        started.elapsed()
    );
    eventually("the podman stream is dropped", || async {
        s.h.fake.open_log_streams() == 0
    })
    .await;
}

#[tokio::test]
async fn a_client_hanging_up_drops_the_podman_stream() {
    let s = setup().await;
    deployed_app(&s.h).await;
    let container = container_of(&s.h);
    s.h.fake
        .script_logs(&container, script(&[(LogSource::Stdout, "hi\n")], true));
    let admin_token = s.issuer.token("adam", &["admins"]);

    let mut response = open(
        &s.token_socket,
        "GET",
        &format!("{}?follow=true", logs_path("web")),
        Some(&admin_token),
        Vec::new(),
    )
    .await;
    let first = tokio::time::timeout(STEP, response.body_mut().frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(first.into_data().is_ok());
    assert_eq!(s.h.fake.open_log_streams(), 1);
    drop(response);
    eventually("the podman stream is dropped", || async {
        s.h.fake.open_log_streams() == 0
    })
    .await;
}

#[tokio::test]
async fn the_unix_socket_has_no_deadline() {
    let h = harness().await;
    deployed_app(&h).await;
    let container = container_of(&h);
    h.fake
        .script_logs(&container, script(&[(LogSource::Stdout, "hi\n")], true));

    let mut response: Response<Incoming> = open(
        &h.running.admin_socket,
        "GET",
        &format!("{}?follow=true", logs_path("web")),
        None,
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut decoder = LogFrameDecoder::default();
    let first = tokio::time::timeout(STEP, response.body_mut().frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        decoder.push(&first.into_data().unwrap()).unwrap(),
        [LogFrame::Stdout(b"hi\n".to_vec())]
    );
    // Nothing ends it by itself: no further frame in a while, and the podman stream is still open.
    assert!(
        tokio::time::timeout(Duration::from_secs(2), response.body_mut().frame())
            .await
            .is_err()
    );
    assert_eq!(h.fake.open_log_streams(), 1);
    drop(response);
    eventually("the podman stream is dropped", || async {
        h.fake.open_log_streams() == 0
    })
    .await;
}

#[tokio::test]
async fn a_forward_ends_at_the_token_expiry_and_removes_its_relay() {
    let s = setup().await;
    deployed_app(&s.h).await;
    s.h.fake.script_next_run(RunScript {
        hang: true,
        ..Default::default()
    });
    let token = token_for(&s, "adam", &["admins"], Duration::from_secs(3));

    let response = open(
        &s.token_socket,
        "POST",
        "/v1/apps/web/forward",
        Some(&token),
        json!({ "port": 8085 }).to_string().into_bytes(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut decoder = ForwardFrameDecoder::default();
    let frames = read_all(response, STEP, |data| decoder.push(data).unwrap()).await;
    let [ForwardFrame::Ready { .. }, ForwardFrame::TokenExpired] = frames.as_slice() else {
        panic!("{frames:?}")
    };
    eventually("the relay is removed", || async {
        !s.h.fake
            .containers()
            .iter()
            .any(|c| c.name.starts_with("wg-fwd."))
    })
    .await;
}
