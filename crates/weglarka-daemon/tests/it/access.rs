//! `GET /v1/apps/{name}/access` (docs/decisions/0063, ADR 0070) over the real admin sockets:
//! the boundary between apps, the `admin` scope, errors before the stream starts, the file history,
//! follow from the byte where history stopped and where a stream ends. The log is a real file under
//! `<state>/ingress-logs`, so no Podman log stream is involved.

use crate::common::*;
use crate::logs::{STEP, deployed_app, open, read_all, token_for};
use crate::token_api::setup;

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use hyper::StatusCode;
use serde_json::json;
use weglarka_api::{
    ACCESS_STREAM_CONTENT_TYPE, AccessEntry, AccessFrame, AccessFrameDecoder, endpoints,
};

fn access_path(app: &str) -> String {
    endpoints::APPS_ACCESS.path.replace("{name}", app)
}

fn line(app: &str, status: u16, path: &str) -> String {
    let now = weglarka_model::secrets::rfc3339_utc(std::time::SystemTime::now());
    line_at(&now, app, status, path)
}

fn line_at(time: &str, app: &str, status: u16, path: &str) -> String {
    format!(
        "{{\"time\":\"{time}\",\"app\":\"{app}\",\"host\":\"{app}.example.com\",\
         \"remote_addr\":\"203.0.113.7\",\"method\":\"GET\",\"path\":\"{path}\",\"status\":{status},\
         \"bytes_sent\":5,\"request_time\":0.001,\"upstream_response_time\":\"0.001\",\
         \"request_id\":\"r\",\"user_agent\":\"curl\",\"secret_new_field\":\"leak\"}}\n"
    )
}

fn traffic() -> String {
    [
        line("web", 200, "/a"),
        line("other", 200, "/their-secret"),
        line("web", 503, "/b"),
        line("-", 200, "/unattributed"),
    ]
    .concat()
}

fn log_dir(h: &Harness) -> PathBuf {
    h.root.join("state").join("ingress-logs")
}

fn write_log(h: &Harness, name: &str, text: &str) {
    let dir = log_dir(h);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join(name), text).unwrap();
}

fn append_log(h: &Harness, text: &str) {
    let dir = log_dir(h);
    fs::create_dir_all(&dir).unwrap();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("access.log"))
        .unwrap();
    file.write_all(text.as_bytes()).unwrap();
    file.flush().unwrap();
}

async fn frames(response: hyper::Response<hyper::body::Incoming>) -> Vec<AccessFrame> {
    let mut decoder = AccessFrameDecoder::default();
    read_all(response, STEP, |data| decoder.push(data).unwrap()).await
}

fn paths(frames: &[AccessFrame]) -> Vec<String> {
    frames
        .iter()
        .filter_map(|f| match f {
            AccessFrame::Entry(AccessEntry { path, .. }) => Some(path.clone()),
            _ => None,
        })
        .collect()
}

/// Reads frames until `seen` contains `want`, or the stream ends; returns the decoded frames.
async fn frames_until(
    response: &mut hyper::Response<hyper::body::Incoming>,
    decoder: &mut AccessFrameDecoder,
    seen: &mut Vec<AccessFrame>,
    want: &str,
) {
    while paths(seen).iter().all(|path| path != want) {
        let frame = tokio::time::timeout(STEP, http_body_util::BodyExt::frame(response.body_mut()))
            .await
            .expect("a frame before the timeout")
            .expect("a frame")
            .expect("a body frame");
        seen.extend(decoder.push(&frame.into_data().unwrap()).unwrap());
    }
}

#[tokio::test]
async fn an_admin_token_gets_only_its_apps_lines_and_not_unknown_fields() {
    let s = setup().await;
    deployed_app(&s.h).await;
    write_log(&s.h, "access.log", &traffic());
    let token = s.issuer.token("adam", &["admins"]);

    let response = open(
        &s.token_socket,
        "GET",
        &access_path("web"),
        Some(&token),
        vec![],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-type"],
        ACCESS_STREAM_CONTENT_TYPE
    );
    let got = frames(response).await;
    assert_eq!(paths(&got), ["/a", "/b"]);
    assert_eq!(got.last(), Some(&AccessFrame::End));
    let AccessFrame::Entry(first) = &got[0] else {
        panic!()
    };
    assert_eq!(
        (first.status, first.host.as_str()),
        (200, "web.example.com")
    );
    // The frame is the allowlisted entry: no `app`, no field nginx added.
    let wire = serde_json::to_string(first).unwrap();
    assert!(
        !wire.contains("leak") && !wire.contains("\"app\""),
        "{wire}"
    );
}

#[tokio::test]
async fn filters_and_tail_apply_in_the_daemon() {
    let s = setup().await;
    deployed_app(&s.h).await;
    write_log(&s.h, "access.log", &traffic());
    let token = s.issuer.token("adam", &["admins"]);
    for (query, want) in [
        ("status=5xx", vec!["/b"]),
        ("tail=1", vec!["/b"]),
        ("tail=0", vec![]),
        ("path=/a", vec!["/a"]),
        ("method=POST", vec![]),
        ("host=web.example.com&status=200", vec!["/a"]),
    ] {
        let response = open(
            &s.token_socket,
            "GET",
            &format!("{}?{query}", access_path("web")),
            Some(&token),
            vec![],
        )
        .await;
        assert_eq!(paths(&frames(response).await), want, "{query}");
    }
}

#[tokio::test]
async fn a_read_token_is_refused_before_anything_is_read() {
    let s = setup().await;
    deployed_app(&s.h).await;
    write_log(&s.h, "access.log", &traffic());
    let reader = s.issuer.token("rita", &["viewers"]);
    let (status, _, body) = crate::token_api::call(
        &s.token_socket,
        "GET",
        &access_path("web"),
        Some(&reader),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn bad_requests_fail_with_json_before_the_stream_starts() {
    let s = setup().await;
    let token = s.issuer.token("adam", &["admins"]);
    deployed_app(&s.h).await;
    let get = |path: String| {
        let (socket, token) = (s.token_socket.clone(), token.clone());
        async move {
            let (status, _, body) =
                crate::token_api::call(&socket, "GET", &path, Some(&token), None).await;
            (status, body)
        }
    };
    let (status, body) = get(access_path("nope")).await;
    assert_eq!(
        (status, &body["code"]),
        (StatusCode::NOT_FOUND, &json!("not_found"))
    );
    let (status, _) = get(access_path("Not_A_Name")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    for bad in [
        "x=1",
        "tail=1001",
        "status=6xx",
        "method=get",
        "path=/a%2fb",
        "host=A.example.com",
        "follow=true&follow=true",
    ] {
        let (status, body) = get(format!("{}?{bad}", access_path("web"))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {body}");
    }
}

#[tokio::test]
async fn without_logs_the_stream_is_empty_not_an_error() {
    let s = setup().await;
    deployed_app(&s.h).await;
    // No log file: history is empty and the stream ends cleanly. The old endpoint answered 404 here
    // because the log lived in the container.
    let token = s.issuer.token("adam", &["admins"]);
    let response = open(
        &s.token_socket,
        "GET",
        &access_path("web"),
        Some(&token),
        vec![],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(frames(response).await, [AccessFrame::End]);
    assert_eq!(s.h.fake.open_log_streams(), 0, "no Podman log stream");
}

#[tokio::test]
async fn follow_reads_history_first_and_then_the_appended_lines_once() {
    let s = setup().await;
    deployed_app(&s.h).await;
    write_log(&s.h, "access.log", &line("web", 200, "/a"));
    let token = token_for(&s, "adam", &["admins"], Duration::from_secs(5));

    let mut response = open(
        &s.token_socket,
        "GET",
        &format!("{}?follow=true", access_path("web")),
        Some(&token),
        vec![],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut decoder = AccessFrameDecoder::default();
    let mut seen = Vec::new();
    frames_until(&mut response, &mut decoder, &mut seen, "/a").await;
    append_log(&s.h, &line("web", 200, "/b"));

    // Drain to the token's end; `/a` from history, `/b` from follow, no duplicate.
    loop {
        let frame = tokio::time::timeout(
            Duration::from_secs(6),
            http_body_util::BodyExt::frame(response.body_mut()),
        )
        .await
        .expect("the token ends the stream")
        .expect("a frame")
        .expect("a body frame");
        seen.extend(decoder.push(&frame.into_data().unwrap()).unwrap());
        if seen.iter().any(|f| matches!(f, AccessFrame::TokenExpired)) {
            break;
        }
    }
    assert_eq!(paths(&seen), ["/a", "/b"]);
    assert_eq!(seen.last(), Some(&AccessFrame::TokenExpired));
}

#[tokio::test]
async fn since_filters_by_the_line_timestamp() {
    let s = setup().await;
    deployed_app(&s.h).await;
    write_log(
        &s.h,
        "access.log",
        &(line_at("2023-01-01T00:00:00+00:00", "web", 200, "/old")
            + &line_at("2025-01-01T00:00:00+00:00", "web", 200, "/new")),
    );
    let token = s.issuer.token("adam", &["admins"]);
    let response = open(
        &s.token_socket,
        "GET",
        &format!("{}?since=1700000000.5", access_path("web")),
        Some(&token),
        vec![],
    )
    .await;
    assert_eq!(paths(&frames(response).await), ["/new"]);
}

#[tokio::test]
async fn a_quiet_followed_stream_ends_at_the_token_expiry() {
    let s = setup().await;
    deployed_app(&s.h).await;
    write_log(&s.h, "access.log", "");
    let token = token_for(&s, "adam", &["admins"], Duration::from_secs(3));
    let started = std::time::Instant::now();
    let response = open(
        &s.token_socket,
        "GET",
        &format!("{}?follow=true", access_path("web")),
        Some(&token),
        vec![],
    )
    .await;
    assert_eq!(frames(response).await, [AccessFrame::TokenExpired]);
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(s.h.fake.open_log_streams(), 0);
}

#[tokio::test]
async fn a_client_hanging_up_ends_the_file_stream() {
    let s = setup().await;
    deployed_app(&s.h).await;
    write_log(&s.h, "access.log", &line("web", 200, "/a"));
    let token = s.issuer.token("adam", &["admins"]);
    let mut response = open(
        &s.token_socket,
        "GET",
        &format!("{}?follow=true", access_path("web")),
        Some(&token),
        vec![],
    )
    .await;
    let first = tokio::time::timeout(STEP, http_body_util::BodyExt::frame(response.body_mut()))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(first.into_data().is_ok());
    assert_eq!(s.h.fake.open_log_streams(), 0);
    drop(response);
}

#[tokio::test]
async fn the_unix_socket_has_no_deadline() {
    let h = harness().await;
    deployed_app(&h).await;
    write_log(&h, "access.log", &line("web", 200, "/a"));
    let mut response = open(
        &h.running.admin_socket,
        "GET",
        &format!("{}?follow=true", access_path("web")),
        None,
        vec![],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut decoder = AccessFrameDecoder::default();
    let mut seen = Vec::new();
    frames_until(&mut response, &mut decoder, &mut seen, "/a").await;
    assert_eq!(paths(&seen), ["/a"]);
    assert!(
        tokio::time::timeout(
            Duration::from_secs(2),
            http_body_util::BodyExt::frame(response.body_mut())
        )
        .await
        .is_err()
    );
    assert_eq!(h.fake.open_log_streams(), 0);
    drop(response);
}
