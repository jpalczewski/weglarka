//! `GET /v1/apps/{name}/access` (docs/decisions/0062) over the real admin sockets on `FakePodman`:
//! the boundary between apps, the `admin` scope, errors before the stream starts, the two-phase read
//! and where a stream ends. The fake ignores `since` and answers every read with the same script, so
//! with `follow` every entry shows up twice (history, then the live read) — asserted below on purpose.

use crate::common::*;
use crate::logs::{STEP, deployed_app, log_calls, open, read_all, script, token_for};
use crate::token_api::setup;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hyper::StatusCode;
use serde_json::json;
use weglarka_api::{
    ACCESS_STREAM_CONTENT_TYPE, AccessEntry, AccessFrame, AccessFrameDecoder, endpoints,
};
use weglarka_model::podman::{LogSource, PodmanClient};

const NGINX: &str = "weglarka-nginx";

fn access_path(app: &str) -> String {
    endpoints::APPS_ACCESS.path.replace("{name}", app)
}

fn line(app: &str, status: u16, path: &str) -> String {
    format!(
        "{{\"time\":\"2026-10-31T12:00:00+00:00\",\"app\":\"{app}\",\"host\":\"{app}.example.com\",\
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

fn script_nginx(h: &Harness, text: &str, hold_open: bool) {
    h.fake
        .script_logs(NGINX, script(&[(LogSource::Stdout, text)], hold_open));
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

#[tokio::test]
async fn an_admin_token_gets_only_its_apps_lines_and_not_unknown_fields() {
    let s = setup().await;
    deployed_app(&s.h).await;
    script_nginx(&s.h, &traffic(), false);
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
    script_nginx(&s.h, &traffic(), false);
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
    assert!(log_calls(&s.h).is_empty());
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
    assert!(log_calls(&s.h).is_empty(), "nothing reached podman");
}

#[tokio::test]
async fn without_an_ingress_container_the_answer_is_json_not_found() {
    let s = setup().await;
    deployed_app(&s.h).await;
    s.h.fake.container_remove(NGINX, true).await.unwrap();
    let token = s.issuer.token("adam", &["admins"]);
    let (status, _, body) = crate::token_api::call(
        &s.token_socket,
        "GET",
        &access_path("web"),
        Some(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert!(log_calls(&s.h).is_empty());
}

#[tokio::test]
async fn follow_reads_history_first_and_then_a_live_stream_from_t() {
    let s = setup().await;
    deployed_app(&s.h).await;
    script_nginx(&s.h, &line("web", 200, "/a"), true);
    let token = token_for(&s, "adam", &["admins"], Duration::from_secs(3));
    let before = SystemTime::now();

    let response = open(
        &s.token_socket,
        "GET",
        &format!("{}?follow=true", access_path("web")),
        Some(&token),
        vec![],
    )
    .await;
    let got = frames(response).await;
    // The fake gives both reads the same script, so the entry is there twice: at-least-once, no dedup.
    assert_eq!(paths(&got), ["/a", "/a"]);
    assert_eq!(got.last(), Some(&AccessFrame::TokenExpired));

    let calls = log_calls(&s.h);
    let nginx: Vec<_> = calls.iter().filter(|(n, _)| n == NGINX).collect();
    let [(_, history), (_, live)] = nginx.as_slice() else {
        panic!("{calls:?}")
    };
    assert!(!history.follow && history.tail.is_none() && !history.timestamps);
    assert!(live.follow && live.tail.is_none());
    // The default window is the last hour; the live read starts at T, taken before the history.
    let window = before.duration_since(history.since.unwrap()).unwrap();
    assert!((window.as_secs() as i64 - 3600).abs() <= 5, "{window:?}");
    let t = live.since.unwrap();
    assert!(
        t >= before - Duration::from_secs(1) && t <= SystemTime::now(),
        "{t:?}"
    );
}

#[tokio::test]
async fn an_explicit_since_reaches_the_history_read() {
    let s = setup().await;
    deployed_app(&s.h).await;
    script_nginx(&s.h, &traffic(), false);
    let token = s.issuer.token("adam", &["admins"]);
    let response = open(
        &s.token_socket,
        "GET",
        &format!("{}?since=1700000000.5", access_path("web")),
        Some(&token),
        vec![],
    )
    .await;
    frames(response).await;
    let calls = log_calls(&s.h);
    let (_, options) = calls.iter().find(|(n, _)| n == NGINX).unwrap();
    assert_eq!(
        options.since,
        Some(UNIX_EPOCH + Duration::new(1_700_000_000, 500_000_000))
    );
}

#[tokio::test]
async fn a_quiet_followed_stream_ends_at_the_token_expiry_and_lets_go_of_podman() {
    let s = setup().await;
    deployed_app(&s.h).await;
    script_nginx(&s.h, "", true);
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
    eventually("the podman stream is dropped", || async {
        s.h.fake.open_log_streams() == 0
    })
    .await;
}

#[tokio::test]
async fn a_client_hanging_up_drops_the_podman_stream() {
    let s = setup().await;
    deployed_app(&s.h).await;
    script_nginx(&s.h, &line("web", 200, "/a"), true);
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
    script_nginx(&h, &line("web", 200, "/a"), true);
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
    // History and the live read each deliver the entry; then nothing ends the stream by itself.
    while seen.len() < 2 {
        let frame = tokio::time::timeout(STEP, http_body_util::BodyExt::frame(response.body_mut()))
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        seen.extend(decoder.push(&frame.into_data().unwrap()).unwrap());
    }
    assert_eq!(paths(&seen), ["/a", "/a"]);
    assert!(
        tokio::time::timeout(
            Duration::from_secs(2),
            http_body_util::BodyExt::frame(response.body_mut())
        )
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
