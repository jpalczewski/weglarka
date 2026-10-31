//! `GET /v1/events` (docs/decisions/0057): recent domain events over the unix socket and over the
//! token listener with a `read` bearer.

use crate::common::*;
use crate::token_api::{call, setup};

use hyper::StatusCode;
use serde_json::{Value, json};

fn kinds(body: &Value) -> Vec<&str> {
    body["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap())
        .collect()
}

#[tokio::test]
async fn a_deploy_shows_up_in_the_history_and_since_pages_through_it() {
    let h = harness().await;
    add(&h, "x", spec("x.example.com")).await;
    deployed(&h, "x").await;

    let (status, body) = admin(&h, "GET", "/v1/events", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(kinds(&body).contains(&"deploy_ok"), "{body}");
    let ok = body["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["kind"] == "deploy_ok")
        .unwrap();
    assert_eq!(ok["app"], "x");
    assert_eq!(ok["severity"], "info");
    assert_eq!(ok["message"], "deployed x");
    assert!(ok["ts"].as_str().unwrap().ends_with('Z'), "{ok}");
    assert_eq!(body["oldest_seq"], 1);
    assert_eq!(body["dropped"], false);

    // The cursor from the answer yields nothing new until something else happens.
    let next = body["next_seq"].as_u64().unwrap();
    assert!(next >= 1);
    let (_, again) = admin(&h, "GET", &format!("/v1/events?since={next}"), None).await;
    assert_eq!(again["events"], json!([]));
    assert_eq!(again["next_seq"], next);

    // A cursor from another process is ignored, and the answer says so.
    let boot = body["boot_id"].as_str().unwrap();
    let (_, same) = admin(
        &h,
        "GET",
        &format!("/v1/events?since={next}&boot={boot}"),
        None,
    )
    .await;
    assert_eq!(same["reset"], false);
    let (_, other) = admin(
        &h,
        "GET",
        &format!("/v1/events?since={next}&boot=dead-beef"),
        None,
    )
    .await;
    assert_eq!(other["reset"], true);
    assert_eq!(other["events"], body["events"]);
    assert_eq!(other["dropped"], false);

    let (status, bad) = admin(&h, "GET", "/v1/events?since=soon", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    h.running.stop().await;
}

#[tokio::test]
async fn limit_keeps_the_newest_events_oldest_first() {
    let h = harness().await;
    add(&h, "x", spec("x.example.com")).await;
    deployed(&h, "x").await;
    add(&h, "y", spec("y.example.com")).await;
    deployed(&h, "y").await;
    let (_, all) = admin(&h, "GET", "/v1/events", None).await;
    let all_events = all["events"].as_array().unwrap();
    assert!(all_events.len() >= 2, "{all}");

    let (status, one) = admin(&h, "GET", "/v1/events?limit=1", None).await;
    assert_eq!(status, StatusCode::OK, "{one}");
    assert_eq!(one["events"], json!([all_events.last().unwrap()]));
    // The cursor and the history bounds still describe everything, not the slice.
    assert_eq!(one["next_seq"], all["next_seq"]);
    assert_eq!(one["oldest_seq"], all["oldest_seq"]);

    let (_, big) = admin(&h, "GET", "/v1/events?limit=1000", None).await;
    assert_eq!(big["events"], all["events"]);

    // `since` selects first, `limit` then keeps the newest of those.
    let (_, after_first) = admin(&h, "GET", "/v1/events?since=1&limit=1", None).await;
    assert_eq!(after_first["events"], json!([all_events.last().unwrap()]));

    let (status, bad) = admin(&h, "GET", "/v1/events?limit=0", None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    h.running.stop().await;
}

#[tokio::test]
async fn a_read_token_may_read_events_and_a_missing_one_may_not() {
    let s = setup().await;
    let sock = &s.token_socket;
    let reader = s.issuer.token("rita", &["viewers"]);
    add(&s.h, "x", spec("x.example.com")).await;
    deployed(&s.h, "x").await;

    let (status, _, body) = call(sock, "GET", "/v1/events", Some(&reader), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(kinds(&body).contains(&"deploy_ok"), "{body}");

    let (status, _, _) = call(sock, "GET", "/v1/events", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    s.h.running.stop().await;
}
