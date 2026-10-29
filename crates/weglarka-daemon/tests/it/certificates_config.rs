//! `GET /v1/certificates` and `GET /v1/config` (docs/decisions/0057) over the unix socket and over
//! the token listener with a `read` bearer.

use crate::common::*;
use crate::token_api::{call, setup};

use hyper::StatusCode;
use serde_json::json;

#[tokio::test]
async fn certificates_are_an_empty_list_with_a_flag_without_acme() {
    let h = harness().await;
    let (status, body) = admin(&h, "GET", "/v1/certificates", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({ "acme_enabled": false, "failures": 0, "certificates": [] })
    );
    h.running.stop().await;
}

#[tokio::test]
async fn the_config_view_shows_the_allow_listed_settings_and_no_host_layout() {
    let h = harness().await;
    let (status, body) = admin(&h, "GET", "/v1/config", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["ingress"]["mode"], "behind");
    assert_eq!(body["ingress"]["bind"], "127.0.0.1:18080");
    assert_eq!(body["webhook"]["domain"], "hooks.example.eu");
    assert_eq!(body["host_configs"], false);
    assert!(body["monitor"]["crash_loop_restarts"].is_u64(), "{body}");
    for absent in ["notify", "acme", "identity", "self_update"] {
        assert!(body.get(absent).is_none(), "{absent} is off: {body}");
    }
    // The root of the test's data layout appears nowhere: no socket, state or file path.
    let text = body.to_string();
    let root = h.root.display().to_string();
    assert!(!text.contains(&root), "{text}");
    h.running.stop().await;
}

#[tokio::test]
async fn a_read_token_may_read_both_views_and_a_missing_one_may_not() {
    let s = setup().await;
    let sock = &s.token_socket;
    let reader = s.issuer.token("rita", &["viewers"]);
    for path in ["/v1/certificates", "/v1/config"] {
        let (status, _, body) = call(sock, "GET", path, Some(&reader), None).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
        let (status, _, _) = call(sock, "GET", path, None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
    }

    let (_, _, config) = call(sock, "GET", "/v1/config", Some(&reader), None).await;
    let http = &config["admin"]["http"];
    assert_eq!(http["clients"], json!(["panel"]));
    assert_eq!(http["audience"], "https://admin.example.com/api/");
    // The group names are authorization policy: only their number is shown.
    assert_eq!(http["read_groups"], 1);
    assert_eq!(http["admin_groups"], 1);
    let text = config.to_string();
    assert!(
        !text.contains("viewers") && !text.contains("admins"),
        "{text}"
    );
    assert_eq!(config["identity"]["issuer"], "https://auth.example.com");
    s.h.running.stop().await;
}
