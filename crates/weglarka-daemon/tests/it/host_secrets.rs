//! Host credentials through the admin API (real unix socket, FakePodman): set/list/remove, the
//! allowlist list view, scope enforcement on the token listener, and the `host.credentials` /
//! `host.orphan_secrets` doctor checks (ADR 0079).

use crate::common::*;
use crate::token_api;

use hyper::StatusCode;
use serde_json::{Value, json};

const NOTIFY: &str = r#"
[notify.ntfy]
url = "https://ntfy.example.com"
topic = "weglarka"
"#;

async fn doctor(h: &Harness) -> Value {
    let (s, v) = admin(h, "GET", "/v1/doctor", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v
}

fn check<'a>(report: &'a Value, id: &str) -> Option<&'a Value> {
    report["checks"].as_array()?.iter().find(|c| c["id"] == id)
}

async fn set_host_secret(h: &Harness, name: &str, value: &str) -> Value {
    let (s, v) = admin(
        h,
        "PUT",
        &format!("/v1/host/secrets/{name}"),
        Some(json!({ "value": value })),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v
}

#[tokio::test]
async fn host_secret_set_list_remove_round_trip_and_the_list_view_has_no_value() {
    let h = harness().await;

    let info = set_host_secret(&h, "ntfy-token", "s3cr3t").await;
    assert_eq!(info["name"], "ntfy-token", "{info}");
    assert_eq!(info["fingerprint"].as_str().unwrap().len(), 8, "{info}");
    assert!(info["updated_at"].as_str().is_some(), "{info}");
    assert!(!info.to_string().contains("s3cr3t"), "{info}");

    let (s, list) = admin(&h, "GET", "/v1/host/secrets", None).await;
    assert_eq!(s, StatusCode::OK, "{list}");
    let rows = list["secrets"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "{list}");
    let row = &rows[0];
    // Allowlist projection: exactly name/fingerprint/updated_at, never the value.
    assert_eq!(row.as_object().unwrap().len(), 3, "{row}");
    assert_eq!(row["name"], "ntfy-token", "{row}");
    assert_eq!(row["fingerprint"], info["fingerprint"], "{row}");
    assert_eq!(row["updated_at"], info["updated_at"], "{row}");
    assert!(!list.to_string().contains("s3cr3t"), "{list}");

    // The value lives on disk (for the daemon's own readers), never in an API answer.
    assert!(
        read(&h.root.join("state/host-secrets.toml")).contains("s3cr3t"),
        "{}",
        read(&h.root.join("state/host-secrets.toml"))
    );

    // Remove: 204, then 404, then an empty list.
    let (s, v) = admin(&h, "DELETE", "/v1/host/secrets/ntfy-token", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{v}");
    let (s, v) = admin(&h, "DELETE", "/v1/host/secrets/ntfy-token", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{v}");
    let (_, list) = admin(&h, "GET", "/v1/host/secrets", None).await;
    assert!(
        list["secrets"].as_array().is_some_and(Vec::is_empty),
        "{list}"
    );

    h.running.stop().await;
}

#[tokio::test]
async fn host_secret_rejects_a_bad_name_and_an_empty_value() {
    let h = harness().await;

    for bad in ["app.x", "x.dot"] {
        let (s, v) = admin(
            &h,
            "PUT",
            &format!("/v1/host/secrets/{bad}"),
            Some(json!({ "value": "v" })),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad} {v}");
        assert!(
            v["message"]
                .as_str()
                .unwrap_or_default()
                .contains("secret name must match"),
            "{v}"
        );
    }
    let (s, v) = admin(
        &h,
        "PUT",
        "/v1/host/secrets/token",
        Some(json!({ "value": "" })),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");

    let (_, list) = admin(&h, "GET", "/v1/host/secrets", None).await;
    assert!(
        list["secrets"].as_array().is_some_and(Vec::is_empty),
        "{list}"
    );

    h.running.stop().await;
}

#[tokio::test]
async fn host_secret_writes_need_admin_and_the_list_is_read() {
    let s = token_api::setup().await;
    let reader = s.issuer.token("rita", &["viewers"]);
    let admin_token = s.issuer.token("adam", &["admins"]);

    let (status, _, body) = token_api::call(
        &s.token_socket,
        "GET",
        "/v1/host/secrets",
        Some(&reader),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, _, body) = token_api::call(
        &s.token_socket,
        "PUT",
        "/v1/host/secrets/token",
        Some(&reader),
        Some(json!({ "value": "v" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let (status, _, body) = token_api::call(
        &s.token_socket,
        "DELETE",
        "/v1/host/secrets/token",
        Some(&reader),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let (status, _, body) = token_api::call(
        &s.token_socket,
        "PUT",
        "/v1/host/secrets/token",
        Some(&admin_token),
        Some(json!({ "value": "v" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, _, body) = token_api::call(
        &s.token_socket,
        "DELETE",
        "/v1/host/secrets/token",
        Some(&admin_token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    s.h.running.stop().await;
}

#[tokio::test]
async fn doctor_reports_an_ok_host_credential() {
    let h = Builder::new()
        .sections(&format!("{NOTIFY}token_secret = \"ntfy-token\"\n"))
        .build()
        .await;
    set_host_secret(&h, "ntfy-token", "s3cr3t").await;

    let report = doctor(&h).await;
    let check = check(&report, "host.credentials").expect("no host.credentials check");
    assert_eq!(check["status"], "ok", "{check}");
    assert!(
        check["message"]
            .as_str()
            .unwrap_or_default()
            .contains("host secret ntfy-token"),
        "{check}"
    );
    assert!(!check.to_string().contains("s3cr3t"), "{check}");

    h.running.stop().await;
}

#[tokio::test]
async fn doctor_fails_a_missing_host_credential_without_leaking() {
    let h = Builder::new()
        .sections(&format!("{NOTIFY}token_secret = \"missing-token\"\n"))
        .build()
        .await;

    let report = doctor(&h).await;
    let check = check(&report, "host.credentials").expect("no host.credentials check");
    assert_eq!(check["status"], "fail", "{check}");
    let message = check["message"].as_str().unwrap_or_default();
    assert!(message.contains("host secret missing-token"), "{message}");
    let hint = check["hint"].as_str().unwrap_or_default();
    assert!(hint.contains("secrets host set"), "{hint}");

    h.running.stop().await;
}

#[tokio::test]
async fn doctor_warns_about_host_secrets_no_config_references() {
    let h = Builder::new()
        .sections(&format!("{NOTIFY}token_secret = \"ntfy-token\"\n"))
        .build()
        .await;
    set_host_secret(&h, "ntfy-token", "s3cr3t").await;
    set_host_secret(&h, "stale-token", "old").await;

    let report = doctor(&h).await;
    let orphan = check(&report, "host.orphan_secrets").expect("no host.orphan_secrets check");
    assert_eq!(orphan["status"], "warn", "{orphan}");
    let message = orphan["message"].as_str().unwrap_or_default();
    assert!(message.contains("stale-token"), "{message}");
    assert!(!message.contains("ntfy-token"), "{message}");
    let hint = orphan["hint"].as_str().unwrap_or_default();
    assert!(hint.contains("secrets host remove"), "{hint}");

    h.running.stop().await;
}
