//! `ingress_logs` and `[logs] reader` (issue #552, ADR 0072) through the admin API: only the
//! configured reader may set the flag, `doctor` reports `logs.reader`, `show` and the config view
//! carry the setting.

use crate::common::*;
use hyper::StatusCode;
use serde_json::{Value, json};

fn reader_spec() -> Value {
    let mut spec = spec("collector.example.com");
    spec["start"] = json!(false);
    spec["ingress_logs"] = json!(true);
    spec
}

async fn harness_with_reader(reader: Option<&str>) -> Harness {
    let sections = reader.map_or(String::new(), |r| format!("\n[logs]\nreader = {r:?}\n"));
    Builder::new().sections(&sections).build().await
}

#[tokio::test]
async fn only_the_configured_reader_may_set_ingress_logs() {
    let h = harness_with_reader(Some("collector")).await;

    let (status, body) = post_app(&h, "web", reader_spec()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.to_string().contains("[logs] reader"), "{body}");

    let (status, body) = post_app(&h, "collector", reader_spec()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let shown = show(&h, "collector").await;
    assert_eq!(shown["ingress_logs"], json!(true), "{shown}");
    assert_eq!(shown["spec"]["ingress_logs"], json!(true));

    let (status, config) = admin(&h, "GET", "/v1/config", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(config["logs_reader"], json!("collector"));
}

#[tokio::test]
async fn without_a_reader_nobody_may_set_it() {
    let h = harness_with_reader(None).await;
    let (status, body) = post_app(&h, "collector", reader_spec()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let mut plain = spec("plain.example.com");
    plain["start"] = json!(false);
    add(&h, "plain", plain).await;
    assert!(show(&h, "plain").await.get("ingress_logs").is_none());
}

#[tokio::test]
async fn doctor_reports_the_reader() {
    let h = harness_with_reader(Some("collector")).await;
    add(&h, "collector", reader_spec()).await;
    let (_, v) = admin(&h, "GET", "/v1/doctor", None).await;
    let check = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "logs.reader")
        .expect("logs.reader check");
    assert_eq!(check["status"], json!("ok"), "{check}");
}
