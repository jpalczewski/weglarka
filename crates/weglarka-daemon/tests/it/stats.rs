//! `GET /v1/stats` and `GET /v1/apps/{name}/stats` (docs/decisions/0065): the `read` projection of the
//! shared resource snapshot, over the unix socket and over the token listener.

use std::collections::BTreeMap;

use crate::common::*;
use crate::token_api::{call, setup};

use hyper::StatusCode;
use serde_json::{Value, json};
use weglarka_engine::testing::FakePodman;
use weglarka_model::podman::{ContainerStats, NetworkIo};

fn stat(name: &str, mib: u64) -> ContainerStats {
    ContainerStats {
        name: name.to_owned(),
        memory_usage: mib << 20,
        cpu_nanos: 2_000_000_000,
        pids: 3,
        block_read_bytes: 10,
        block_write_bytes: 20,
        network: Some(NetworkIo {
            rx_bytes: 30,
            tx_bytes: 40,
        }),
    }
}

fn labelled(fake: &FakePodman, name: &str, labels: &[(&str, &str)]) {
    fake.add_foreign_container(name, IMAGE);
    fake.set_container_labels(
        name,
        labels
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect::<BTreeMap<_, _>>(),
    );
}

async fn app(h: &Harness, name: &str, memory: Option<&str>) {
    let mut spec = spec(&format!("{name}.example.com"));
    if let Some(memory) = memory {
        spec["resources"] = json!({ "memory": memory });
    }
    add(h, name, spec).await;
    deployed(h, name).await;
}

/// The response with the sampling time replaced, so a snapshot does not depend on the clock.
fn stable(mut body: Value) -> Value {
    fn walk(v: &mut Value) {
        match v {
            Value::Object(map) => {
                if map.get("sampled_at").is_some_and(Value::is_string) {
                    map.insert("sampled_at".into(), json!("<time>"));
                }
                map.values_mut().for_each(walk);
            }
            Value::Array(items) => items.iter_mut().for_each(walk),
            _ => {}
        }
    }
    walk(&mut body);
    body
}

#[tokio::test]
async fn a_blue_green_switch_shows_the_active_and_the_challenger() {
    let h = harness().await;
    app(&h, "alpha", Some("64M")).await;
    labelled(&h.fake, "alpha.next", &[("weglarka.instance", "alpha")]);
    h.fake.set_restarts("alpha", 2);
    h.fake
        .script_stats([stat("alpha", 5), stat("alpha.next", 6)]);

    let (status, body) = admin(&h, "GET", "/v1/apps/alpha/stats", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    insta::assert_json_snapshot!("app_blue_green", stable(body));
    h.running.stop().await;
}

#[tokio::test]
async fn zeros_and_a_missing_limit_are_null_and_nothing_identifies_a_container() {
    let h = harness().await;
    app(&h, "alpha", None).await;
    h.fake.script_stats([ContainerStats {
        name: "alpha".to_owned(),
        ..Default::default()
    }]);

    let (_, body) = admin(&h, "GET", "/v1/apps/alpha/stats", None).await;
    let row = &body["containers"][0];
    assert_eq!(row["memory_bytes"], Value::Null, "{body}");
    assert_eq!(row["memory_limit_bytes"], Value::Null, "{body}");
    assert_eq!(row["pids"], Value::Null, "{body}");
    insta::assert_json_snapshot!("app_no_data", stable(body.clone()));
    let text = body.to_string();
    for leak in ["container_id", "image", "example.com/app", "id-alpha"] {
        assert!(!text.contains(leak), "{leak}: {text}");
    }
    h.running.stop().await;
}

#[tokio::test]
async fn a_stopped_app_keeps_its_row_without_numbers_and_an_unknown_one_is_404() {
    let h = harness().await;
    app(&h, "alpha", None).await;
    h.fake.crash_container("alpha", 1);
    let (status, body) = admin(&h, "GET", "/v1/apps/alpha/stats", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["available"], true);
    // The row stays (restarts and OOM kills matter most for a dead container), every number is null.
    insta::assert_json_snapshot!("app_stopped", stable(body));

    let (status, _) = admin(&h, "GET", "/v1/apps/ghost/stats", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    h.running.stop().await;
}

#[tokio::test]
async fn one_off_containers_are_absent_and_every_app_is_listed_by_name() {
    let h = harness().await;
    app(&h, "beta", None).await;
    app(&h, "alpha", None).await;
    labelled(
        &h.fake,
        "alpha-run-abc123",
        &[("weglarka.instance", "alpha"), ("weglarka.run", "true")],
    );
    h.fake.script_stats([
        stat("alpha", 1),
        stat("beta", 2),
        stat("alpha-run-abc123", 3),
    ]);

    let (status, body) = admin(&h, "GET", "/v1/stats", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    insta::assert_json_snapshot!("all_apps", stable(body.clone()));
    assert!(!body.to_string().contains("run-abc123"), "{body}");
    h.running.stop().await;
}

#[tokio::test]
async fn a_libpod_error_is_available_false_and_not_a_5xx() {
    let h = harness().await;
    app(&h, "alpha", None).await;
    h.fake.fail_stats(Some("cgroup stats unavailable"));

    let (status, all) = admin(&h, "GET", "/v1/stats", None).await;
    assert_eq!(status, StatusCode::OK, "{all}");
    insta::assert_json_snapshot!("all_unavailable", all.clone());
    let (status, one) = admin(&h, "GET", "/v1/apps/alpha/stats", None).await;
    assert_eq!(status, StatusCode::OK, "{one}");
    insta::assert_json_snapshot!("app_unavailable", one.clone());
    assert!(!format!("{all}{one}").contains("cgroup"), "no libpod text");
    h.running.stop().await;
}

#[tokio::test]
async fn a_read_token_gets_200_no_token_gets_401_and_an_unknown_app_404() {
    let s = setup().await;
    add(&s.h, "alpha", spec("alpha.example.com")).await;
    deployed(&s.h, "alpha").await;
    let sock = &s.token_socket;
    let reader = s.issuer.token("rita", &["viewers"]);
    for path in ["/v1/stats", "/v1/apps/alpha/stats"] {
        let (status, _, body) = call(sock, "GET", path, Some(&reader), None).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
        let (status, _, _) = call(sock, "GET", path, None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
    }
    let (status, _, _) = call(sock, "GET", "/v1/apps/ghost/stats", Some(&reader), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    s.h.running.stop().await;
}
