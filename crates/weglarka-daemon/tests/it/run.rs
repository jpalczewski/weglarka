//! `POST /v1/apps/{name}/run` (issue #106) over the real admin socket on `FakePodman`: the framed
//! response stream, errors before the stream starts, and that a hung-up client does not leave a
//! container behind.

use crate::common::*;
use hyper::StatusCode;
use serde_json::json;
use weglarka_api::{RunFrame, RunFrameDecoder};
use weglarka_core::podman::LogSource;
use weglarka_core::testing::{Call, RunScript};

fn frames(body: &[u8]) -> Vec<RunFrame> {
    let mut decoder = RunFrameDecoder::default();
    let frames = decoder.push(body).unwrap();
    assert!(decoder.is_clean(), "the stream ended inside a frame");
    frames
}

async fn deployed_app() -> Harness {
    let h = harness().await;
    let mut body = spec("ntfy.example.eu");
    body["env"] = json!({ "MODE": "prod" });
    body["host_ports"] = json!([{ "host": 2222, "container": 22 }]);
    add(&h, "ntfy", body).await;
    deployed(&h, "ntfy").await;
    h
}

fn run_containers(h: &Harness) -> Vec<String> {
    h.fake
        .containers()
        .into_iter()
        .map(|c| c.name)
        .filter(|n| n.starts_with("wg-run."))
        .collect()
}

#[tokio::test]
async fn a_run_streams_its_output_then_the_exit_code_and_leaves_no_container() {
    let h = deployed_app().await;
    h.fake.script_next_run(RunScript {
        output: vec![
            (LogSource::Stdout, b"migrated 3 rows\n".to_vec()),
            (LogSource::Stderr, b"deprecated flag\n".to_vec()),
        ],
        exit_code: 2,
        hang: false,
    });
    let (status, body) = raw(
        &h,
        "POST",
        "/v1/apps/ntfy/run",
        json!({ "command": ["migrate"], "env": { "MODE": "debug" } })
            .to_string()
            .into_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        frames(&body),
        [
            RunFrame::Stdout(b"migrated 3 rows\n".to_vec()),
            RunFrame::Stderr(b"deprecated flag\n".to_vec()),
            RunFrame::Exit(2),
        ]
    );

    let run = h
        .fake
        .created_specs()
        .into_iter()
        .find(|s| s.name.starts_with("wg-run."))
        .expect("a run container was created");
    assert_eq!(run.command, ["migrate"]);
    assert_eq!(
        run.env["MODE"], "debug",
        "the request wins over the app's env"
    );
    assert!(run.publish.is_empty(), "host_ports must not be published");
    assert!(run_containers(&h).is_empty());
    assert!(
        h.fake.containers().iter().any(|c| c.name == "ntfy"),
        "the app itself is untouched"
    );
}

#[tokio::test]
async fn what_cannot_run_is_refused_with_a_json_error_before_any_stream() {
    let h = deployed_app().await;
    let (status, v) = admin(&h, "POST", "/v1/apps/ntfy/run", Some(json!({}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
    assert!(
        v["message"].as_str().unwrap().contains("nothing to run"),
        "{v}"
    );

    let (status, v) = admin(
        &h,
        "POST",
        "/v1/apps/ntfy/run",
        Some(json!({ "cmd": ["x"] })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");

    let (status, v) = admin(
        &h,
        "POST",
        "/v1/apps/nope/run",
        Some(json!({ "command": ["true"] })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{v}");
    assert!(run_containers(&h).is_empty());
    assert!(
        !h.fake
            .created_specs()
            .iter()
            .any(|s| s.name.starts_with("wg-run.")),
        "nothing was created"
    );
}

/// A provisioned app (`start = false`) has a pinned image and its volumes but no container: the
/// case for running a migration *before* the first start.
#[tokio::test]
async fn a_provisioned_app_that_is_not_started_can_run_a_one_off_command() {
    let h = harness().await;
    let mut body = spec("ntfy.example.eu");
    body["start"] = json!(false);
    add(&h, "ntfy", body).await;
    deployed(&h, "ntfy").await;
    assert!(h.fake.containers().iter().all(|c| c.name != "ntfy"));
    h.fake.script_next_run(RunScript::default());
    let (status, body) = raw(
        &h,
        "POST",
        "/v1/apps/ntfy/run",
        json!({ "command": ["migrate"] }).to_string().into_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(frames(&body), [RunFrame::Exit(0)]);
    // Neither a run container nor the app's own: only the ingress is there.
    let left: Vec<_> = h.fake.containers().into_iter().map(|c| c.name).collect();
    assert_eq!(left, ["weglarka-nginx"]);
}

#[tokio::test]
async fn a_timeout_ends_the_stream_with_a_timed_out_frame() {
    let h = deployed_app().await;
    h.fake.script_next_run(RunScript {
        hang: true,
        ..Default::default()
    });
    let (status, body) = raw(
        &h,
        "POST",
        "/v1/apps/ntfy/run",
        json!({ "command": ["sleep", "infinity"], "timeout_secs": 1 })
            .to_string()
            .into_bytes(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(frames(&body), [RunFrame::TimedOut]);
    assert!(run_containers(&h).is_empty());
    assert!(h.fake.calls().iter().any(|c| matches!(
        c,
        Call::ContainerKill { name, signal } if name.starts_with("wg-run.") && signal == "KILL"
    )));
}

#[tokio::test]
async fn a_client_that_hangs_up_kills_the_run() {
    let h = deployed_app().await;
    h.fake.script_next_run(RunScript {
        hang: true,
        ..Default::default()
    });
    // Send the request, read the response head, then drop the connection mid-run.
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
        .uri("/v1/apps/ntfy/run")
        .header("host", "weglarka")
        .body(http_body_util::Full::new(bytes::Bytes::from(
            json!({ "command": ["sleep", "infinity"] }).to_string(),
        )))
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    eventually("the run container exists", || async {
        run_containers(&h).len() == 1
    })
    .await;
    drop(response);
    drop(sender);
    eventually("the run container is gone", || async {
        run_containers(&h).is_empty()
    })
    .await;
}

#[tokio::test]
async fn a_daemon_start_sweeps_run_containers_an_earlier_daemon_left_behind() {
    let h = deployed_app().await;
    let mut stale = h.fake.container_spec("ntfy").unwrap();
    stale.name = "wg-run.ntfy.dead".into();
    stale.labels = [
        ("weglarka.run".to_owned(), "true".to_owned()),
        ("weglarka.run-for".to_owned(), "ntfy".to_owned()),
    ]
    .into();
    use weglarka_core::podman::PodmanClient as _;
    h.fake.container_create(&stale).await.unwrap();
    assert_eq!(run_containers(&h), ["wg-run.ntfy.dead"]);
    // The engine's start-up sweep is what a restarted daemon runs.
    assert_eq!(
        h.running.daemon.engine.remove_stale_runs().await.unwrap(),
        1
    );
    assert!(run_containers(&h).is_empty());
}
