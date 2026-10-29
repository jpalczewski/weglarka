//! The daemon client against a fake daemon on a unix socket.

use std::time::Duration;

use weglarka_api::endpoints::{APPS_LIST, APPS_SHOW};
use weglarka_api::{ErrorCode, ListAppsResponse};
use weglarka_panel::{Call, DaemonClient, DaemonError, Secret};
use weglarka_unix_http::testing::{Reply, mock, mock_with};

type Check = fn(&DaemonError) -> bool;

const TOKEN: &str = "tok.en.value-1234";

fn client(socket: &std::path::Path) -> DaemonClient {
    DaemonClient::new(socket, Duration::from_secs(5))
}

fn envelope(code: ErrorCode, message: &str) -> String {
    serde_json::json!({ "code": code, "message": message }).to_string()
}

#[tokio::test]
async fn sends_the_bearer_token_and_decodes_json() {
    let daemon = mock(|_, _| (200, r#"{"apps":[]}"#.into())).await;
    let got: ListAppsResponse = client(&daemon)
        .send(&Secret::new(TOKEN), &Call::new(&APPS_LIST))
        .await
        .unwrap();
    assert!(got.apps.is_empty());

    let seen = daemon.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].method, "GET");
    assert_eq!(seen[0].path, "/v1/apps");
    assert_eq!(
        seen[0].header("authorization"),
        Some(format!("Bearer {TOKEN}").as_str())
    );
    // The token is in the header and nowhere else.
    assert!(!seen[0].uri().contains(TOKEN));
}

#[tokio::test]
async fn path_parameters_and_query_reach_the_daemon() {
    let daemon = mock(|_, _| (200, "{}".into())).await;
    let call = Call::new(&APPS_SHOW).param("name", "web").query("x", "1");
    let _: serde_json::Value = client(&daemon)
        .send(&Secret::new(TOKEN), &call)
        .await
        .unwrap();
    assert_eq!(daemon.seen.lock().unwrap()[0].uri(), "/v1/apps/web?x=1");
}

#[tokio::test]
async fn error_envelope_maps_to_a_panel_error() {
    let cases: [(u16, ErrorCode, Check); 5] = [
        (401, ErrorCode::Unauthorized, |e| {
            matches!(e, DaemonError::Unauthorized)
        }),
        (403, ErrorCode::Forbidden, |e| {
            matches!(e, DaemonError::Forbidden)
        }),
        (
            404,
            ErrorCode::NotFound,
            |e| matches!(e, DaemonError::NotFound(m) if m == "no such app"),
        ),
        (409, ErrorCode::Conflict, |e| {
            matches!(e, DaemonError::Rejected { status: 409, .. })
        }),
        (503, ErrorCode::Busy, |e| {
            matches!(e, DaemonError::Server { status: 503, .. })
        }),
    ];
    for (status, code, check) in cases {
        let body = envelope(code, "no such app");
        let daemon = mock(move |_, _| (status, body.clone())).await;
        let err = client(&daemon)
            .send::<serde_json::Value>(&Secret::new(TOKEN), &Call::new(&APPS_LIST))
            .await
            .unwrap_err();
        assert!(check(&err), "{status}: {err:?}");
        assert!(!format!("{err} {err:?}").contains(TOKEN));
    }
}

#[tokio::test]
async fn a_status_without_an_envelope_still_maps_and_the_body_is_not_quoted() {
    for (status, check) in [
        (
            401u16,
            (|e: &DaemonError| matches!(e, DaemonError::Unauthorized)) as Check,
        ),
        (403, |e| matches!(e, DaemonError::Forbidden)),
        (404, |e| matches!(e, DaemonError::NotFound(_))),
        (502, |e| {
            matches!(e, DaemonError::Server { status: 502, .. })
        }),
    ] {
        let daemon = mock(move |_, _| (status, "<html>secret-looking body</html>".into())).await;
        let err = client(&daemon)
            .send::<serde_json::Value>(&Secret::new(TOKEN), &Call::new(&APPS_LIST))
            .await
            .unwrap_err();
        assert!(check(&err), "{status}: {err:?}");
        assert!(!format!("{err:?}").contains("secret-looking"));
    }
}

#[tokio::test]
async fn a_slow_daemon_hits_the_deadline() {
    let daemon = mock_with(|_, _| Reply::new(200, "{}").head_delay(Duration::from_secs(5))).await;
    let slow = DaemonClient::new(&*daemon, Duration::from_millis(100));
    let started = std::time::Instant::now();
    let err = slow
        .send::<serde_json::Value>(&Secret::new(TOKEN), &Call::new(&APPS_LIST))
        .await
        .unwrap_err();
    assert!(matches!(err, DaemonError::Timeout), "{err:?}");
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn a_missing_socket_is_unreachable() {
    let err = client(std::path::Path::new("/nonexistent/weglarka/api.sock"))
        .send::<serde_json::Value>(&Secret::new(TOKEN), &Call::new(&APPS_LIST))
        .await
        .unwrap_err();
    assert!(matches!(err, DaemonError::Unreachable), "{err:?}");
}

#[tokio::test]
async fn a_bad_body_reports_only_its_position() {
    let daemon = mock(|_, _| (200, r#"{"apps": "hunter2-not-a-list"}"#.into())).await;
    let err = client(&daemon)
        .send::<ListAppsResponse>(&Secret::new(TOKEN), &Call::new(&APPS_LIST))
        .await
        .unwrap_err();
    assert!(matches!(err, DaemonError::Decode { .. }), "{err:?}");
    assert!(!format!("{err} {err:?}").contains("hunter2"));
}

#[tokio::test]
async fn a_token_that_is_not_a_header_value_never_leaves_the_process() {
    let daemon = mock(|_, _| (200, "{}".into())).await;
    let bad = Secret::new("line\nbreak");
    let err = client(&daemon)
        .send::<serde_json::Value>(&bad, &Call::new(&APPS_LIST))
        .await
        .unwrap_err();
    assert!(matches!(err, DaemonError::InvalidRequest(_)), "{err:?}");
    assert!(!err.to_string().contains("break"));
    assert!(daemon.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn no_content_is_success_for_send_empty() {
    let daemon = mock(|_, _| (204, String::new())).await;
    client(&daemon)
        .send_empty(&Secret::new(TOKEN), &Call::new(&APPS_LIST))
        .await
        .unwrap();
}

#[tokio::test]
async fn a_call_can_override_the_deadline() {
    let daemon =
        mock_with(|_, _| Reply::new(200, "{}").head_delay(Duration::from_millis(400))).await;
    let short = DaemonClient::new(&*daemon, Duration::from_millis(100));
    let token = Secret::new(TOKEN);
    let slow = Call::new(&APPS_LIST);
    assert!(matches!(
        short.send::<serde_json::Value>(&token, &slow).await,
        Err(DaemonError::Timeout)
    ));
    // The same client waits for a call that opts out of the deadline.
    let patient = Call::new(&APPS_LIST).timeout(None);
    short
        .send::<serde_json::Value>(&token, &patient)
        .await
        .unwrap();
}
