//! `/_weglarka/api/v1/*`: the bearer-only relay to the daemon (docs/decisions/0060).

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use tower::ServiceExt;
use weglarka_api::{ApiError, ErrorCode};
use weglarka_panel::config::{
    ENV_API_AUDIENCE, ENV_CLIENT_ID, ENV_CLIENT_SECRET, ENV_ISSUER, ENV_PUBLIC_URL, ENV_SOCKET,
};
use weglarka_panel::limit::AddressLimiter;
use weglarka_panel::session::Clock;
use weglarka_panel::{AppState, PanelConfig, router};
use weglarka_unix_http::testing::{Mock, Reply, mock_seen};

const TOKEN: &str = "tok.en.value";

fn state_for(daemon: &Mock) -> AppState {
    let socket = daemon.socket.display().to_string();
    let config = PanelConfig::from_lookup(|var| match var {
        ENV_CLIENT_ID => Some("panel".into()),
        ENV_CLIENT_SECRET => Some("secret".into()),
        ENV_ISSUER => Some("https://auth.example.com".into()),
        ENV_PUBLIC_URL => Some("https://panel.example.com".into()),
        ENV_API_AUDIENCE => Some("https://admin.example.com/api/".into()),
        ENV_SOCKET => Some(socket.clone()),
        _ => None,
    })
    .unwrap();
    AppState::new(config).unwrap()
}

async fn relay_to(
    reply: impl Fn(&weglarka_unix_http::testing::Seen) -> Reply + Send + Sync + 'static,
) -> (Router, Mock) {
    let daemon = mock_seen(reply).await;
    (router(state_for(&daemon)), daemon)
}

fn request(method: Method, path: &str) -> axum::http::request::Builder {
    Request::builder().method(method).uri(path)
}

async fn send(
    app: &Router,
    request: Request<Body>,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let response = app.clone().oneshot(request).await.unwrap();
    let (parts, body) = response.into_parts();
    (
        parts.status,
        parts.headers,
        body.collect().await.unwrap().to_bytes().to_vec(),
    )
}

fn envelope(body: &[u8]) -> ApiError {
    serde_json::from_slice(body).expect("an API error envelope")
}

#[tokio::test]
async fn a_request_is_forwarded_with_only_the_bearer_and_the_answer_comes_back() {
    let (app, daemon) =
        relay_to(|_| Reply::new(200, r#"{"apps":[]}"#).content_type("application/json")).await;
    let (status, headers, body) = send(
        &app,
        request(Method::GET, "/_weglarka/api/v1/apps?x=1")
            .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
            .header(header::COOKIE, "__Host-session=abc")
            .header("x-forwarded-for", "203.0.113.9")
            .header("x-evil", "1")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, br#"{"apps":[]}"#);
    assert_eq!(headers[header::CONTENT_TYPE], "application/json");
    // The panel's own policy still applies to what it relays.
    assert!(headers.contains_key(header::CONTENT_SECURITY_POLICY));

    let seen = daemon.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        (seen[0].method.as_str(), seen[0].uri().as_str()),
        ("GET", "/v1/apps?x=1")
    );
    assert_eq!(
        seen[0].header("authorization"),
        Some(&*format!("Bearer {TOKEN}"))
    );
    for forbidden in ["cookie", "x-forwarded-for", "x-evil"] {
        assert!(
            seen[0].header(forbidden).is_none(),
            "{forbidden} reached the daemon"
        );
    }
}

#[tokio::test]
async fn only_declared_endpoints_are_relayed() {
    let (app, daemon) = relay_to(|_| Reply::new(200, "{}")).await;
    for (method, path) in [
        (Method::GET, "/_weglarka/api/v2/apps"),
        (Method::GET, "/_weglarka/api/v1/nothing"),
        (Method::PATCH, "/_weglarka/api/v1/apps/web"),
        (Method::OPTIONS, "/_weglarka/api/v1/apps"),
        (Method::GET, "/_weglarka/api/v1/apps/../status"),
        (Method::GET, "/_weglarka/api/v1/apps/a%2Fb"),
    ] {
        let (status, _, body) = send(
            &app,
            request(method.clone(), path)
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}");
        assert_eq!(envelope(&body).code, ErrorCode::NotFound);
    }
    assert!(daemon.seen.lock().unwrap().is_empty());
    // The bare prefix is not part of the relay: it falls to the session gate like any unknown path.
    let (status, _, _) = send(
        &app,
        request(Method::GET, "/_weglarka/api")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_cookie_or_a_wrong_scheme_never_authenticates() {
    let (app, daemon) = relay_to(|_| Reply::new(200, "{}")).await;
    for builder in [
        request(Method::GET, "/_weglarka/api/v1/apps").header(header::COOKIE, "__Host-session=abc"),
        request(Method::GET, "/_weglarka/api/v1/apps").header(header::AUTHORIZATION, "Basic dTpw"),
        request(Method::GET, "/_weglarka/api/v1/apps").header(header::AUTHORIZATION, "Bearer "),
        request(Method::GET, "/_weglarka/api/v1/apps"),
    ] {
        let (status, _, body) = send(&app, builder.body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(envelope(&body).code, ErrorCode::Unauthorized);
    }
    assert!(
        daemon.seen.lock().unwrap().is_empty(),
        "refused before any upstream call"
    );
}

#[tokio::test]
async fn health_needs_no_token() {
    let (app, daemon) = relay_to(|_| Reply::new(200, r#"{"status":"ok"}"#)).await;
    let (status, _, _) = send(
        &app,
        request(Method::GET, "/_weglarka/api/v1/health")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(daemon.seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn the_daemons_refusals_pass_through_unchanged() {
    for (status, code) in [(401, "unauthorized"), (403, "forbidden"), (409, "busy")] {
        let body = format!(r#"{{"code":"{code}","message":"from the daemon"}}"#);
        let expected = body.clone();
        let (app, _daemon) =
            relay_to(move |_| Reply::new(status, body.clone()).content_type("application/json"))
                .await;
        let (got, _, bytes) = send(
            &app,
            request(Method::GET, "/_weglarka/api/v1/apps")
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(got.as_u16(), status);
        assert_eq!(String::from_utf8(bytes).unwrap(), expected);
    }
}

#[tokio::test]
async fn a_body_goes_upstream_as_sent_and_an_oversized_one_never_does() {
    let (app, daemon) = relay_to(|_| Reply::new(204, "")).await;
    let payload = br#"{"image":"x:1"}"#.to_vec();
    let (status, _, _) = send(
        &app,
        request(Method::POST, "/_weglarka/api/v1/apps")
            .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CONTENT_LENGTH, payload.len())
            .body(Body::from(payload.clone()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    {
        let seen = daemon.seen.lock().unwrap();
        assert_eq!(seen[0].raw_body, payload);
        assert_eq!(seen[0].header("content-type"), Some("application/json"));
    }

    // A JSON endpoint refuses more than a megabyte by its declared length, before the daemon is asked.
    let (status, _, body) = send(
        &app,
        request(Method::POST, "/_weglarka/api/v1/apps")
            .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
            .header(header::CONTENT_LENGTH, 2 * 1024 * 1024)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(envelope(&body).code, ErrorCode::InvalidRequest);
    assert_eq!(daemon.seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_streamed_answer_arrives_whole_and_in_order() {
    let chunks = [b"{\"a\":1}\n".as_slice(), b"{\"b\":2}\n", b"{\"c\":3}\n"];
    let (app, _daemon) = relay_to(move |_| {
        Reply::chunks(
            200,
            chunks
                .iter()
                .map(|c| weglarka_unix_http::Bytes::copy_from_slice(c)),
        )
        .content_type("application/x-ndjson")
    })
    .await;
    let (status, headers, body) = send(
        &app,
        request(Method::GET, "/_weglarka/api/v1/apps/web/logs")
            .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "application/x-ndjson");
    assert_eq!(body, chunks.concat());
}

#[tokio::test]
async fn an_unreachable_daemon_is_a_bad_gateway_in_the_api_envelope() {
    let daemon = mock_seen(|_| Reply::new(200, "{}")).await;
    let app = router(state_for(&daemon));
    drop(daemon); // the socket is gone
    let (status, _, body) = send(
        &app,
        request(Method::GET, "/_weglarka/api/v1/apps")
            .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(envelope(&body).code, ErrorCode::Internal);
}

#[tokio::test]
async fn one_address_is_limited_and_told_to_wait() {
    let daemon = mock_seen(|_| Reply::new(200, "{}")).await;
    let mut state = state_for(&daemon);
    state.api_limit = Arc::new(AddressLimiter::with_limits(
        Clock::default(),
        2,
        Duration::from_secs(60),
    ));
    let app = router(state);
    let mut statuses = Vec::new();
    for _ in 0..3 {
        let (status, headers, body) = send(
            &app,
            request(Method::GET, "/_weglarka/api/v1/apps")
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            assert!(headers.contains_key(header::RETRY_AFTER));
            // `busy` makes the CLI back off and retry, which is what a rate limit asks for.
            assert_eq!(envelope(&body).code, ErrorCode::Busy);
        }
        statuses.push(status.as_u16());
    }
    assert_eq!(statuses, [200, 200, 429]);
    assert_eq!(daemon.seen.lock().unwrap().len(), 2);
}
