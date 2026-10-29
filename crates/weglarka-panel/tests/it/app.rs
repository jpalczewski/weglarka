//! The router: headers on every response, default-deny, no daemon call for `/healthz`.

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use tower::ServiceExt;
use weglarka_panel::config::{
    ENV_API_AUDIENCE, ENV_CLIENT_ID, ENV_CLIENT_SECRET, ENV_ISSUER, ENV_PUBLIC_URL, ENV_SOCKET,
};
use weglarka_panel::headers::CONTENT_SECURITY_POLICY_VALUE;
use weglarka_panel::{AppState, PanelConfig, router};
use weglarka_unix_http::testing::{Mock, mock};

async fn app() -> (Router, Mock) {
    let daemon = mock(|_, _| (200, "{}".into())).await;
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
    (router(AppState::new(config).unwrap()), daemon)
}

async fn call(app: &Router, method: Method, path: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

/// Status line plus sorted `name: value` lines, for snapshots.
fn describe(response: &axum::response::Response) -> String {
    let mut lines: Vec<String> = response
        .headers()
        .iter()
        .map(|(n, v)| format!("{n}: {}", v.to_str().unwrap()))
        .collect();
    lines.sort();
    format!("{}\n{}", response.status(), lines.join("\n"))
}

#[tokio::test]
async fn healthz_is_open_and_never_calls_the_daemon() {
    let (app, daemon) = app().await;
    let response = call(&app, Method::GET, "/healthz").await;
    assert_eq!(response.status(), StatusCode::OK);
    insta::assert_snapshot!("healthz_headers", describe(&response));
    assert!(daemon.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn everything_else_is_denied_by_default() {
    let (app, daemon) = app().await;
    let response = call(&app, Method::GET, "/v1/apps").await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    insta::assert_snapshot!("denied_headers", describe(&response));

    // A route that does not exist is refused the same way: no probing for real pages.
    for (method, path) in [
        (Method::GET, "/"),
        (Method::GET, "/apps/web"),
        (Method::POST, "/apps/web/deploy"),
        (Method::DELETE, "/anything"),
        (Method::POST, "/healthz"),
    ] {
        let denied = call(&app, method.clone(), path).await;
        assert!(
            matches!(
                denied.status(),
                StatusCode::UNAUTHORIZED | StatusCode::METHOD_NOT_ALLOWED
            ),
            "{method} {path}: {}",
            denied.status()
        );
        // An Authorization header and an unknown session cookie make no difference.
    }
    let with_creds = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header(header::AUTHORIZATION, "Bearer anything")
                .header(header::COOKIE, "__Host-session=anything")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(with_creds.status(), StatusCode::UNAUTHORIZED);
    assert!(daemon.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn embedded_assets_are_public_and_cacheable() {
    let (app, _daemon) = app().await;
    let css = call(&app, Method::GET, "/static/app.css").await;
    assert_eq!(css.status(), StatusCode::OK);
    assert_eq!(
        css.headers()[header::CONTENT_TYPE],
        "text/css; charset=utf-8"
    );
    assert_eq!(css.headers()[header::CACHE_CONTROL], "public, no-cache");
    assert_eq!(css.headers()[header::X_CONTENT_TYPE_OPTIONS], "nosniff");

    for path in ["/static/missing.js", "/static/..%2fCargo.toml"] {
        let response = call(&app, Method::GET, path).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
    }
    // Not a single file name: not an asset route at all, so it is denied like any other path.
    let nested = call(&app, Method::GET, "/static/a/b").await;
    assert_eq!(nested.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn no_response_lacks_the_security_headers() {
    let (app, _daemon) = app().await;
    for (method, path) in [
        (Method::GET, "/healthz"),
        (Method::HEAD, "/healthz"),
        (Method::POST, "/healthz"),
        (Method::GET, "/static/app.css"),
        (Method::GET, "/static/favicon.svg"),
        (Method::GET, "/static/missing"),
        (Method::GET, "/"),
        (Method::GET, "/v1/apps"),
        (Method::POST, "/v1/apps"),
        (Method::OPTIONS, "/"),
        (Method::GET, "/%ff"),
    ] {
        let response = call(&app, method.clone(), path).await;
        let h = response.headers();
        assert_eq!(
            h[header::CONTENT_SECURITY_POLICY],
            CONTENT_SECURITY_POLICY_VALUE,
            "{method} {path}"
        );
        assert_eq!(
            h[header::X_CONTENT_TYPE_OPTIONS],
            "nosniff",
            "{method} {path}"
        );
        assert_eq!(h[header::REFERRER_POLICY], "no-referrer", "{method} {path}");
        assert_eq!(
            h["cross-origin-opener-policy"], "same-origin",
            "{method} {path}"
        );
        assert_eq!(
            h["cross-origin-resource-policy"], "same-origin",
            "{method} {path}"
        );
        assert!(h.contains_key(header::CACHE_CONTROL), "{method} {path}");
    }
}

#[test]
fn the_policy_forbids_inline_and_framing() {
    for needed in [
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "frame-ancestors 'none'",
        "form-action 'self'",
        "base-uri 'none'",
    ] {
        assert!(CONTENT_SECURITY_POLICY_VALUE.contains(needed), "{needed}");
    }
    assert!(!CONTENT_SECURITY_POLICY_VALUE.contains("unsafe-"));
}
