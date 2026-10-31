//! `/_weglarka/api/v1/*`: a bearer-only relay to the daemon's token socket, for `weglarka login` clients
//! (docs/decisions/0060).
//!
//! The relay **decides nothing about who may do what**: it forwards the caller's own
//! `Authorization: Bearer …` and the daemon verifies signature, audience and groups and applies the
//! scope, exactly as on the socket. What it does add is a narrow, cheap front:
//!
//! - an allowlist: only a method and path that match an entry of [`weglarka_api::endpoints::ENDPOINTS`]
//!   are forwarded, everything else is `404`;
//! - bearer only: no cookie is ever read or forwarded, so a browser session cannot authenticate here;
//! - nothing but `Authorization`, `Content-Type`, `Accept` and `Content-Length` goes upstream;
//! - a per-address rate limit and a cap on concurrent relayed requests, both checked before any
//!   upstream connection exists;
//! - request and response bodies pass through unbuffered, so a stream ends when the daemon ends it
//!   (including its `TokenExpired` frame at the token's expiry).
//!
//! Local refusals use the admin API's error envelope so the CLI reads them like the daemon's own.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::header::{ACCEPT, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, RETRY_AFTER};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::stream;
use http_body_util::Limited;
use tokio::sync::OwnedSemaphorePermit;
use weglarka_api::endpoints::{self, ENDPOINTS};
use weglarka_api::{ApiError, Endpoint, ErrorCode};
use weglarka_model::admin_auth::{RELAY_MAX_BODY_BYTES, RELAY_PREFIX};
use weglarka_unix_http::{Bytes, bearer};

use crate::app::AppState;
use crate::daemon::{DaemonError, RelayedResponse};

/// Where the relay is mounted; the rest of the path is the daemon's (`/_weglarka/api/v1/apps` →
/// `/v1/apps`). The ingress knows this prefix too and carves it out of forward auth by itself.
pub const PREFIX: &str = RELAY_PREFIX;
/// Requests one address may make per [`LIMIT_WINDOW`].
pub const LIMIT: usize = 300;
pub const LIMIT_WINDOW: Duration = Duration::from_secs(60);
/// Relayed requests in flight at once, streams included.
pub const MAX_CONCURRENT: usize = 64;
/// How long the daemon may take to answer the head: a deploy answers when it is finished.
const HEAD_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// A JSON request body (everything but the uploads below).
const SMALL_BODY: u64 = 1024 * 1024;
/// Image archives and volume imports.
const UPLOAD_BODY: u64 = RELAY_MAX_BODY_BYTES;
/// The longest `Authorization` value forwarded; a JWT is a few kilobytes.
const MAX_AUTHORIZATION: usize = 16 * 1024;

/// What a request may carry upstream, by endpoint.
fn body_cap(endpoint: &Endpoint) -> u64 {
    if *endpoint == endpoints::APPS_PUSH_IMAGE || *endpoint == endpoints::VOLUMES_IMPORT {
        UPLOAD_BODY
    } else {
        SMALL_BODY
    }
}

/// The endpoint `method` and the concrete `path` belong to. Path parameters match one segment of
/// the characters a name can have, so a parameter can never add a segment or climb out.
pub fn find_endpoint(method: &str, path: &str) -> Option<&'static Endpoint> {
    ENDPOINTS
        .iter()
        .find(|e| e.method.as_str() == method && matches_template(e.path, path))
}

fn matches_template(template: &str, path: &str) -> bool {
    let (mut template, mut path) = (template.split('/'), path.split('/'));
    loop {
        match (template.next(), path.next()) {
            (None, None) => return true,
            (Some(t), Some(p)) if t.starts_with('{') && t.ends_with('}') => {
                if !valid_segment(p) {
                    return false;
                }
            }
            (Some(t), Some(p)) if t == p => {}
            _ => return false,
        }
    }
}

fn valid_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn refuse(status: StatusCode, code: ErrorCode, message: &str) -> Response {
    let body = serde_json::to_vec(&ApiError {
        code,
        message: message.to_owned(),
    })
    .unwrap_or_default();
    let mut response = (status, body).into_response();
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

/// A `Bearer` credential is present; whether it is any good is the daemon's call.
fn has_bearer(request: &Request) -> bool {
    request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.len() <= MAX_AUTHORIZATION
                && v.split_once(' ').is_some_and(|(scheme, token)| {
                    scheme.eq_ignore_ascii_case("bearer") && !token.trim().is_empty()
                })
        })
}

pub async fn handle(State(state): State<AppState>, request: Request) -> Response {
    let Some(path) = request.uri().path().strip_prefix(PREFIX) else {
        return refuse(
            StatusCode::NOT_FOUND,
            ErrorCode::NotFound,
            "no such endpoint",
        );
    };
    let Some(endpoint) = find_endpoint(request.method().as_str(), path) else {
        return refuse(
            StatusCode::NOT_FOUND,
            ErrorCode::NotFound,
            "no such endpoint",
        );
    };

    // Cheap refusal first, and before the rate limit is charged: the endpoints that need a token
    // get one or nothing, and tokenless traffic must not eat the budget of authenticated calls
    // from the same address.
    // Cheap refusal before anything upstream: the endpoints that need a token get one or nothing.
    if endpoint.scope.is_some() && !has_bearer(&request) {
        return refuse(
            StatusCode::UNAUTHORIZED,
            ErrorCode::Unauthorized,
            "a bearer token is required",
        );
    }

    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(IpAddr::from([0, 0, 0, 0]), |c| c.0.ip());
    let client = state.client_addr(peer, request.headers());
    if !state.api_limit.admit(client) {
        tracing::warn!(%client, "too many API requests from one address");
        return slow_down();
    }
    let Ok(permit) = state.api_slots.clone().try_acquire_owned() else {
        return slow_down();
    };

    let cap = body_cap(endpoint);
    let declared = request
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > cap) {
        return refuse(
            StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::InvalidRequest,
            "the request body is too large for this endpoint",
        );
    }

    let Some(upstream) = upstream_request(&request, path) else {
        return refuse(
            StatusCode::BAD_REQUEST,
            ErrorCode::InvalidRequest,
            "the request cannot be relayed",
        );
    };
    let (_, body) = request.into_parts();
    let upstream = upstream.map(|()| Limited::new(body, cap as usize));
    match state.daemon.relay(upstream, HEAD_TIMEOUT).await {
        Ok(reply) => respond(reply, permit),
        Err(DaemonError::Timeout) => refuse(
            StatusCode::GATEWAY_TIMEOUT,
            ErrorCode::Internal,
            "the daemon did not answer in time",
        ),
        Err(DaemonError::InvalidRequest(_)) => refuse(
            StatusCode::BAD_REQUEST,
            ErrorCode::InvalidRequest,
            "the request cannot be relayed",
        ),
        Err(_) => refuse(
            StatusCode::BAD_GATEWAY,
            ErrorCode::Internal,
            "the daemon is unreachable",
        ),
    }
}

fn slow_down() -> Response {
    let mut response = refuse(
        StatusCode::TOO_MANY_REQUESTS,
        ErrorCode::Busy,
        "too many requests; wait a moment and try again",
    );
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from(5u64));
    response
}

/// The request head for the daemon: the path without the prefix, the query as sent, and only the
/// four headers listed in the module docs. `None` when the request cannot be expressed.
fn upstream_request(request: &Request, path: &str) -> Option<weglarka_unix_http::Request<()>> {
    let target = match request.uri().query() {
        Some(query) => format!("{path}?{query}"),
        None => path.to_owned(),
    };
    let mut builder = weglarka_unix_http::Request::builder()
        .method(request.method().clone())
        .uri(target);
    if let Some(value) = request.headers().get(AUTHORIZATION) {
        let (_, token) = value.to_str().ok()?.split_once(' ')?;
        builder = builder.header(AUTHORIZATION, bearer(token.trim()).ok()?);
    }
    for name in [CONTENT_TYPE, ACCEPT, CONTENT_LENGTH] {
        if let Some(value) = request.headers().get(&name) {
            builder = builder.header(name, value.clone());
        }
    }
    builder.body(()).ok()
}

/// The daemon's answer, streamed. The permit lives as long as the body, so a long stream counts.
fn respond(reply: RelayedResponse, permit: OwnedSemaphorePermit) -> Response {
    let status = reply.status;
    let content_type = reply.headers.get(CONTENT_TYPE).cloned();
    let body = stream::unfold(Some((reply, Arc::new(permit))), |state| async move {
        let (mut reply, permit) = state?;
        match reply.chunk().await {
            None => None,
            Some(Ok(chunk)) => Some((Ok::<Bytes, std::io::Error>(chunk), Some((reply, permit)))),
            // One error ends the stream; asking again after it could loop forever.
            Some(Err(e)) => Some((Err(std::io::Error::other(e.to_string())), None)),
        }
    });
    let mut response = Response::new(Body::from_stream(body));
    *response.status_mut() = status;
    if let Some(content_type) = content_type {
        response.headers_mut().insert(CONTENT_TYPE, content_type);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_match_their_template_and_nothing_else() {
        let show = find_endpoint("GET", "/v1/apps/my-app.1").unwrap();
        assert_eq!(show.path, "/v1/apps/{name}");
        assert_eq!(find_endpoint("GET", "/v1/apps").unwrap().path, "/v1/apps");
        assert!(find_endpoint("PUT", "/v1/apps/web").is_some());
        for (method, path) in [
            ("GET", "/v1/apps/"),
            ("GET", "/v1/apps/.."),
            ("GET", "/v1/apps/a/b"),
            ("GET", "/v1/apps/a%2fb"),
            ("GET", "/v1/apps/a b"),
            ("PATCH", "/v1/apps/web"),
            ("GET", "/v2/apps"),
            ("GET", "/v1"),
            ("GET", ""),
            ("OPTIONS", "/v1/apps"),
        ] {
            assert!(find_endpoint(method, path).is_none(), "{method} {path}");
        }
    }

    #[test]
    fn every_declared_endpoint_is_reachable_through_its_own_template() {
        for e in ENDPOINTS {
            let concrete = e
                .path
                .split('/')
                .map(|s| if s.starts_with('{') { "x-1" } else { s })
                .collect::<Vec<_>>()
                .join("/");
            assert_eq!(
                find_endpoint(e.method.as_str(), &concrete),
                Some(e),
                "{}",
                e.path
            );
        }
    }

    #[test]
    fn only_uploads_get_a_large_body() {
        for e in ENDPOINTS {
            let large = *e == endpoints::APPS_PUSH_IMAGE || *e == endpoints::VOLUMES_IMPORT;
            assert_eq!(body_cap(e) > SMALL_BODY, large, "{}", e.path);
        }
    }
}
