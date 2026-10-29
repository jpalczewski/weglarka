//! Security headers for every response, whatever produced it (a page, an asset, a 404, a 405,
//! the default-deny answer). One layer, applied last, so no route can forget them.

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, HeaderName, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS,
};
use axum::middleware::Next;
use axum::response::Response;

/// ADR 0057, decision 2: no inline script or style, no eval, no framing, forms and `<base>` pinned.
pub const CONTENT_SECURITY_POLICY_VALUE: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'";

const COOP: HeaderName = HeaderName::from_static("cross-origin-opener-policy");
const CORP: HeaderName = HeaderName::from_static("cross-origin-resource-policy");

pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY_VALUE),
    );
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(COOP, HeaderValue::from_static("same-origin"));
    headers.insert(CORP, HeaderValue::from_static("same-origin"));
    // Dynamic responses are never stored; a handler that sets its own policy (static files) keeps it.
    if !headers.contains_key(CACHE_CONTROL) {
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}
