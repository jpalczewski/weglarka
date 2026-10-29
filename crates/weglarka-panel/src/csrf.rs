//! CSRF protection for every request that is not `GET`/`HEAD` (docs/decisions/0057, decision 3).
//!
//! Two independent checks, both required:
//! 1. `Sec-Fetch-Site`, when the browser sends it, must be `same-origin` (or `none`: a user-typed
//!    request). `cross-site` and `same-site` (a sibling subdomain) are refused;
//! 2. the session's CSRF token must arrive in `X-CSRF-Token` or the `_csrf` field of a urlencoded
//!    form, compared in constant time.

use axum::body::{Body, to_bytes};
use axum::extract::Request;
use axum::http::{StatusCode, header};
use axum::response::Response;

use crate::pages::ErrorPage;
use crate::secure::constant_time_eq;

pub const HEADER: &str = "x-csrf-token";
pub const FIELD: &str = "_csrf";
/// Larger forms are not something the panel sends; the body is buffered to find the field.
const MAX_FORM_BYTES: usize = 64 * 1024;

fn forbidden() -> Box<Response> {
    Box::new(ErrorPage {
        title: "Forbidden",
        message: "The request was refused as a possible cross-site request. Reload the page and try again.",
        sign_in: None,
    }
    .respond(StatusCode::FORBIDDEN))
}

/// Returns the request (its body restored) if it carries `csrf` and comes from the same origin.
pub async fn check(request: Request, csrf: &str) -> Result<Request, Box<Response>> {
    let fetch_site = request
        .headers()
        .get("sec-fetch-site")
        .map(|v| v.as_bytes().to_ascii_lowercase());
    if let Some(site) = fetch_site
        && site != b"same-origin"
        && site != b"none"
    {
        return Err(forbidden());
    }

    if let Some(value) = request.headers().get(HEADER) {
        let ok = value.to_str().is_ok_and(|v| constant_time_eq(v, csrf));
        return if ok { Ok(request) } else { Err(forbidden()) };
    }

    let is_form = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(';').next().is_some_and(|t| {
                t.trim()
                    .eq_ignore_ascii_case("application/x-www-form-urlencoded")
            })
        });
    if !is_form {
        return Err(forbidden());
    }
    let (parts, body) = request.into_parts();
    let bytes = to_bytes(body, MAX_FORM_BYTES)
        .await
        .map_err(|_| forbidden())?;
    let ok = url::form_urlencoded::parse(&bytes)
        .any(|(name, value)| name == FIELD && constant_time_eq(&value, csrf));
    if ok {
        Ok(Request::from_parts(parts, Body::from(bytes)))
    } else {
        Err(forbidden())
    }
}
