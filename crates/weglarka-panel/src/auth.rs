//! Login, callback and logout, the session cookie, and the `require_session` middleware.
//!
//! Cookies are `__Host-` prefixed (`Secure`, `Path=/`, no `Domain`, so a sibling subdomain cannot
//! set or shadow them), `HttpOnly` and `SameSite=Lax` (the redirect back from the provider is a
//! top-level GET, which Lax sends). The session id is minted at the callback, never taken from
//! anything the browser sent before logging in, so a planted id gains nothing (session fixation).

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::header::{COOKIE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};

use crate::app::AppState;
use crate::config::Secret;
use crate::csrf;
use crate::pages::ErrorPage;
use crate::secure::constant_time_eq;
use crate::session::{PendingLogin, Session, SessionView, Tokens, User};

pub const SESSION_COOKIE: &str = "__Host-weglarka-session";
pub const LOGIN_COOKIE: &str = "__Host-weglarka-login";
/// The access token is refreshed when it has less than this left.
pub const REFRESH_MARGIN: std::time::Duration = std::time::Duration::from_secs(60);
const MAX_RETURN_TO: usize = 512;

fn cookie(name: &str, value: &str, max_age: Option<u64>) -> HeaderValue {
    let age = max_age
        .map(|s| format!("; Max-Age={s}"))
        .unwrap_or_default();
    // Values are base64url or empty, so this is always a valid header value.
    HeaderValue::try_from(format!(
        "{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax{age}"
    ))
    .expect("cookie header")
}

fn clear_cookie(name: &str) -> HeaderValue {
    cookie(name, "", Some(0))
}

/// The value of cookie `name`; a name that appears twice is ambiguous and counts as absent.
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut found = None;
    for header in headers.get_all(COOKIE) {
        for pair in header.to_str().ok()?.split(';') {
            if let Some((n, v)) = pair.trim().split_once('=')
                && n == name
            {
                if found.is_some() {
                    return None;
                }
                found = Some(v.to_owned());
            }
        }
    }
    found
}

/// A post-login destination must be a local absolute path: starts with one `/`, no `//`, no
/// backslash, no control characters or spaces, and not the auth endpoints (no loops). Anything
/// else becomes `/`.
pub fn safe_return_to(raw: Option<&str>) -> String {
    let ok = |p: &str| {
        p.is_ascii()
            && p.starts_with('/')
            && !p.starts_with("//")
            && !p.starts_with("/auth/")
            && p.len() <= MAX_RETURN_TO
            && !p.contains('\\')
            && !p.chars().any(|c| c.is_control() || c.is_whitespace())
    };
    match raw {
        Some(p) if ok(p) => p.to_owned(),
        _ => "/".to_owned(),
    }
}

fn failure(status: StatusCode, title: &str, message: &str) -> Response {
    ErrorPage {
        title,
        message,
        sign_in: Some("/auth/login"),
    }
    .respond(status)
}

fn query_param(uri: &Uri, name: &str) -> Option<String> {
    url::form_urlencoded::parse(uri.query().unwrap_or("").as_bytes())
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.into_owned())
}

/// `GET /auth/login`: starts a login and sends the browser to the provider.
pub async fn login(State(state): State<AppState>, uri: Uri) -> Response {
    let return_to = safe_return_to(query_param(&uri, "return_to").as_deref());
    let request = match state.oidc.begin_login().await {
        Ok(request) => request,
        Err(e) => {
            tracing::warn!(error = %e, "cannot start a login");
            return failure(
                StatusCode::BAD_GATEWAY,
                "Sign-in unavailable",
                "The identity provider could not be reached. Try again in a moment.",
            );
        }
    };
    let pending = PendingLogin::new(
        request.state,
        request.nonce,
        request.verifier,
        return_to,
        state.clock.now(),
    );
    let Ok(id) = state.logins.insert(pending) else {
        tracing::warn!("too many logins in progress");
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Busy",
            "Too many sign-ins are in progress. Try again in a few minutes.",
        );
    };
    let mut response = Redirect::to(&request.redirect).into_response();
    response.headers_mut().append(
        SET_COOKIE,
        cookie(
            LOGIN_COOKIE,
            &id,
            Some(crate::session::PENDING_LOGIN_TTL.as_secs()),
        ),
    );
    response
}

/// `GET /auth/callback`: the provider's answer. Every failure ends here with a generic page; the
/// reason goes to the log (never the code, the state, a token or the secret).
pub async fn callback(State(state): State<AppState>, uri: Uri, headers: HeaderMap) -> Response {
    let pending = cookie_value(&headers, LOGIN_COOKIE).and_then(|id| state.logins.take(&id));
    let mut response = callback_inner(&state, &uri, &headers, pending).await;
    // The login cookie has done its job, whatever the outcome.
    response
        .headers_mut()
        .append(SET_COOKIE, clear_cookie(LOGIN_COOKIE));
    response
}

async fn callback_inner(
    state: &AppState,
    uri: &Uri,
    headers: &HeaderMap,
    pending: Option<PendingLogin>,
) -> Response {
    let retry = |message: &str| failure(StatusCode::BAD_REQUEST, "Sign-in failed", message);
    let Some(pending) = pending else {
        tracing::warn!("callback without a pending login");
        return retry("The sign-in expired or was not started here. Start again.");
    };
    if let Some(error) = query_param(uri, "error") {
        // An authorization error code is a short token from a fixed list; bound it anyway.
        let code: String = error
            .chars()
            .filter(|c| c.is_ascii_graphic())
            .take(40)
            .collect();
        tracing::warn!(error = %code, "the provider refused the sign-in");
        return retry("The identity provider did not allow the sign-in.");
    }
    let (Some(code), Some(returned_state)) = (query_param(uri, "code"), query_param(uri, "state"))
    else {
        return retry("The sign-in response was incomplete. Start again.");
    };
    if !constant_time_eq(&returned_state, &pending.state) {
        tracing::warn!("callback state mismatch");
        return retry("The sign-in response did not match the request. Start again.");
    }
    let tokens = match state.oidc.exchange_code(&code, &pending.verifier).await {
        Ok(tokens) => tokens,
        Err(e) => {
            tracing::warn!(error = %e, "the code exchange failed");
            return failure(
                StatusCode::BAD_GATEWAY,
                "Sign-in failed",
                "The identity provider rejected the sign-in. Start again.",
            );
        }
    };
    let Some(id_token) = &tokens.id_token else {
        tracing::warn!("the token response has no id token");
        return retry("The identity provider did not identify you. Start again.");
    };
    let identity = match state
        .oidc
        .verify_id_token(id_token.expose(), &pending.nonce)
        .await
    {
        Ok(identity) => identity,
        Err(e) => {
            tracing::warn!(error = %e, "the id token was rejected");
            return retry("The identity provider's answer could not be verified. Start again.");
        }
    };

    let now = state.clock.now();
    let session = Session::new(
        User {
            sub: identity.sub,
            name: identity.name,
        },
        Tokens {
            access: Arc::new(tokens.access),
            refresh: tokens.refresh,
            access_expires: now + tokens.expires_in,
        },
        now,
    );
    // Whatever session this browser had is replaced, not upgraded.
    if let Some(old) = cookie_value(headers, SESSION_COOKIE) {
        state.sessions.remove(&old);
    }
    let Ok(session_id) = state.sessions.insert(session) else {
        tracing::warn!("too many sessions");
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Busy",
            "Too many people are signed in. Try again later.",
        );
    };
    let mut response = Redirect::to(&pending.return_to).into_response();
    response
        .headers_mut()
        .append(SET_COOKIE, cookie(SESSION_COOKIE, &session_id, None));
    response
}

/// `POST /auth/logout` (behind [`require_session`], so CSRF-checked): ends the session.
pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(id) = cookie_value(&headers, SESSION_COOKIE) {
        state.sessions.remove(&id);
    }
    // 303 to a page on this origin: a redirect to the provider would be blocked by `form-action 'self'`.
    let mut response = Redirect::to("/").into_response();
    response
        .headers_mut()
        .append(SET_COOKIE, clear_cookie(SESSION_COOKIE));
    response
}

/// The answer for a request with no usable session. A `GET` page carries a link that returns to it.
fn signed_out(request: &Request, clear: bool) -> Response {
    let href;
    let sign_in = if matches!(*request.method(), Method::GET | Method::HEAD) {
        let target = request.uri().path_and_query().map_or("/", |p| p.as_str());
        let encoded: String = url::form_urlencoded::byte_serialize(target.as_bytes()).collect();
        href = format!("/auth/login?return_to={encoded}");
        &href
    } else {
        "/auth/login"
    };
    let mut response = ErrorPage {
        title: "Sign-in required",
        message: "You need to sign in to use the panel.",
        sign_in: Some(sign_in),
    }
    .respond(StatusCode::UNAUTHORIZED);
    if clear {
        response
            .headers_mut()
            .append(SET_COOKIE, clear_cookie(SESSION_COOKIE));
    }
    response
}

/// The single authentication point (default-deny): resolves the session cookie, enforces the idle
/// and absolute lifetimes, checks CSRF on state-changing requests, refreshes the access token when
/// it is about to expire, and hands handlers a [`SessionView`]. Unauthenticated callers cannot tell
/// a real route from a missing one.
pub async fn require_session(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(id) = cookie_value(request.headers(), SESSION_COOKIE) else {
        return signed_out(&request, false);
    };
    let Some(session) = state.sessions.get(&id) else {
        return signed_out(&request, true);
    };
    if !matches!(*request.method(), Method::GET | Method::HEAD) {
        request = match csrf::check(request, &session.csrf).await {
            Ok(request) => request,
            Err(response) => return *response,
        };
    }
    let Some(token) = fresh_token(&state, &session).await else {
        state.sessions.remove(&id);
        return signed_out(&request, true);
    };
    request.extensions_mut().insert(SessionView {
        token,
        csrf: session.csrf.clone(),
        user: session.user.clone(),
    });
    next.run(request).await
}

/// The session's access token, refreshed first when it is within [`REFRESH_MARGIN`] of expiry.
/// `None` ends the session: the grant was refused, or the token expired and cannot be renewed.
/// The tokens' lock is held across the refresh, so concurrent requests share one refresh.
async fn fresh_token(state: &AppState, session: &Session) -> Option<Arc<Secret>> {
    let mut tokens = session.tokens.lock().await;
    let now = state.clock.now();
    if tokens.access_expires.saturating_duration_since(now) > REFRESH_MARGIN {
        return Some(tokens.access.clone());
    }
    let expired = now >= tokens.access_expires;
    let Some(refresh) = tokens.refresh.as_ref() else {
        if expired {
            session.end();
            return None;
        }
        return Some(tokens.access.clone());
    };
    match state.oidc.refresh(refresh).await {
        Ok(set) => {
            tokens.access = Arc::new(set.access);
            if let Some(rotated) = set.refresh {
                tokens.refresh = Some(rotated);
            }
            tokens.access_expires = state.clock.now() + set.expires_in;
            Some(tokens.access.clone())
        }
        // A transient failure while the token still works: keep going, retry on the next request.
        Err(e) if !e.is_definitive() && !expired => {
            tracing::warn!(error = %e, "refreshing the session token failed; will retry");
            Some(tokens.access.clone())
        }
        Err(e) => {
            tracing::warn!(error = %e, "refreshing the session token failed; ending the session");
            session.end();
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_to_must_be_a_local_path() {
        for good in ["/", "/apps/web", "/apps?x=1&y=2", "/a/b#frag"] {
            assert_eq!(safe_return_to(Some(good)), good);
        }
        for bad in [
            "//evil.example.com",
            "///evil",
            "https://evil.example.com/",
            "javascript:alert(1)",
            "/\\evil.example.com",
            "\\\\evil",
            "evil",
            "",
            "/a b",
            "/ąę",
            "/a\r\nSet-Cookie: x=y",
            "/auth/login",
            "/auth/callback?code=1",
        ] {
            assert_eq!(safe_return_to(Some(bad)), "/", "{bad:?}");
        }
        assert_eq!(safe_return_to(None), "/");
        assert_eq!(safe_return_to(Some(&format!("/{}", "a".repeat(600)))), "/");
    }

    #[test]
    fn cookies_are_parsed_strictly() {
        let mut h = HeaderMap::new();
        h.append(
            COOKIE,
            "a=1; __Host-weglarka-session=abc; b=2".parse().unwrap(),
        );
        assert_eq!(cookie_value(&h, SESSION_COOKIE).as_deref(), Some("abc"));
        h.append(COOKIE, "__Host-weglarka-session=other".parse().unwrap());
        assert_eq!(
            cookie_value(&h, SESSION_COOKIE),
            None,
            "duplicates are ambiguous"
        );
        assert_eq!(cookie_value(&HeaderMap::new(), SESSION_COOKIE), None);
    }

    #[test]
    fn cookie_attributes() {
        let c = cookie(SESSION_COOKIE, "id", None);
        let c = c.to_str().unwrap();
        assert!(c.starts_with("__Host-weglarka-session=id;"));
        for attr in ["Path=/", "Secure", "HttpOnly", "SameSite=Lax"] {
            assert!(c.contains(attr), "{c}");
        }
        assert!(!c.contains("Domain"));
    }
}
