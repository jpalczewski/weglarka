//! The OIDC login and the session lifecycle, against the fake provider and a fake daemon.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use tower::ServiceExt;
use weglarka_http::reqwest;
use weglarka_panel::config::{
    ENV_API_AUDIENCE, ENV_CLIENT_ID, ENV_CLIENT_SECRET, ENV_ISSUER, ENV_PUBLIC_URL,
    ENV_SESSION_IDLE_SECS, ENV_SESSION_MAX_SECS, ENV_SOCKET,
};
use weglarka_panel::session::Clock;
use weglarka_panel::{AppState, PanelConfig, router};
use weglarka_unix_http::testing::{Mock, mock};

use crate::provider::{AUDIENCE, CLIENT_SECRET, Provider, Refresh};

const PUBLIC: &str = "https://panel.example.com";
const SESSION: &str = "__Host-weglarka-session";
const LOGIN: &str = "__Host-weglarka-login";

struct Setup {
    provider: Provider,
    daemon: Mock,
    state: AppState,
    app: Router,
    clock: Clock,
}

async fn setup() -> Setup {
    setup_with(&[]).await
}

async fn setup_with(extra: &[(&str, &str)]) -> Setup {
    let provider = Provider::start().await;
    setup_for(provider, extra).await
}

async fn setup_for(provider: Provider, extra: &[(&str, &str)]) -> Setup {
    let daemon = mock(|_, _| (200, r#"{"apps":[]}"#.into())).await;
    let socket = daemon.socket.display().to_string();
    let issuer = provider.issuer.clone();
    let extra: BTreeMap<String, String> = extra
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let config = PanelConfig::from_lookup(|var| {
        if let Some(v) = extra.get(var) {
            return Some(v.clone());
        }
        match var {
            ENV_CLIENT_ID => Some("panel".into()),
            ENV_CLIENT_SECRET => Some(CLIENT_SECRET.into()),
            ENV_ISSUER => Some(issuer.clone()),
            ENV_PUBLIC_URL => Some(PUBLIC.into()),
            ENV_API_AUDIENCE => Some(AUDIENCE.into()),
            ENV_SOCKET => Some(socket.clone()),
            _ => None,
        }
    })
    .unwrap();
    let clock = Clock::default();
    let state = AppState::with_clock(config, clock.clone()).unwrap();
    Setup {
        provider,
        daemon,
        app: router(state.clone()),
        state,
        clock,
    }
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Reply {
    fn location(&self) -> String {
        self.headers[header::LOCATION].to_str().unwrap().to_owned()
    }

    fn set_cookies(&self) -> Vec<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect()
    }
}

/// A browser: a cookie jar in front of the router, and a plain client for the provider.
struct Browser {
    app: Router,
    jar: BTreeMap<String, String>,
    provider_client: reqwest::Client,
}

impl Browser {
    fn new(app: &Router) -> Self {
        Self {
            app: app.clone(),
            jar: BTreeMap::new(),
            // Redirects are never followed by this client, so the test reads each Location itself.
            provider_client: weglarka_http::client(weglarka_http::Purpose::Api).unwrap(),
        }
    }

    fn cookie(&self, name: &str) -> Option<&str> {
        self.jar.get(name).map(String::as_str)
    }

    async fn send(&mut self, request: http_request::Builder) -> Reply {
        self.send_with(request, Body::empty()).await
    }

    async fn send_with(&mut self, builder: http_request::Builder, body: Body) -> Reply {
        let mut builder = builder;
        if !self.jar.is_empty() {
            let cookies: Vec<String> = self.jar.iter().map(|(k, v)| format!("{k}={v}")).collect();
            builder = builder.header(header::COOKIE, cookies.join("; "));
        }
        let response = self
            .app
            .clone()
            .oneshot(builder.body(body).unwrap())
            .await
            .unwrap();
        let (parts, body) = response.into_parts();
        let reply = Reply {
            status: parts.status,
            headers: parts.headers,
            body: String::from_utf8_lossy(&to_bytes(body, usize::MAX).await.unwrap()).into_owned(),
        };
        for cookie in reply.set_cookies() {
            let pair = cookie.split(';').next().unwrap();
            let (name, value) = pair.split_once('=').unwrap();
            if cookie.contains("Max-Age=0") {
                self.jar.remove(name);
            } else {
                self.jar.insert(name.to_owned(), value.to_owned());
            }
        }
        reply
    }

    async fn get(&mut self, path: &str) -> Reply {
        self.send(Request::builder().method(Method::GET).uri(path))
            .await
    }

    /// Starts a login and lets the provider approve it; returns the callback path and query.
    async fn approve(&mut self, return_to: &str) -> String {
        let start = self
            .get(&format!(
                "/auth/login?return_to={}",
                url::form_urlencoded::byte_serialize(return_to.as_bytes()).collect::<String>()
            ))
            .await;
        assert_eq!(start.status, StatusCode::SEE_OTHER, "{}", start.body);
        let answer = self
            .provider_client
            .get(start.location())
            .send()
            .await
            .unwrap();
        assert_eq!(answer.status(), StatusCode::FOUND);
        let callback = answer.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .to_owned();
        callback.strip_prefix(PUBLIC).unwrap().to_owned()
    }

    async fn login(&mut self) -> Reply {
        let callback = self.approve("/").await;
        self.get(&callback).await
    }

    /// The CSRF token from the signed-in page.
    async fn csrf(&mut self) -> String {
        let page = self.get("/apps").await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        let marker = "name=\"_csrf\" value=\"";
        let start = page.body.find(marker).unwrap() + marker.len();
        let end = start + page.body[start..].find('"').unwrap();
        page.body[start..end].to_owned()
    }

    async fn post_logout(
        &mut self,
        token: Option<(&str, &str)>,
        fetch_site: Option<&str>,
    ) -> Reply {
        let mut builder = Request::builder().method(Method::POST).uri("/auth/logout");
        if let Some(site) = fetch_site {
            builder = builder.header("sec-fetch-site", site);
        }
        let body = match token {
            Some(("header", t)) => {
                builder = builder.header("x-csrf-token", t);
                Body::empty()
            }
            Some((_, t)) => {
                builder = builder.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
                Body::from(format!("_csrf={t}"))
            }
            None => Body::empty(),
        };
        self.send_with(builder, body).await
    }
}

use axum::http::request as http_request;

fn bearer_seen(daemon: &Mock) -> Vec<String> {
    daemon
        .seen
        .lock()
        .unwrap()
        .iter()
        .map(|s| s.header("authorization").unwrap_or("").to_owned())
        .collect()
}

#[tokio::test]
async fn the_full_login_flow() {
    let s = setup().await;
    let mut b = Browser::new(&s.app);

    // Signed out: 401 with a link back to this page after login.
    let denied = b.get("/apps/web?tab=logs").await;
    assert_eq!(denied.status, StatusCode::UNAUTHORIZED);
    assert!(
        denied
            .body
            .contains("/auth/login?return_to=%2Fapps%2Fweb%3Ftab%3Dlogs"),
        "{}",
        denied.body
    );

    let callback = b.approve("/apps/web?tab=logs").await;
    // What the panel asked the provider for.
    let asked = &s.provider.requests("/authorize")[0];
    let q: BTreeMap<String, String> = url::form_urlencoded::parse(asked.query.as_bytes())
        .into_owned()
        .collect();
    assert_eq!(q["client_id"], "panel");
    assert_eq!(q["redirect_uri"], "https://panel.example.com/auth/callback");
    assert_eq!(q["code_challenge_method"], "S256");
    assert_eq!(q["audience"], AUDIENCE);
    assert!(q["scope"].contains("offline_access") && q["scope"].contains("groups"));

    let done = b.get(&callback).await;
    assert_eq!(done.status, StatusCode::SEE_OTHER);
    assert_eq!(done.location(), "/apps/web?tab=logs");
    assert!(b.cookie(SESSION).is_some());
    assert!(b.cookie(LOGIN).is_none(), "the login cookie is cleared");

    // The code exchange authenticated with client_secret_basic and sent the PKCE verifier.
    let exchange = &s.provider.requests("/token")[0];
    assert!(
        exchange
            .authorization
            .as_deref()
            .unwrap()
            .starts_with("Basic ")
    );
    assert!(exchange.body.contains("grant_type=authorization_code"));
    assert!(exchange.body.contains("code_verifier="));
    assert!(
        !exchange.body.contains(CLIENT_SECRET),
        "the secret is in the header only"
    );

    let page = b.get("/apps").await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("Alice Example"), "{}", page.body);
    // The daemon was called with the user's own access token.
    assert_eq!(bearer_seen(&s.daemon), vec!["Bearer access-token-1"]);

    // The callback is single use: replaying it fails and creates no second session.
    let mut other = Browser::new(&s.app);
    other.jar = b.jar.clone();
    let replay = other.get(&callback).await;
    assert_eq!(replay.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn cookies_carry_the_host_prefix_and_attributes() {
    let s = setup().await;
    let mut b = Browser::new(&s.app);
    let start = b.get("/auth/login").await;
    let login_cookie = start.set_cookies().remove(0);
    let callback = {
        let answer = b
            .provider_client
            .get(start.location())
            .send()
            .await
            .unwrap();
        answer.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .replacen(PUBLIC, "", 1)
    };
    let done = b.get(&callback).await;
    let cookies = done.set_cookies();
    let session_cookie = cookies.iter().find(|c| c.starts_with(SESSION)).unwrap();
    for cookie in [&login_cookie, session_cookie] {
        assert!(cookie.starts_with("__Host-"), "{cookie}");
        for attr in ["Path=/", "Secure", "HttpOnly", "SameSite=Lax"] {
            assert!(cookie.contains(attr), "{cookie}");
        }
        assert!(!cookie.contains("Domain"), "{cookie}");
    }
    // Session cookie: no Max-Age, it dies with the browser session; the id is 256 random bits.
    assert!(!session_cookie.contains("Max-Age"));
    let id = session_cookie
        .split(';')
        .next()
        .unwrap()
        .split('=')
        .nth(1)
        .unwrap();
    assert_eq!(id.len(), 43);
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with(LOGIN) && c.contains("Max-Age=0"))
    );
}

#[tokio::test]
async fn login_never_reuses_a_session_id() {
    let s = setup().await;
    let mut b = Browser::new(&s.app);
    // An id planted before login (fixation) is neither honoured nor kept.
    b.jar.insert(SESSION.into(), "attacker-chosen-id".into());
    let done = b.login().await;
    assert_eq!(done.status, StatusCode::SEE_OTHER);
    let first = b.cookie(SESSION).unwrap().to_owned();
    assert_ne!(first, "attacker-chosen-id");
    assert_eq!(s.state.sessions.len(), 1);

    // Logging in again replaces the session: new id, old one gone.
    let done = b.login().await;
    assert_eq!(done.status, StatusCode::SEE_OTHER);
    let second = b.cookie(SESSION).unwrap().to_owned();
    assert_ne!(first, second);
    assert_eq!(s.state.sessions.len(), 1);
    assert!(s.state.sessions.get(&first).is_none());
    assert!(s.state.sessions.get(&second).is_some());
}

#[tokio::test]
async fn a_bad_callback_creates_no_session() {
    let s = setup().await;
    let mut b = Browser::new(&s.app);

    // Wrong state.
    let callback = b.approve("/").await;
    let tampered = callback.replacen("state=", "state=x", 1);
    let bad = b.get(&tampered).await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    assert!(b.cookie(SESSION).is_none());
    // The pending login was consumed by the failed attempt: the genuine answer no longer works either.
    let again = b.get(&callback).await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST);

    // Missing state, missing code, error from the provider, no login cookie at all.
    for variant in ["code-only", "state-only", "error"] {
        let callback = b.approve("/").await;
        let (code, state) = {
            let q: BTreeMap<String, String> =
                url::form_urlencoded::parse(callback.split_once('?').unwrap().1.as_bytes())
                    .into_owned()
                    .collect();
            (q["code"].clone(), q["state"].clone())
        };
        let path = match variant {
            "code-only" => format!("/auth/callback?code={code}"),
            "state-only" => format!("/auth/callback?state={state}"),
            _ => format!("/auth/callback?error=access_denied&state={state}"),
        };
        assert_eq!(
            b.get(&path).await.status,
            StatusCode::BAD_REQUEST,
            "{variant}"
        );
    }
    let mut stranger = Browser::new(&s.app);
    let callback = b.approve("/").await;
    assert_eq!(
        stranger.get(&callback).await.status,
        StatusCode::BAD_REQUEST
    );

    assert!(b.cookie(SESSION).is_none());
    assert!(s.state.sessions.is_empty());
}

#[tokio::test]
async fn id_tokens_that_do_not_verify_are_refused() {
    type Tweak = Box<dyn Fn(&mut crate::provider::Behaviour)>;
    let cases: Vec<(&str, Tweak)> = vec![
        (
            "wrong nonce",
            Box::new(|b| b.id_nonce = Some("not-the-nonce".into())),
        ),
        (
            "wrong audience",
            Box::new(|b| b.id_aud = "someone-else".into()),
        ),
        (
            "foreign azp",
            Box::new(|b| b.id_azp = Some("someone-else".into())),
        ),
        (
            "bad signature",
            Box::new(|b| {
                b.id_signer = Some(Arc::new(
                    weglarka_model::admin_auth::testing::TestIssuer::new("k1"),
                ))
            }),
        ),
        ("no id token", Box::new(|b| b.omit_id_token = true)),
        (
            "wrong issuer",
            Box::new(|b| b.id_iss = Some("https://other.example.com".into())),
        ),
        ("expired", Box::new(|b| b.id_expired = true)),
    ];
    for (name, tweak) in cases {
        let s = setup().await;
        let mut b = Browser::new(&s.app);
        s.provider.set(|p| tweak(p));
        let done = b.login().await;
        assert_eq!(
            done.status,
            StatusCode::BAD_REQUEST,
            "{name}: {}",
            done.body
        );
        let after = b.get("/apps").await;
        assert_eq!(after.status, StatusCode::UNAUTHORIZED, "{name}");
    }
}

#[tokio::test]
async fn discovery_must_name_the_configured_issuer_and_safe_endpoints() {
    // A different issuer in the document.
    let s = setup().await;
    s.provider
        .set(|p| p.discovery_issuer = Some("http://127.0.0.1:1".into()));
    let mut b = Browser::new(&s.app);
    assert_eq!(b.get("/auth/login").await.status, StatusCode::BAD_GATEWAY);
    assert!(b.cookie(LOGIN).is_none());

    // Same byte for byte only: a trailing slash is a different issuer.
    let s = setup().await;
    let with_slash = format!("{}/", s.provider.issuer);
    s.provider.set(|p| p.discovery_issuer = Some(with_slash));
    assert_eq!(
        Browser::new(&s.app).get("/auth/login").await.status,
        StatusCode::BAD_GATEWAY
    );

    // An endpoint that is plain http to a non-loopback host.
    let s = setup().await;
    s.provider
        .set(|p| p.authorization_endpoint = Some("http://auth.example.com/authorize".into()));
    assert_eq!(
        Browser::new(&s.app).get("/auth/login").await.status,
        StatusCode::BAD_GATEWAY
    );
}

#[tokio::test]
async fn the_issuer_must_be_https_unless_it_is_loopback() {
    for bad in [
        "http://auth.example.com",
        "ftp://127.0.0.1",
        "http://127.0.0.1.example.com",
    ] {
        let err = PanelConfig::from_lookup(|var| match var {
            ENV_ISSUER => Some(bad.into()),
            ENV_CLIENT_ID => Some("panel".into()),
            ENV_CLIENT_SECRET => Some("s".into()),
            ENV_PUBLIC_URL => Some(PUBLIC.into()),
            ENV_API_AUDIENCE => Some(AUDIENCE.into()),
            _ => None,
        })
        .unwrap_err();
        assert!(err.to_string().contains(ENV_ISSUER), "{bad}: {err}");
    }
}

#[tokio::test]
async fn keys_are_refetched_for_an_unknown_kid_at_most_every_30_seconds() {
    let s = setup().await;
    let mut b = Browser::new(&s.app);
    assert_eq!(b.login().await.status, StatusCode::SEE_OTHER);
    assert_eq!(s.provider.requests("/jwks").len(), 1);

    // The provider rotates its key. Within 30 s the panel does not hammer the JWKS endpoint.
    s.provider
        .set(|p| p.signer = Arc::new(weglarka_model::admin_auth::testing::TestIssuer::new("k2")));
    assert_eq!(b.login().await.status, StatusCode::BAD_REQUEST);
    assert_eq!(s.provider.requests("/jwks").len(), 1);

    // Later it does, and the new key is accepted.
    s.clock.advance(Duration::from_secs(31));
    assert_eq!(b.login().await.status, StatusCode::SEE_OTHER);
    assert_eq!(s.provider.requests("/jwks").len(), 2);

    // A failing JWKS endpoint keeps the keys that are cached: the cached k2 still verifies, and an
    // unknown k3 is refused after the refetch fails.
    s.provider.set(|p| p.jwks_down = true);
    s.clock.advance(Duration::from_secs(31));
    assert_eq!(b.login().await.status, StatusCode::SEE_OTHER);
    s.provider
        .set(|p| p.signer = Arc::new(weglarka_model::admin_auth::testing::TestIssuer::new("k3")));
    s.clock.advance(Duration::from_secs(31));
    assert_eq!(b.login().await.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        s.provider.requests("/jwks").len(),
        3,
        "the failed refetch was attempted once"
    );
}

#[tokio::test]
async fn sessions_end_when_idle_or_too_old() {
    let s = setup_with(&[
        (ENV_SESSION_IDLE_SECS, "120"),
        (ENV_SESSION_MAX_SECS, "600"),
    ])
    .await;
    let mut b = Browser::new(&s.app);

    b.login().await;
    let session = s.state.sessions.get(b.cookie(SESSION).unwrap()).unwrap();
    let ended = session.ended();
    // Activity keeps it alive past the idle limit...
    for _ in 0..5 {
        s.clock.advance(Duration::from_secs(100));
        assert_eq!(b.get("/apps").await.status, StatusCode::OK);
    }
    assert!(!*ended.borrow());
    // ...but never past the absolute one.
    s.clock.advance(Duration::from_secs(101));
    let late = b.get("/apps").await;
    assert_eq!(late.status, StatusCode::UNAUTHORIZED);
    assert!(*ended.borrow());
    assert!(b.cookie(SESSION).is_none(), "the dead cookie is cleared");

    // Idle.
    b.login().await;
    let ended = s
        .state
        .sessions
        .get(b.cookie(SESSION).unwrap())
        .unwrap()
        .ended();
    s.clock.advance(Duration::from_secs(121));
    assert_eq!(b.get("/apps").await.status, StatusCode::UNAUTHORIZED);
    assert!(*ended.borrow());
}

#[tokio::test]
async fn a_forged_post_does_not_extend_the_idle_timer() {
    let s = setup_with(&[
        (ENV_SESSION_IDLE_SECS, "120"),
        (ENV_SESSION_MAX_SECS, "600"),
    ])
    .await;

    // Forged requests keep nothing alive: refused at 110 s, the session is still idle-dead at 130 s.
    let mut b = Browser::new(&s.app);
    b.login().await;
    let csrf = b.csrf().await;
    s.clock.advance(Duration::from_secs(110));
    let wrong = b.post_logout(Some(("header", "wrong")), None).await;
    assert_eq!(wrong.status, StatusCode::FORBIDDEN, "wrong token");
    let cross = b
        .post_logout(Some(("header", csrf.as_str())), Some("cross-site"))
        .await;
    assert_eq!(cross.status, StatusCode::FORBIDDEN, "cross-site");
    s.clock.advance(Duration::from_secs(20));
    assert_eq!(b.get("/apps").await.status, StatusCode::UNAUTHORIZED);

    // Control: a genuine request at the same moment does keep the session alive.
    let mut b = Browser::new(&s.app);
    b.login().await;
    s.clock.advance(Duration::from_secs(110));
    assert_eq!(b.get("/apps").await.status, StatusCode::OK);
    s.clock.advance(Duration::from_secs(20));
    assert_eq!(b.get("/apps").await.status, StatusCode::OK);
}

#[tokio::test]
async fn state_changing_requests_need_the_csrf_token() {
    let s = setup().await;
    let mut b = Browser::new(&s.app);
    b.login().await;
    let csrf = b.csrf().await;
    let ended = s
        .state
        .sessions
        .get(b.cookie(SESSION).unwrap())
        .unwrap()
        .ended();

    for (what, token, site) in [
        ("no token", None, None),
        ("wrong header token", Some(("header", "wrong")), None),
        ("wrong form token", Some(("form", "wrong")), None),
        (
            "right token, cross-site",
            Some(("header", csrf.as_str())),
            Some("cross-site"),
        ),
        (
            "right token, same-site",
            Some(("form", csrf.as_str())),
            Some("same-site"),
        ),
    ] {
        let r = b.post_logout(token, site).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{what}");
        assert!(!*ended.borrow(), "{what}");
    }
    // A JSON body is not a form, so without the header there is no token to find.
    let json = b
        .send_with(
            Request::builder()
                .method(Method::POST)
                .uri("/auth/logout")
                .header(header::CONTENT_TYPE, "application/json"),
            Body::from(format!(r#"{{"_csrf":"{csrf}"}}"#)),
        )
        .await;
    assert_eq!(json.status, StatusCode::FORBIDDEN, "json body, no header");
    assert!(!*ended.borrow());
    // Logging out by GET is not a thing.
    assert_eq!(
        b.get("/auth/logout").await.status,
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert!(!*ended.borrow());
    assert_eq!(b.get("/apps").await.status, StatusCode::OK);

    // The form field works; so does the header.
    let done = b
        .post_logout(Some(("form", &csrf)), Some("same-origin"))
        .await;
    assert_eq!(done.status, StatusCode::SEE_OTHER);
    assert_eq!(done.location(), "/");
    assert!(*ended.borrow());
    assert!(b.cookie(SESSION).is_none());
    assert_eq!(b.get("/apps").await.status, StatusCode::UNAUTHORIZED);

    b.login().await;
    let csrf = b.csrf().await;
    let done = b.post_logout(Some(("header", &csrf)), None).await;
    assert_eq!(done.status, StatusCode::SEE_OTHER);
    assert!(s.state.sessions.is_empty());
}

#[tokio::test]
async fn a_logged_out_cookie_is_useless_even_if_replayed() {
    let s = setup().await;
    let mut b = Browser::new(&s.app);
    b.login().await;
    let stolen = b.cookie(SESSION).unwrap().to_owned();
    let csrf = b.csrf().await;
    b.post_logout(Some(("header", &csrf)), None).await;
    let mut thief = Browser::new(&s.app);
    thief.jar.insert(SESSION.into(), stolen);
    assert_eq!(thief.get("/apps").await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_access_token_is_refreshed_once_and_the_daemon_sees_the_new_one() {
    let s = setup().await;
    // Tokens that live 30 s are always "about to expire" (the margin is 60 s).
    s.provider.set(|p| p.expires_in = 30);
    let mut b = Browser::new(&s.app);
    b.login().await;

    // Five requests at once: one refresh, all five use the new token.
    let one = || {
        let mut browser = Browser::new(&s.app);
        browser.jar = b.jar.clone();
        async move { browser.get("/apps").await.status }
    };
    let statuses = tokio::join!(one(), one(), one(), one(), one());
    let statuses = [statuses.0, statuses.1, statuses.2, statuses.3, statuses.4];
    assert!(
        statuses.iter().all(|s| *s == StatusCode::OK),
        "{statuses:?}"
    );
    let refreshes: Vec<_> = s
        .provider
        .requests("/token")
        .into_iter()
        .filter(|r| r.body.contains("grant_type=refresh_token"))
        .collect();
    assert_eq!(refreshes.len(), 1, "one refresh in flight at a time");
    assert!(refreshes[0].body.contains("refresh_token=refresh-token-1"));
    let seen = bearer_seen(&s.daemon);
    assert_eq!(seen.len(), 5);
    assert!(
        seen.iter().all(|h| h == "Bearer access-token-2"),
        "{seen:?}"
    );
}

#[tokio::test]
async fn a_refused_refresh_ends_the_session() {
    let s = setup().await;
    s.provider.set(|p| p.expires_in = 30);
    let mut b = Browser::new(&s.app);
    b.login().await;
    let ended = s
        .state
        .sessions
        .get(b.cookie(SESSION).unwrap())
        .unwrap()
        .ended();
    s.provider.set(|p| p.refresh = Refresh::Revoked);

    let r = b.get("/apps").await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(
        *ended.borrow(),
        "ended() flips so streams tied to the session close"
    );
    assert!(s.state.sessions.is_empty());
    assert_eq!(b.get("/apps").await.status, StatusCode::UNAUTHORIZED);
    // Nothing reached the daemon with the dead session.
    assert!(s.daemon.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_provider_outage_does_not_log_out_a_token_that_still_works() {
    let s = setup().await;
    s.provider.set(|p| p.expires_in = 30);
    let mut b = Browser::new(&s.app);
    b.login().await;
    s.provider.set(|p| p.refresh = Refresh::Down);

    // Valid for 30 s more: keep going on the current token, retry next time.
    assert_eq!(b.get("/apps").await.status, StatusCode::OK);
    assert_eq!(bearer_seen(&s.daemon), vec!["Bearer access-token-1"]);

    // Once it has expired and cannot be renewed, the session ends.
    s.clock.advance(Duration::from_secs(31));
    assert_eq!(b.get("/apps").await.status, StatusCode::UNAUTHORIZED);
    assert!(s.state.sessions.is_empty());
}

/// A panel whose daemon answers every request with `status` and `body`.
async fn setup_refusing_daemon(s: &Setup, status: u16, body: &'static str) -> (AppState, Router) {
    let daemon = mock(move |_, _| (status, body.into())).await;
    let config = PanelConfig::from_lookup(|var| match var {
        ENV_CLIENT_ID => Some("panel".into()),
        ENV_CLIENT_SECRET => Some(CLIENT_SECRET.into()),
        ENV_ISSUER => Some(s.provider.issuer.clone()),
        ENV_PUBLIC_URL => Some(PUBLIC.into()),
        ENV_API_AUDIENCE => Some(AUDIENCE.into()),
        ENV_SOCKET => Some(daemon.socket.display().to_string()),
        _ => None,
    })
    .unwrap();
    let state = AppState::with_clock(config, s.clock.clone()).unwrap();
    // The mock's socket lives as long as its handle; leak it for the test's duration.
    std::mem::forget(daemon);
    let app = router(state.clone());
    (state, app)
}

#[tokio::test]
async fn a_daemon_that_gives_the_user_no_access_ends_the_session() {
    for (status, body) in [
        (401, r#"{"code":"unauthorized","message":"no"}"#),
        (403, r#"{"code":"forbidden","message":"no scope"}"#),
    ] {
        let s = setup().await;
        let (state, app) = setup_refusing_daemon(&s, status, body).await;
        let mut b = Browser::new(&app);
        b.login().await;
        assert_eq!(state.sessions.len(), 1);
        let r = b.get("/apps").await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{status}");
        assert!(r.body.contains("Sign in"));
        assert!(
            state.sessions.is_empty(),
            "{status}: a user the daemon refuses holds no session"
        );
        assert!(b.cookie(SESSION).is_none(), "the cookie is cleared");
    }
}

#[tokio::test]
async fn an_anonymous_flood_of_logins_blocks_nobody() {
    let s = setup().await;
    // Far past any old table size: starting a login stores nothing on the server.
    for _ in 0..3000 {
        let r = Browser::new(&s.app).get("/auth/login").await;
        assert_eq!(r.status, StatusCode::SEE_OTHER);
    }
    let mut b = Browser::new(&s.app);
    let done = b.login().await;
    assert_eq!(done.status, StatusCode::SEE_OTHER, "{}", done.body);
    assert!(b.cookie(SESSION).is_some());
    assert_eq!(s.state.logins.used_len(), 1);
}

#[tokio::test]
async fn a_replayed_callback_with_its_cookie_is_refused() {
    let s = setup().await;
    let mut b = Browser::new(&s.app);
    let start = b.get("/auth/login").await;
    let login_cookie = start
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with(LOGIN))
        .unwrap();
    let login_value = login_cookie
        .split(';')
        .next()
        .unwrap()
        .split_once('=')
        .unwrap()
        .1
        .to_owned();
    let callback = b
        .provider_client
        .get(start.location())
        .send()
        .await
        .unwrap()
        .headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .replacen(PUBLIC, "", 1);
    assert_eq!(b.get(&callback).await.status, StatusCode::SEE_OTHER);

    // A browser (or attacker) that kept the login cookie replays the same answer.
    let mut replay = Browser::new(&s.app);
    replay.jar.insert(LOGIN.into(), login_value.clone());
    assert_eq!(replay.get(&callback).await.status, StatusCode::BAD_REQUEST);
    assert!(replay.cookie(SESSION).is_none());
    assert_eq!(s.state.sessions.len(), 1);

    // A cookie the panel did not seal is just as useless.
    let mut forger = Browser::new(&s.app);
    forger.jar.insert(LOGIN.into(), "A".repeat(200));
    assert_eq!(forger.get(&callback).await.status, StatusCode::BAD_REQUEST);

    // And one that outlived its ten minutes.
    let mut late = Browser::new(&s.app);
    let start = late.get("/auth/login").await;
    let callback = late
        .provider_client
        .get(start.location())
        .send()
        .await
        .unwrap()
        .headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .replacen(PUBLIC, "", 1);
    s.clock.advance(Duration::from_secs(601));
    assert_eq!(late.get(&callback).await.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn one_identity_cannot_fill_the_session_table() {
    let s = setup().await;
    let mut first = Browser::new(&s.app);
    first.login().await;
    let first_id = first.cookie(SESSION).unwrap().to_owned();
    // The same account signing in again and again without ever sending its old cookie.
    for _ in 0..20 {
        let done = Browser::new(&s.app).login().await;
        assert_eq!(done.status, StatusCode::SEE_OTHER);
    }
    assert_eq!(
        s.state.sessions.len(),
        weglarka_panel::session::MAX_SESSIONS_PER_SUB
    );
    assert!(
        s.state.sessions.get(&first_id).is_none(),
        "the oldest session made room"
    );
}

#[tokio::test]
async fn the_jwks_is_refetched_after_an_hour_even_for_a_known_kid() {
    let s = setup().await;
    let mut b = Browser::new(&s.app);
    assert_eq!(b.login().await.status, StatusCode::SEE_OTHER);
    assert_eq!(s.provider.requests("/jwks").len(), 1);

    // The provider drops its key (k1) but is still seen signing with it: a revoked key.
    let mut old = None;
    s.provider.set(|p| old = Some(p.signer.clone()));
    s.provider.set(|p| {
        p.signer = Arc::new(weglarka_model::admin_auth::testing::TestIssuer::new("k2"));
        p.id_signer = old.take();
    });
    s.clock.advance(Duration::from_secs(40 * 60));
    assert_eq!(
        b.login().await.status,
        StatusCode::SEE_OTHER,
        "within the hour the cached key still counts"
    );
    assert_eq!(s.provider.requests("/jwks").len(), 1);

    s.clock.advance(Duration::from_secs(21 * 60));
    assert_eq!(b.login().await.status, StatusCode::BAD_REQUEST);
    assert_eq!(s.provider.requests("/jwks").len(), 2);

    // A provider that is down at that moment does not take the cached keys away.
    s.provider.set(|p| p.id_signer = None);
    assert_eq!(b.login().await.status, StatusCode::SEE_OTHER);
    s.provider.set(|p| p.jwks_down = true);
    s.clock.advance(Duration::from_secs(61 * 60));
    assert_eq!(b.login().await.status, StatusCode::SEE_OTHER);
    assert!(s.provider.requests("/jwks").len() >= 3, "it tried");
}

#[tokio::test]
async fn a_failed_discovery_is_not_retried_for_ten_seconds() {
    let s = setup().await;
    s.provider
        .set(|p| p.discovery_issuer = Some("http://127.0.0.1:1".into()));
    for _ in 0..5 {
        assert_eq!(
            Browser::new(&s.app).get("/auth/login").await.status,
            StatusCode::BAD_GATEWAY
        );
    }
    assert_eq!(
        s.provider
            .requests("/.well-known/openid-configuration")
            .len(),
        1
    );

    // Recovered provider, but the failure is remembered until the pause is over.
    s.provider.set(|p| p.discovery_issuer = None);
    assert_eq!(
        Browser::new(&s.app).get("/auth/login").await.status,
        StatusCode::BAD_GATEWAY
    );
    s.clock.advance(Duration::from_secs(11));
    assert_eq!(
        Browser::new(&s.app).get("/auth/login").await.status,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        s.provider
            .requests("/.well-known/openid-configuration")
            .len(),
        2
    );
}

#[tokio::test]
async fn the_token_endpoint_must_stay_on_the_issuers_host() {
    // A poisoned discovery document points the token endpoint (and with it the client secret) elsewhere.
    let s = setup().await;
    s.provider
        .set(|p| p.token_endpoint = Some("http://127.0.0.2:9/token".into()));
    assert_eq!(
        Browser::new(&s.app).get("/auth/login").await.status,
        StatusCode::BAD_GATEWAY
    );

    // The operator can name the extra host explicitly.
    let s = setup_with(&[(weglarka_panel::config::ENV_ENDPOINT_HOSTS, "127.0.0.2")]).await;
    s.provider
        .set(|p| p.token_endpoint = Some("http://127.0.0.2:9/token".into()));
    assert_eq!(
        Browser::new(&s.app).get("/auth/login").await.status,
        StatusCode::SEE_OTHER
    );
}

/// A tracing sink that collects what is logged, to search it for secrets.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Capture {
        self.clone()
    }
}

#[tokio::test]
async fn no_secret_appears_in_logs_urls_or_debug_output() {
    let logs = Capture::default();
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_max_level(tracing::Level::DEBUG)
            .finish(),
    );
    let s = setup().await;
    s.provider.set(|p| p.expires_in = 30);
    let mut b = Browser::new(&s.app);

    let mut locations = Vec::new();
    let start = b.get("/auth/login?return_to=%2Fapps").await;
    let mut login_cookies = vec![b.cookie(LOGIN).unwrap().to_owned()];
    locations.push(start.location());
    let answer = b
        .provider_client
        .get(start.location())
        .send()
        .await
        .unwrap();
    let callback = answer.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .replacen(PUBLIC, "", 1);
    let done = b.get(&callback).await;
    locations.push(done.location());
    // Failures too: a bad state, a refused refresh, a bad id token.
    let bad = b.approve("/").await;
    login_cookies.push(b.cookie(LOGIN).unwrap().to_owned());
    b.get(&bad.replacen("state=", "state=x", 1)).await;
    let session = s.state.sessions.get(b.cookie(SESSION).unwrap()).unwrap();
    let csrf = session.csrf.clone();
    let session_id = b.cookie(SESSION).unwrap().to_owned();
    let view_debug = {
        let tokens = session.tokens.lock().await;
        format!("{session:?} {tokens:?}")
    };
    b.get("/apps").await; // refreshes
    s.provider.set(|p| p.refresh = Refresh::Revoked);
    b.get("/apps").await; // refresh refused
    s.provider.set(|p| p.id_nonce = Some("x".into()));
    b.login().await;

    let mut secrets = s.provider.secrets();
    secrets.extend([CLIENT_SECRET.to_owned(), csrf, session_id]);
    assert!(secrets.len() >= 8, "{secrets:?}");

    // The panel's own per-login values: `state` and `nonce` from what the provider was asked (the
    // authorization redirect legitimately carries them, so it is not swept), the PKCE verifier from
    // the code exchange, and the sealed login cookie that holds all three.
    let mut own = Vec::new();
    for asked in s.provider.requests("/authorize") {
        let q: BTreeMap<String, String> = url::form_urlencoded::parse(asked.query.as_bytes())
            .into_owned()
            .collect();
        own.extend([q["state"].clone(), q["nonce"].clone()]);
    }
    for exchange in s.provider.requests("/token") {
        let form: BTreeMap<String, String> = url::form_urlencoded::parse(exchange.body.as_bytes())
            .into_owned()
            .collect();
        if let Some(verifier) = form.get("code_verifier") {
            own.push(verifier.clone());
        }
    }
    own.extend(login_cookies);
    assert!(own.len() >= 6, "{own:?}");
    let log = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(log.contains("WARN"), "the failures were logged: {log}");
    let debug = format!("{view_debug} {:?}", s.state.config);
    for secret in &secrets {
        assert!(
            !log.contains(secret.as_str()),
            "a secret is in the logs: {secret}"
        );
        assert!(
            !debug.contains(secret.as_str()),
            "a secret is in Debug output: {secret}"
        );
        for location in &locations {
            assert!(
                !location.contains(secret.as_str()),
                "{secret} in {location}"
            );
        }
    }
    for value in &own {
        assert!(
            !log.contains(value.as_str()),
            "a login value is in the logs: {value}"
        );
        assert!(
            !debug.contains(value.as_str()),
            "a login value is in Debug output: {value}"
        );
        // The callback redirect carries none of them either.
        assert!(
            !locations[1].contains(value.as_str()),
            "{value} in the callback redirect"
        );
    }
    // Neither the PKCE verifier nor the state travel in the callback redirect.
    assert_eq!(locations[1], "/apps");
}
