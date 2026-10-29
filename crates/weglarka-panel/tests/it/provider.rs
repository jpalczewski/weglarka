//! A fake OIDC provider on 127.0.0.1: discovery, JWKS, authorize and token endpoints, signing id
//! tokens with `TestIssuer`. It validates what a real provider would (client authentication, PKCE,
//! single-use codes, redirect URI) so the tests exercise the panel's requests, not just its parsing.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::digest::{SHA256, digest};
use serde_json::json;
use weglarka_model::admin_auth::testing::TestIssuer;

pub const CLIENT_ID: &str = "panel";
pub const CLIENT_SECRET: &str = "provider-client-secret-8c1d";
pub const REDIRECT_URI: &str = "https://panel.example.com/auth/callback";
pub const AUDIENCE: &str = "https://admin.example.com/api/";

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Refresh {
    Ok,
    /// `400 invalid_grant`: the grant is gone.
    Revoked,
    /// `503`: the provider is down.
    Down,
}

/// Knobs a test turns before (or between) logins.
pub struct Behaviour {
    pub signer: Arc<TestIssuer>,
    /// Signs id tokens when it differs from the key in the JWKS.
    pub id_signer: Option<Arc<TestIssuer>>,
    pub discovery_issuer: Option<String>,
    pub authorization_endpoint: Option<String>,
    pub id_aud: String,
    pub id_nonce: Option<String>,
    pub id_azp: Option<String>,
    pub omit_id_token: bool,
    pub expires_in: u64,
    pub refresh_expires_in: u64,
    pub refresh: Refresh,
    pub jwks_down: bool,
}

#[derive(Debug, Clone)]
pub struct Recorded {
    pub path: String,
    pub query: String,
    pub authorization: Option<String>,
    pub body: String,
}

struct Grant {
    nonce: String,
    challenge: String,
}

struct Inner {
    issuer: String,
    behaviour: Mutex<Behaviour>,
    codes: Mutex<HashMap<String, Grant>>,
    refresh_tokens: Mutex<Vec<String>>,
    issued: Mutex<Vec<String>>,
    seen: Mutex<Vec<Recorded>>,
    counter: Mutex<u32>,
}

#[derive(Clone)]
pub struct Provider {
    inner: Arc<Inner>,
    pub issuer: String,
}

impl Provider {
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let issuer = format!("http://{addr}");
        let inner = Arc::new(Inner {
            issuer: issuer.clone(),
            behaviour: Mutex::new(Behaviour {
                signer: Arc::new(TestIssuer::new("k1")),
                id_signer: None,
                discovery_issuer: None,
                authorization_endpoint: None,
                id_aud: CLIENT_ID.to_owned(),
                id_nonce: None,
                id_azp: None,
                omit_id_token: false,
                expires_in: 3600,
                refresh_expires_in: 3600,
                refresh: Refresh::Ok,
                jwks_down: false,
            }),
            codes: Mutex::default(),
            refresh_tokens: Mutex::default(),
            issued: Mutex::default(),
            seen: Mutex::default(),
            counter: Mutex::default(),
        });
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/authorize", get(authorize))
            .route("/token", post(token))
            .with_state(inner.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { inner, issuer }
    }

    pub fn set(&self, change: impl FnOnce(&mut Behaviour)) {
        change(&mut self.inner.behaviour.lock().unwrap());
    }

    /// Requests that reached `path`, oldest first.
    pub fn requests(&self, path: &str) -> Vec<Recorded> {
        self.inner
            .seen
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.path == path)
            .cloned()
            .collect()
    }

    /// Every code, token and refresh token handed out: values that must never show up in a log,
    /// a URL or a `Debug` print of the panel.
    pub fn secrets(&self) -> Vec<String> {
        self.inner.issued.lock().unwrap().clone()
    }
}

fn record(inner: &Inner, uri: &Uri, headers: &HeaderMap, body: &str) {
    inner.seen.lock().unwrap().push(Recorded {
        path: uri.path().to_owned(),
        query: uri.query().unwrap_or("").to_owned(),
        authorization: headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
        body: body.to_owned(),
    });
}

async fn discovery(State(inner): State<Arc<Inner>>, uri: Uri, headers: HeaderMap) -> Response {
    record(&inner, &uri, &headers, "");
    let b = inner.behaviour.lock().unwrap();
    axum::Json(json!({
        "issuer": b.discovery_issuer.clone().unwrap_or_else(|| inner.issuer.clone()),
        "authorization_endpoint": b.authorization_endpoint.clone()
            .unwrap_or_else(|| format!("{}/authorize", inner.issuer)),
        "token_endpoint": format!("{}/token", inner.issuer),
        "jwks_uri": format!("{}/jwks", inner.issuer),
    }))
    .into_response()
}

async fn jwks(State(inner): State<Arc<Inner>>, uri: Uri, headers: HeaderMap) -> Response {
    record(&inner, &uri, &headers, "");
    let b = inner.behaviour.lock().unwrap();
    if b.jwks_down {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    (
        [(header::CONTENT_TYPE, "application/json")],
        b.signer.jwks_json(),
    )
        .into_response()
}

fn query(uri: &Uri) -> HashMap<String, String> {
    url::form_urlencoded::parse(uri.query().unwrap_or("").as_bytes())
        .into_owned()
        .collect()
}

/// The browser's visit: checks the request the way a provider would, then "approves" it.
async fn authorize(State(inner): State<Arc<Inner>>, uri: Uri, headers: HeaderMap) -> Response {
    record(&inner, &uri, &headers, "");
    let q = query(&uri);
    let get = |k: &str| q.get(k).cloned().unwrap_or_default();
    if get("response_type") != "code"
        || get("client_id") != CLIENT_ID
        || get("redirect_uri") != REDIRECT_URI
        || get("code_challenge_method") != "S256"
        || get("code_challenge").len() < 43
        || get("state").len() < 43
        || get("nonce").len() < 43
        || get("audience") != AUDIENCE
        || !get("scope").split(' ').any(|s| s == "openid")
    {
        return (StatusCode::BAD_REQUEST, "bad authorization request").into_response();
    }
    let code = format!("code-{}", crate::provider::unique());
    inner.issued.lock().unwrap().push(code.clone());
    inner.codes.lock().unwrap().insert(
        code.clone(),
        Grant {
            nonce: get("nonce"),
            challenge: get("code_challenge"),
        },
    );
    let location = format!("{REDIRECT_URI}?code={code}&state={}", get("state"));
    (StatusCode::FOUND, [(header::LOCATION, location)]).into_response()
}

pub fn unique() -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    format!("{:04}", N.fetch_add(1, Ordering::Relaxed))
}

fn error(status: StatusCode, code: &str) -> Response {
    (status, axum::Json(json!({"error": code}))).into_response()
}

async fn token(
    State(inner): State<Arc<Inner>>,
    uri: Uri,
    headers: HeaderMap,
    body: String,
) -> Response {
    record(&inner, &uri, &headers, &body);
    // client_secret_basic, credentials form-encoded then base64'd (RFC 6749 2.3.1).
    let expected = format!(
        "Basic {}",
        STANDARD.encode(format!("{CLIENT_ID}:{}", encode(CLIENT_SECRET)))
    );
    if headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        != Some(&expected)
    {
        return error(StatusCode::UNAUTHORIZED, "invalid_client");
    }
    let form: HashMap<String, String> = url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect();
    let field = |k: &str| form.get(k).cloned().unwrap_or_default();
    let n = {
        let mut counter = inner.counter.lock().unwrap();
        *counter += 1;
        *counter
    };
    let b = inner.behaviour.lock().unwrap();
    match field("grant_type").as_str() {
        "authorization_code" => {
            let Some(grant) = inner.codes.lock().unwrap().remove(&field("code")) else {
                return error(StatusCode::BAD_REQUEST, "invalid_grant");
            };
            let challenge =
                URL_SAFE_NO_PAD.encode(digest(&SHA256, field("code_verifier").as_bytes()));
            if challenge != grant.challenge || field("redirect_uri") != REDIRECT_URI {
                return error(StatusCode::BAD_REQUEST, "invalid_grant");
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let mut claims = json!({
                "iss": inner.issuer, "aud": b.id_aud, "sub": "alice-sub",
                "name": "Alice Example", "iat": now, "exp": now + 600,
                "nonce": b.id_nonce.clone().unwrap_or(grant.nonce),
            });
            if let Some(azp) = &b.id_azp {
                claims["azp"] = azp.clone().into();
            }
            let refresh = format!("refresh-token-{n}");
            inner.refresh_tokens.lock().unwrap().push(refresh.clone());
            let mut answer = json!({
                "access_token": format!("access-token-{n}"), "token_type": "bearer",
                "expires_in": b.expires_in, "refresh_token": refresh,
            });
            let access = format!("access-token-{n}");
            inner
                .issued
                .lock()
                .unwrap()
                .extend([access, refresh_for_log(n)]);
            if !b.omit_id_token {
                let id_token = b
                    .id_signer
                    .as_ref()
                    .unwrap_or(&b.signer)
                    .sign_with_typ(None, &claims);
                inner.issued.lock().unwrap().push(id_token.clone());
                answer["id_token"] = id_token.into();
            }
            axum::Json(answer).into_response()
        }
        "refresh_token" => {
            if !inner
                .refresh_tokens
                .lock()
                .unwrap()
                .contains(&field("refresh_token"))
            {
                return error(StatusCode::BAD_REQUEST, "invalid_grant");
            }
            match b.refresh {
                Refresh::Revoked => error(StatusCode::BAD_REQUEST, "invalid_grant"),
                Refresh::Down => StatusCode::SERVICE_UNAVAILABLE.into_response(),
                Refresh::Ok => {
                    let refresh = format!("refresh-token-{n}");
                    inner.refresh_tokens.lock().unwrap().push(refresh.clone());
                    inner
                        .issued
                        .lock()
                        .unwrap()
                        .extend([format!("access-token-{n}"), refresh.clone()]);
                    axum::Json(json!({
                        "access_token": format!("access-token-{n}"), "token_type": "Bearer",
                        "expires_in": b.refresh_expires_in, "refresh_token": refresh,
                    }))
                    .into_response()
                }
            }
        }
        _ => error(StatusCode::BAD_REQUEST, "unsupported_grant_type"),
    }
}

fn refresh_for_log(n: u32) -> String {
    format!("refresh-token-{n}")
}

fn encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
