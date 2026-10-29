//! The token admin listener (docs/decisions/0056): the same routes as the admin socket, behind a
//! bearer-token check. Everything here is transport glue — validation and the group → scope mapping
//! are the pure functions in `weglarka_model::admin_auth`; this module fetches the provider's JWKS
//! over the ingress probe socket (the daemon shares no network with the provider), caches it, and
//! puts the check in front of the routes.
//!
//! The check fails closed: a route that is not in `weglarka_api::ENDPOINTS` is refused even to a valid
//! admin, and only `GET /v1/health` answers without a token.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::Mutex as AsyncMutex;

use axum::Router;
use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderMap, HeaderValue, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use weglarka_api::endpoints::APPS_SHOW;
use weglarka_api::{Endpoint, ErrorCode};
use weglarka_model::admin_auth::{self, AuthError, JwkSet, Principal, Scope, Validation};
use weglarka_model::podman::PodmanClient;

use crate::admin::{self, Fail};
use crate::app::Daemon;
use crate::health_probe;

/// Where the provider publishes its signing keys (Authelia).
const JWKS_PATH: &str = "/jwks.json";
/// A JWKS is a few keys; anything bigger is not one.
const MAX_JWKS_BYTES: usize = 64 * 1024;
/// Unknown `kid`s trigger at most one fetch per this long, so a flood of forged tokens cannot make
/// the daemon hammer the provider.
pub const MIN_REFRESH: Duration = Duration::from_secs(30);
/// Keys are refetched after this long even when every `kid` is known, so a withdrawn key stops
/// verifying within the hour.
pub const MAX_KEY_AGE: Duration = Duration::from_secs(3600);
/// While no fetch has ever succeeded there is nothing to protect from a stampede and every token is
/// refused, so a failed first fetch is retried after this much instead of [`MIN_REFRESH`].
const EMPTY_RETRY: Duration = Duration::from_secs(1);

/// Source of the provider's `jwks.json`.
pub trait JwksFetcher: Send + Sync + 'static {
    fn fetch(&self) -> impl Future<Output = Result<Vec<u8>, String>> + Send;
}

/// Fetches the JWKS over the probe socket with the issuer's host as `Host`, the way nginx would
/// route a client, minus TLS and forward auth.
pub struct ProbeJwks {
    pub socket: PathBuf,
    pub issuer_host: String,
}

impl JwksFetcher for ProbeJwks {
    async fn fetch(&self) -> Result<Vec<u8>, String> {
        let response =
            health_probe::probe_get(&self.socket, &self.issuer_host, JWKS_PATH, MAX_JWKS_BYTES)
                .await?;
        if response.status != 200 {
            return Err(format!("the provider answered {}", response.status));
        }
        Ok(response.body)
    }
}

struct Cache {
    keys: Arc<JwkSet>,
    /// When the last fetch was *attempted* (failures count: they are rate limited too).
    attempted: Option<Instant>,
    /// When `keys` was last fetched successfully.
    fetched: Option<Instant>,
}

/// Verifies bearer tokens against the provider's cached keys.
pub struct JwksVerifier<F: JwksFetcher> {
    fetcher: F,
    expected: Validation,
    cache: Mutex<Cache>,
    /// Held across a fetch: concurrent requests that need keys wait for the one fetch in flight and
    /// then use its result, instead of racing past it with an empty or stale set.
    flight: AsyncMutex<()>,
    min_refresh: Duration,
}

impl<F: JwksFetcher> JwksVerifier<F> {
    pub fn new(fetcher: F, expected: Validation) -> Self {
        Self {
            fetcher,
            expected,
            cache: Mutex::new(Cache {
                keys: Arc::new(JwkSet::default()),
                attempted: None,
                fetched: None,
            }),
            flight: AsyncMutex::new(()),
            min_refresh: MIN_REFRESH,
        }
    }

    /// Overrides the refresh rate limit (tests).
    pub fn with_min_refresh(mut self, min_refresh: Duration) -> Self {
        self.min_refresh = min_refresh;
        self
    }

    pub async fn verify(&self, token: &str, now: SystemTime) -> Result<Principal, AuthError> {
        let kid = admin_auth::key_id(token)?;
        if self.stale(&kid) {
            let _flight = self.flight.lock().await;
            // Whoever held the lock before us may have fetched what we need.
            if self.claim_fetch(&kid) {
                self.refresh().await;
            }
        }
        let keys = self.lock().keys.clone();
        admin_auth::validate(token, &keys, &self.expected, now)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The cached keys cannot be trusted to verify a token with this `kid`: it is unknown, or the set
    /// is older than [`MAX_KEY_AGE`].
    fn stale(&self, kid: &str) -> bool {
        let cache = self.lock();
        !cache.keys.contains(kid) || cache.fetched.is_none_or(|at| at.elapsed() > MAX_KEY_AGE)
    }

    /// Under the flight lock: whether this request should fetch (still stale, and the rate limit
    /// allows it), reserving the slot.
    fn claim_fetch(&self, kid: &str) -> bool {
        if !self.stale(kid) {
            return false;
        }
        let mut cache = self.lock();
        let wait = if cache.keys.is_empty() {
            self.min_refresh.min(EMPTY_RETRY)
        } else {
            self.min_refresh
        };
        if cache.attempted.is_some_and(|at| at.elapsed() < wait) {
            return false;
        }
        cache.attempted = Some(Instant::now());
        true
    }

    async fn refresh(&self) {
        let fetched = self
            .fetcher
            .fetch()
            .await
            .and_then(|body| JwkSet::from_json(&body).map_err(|e| e.to_string()));
        match fetched {
            Ok(keys) if !keys.is_empty() => {
                let mut cache = self.lock();
                cache.keys = Arc::new(keys);
                cache.fetched = Some(Instant::now());
            }
            // Keep verifying with the old keys: a provider that blips must not lock operators out.
            Ok(_) => tracing::warn!("the provider's JWKS has no usable signing key"),
            Err(error) => tracing::warn!(%error, "cannot fetch the provider's JWKS"),
        }
    }
}

type VerifyFuture<'a> = Pin<Box<dyn Future<Output = Result<Principal, AuthError>> + Send + 'a>>;

/// What the middleware needs; object-safe so the router is not generic over the fetcher.
pub trait TokenVerifier: Send + Sync + 'static {
    fn verify<'a>(&'a self, token: &'a str, now: SystemTime) -> VerifyFuture<'a>;
}

impl<F: JwksFetcher> TokenVerifier for JwksVerifier<F> {
    fn verify<'a>(&'a self, token: &'a str, now: SystemTime) -> VerifyFuture<'a> {
        Box::pin(JwksVerifier::verify(self, token, now))
    }
}

/// The admin API for token holders: [`admin::api_routes`] behind [`authenticate`].
pub fn token_router<P: PodmanClient + 'static>(
    daemon: Arc<Daemon<P>>,
    verifier: Arc<dyn TokenVerifier>,
) -> Router {
    // `layer` after every merge: it wraps each route and the fallback, so nothing is left open.
    admin::api_routes::<P>()
        .layer(middleware::from_fn_with_state(verifier, authenticate))
        .with_state(daemon)
}

/// The single `Authorization: Bearer <token>` of a request.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let (scheme, token) = value.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.trim().is_empty()).then(|| token.trim())
}

fn deny(code: ErrorCode, message: &str) -> Response {
    let mut response = Fail(code, message.to_owned()).into_response();
    if code == ErrorCode::Unauthorized {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    response
}

async fn authenticate(
    State(verifier): State<Arc<dyn TokenVerifier>>,
    mut request: Request,
    next: Next,
) -> Response {
    let method = request.method().as_str().to_owned();
    let matched = request
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_owned());
    let endpoint = matched
        .as_deref()
        .map(|path| Endpoint::lookup(&method, path));

    // The only open route: the readiness probe, which never calls Podman or reads state.
    if let Some(Some(e)) = endpoint
        && e.scope.is_none()
    {
        return next.run(request).await;
    }
    let route = matched.as_deref().unwrap_or("<unmatched>").to_owned();

    let Some(token) = bearer(request.headers()) else {
        tracing::warn!(%method, %route, "admin token API: no bearer token");
        return deny(ErrorCode::Unauthorized, "a bearer token is required");
    };
    let principal = match verifier.verify(token, SystemTime::now()).await {
        Ok(principal) => principal,
        // A genuine token of someone the host maps to no scope: authenticated, not authorized.
        Err(AuthError::NoScope) => {
            tracing::warn!(%method, %route, "admin token API: the token's groups map to no scope");
            return deny(
                ErrorCode::Forbidden,
                "the token's groups give no access to the admin API",
            );
        }
        Err(error) => {
            tracing::warn!(%method, %route, %error, "admin token API: token refused");
            return deny(ErrorCode::Unauthorized, "invalid bearer token");
        }
    };
    let required = match endpoint {
        Some(Some(e)) => e.scope,
        // A matched route with no declared scope: refuse rather than guess (fail closed).
        Some(None) => {
            tracing::error!(%method, %route, "admin token API: route has no declared scope");
            return deny(
                ErrorCode::Forbidden,
                "this endpoint is not available to tokens",
            );
        }
        // No route matched: the fallback answers 404, after the token proved itself.
        None => return next.run(request).await,
    };
    if let Err(error) = admin_auth::authorize(&principal, required) {
        tracing::warn!(sub = %principal.sub, %method, %route, %error, "admin token API: denied");
        return deny(
            ErrorCode::Forbidden,
            "the token's scopes do not allow this endpoint",
        );
    }

    // `GET /v1/apps/{name}` is a `read` endpoint, but for an `admin` token it returns the real `env`
    // values, so that read joins the audit trail.
    let reveals_env = method == "GET"
        && matched.as_deref() == Some(APPS_SHOW.path)
        && principal.has(Scope::Admin);
    let audited = required == Some(Scope::Admin) || reveals_env;
    let sub = principal.sub.clone();
    // Handlers that answer with app data decide what this caller may see (`app_view::Access`); the
    // unix socket never inserts one, so it stays full trust.
    request.extensions_mut().insert(principal);
    let response = next.run(request).await;
    if audited {
        // The audit trail of everything done with `admin`: every mutation, and the reads that return
        // credentials or app data (exports, the OIDC client list). Who, what, and how it ended.
        let status = response.status().as_u16();
        tracing::info!(%sub, %method, %route, status, "admin token API call");
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use weglarka_model::admin_auth::testing::{TestIssuer, validation};

    struct Counting {
        jwks: Mutex<Result<String, String>>,
        calls: Arc<AtomicUsize>,
        /// How long a fetch takes, so concurrent requests overlap it.
        delay: Duration,
    }

    impl JwksFetcher for Counting {
        async fn fetch(&self) -> Result<Vec<u8>, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            self.jwks.lock().unwrap().clone().map(String::into_bytes)
        }
    }

    fn verifier(
        jwks: Result<String, String>,
        min_refresh: Duration,
    ) -> (JwksVerifier<Counting>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let fetcher = Counting {
            jwks: Mutex::new(jwks),
            calls: calls.clone(),
            delay: Duration::ZERO,
        };
        (
            JwksVerifier::new(fetcher, validation()).with_min_refresh(min_refresh),
            calls,
        )
    }

    #[tokio::test]
    async fn fetches_once_and_then_serves_from_the_cache() {
        let issuer = TestIssuer::new("k1");
        let (v, calls) = verifier(Ok(issuer.jwks_json()), Duration::ZERO);
        let token = issuer.token("alice", &["admins"]);
        for _ in 0..3 {
            let p = v.verify(&token, SystemTime::now()).await.unwrap();
            assert_eq!(p.sub, "alice");
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn concurrent_first_requests_share_one_fetch_and_all_succeed() {
        let issuer = TestIssuer::new("k1");
        let (mut v, calls) = verifier(Ok(issuer.jwks_json()), MIN_REFRESH);
        v.fetcher.delay = Duration::from_millis(50);
        let v = Arc::new(v);
        let token = issuer.token("alice", &["admins"]);
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let (v, token) = (v.clone(), token.clone());
            tasks.push(tokio::spawn(async move {
                v.verify(&token, SystemTime::now()).await
            }));
        }
        for task in tasks {
            // Not a spurious `UnknownKey` for the requests that arrived during the fetch.
            assert_eq!(task.await.unwrap().unwrap().sub, "alice");
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_failed_first_fetch_is_retried_soon_not_after_the_full_rate_limit() {
        let issuer = TestIssuer::new("k1");
        let (v, calls) = verifier(Err("down".into()), MIN_REFRESH);
        let token = issuer.token("alice", &["admins"]);
        assert_eq!(
            v.verify(&token, SystemTime::now()).await.unwrap_err(),
            AuthError::UnknownKey
        );
        // Still inside the retry backoff: no second fetch.
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        *v.fetcher.jwks.lock().unwrap() = Ok(issuer.jwks_json());
        tokio::time::sleep(EMPTY_RETRY + Duration::from_millis(100)).await;
        assert_eq!(
            v.verify(&token, SystemTime::now()).await.unwrap().sub,
            "alice"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn an_unknown_kid_refetches_but_is_rate_limited() {
        let known = TestIssuer::new("k1");
        let stranger = TestIssuer::new("k2");
        let (v, calls) = verifier(Ok(known.jwks_json()), MIN_REFRESH);
        v.verify(&known.token("a", &["admins"]), SystemTime::now())
            .await
            .unwrap();
        // The forged token's kid is unknown, but the fetch slot was used a moment ago.
        for _ in 0..3 {
            let err = v
                .verify(&stranger.token("a", &["admins"]), SystemTime::now())
                .await
                .unwrap_err();
            assert_eq!(err, AuthError::UnknownKey);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Without the rate limit the unknown kid does trigger a refetch (key rotation).
        let (v, calls) = verifier(Ok(known.jwks_json()), Duration::ZERO);
        v.verify(&known.token("a", &["admins"]), SystemTime::now())
            .await
            .unwrap();
        *v.fetcher.jwks.lock().unwrap() = Ok(stranger.jwks_json());
        v.verify(&stranger.token("a", &["admins"]), SystemTime::now())
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_failing_provider_keeps_the_old_keys_and_refuses_unknown_ones() {
        let issuer = TestIssuer::new("k1");
        let (v, _) = verifier(Ok(issuer.jwks_json()), Duration::ZERO);
        let token = issuer.token("a", &["admins"]);
        v.verify(&token, SystemTime::now()).await.unwrap();
        *v.fetcher.jwks.lock().unwrap() = Err("down".into());
        v.verify(&token, SystemTime::now()).await.unwrap();

        let (down, _) = verifier(Err("down".into()), Duration::ZERO);
        assert_eq!(
            down.verify(&token, SystemTime::now()).await.unwrap_err(),
            AuthError::UnknownKey
        );
    }

    #[test]
    fn bearer_needs_exactly_one_well_formed_header() {
        let headers = |values: &[&str]| {
            let mut map = HeaderMap::new();
            for v in values {
                map.append(header::AUTHORIZATION, v.parse().unwrap());
            }
            map
        };
        assert_eq!(bearer(&headers(&["Bearer abc"])), Some("abc"));
        assert_eq!(bearer(&headers(&["bearer abc"])), Some("abc"));
        assert_eq!(bearer(&headers(&["Basic abc"])), None);
        assert_eq!(bearer(&headers(&["Bearer "])), None);
        assert_eq!(bearer(&headers(&["Bearer a", "Bearer b"])), None);
        assert_eq!(bearer(&headers(&[])), None);
    }
}
