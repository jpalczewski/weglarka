//! The panel as an OIDC confidential client: authorization code flow with PKCE (S256), discovery,
//! code exchange and refresh with `client_secret_basic`, and id token verification against the
//! provider's JWKS (docs/decisions/0057, decision 4). The transport-independent protocol steps
//! live in `weglarka-oidc` (docs/decisions/0060); this module adds the `reqwest` transport, the
//! caches and the id token checks.
//!
//! Tokens are opaque here except the id token, which is verified once at login (signature,
//! `iss`, `aud`, `exp`, `nonce`, `azp`) to learn who signed in; its claims are then dropped except
//! `sub` and a display name. The access token is only ever forwarded to the daemon, which checks it.
//! No error, log line or URL built in this module carries a token, a code or the client secret.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use tokio::sync::Mutex;
use url::Url;
use weglarka_http::reqwest;
use weglarka_http::{BodyError, error_chain, read_capped};
use weglarka_model::admin_auth::{AuthError, JwkSet, TokenKind, verify};
use weglarka_oidc::{
    AuthorizationRequest, ClientAuth, DiscoveryPolicy, Endpoints, HttpResponse, Transport,
};

pub use weglarka_oidc::{Secret, TokenSet};

use crate::config::PanelConfig;
use crate::secure::{random_b64url, random_token};
use crate::session::Clock;

const DISCOVERY_TTL: Duration = Duration::from_secs(60 * 60);
/// The cached JWKS is refetched after this long even when every `kid` is known, so a key the
/// provider revoked stops verifying; the same lifetime as discovery.
const JWKS_MAX_AGE: Duration = DISCOVERY_TTL;
/// A failed discovery is not retried for this long, so a provider outage is not hammered by every
/// anonymous `GET /auth/login`.
const DISCOVERY_RETRY_AFTER: Duration = Duration::from_secs(10);
/// Unknown `kid`s trigger a JWKS fetch at most this often (a forged `kid` cannot make us hammer the provider).
const JWKS_MIN_INTERVAL: Duration = Duration::from_secs(30);
const SCOPE: &str = "openid profile groups offline_access";
const MAX_NAME_CHARS: usize = 100;

#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error(transparent)]
    Provider(#[from] weglarka_oidc::Error),
    #[error("id token rejected: {0}")]
    IdToken(#[from] AuthError),
}

impl OidcError {
    /// A refresh that failed for a reason retrying cannot fix (revoked or expired grant).
    pub fn is_definitive(&self) -> bool {
        matches!(self, Self::Provider(e) if e.is_definitive())
    }
}

impl From<BodyError> for OidcError {
    fn from(e: BodyError) -> Self {
        Self::Provider(weglarka_oidc::Error::Network(e.to_string()))
    }
}

/// `weglarka-oidc`'s transport on the shared `reqwest` client: no redirects (the `Api` purpose),
/// bodies capped while read, the `Authorization` value marked sensitive.
struct ReqwestTransport(reqwest::Client);

impl ReqwestTransport {
    async fn finish(
        request: reqwest::RequestBuilder,
        limit: usize,
    ) -> Result<HttpResponse, weglarka_oidc::Error> {
        let response = request
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| weglarka_oidc::Error::Network(error_chain(&e)))?;
        let status = response.status().as_u16();
        let body = read_capped(response, limit)
            .await
            .map_err(|e| weglarka_oidc::Error::Network(e.to_string()))?;
        Ok(HttpResponse { status, body })
    }
}

impl Transport for ReqwestTransport {
    async fn get(&self, url: &Url, limit: usize) -> Result<HttpResponse, weglarka_oidc::Error> {
        Self::finish(self.0.get(url.clone()), limit).await
    }

    async fn post_form(
        &self,
        url: &Url,
        authorization: Option<&Secret>,
        body: String,
        limit: usize,
    ) -> Result<HttpResponse, weglarka_oidc::Error> {
        let mut request = self
            .0
            .post(url.clone())
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(body);
        if let Some(value) = authorization {
            let mut header =
                reqwest::header::HeaderValue::try_from(value.expose()).map_err(|_| {
                    weglarka_oidc::Error::BadResponse("credentials are not a header value")
                })?;
            header.set_sensitive(true);
            request = request.header(reqwest::header::AUTHORIZATION, header);
        }
        Self::finish(request, limit).await
    }
}

/// A login that was started: send the browser to `redirect`, and keep the rest until the callback.
pub struct AuthRequest {
    pub redirect: String,
    pub state: String,
    pub nonce: String,
    pub verifier: Secret,
}

/// Who signed in, from a verified id token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub sub: String,
    pub name: String,
}

#[derive(Default)]
struct JwksCache {
    keys: Option<JwkSet>,
    fetched_at: Option<Instant>,
    last_attempt: Option<Instant>,
}

#[derive(Default)]
struct DiscoveryCache {
    found: Option<(Instant, Arc<Endpoints>)>,
    failed_at: Option<Instant>,
}

pub struct OidcClient {
    config: Arc<PanelConfig>,
    http: ReqwestTransport,
    clock: Clock,
    discovery: Mutex<DiscoveryCache>,
    jwks: Mutex<JwksCache>,
}

impl OidcClient {
    pub fn new(config: Arc<PanelConfig>, http: reqwest::Client, clock: Clock) -> Self {
        Self {
            config,
            http: ReqwestTransport(http),
            clock,
            discovery: Mutex::new(DiscoveryCache::default()),
            jwks: Mutex::new(JwksCache::default()),
        }
    }

    pub fn redirect_uri(&self) -> String {
        format!(
            "{}/auth/callback",
            self.config.public_url.as_str().trim_end_matches('/')
        )
    }

    pub async fn endpoints(&self) -> Result<Arc<Endpoints>, OidcError> {
        let mut cached = self.discovery.lock().await;
        let now = self.clock.now();
        if let Some((at, endpoints)) = cached.found.as_ref()
            && now.saturating_duration_since(*at) < DISCOVERY_TTL
        {
            return Ok(endpoints.clone());
        }
        if let Some(at) = cached.failed_at
            && now.saturating_duration_since(at) < DISCOVERY_RETRY_AFTER
        {
            return Err(weglarka_oidc::Error::Discovery(
                "the last attempt failed; not retrying yet".into(),
            )
            .into());
        }
        match self.discover().await {
            Ok(endpoints) => {
                let endpoints = Arc::new(endpoints);
                cached.found = Some((self.clock.now(), endpoints.clone()));
                cached.failed_at = None;
                Ok(endpoints)
            }
            Err(e) => {
                cached.failed_at = Some(self.clock.now());
                Err(e)
            }
        }
    }

    async fn discover(&self) -> Result<Endpoints, OidcError> {
        let policy = DiscoveryPolicy {
            extra_hosts: self.config.oidc.extra_endpoint_hosts.clone(),
        };
        Ok(weglarka_oidc::discover(&self.http, &self.config.oidc.issuer, &policy).await?)
    }

    /// Builds the authorization request: fresh `state`, `nonce` and PKCE verifier.
    pub async fn begin_login(&self) -> Result<AuthRequest, OidcError> {
        let endpoints = self.endpoints().await?;
        let state = random_token();
        let nonce = random_token();
        let verifier = random_b64url(32);
        let url = weglarka_oidc::authorization_url(
            &endpoints.authorization,
            &AuthorizationRequest {
                client_id: &self.config.oidc.client_id,
                redirect_uri: &self.redirect_uri(),
                scope: SCOPE,
                audience: &self.config.oidc.audience,
                state: &state,
                nonce: &nonce,
                verifier: &verifier,
            },
        );
        Ok(AuthRequest {
            redirect: url.into(),
            state,
            nonce,
            verifier: Secret::new(verifier),
        })
    }

    fn client_auth(&self) -> ClientAuth<'_> {
        ClientAuth::Secret {
            id: &self.config.oidc.client_id,
            secret: &self.config.oidc.client_secret,
        }
    }

    pub async fn exchange_code(
        &self,
        code: &str,
        verifier: &Secret,
    ) -> Result<TokenSet, OidcError> {
        let endpoints = self.endpoints().await?;
        let redirect_uri = self.redirect_uri();
        Ok(weglarka_oidc::token_request(
            &self.http,
            &endpoints.token,
            self.client_auth(),
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", &redirect_uri),
                ("code_verifier", verifier.expose()),
            ],
        )
        .await?)
    }

    pub async fn refresh(&self, refresh_token: &Secret) -> Result<TokenSet, OidcError> {
        let endpoints = self.endpoints().await?;
        Ok(weglarka_oidc::refresh(
            &self.http,
            &endpoints.token,
            self.client_auth(),
            refresh_token,
            SCOPE,
        )
        .await?)
    }

    /// Verifies `id_token` for the login whose nonce is `nonce`.
    pub async fn verify_id_token(
        &self,
        id_token: &str,
        nonce: &str,
    ) -> Result<Identity, OidcError> {
        let oidc = &self.config.oidc;
        let check = |keys: &JwkSet| {
            verify(
                id_token,
                keys,
                &oidc.issuer,
                TokenKind::Id {
                    client_id: &oidc.client_id,
                    nonce,
                },
                SystemTime::now(),
            )
        };
        let verified = match check(&self.jwks(false).await?) {
            // Keys rotate: one refetch (rate limited) before giving up on an unknown `kid`.
            Err(AuthError::UnknownKey) => check(&self.jwks(true).await?)?,
            other => other?,
        };
        Ok(Identity {
            name: display_name(id_token).unwrap_or_else(|| verified.sub.clone()),
            sub: verified.sub,
        })
    }

    /// The cached key set. `refetch` asks for a fresh one, honoured at most every [`JWKS_MIN_INTERVAL`];
    /// a failed fetch keeps the old keys.
    async fn jwks(&self, refetch: bool) -> Result<JwkSet, OidcError> {
        let mut cache = self.jwks.lock().await;
        let now = self.clock.now();
        if let (Some(keys), Some(fetched), Some(attempt)) =
            (&cache.keys, cache.fetched_at, cache.last_attempt)
        {
            let stale = now.saturating_duration_since(fetched) >= JWKS_MAX_AGE;
            let recent = now.saturating_duration_since(attempt) < JWKS_MIN_INTERVAL;
            // Stale keys are replaced, but a provider that keeps failing is tried once per interval.
            if !(refetch || stale) || recent {
                return Ok(keys.clone());
            }
        }
        cache.last_attempt = Some(now);
        let fetched = async {
            let endpoints = self.endpoints().await?;
            let body = weglarka_oidc::get_ok(&self.http, &endpoints.jwks).await?;
            let keys = JwkSet::from_json(&body)
                .map_err(|_| weglarka_oidc::Error::BadResponse("the JWKS is not valid"))?;
            if keys.is_empty() {
                return Err(weglarka_oidc::Error::BadResponse("the JWKS has no usable key").into());
            }
            Ok(keys)
        }
        .await;
        match (fetched, cache.keys.clone()) {
            (Ok(keys), _) => {
                cache.keys = Some(keys.clone());
                cache.fetched_at = Some(self.clock.now());
                Ok(keys)
            }
            (Err(e), Some(old)) => {
                tracing::warn!(error = %e, "fetching the JWKS failed; keeping the cached keys");
                Ok(old)
            }
            (Err(e), None) => Err(e),
        }
    }
}

/// A name to show, from an id token that [`verify`] has already accepted. Control characters are
/// dropped and the length bounded; the template escapes the rest.
fn display_name(id_token: &str) -> Option<String> {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Profile {
        name: Option<String>,
        preferred_username: Option<String>,
        email: Option<String>,
    }
    let payload = id_token.split('.').nth(1)?;
    let profile: Profile = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
    [profile.name, profile.preferred_username, profile.email]
        .into_iter()
        .flatten()
        .map(|n| {
            n.chars()
                .filter(|c| !c.is_control())
                .take(MAX_NAME_CHARS)
                .collect::<String>()
        })
        .find(|n| !n.trim().is_empty())
}
