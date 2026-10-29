//! The panel as an OIDC confidential client: authorization code flow with PKCE (S256), discovery,
//! code exchange and refresh with `client_secret_basic`, and id token verification against the
//! provider's JWKS (docs/decisions/0057, decision 4).
//!
//! Tokens are opaque here except the id token, which is verified once at login (signature,
//! `iss`, `aud`, `exp`, `nonce`, `azp`) to learn who signed in; its claims are then dropped except
//! `sub` and a display name. The access token is only ever forwarded to the daemon, which checks it.
//! No error, log line or URL built in this module carries a token, a code or the client secret.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::digest::{SHA256, digest};
use serde::Deserialize;
use tokio::sync::Mutex;
use url::Url;
use weglarka_http::reqwest;
use weglarka_http::{BodyError, error_chain, read_capped, transport_allowed};
use weglarka_model::admin_auth::{AuthError, JwkSet, TokenKind, verify};

use crate::config::{PanelConfig, Secret};
use crate::secure::{random_b64url, random_token};
use crate::session::Clock;

/// Largest discovery document, JWKS or token response read.
const MAX_BODY: usize = 256 * 1024;
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
/// Used when the token response omits `expires_in`.
const DEFAULT_EXPIRES_IN: Duration = Duration::from_secs(300);
const MAX_EXPIRES_IN: u64 = 24 * 60 * 60;
const MAX_NAME_CHARS: usize = 100;

#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("provider discovery failed: {0}")]
    Discovery(String),
    #[error("cannot reach the provider: {0}")]
    Network(String),
    /// The provider answered with a 4xx: the grant or credentials were refused.
    #[error("the provider refused the request (HTTP {0})")]
    Refused(u16),
    /// A 5xx or any other unusable status.
    #[error("the provider failed (HTTP {0})")]
    ProviderFailed(u16),
    #[error("unexpected provider response: {0}")]
    BadResponse(&'static str),
    #[error("id token rejected: {0}")]
    IdToken(#[from] AuthError),
}

impl OidcError {
    /// A refresh that failed for a reason retrying cannot fix (revoked or expired grant).
    pub fn is_definitive(&self) -> bool {
        matches!(self, Self::Refused(_) | Self::BadResponse(_))
    }
}

impl From<BodyError> for OidcError {
    fn from(e: BodyError) -> Self {
        Self::Network(e.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct Endpoints {
    pub authorization: Url,
    pub token: Url,
    pub jwks: Url,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct DiscoveryDocument {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

/// A login that was started: send the browser to `redirect`, and keep the rest until the callback.
pub struct AuthRequest {
    pub redirect: String,
    pub state: String,
    pub nonce: String,
    pub verifier: Secret,
}

/// A successful token endpoint answer.
pub struct TokenSet {
    pub access: Secret,
    pub refresh: Option<Secret>,
    pub id_token: Option<Secret>,
    pub expires_in: Duration,
}

impl std::fmt::Debug for TokenSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TokenSet(<redacted>)")
    }
}

/// Who signed in, from a verified id token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub sub: String,
    pub name: String,
}

#[derive(Deserialize)]
struct RawTokens {
    #[serde(default)]
    access_token: String,
    #[serde(default)]
    token_type: String,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
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
    http: reqwest::Client,
    clock: Clock,
    discovery: Mutex<DiscoveryCache>,
    jwks: Mutex<JwksCache>,
}

impl OidcClient {
    pub fn new(config: Arc<PanelConfig>, http: reqwest::Client, clock: Clock) -> Self {
        Self {
            config,
            http,
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

    /// Plain `http://` endpoints are only accepted when the configured issuer itself is a loopback
    /// `http://` one (a test provider); otherwise everything the provider names must be https.
    fn endpoint_allowed(&self, url: &Url) -> bool {
        let http_issuer = self.config.oidc.issuer.starts_with("http://");
        let scheme_ok = url.scheme() == "https" || (http_issuer && transport_allowed(url));
        scheme_ok
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.fragment().is_none()
    }

    /// `url` is on the issuer's host and port, or on a host the operator listed.
    fn host_allowed(&self, url: &Url) -> bool {
        let Ok(issuer) = Url::parse(&self.config.oidc.issuer) else {
            return false;
        };
        let origin = |u: &Url| {
            (
                u.host_str().map(str::to_ascii_lowercase),
                u.port_or_known_default(),
            )
        };
        origin(url) == origin(&issuer)
            || url.host_str().is_some_and(|h| {
                self.config
                    .oidc
                    .extra_endpoint_hosts
                    .iter()
                    .any(|extra| extra.eq_ignore_ascii_case(h))
            })
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
            return Err(OidcError::Discovery(
                "the last attempt failed; not retrying yet".into(),
            ));
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
        let fail = |reason: &str| OidcError::Discovery(reason.to_owned());
        let issuer = &self.config.oidc.issuer;
        let url = Url::parse(&format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        ))
        .map_err(|_| fail("the issuer is not a URL"))?;
        let body = self.get(&url).await?;
        let doc: DiscoveryDocument =
            serde_json::from_slice(&body).map_err(|_| fail("the document is not JSON"))?;
        // Byte for byte (OIDC Discovery 4.3): a mismatch means the document is not this issuer's.
        if doc.issuer != *issuer {
            return Err(fail("the document's issuer is not the configured one"));
        }
        let parse = |raw: &str, what: &str| {
            Url::parse(raw)
                .ok()
                .filter(|u| self.endpoint_allowed(u))
                .ok_or_else(|| fail(&format!("{what} is missing or not an https URL")))
        };
        // The token endpoint receives the client secret and the JWKS decides who is trusted, so
        // both stay on the issuer's host unless the operator lists others.
        let same_host = |url: Url, what: &str| {
            if self.host_allowed(&url) {
                Ok(url)
            } else {
                Err(fail(&format!(
                    "{what} is on a host other than the issuer's (see OIDC_ENDPOINT_HOSTS)"
                )))
            }
        };
        Ok(Endpoints {
            authorization: parse(&doc.authorization_endpoint, "authorization_endpoint")?,
            token: same_host(
                parse(&doc.token_endpoint, "token_endpoint")?,
                "token_endpoint",
            )?,
            jwks: same_host(parse(&doc.jwks_uri, "jwks_uri")?, "jwks_uri")?,
        })
    }

    /// GET with the body capped; the status must be 200.
    async fn get(&self, url: &Url) -> Result<Vec<u8>, OidcError> {
        if !self.endpoint_allowed(url) {
            return Err(OidcError::Network("refusing a non-https URL".into()));
        }
        let response = self
            .http
            .get(url.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| OidcError::Network(error_chain(&e)))?;
        let status = response.status();
        if !status.is_success() {
            return Err(status_error(status.as_u16()));
        }
        Ok(read_capped(response, MAX_BODY).await?)
    }

    /// Builds the authorization request: fresh `state`, `nonce` and PKCE verifier.
    pub async fn begin_login(&self) -> Result<AuthRequest, OidcError> {
        let endpoints = self.endpoints().await?;
        let state = random_token();
        let nonce = random_token();
        let verifier = random_b64url(32);
        let challenge = URL_SAFE_NO_PAD.encode(digest(&SHA256, verifier.as_bytes()));
        let mut url = endpoints.authorization.clone();
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.oidc.client_id)
            .append_pair("redirect_uri", &self.redirect_uri())
            .append_pair("scope", SCOPE)
            .append_pair("audience", &self.config.oidc.audience)
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(AuthRequest {
            redirect: url.into(),
            state,
            nonce,
            verifier: Secret::new(verifier),
        })
    }

    pub async fn exchange_code(
        &self,
        code: &str,
        verifier: &Secret,
    ) -> Result<TokenSet, OidcError> {
        let redirect_uri = self.redirect_uri();
        self.token_request(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &redirect_uri),
            ("code_verifier", verifier.expose()),
        ])
        .await
    }

    pub async fn refresh(&self, refresh_token: &Secret) -> Result<TokenSet, OidcError> {
        self.token_request(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.expose()),
            ("scope", SCOPE),
        ])
        .await
    }

    /// `client_secret_basic` (RFC 6749 2.3.1): the id and secret are form-encoded, then base64'd.
    /// The body is built by hand, so no HTTP-client feature beyond the shared build is needed.
    async fn token_request(&self, form: &[(&str, &str)]) -> Result<TokenSet, OidcError> {
        let endpoints = self.endpoints().await?;
        let encode =
            |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
        let credentials = format!(
            "{}:{}",
            encode(&self.config.oidc.client_id),
            encode(self.config.oidc.client_secret.expose())
        );
        let mut auth = reqwest::header::HeaderValue::try_from(format!(
            "Basic {}",
            STANDARD.encode(credentials)
        ))
        .map_err(|_| OidcError::BadResponse("credentials are not a header value"))?;
        auth.set_sensitive(true);
        // Scoped: the serializer is not `Send` and must not live across the request's `.await`.
        let body = {
            let mut body = url::form_urlencoded::Serializer::new(String::new());
            for (name, value) in form {
                body.append_pair(name, value);
            }
            body.finish()
        };
        let response = self
            .http
            .post(endpoints.token.clone())
            .header(reqwest::header::AUTHORIZATION, auth)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .header(reqwest::header::ACCEPT, "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| OidcError::Network(error_chain(&e)))?;
        let status = response.status();
        if !status.is_success() {
            // The error body is dropped unread: it is the provider's text, not ours to quote.
            return Err(status_error(status.as_u16()));
        }
        let body = read_capped(response, MAX_BODY).await?;
        let raw: RawTokens = serde_json::from_slice(&body)
            .map_err(|_| OidcError::BadResponse("the token response is not JSON"))?;
        if raw.access_token.is_empty() {
            return Err(OidcError::BadResponse("no access token"));
        }
        if !raw.token_type.eq_ignore_ascii_case("bearer") {
            return Err(OidcError::BadResponse("the token type is not Bearer"));
        }
        let expires_in = raw.expires_in.map_or(DEFAULT_EXPIRES_IN, |s| {
            Duration::from_secs(s.min(MAX_EXPIRES_IN))
        });
        Ok(TokenSet {
            access: Secret::new(raw.access_token),
            refresh: raw.refresh_token.filter(|t| !t.is_empty()).map(Secret::new),
            id_token: raw.id_token.filter(|t| !t.is_empty()).map(Secret::new),
            expires_in,
        })
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
                &oidc.client_id,
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
            let body = self.get(&endpoints.jwks).await?;
            let keys = JwkSet::from_json(&body)
                .map_err(|_| OidcError::BadResponse("the JWKS is not valid"))?;
            if keys.is_empty() {
                return Err(OidcError::BadResponse("the JWKS has no usable key"));
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

fn status_error(status: u16) -> OidcError {
    if (400..500).contains(&status) {
        OidcError::Refused(status)
    } else {
        OidcError::ProviderFailed(status)
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
