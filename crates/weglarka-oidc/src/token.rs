//! PKCE, the authorization URL and token endpoint requests.

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::digest::{SHA256, digest};
use serde::Deserialize;
use url::Url;

use crate::{Error, MAX_BODY, Secret, Transport, form_body, status_error};

/// Used when the token response omits `expires_in`.
const DEFAULT_EXPIRES_IN: Duration = Duration::from_secs(300);
const MAX_EXPIRES_IN: u64 = 24 * 60 * 60;

/// How the client proves who it is at the token endpoint.
pub enum ClientAuth<'a> {
    /// `client_secret_basic` (RFC 6749 2.3.1).
    Secret { id: &'a str, secret: &'a Secret },
    /// A public client: only `client_id` in the form (RFC 6749 3.2.1), no secret.
    Public { id: &'a str },
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

/// The S256 code challenge of a PKCE verifier.
pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(digest(&SHA256, verifier.as_bytes()))
}

/// The parameters of an authorization code request (PKCE S256).
pub struct AuthorizationRequest<'a> {
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub scope: &'a str,
    pub audience: &'a str,
    pub state: &'a str,
    pub nonce: &'a str,
    pub verifier: &'a str,
}

/// `endpoint` with the authorization request's query.
pub fn authorization_url(endpoint: &Url, request: &AuthorizationRequest<'_>) -> Url {
    let mut url = endpoint.clone();
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", request.client_id)
        .append_pair("redirect_uri", request.redirect_uri)
        .append_pair("scope", request.scope)
        .append_pair("audience", request.audience)
        .append_pair("state", request.state)
        .append_pair("nonce", request.nonce)
        .append_pair("code_challenge", &pkce_challenge(request.verifier))
        .append_pair("code_challenge_method", "S256");
    url
}

/// One token endpoint request. A non-2xx answer is an error; its body is dropped unread (it is
/// the provider's text, not ours to quote).
pub async fn token_request<T: Transport>(
    transport: &T,
    endpoint: &Url,
    auth: ClientAuth<'_>,
    form: &[(&str, &str)],
) -> Result<TokenSet, Error> {
    let (header, body) = signed_form(auth, form)?;
    let response = transport
        .post_form(endpoint, header.as_ref(), body, MAX_BODY)
        .await?;
    if !(200..300).contains(&response.status) {
        return Err(status_error(response.status));
    }
    parse_tokens(&response.body)
}

pub(crate) fn parse_tokens(body: &[u8]) -> Result<TokenSet, Error> {
    let raw: RawTokens = serde_json::from_slice(body)
        .map_err(|_| Error::BadResponse("the token response is not JSON"))?;
    if raw.access_token.is_empty() {
        return Err(Error::BadResponse("no access token"));
    }
    if !raw.token_type.eq_ignore_ascii_case("bearer") {
        return Err(Error::BadResponse("the token type is not Bearer"));
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

/// The form with the client identification applied, and the `Authorization` value if any.
pub(crate) fn signed_form(
    auth: ClientAuth<'_>,
    form: &[(&str, &str)],
) -> Result<(Option<Secret>, String), Error> {
    match auth {
        ClientAuth::Secret { id, secret } => {
            let encode =
                |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
            let credentials = format!("{}:{}", encode(id), encode(secret.expose()));
            Ok((
                Some(Secret::new(format!(
                    "Basic {}",
                    STANDARD.encode(credentials)
                ))),
                form_body(form),
            ))
        }
        ClientAuth::Public { id } => {
            let mut all = vec![("client_id", id)];
            all.extend_from_slice(form);
            Ok((None, form_body(&all)))
        }
    }
}

/// A `refresh_token` grant.
pub async fn refresh<T: Transport>(
    transport: &T,
    endpoint: &Url,
    auth: ClientAuth<'_>,
    refresh_token: &Secret,
    scope: &str,
) -> Result<TokenSet, Error> {
    token_request(
        transport,
        endpoint,
        auth,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.expose()),
            ("scope", scope),
        ],
    )
    .await
}

/// RFC 7009 revocation of a refresh token. The answer is `200` whether or not the token existed.
pub async fn revoke<T: Transport>(
    transport: &T,
    endpoint: &Url,
    auth: ClientAuth<'_>,
    token: &Secret,
) -> Result<(), Error> {
    let (header, body) = signed_form(
        auth,
        &[
            ("token", token.expose()),
            ("token_type_hint", "refresh_token"),
        ],
    )?;
    let response = transport
        .post_form(endpoint, header.as_ref(), body, MAX_BODY)
        .await?;
    if (200..300).contains(&response.status) {
        Ok(())
    } else {
        Err(status_error(response.status))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Script;

    const TOKENS: &str =
        r#"{"access_token":"a","token_type":"Bearer","expires_in":900,"refresh_token":"r"}"#;

    #[test]
    fn the_s256_challenge_matches_the_rfc_example() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[tokio::test]
    async fn a_confidential_client_sends_basic_auth_and_a_public_one_its_id() {
        let endpoint = Url::parse("https://auth.example.com/token").unwrap();
        let script = Script::default();
        script.push(200, TOKENS);
        script.push(200, TOKENS);
        let secret = Secret::new("s3cret");
        let set = token_request(
            &script,
            &endpoint,
            ClientAuth::Secret {
                id: "panel",
                secret: &secret,
            },
            &[("grant_type", "authorization_code")],
        )
        .await
        .unwrap();
        assert_eq!(set.access.expose(), "a");
        assert_eq!(set.expires_in, Duration::from_secs(900));
        token_request(
            &script,
            &endpoint,
            ClientAuth::Public { id: "cli" },
            &[("grant_type", "refresh_token")],
        )
        .await
        .unwrap();
        let seen = script.seen.lock().unwrap();
        assert!(seen[0].1.as_deref().unwrap().starts_with("Basic "));
        assert_eq!(seen[0].2, "grant_type=authorization_code");
        assert_eq!(seen[1].1, None);
        assert_eq!(seen[1].2, "client_id=cli&grant_type=refresh_token");
    }

    #[tokio::test]
    async fn refusals_and_odd_answers_are_errors_without_the_body() {
        let endpoint = Url::parse("https://auth.example.com/token").unwrap();
        let script = Script::default();
        script.push(400, r#"{"error":"invalid_grant","secret":"leak"}"#);
        script.push(503, "");
        script.push(200, r#"{"access_token":"a","token_type":"mac"}"#);
        script.push(200, "nope");
        let public = || ClientAuth::Public { id: "cli" };
        let err = token_request(&script, &endpoint, public(), &[])
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Refused(400)) && !err.to_string().contains("leak"));
        assert!(matches!(
            token_request(&script, &endpoint, public(), &[]).await,
            Err(Error::ProviderFailed(503))
        ));
        for _ in 0..2 {
            assert!(matches!(
                token_request(&script, &endpoint, public(), &[]).await,
                Err(Error::BadResponse(_))
            ));
        }
    }

    #[test]
    fn the_token_set_never_shows_a_token() {
        let set = parse_tokens(TOKENS.as_bytes()).unwrap();
        assert_eq!(format!("{set:?}"), "TokenSet(<redacted>)");
    }
}
