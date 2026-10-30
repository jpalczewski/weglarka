//! Provider discovery with the scheme and host policy (docs/decisions/0057, decision 4).

use serde::Deserialize;
use url::Url;

use crate::{Error, Transport, get_ok, loopback_http};

/// What the caller allows the provider to name.
#[derive(Debug, Clone, Default)]
pub struct DiscoveryPolicy {
    /// Hosts, besides the issuer's, that may serve the token, JWKS, device and revocation endpoints.
    pub extra_hosts: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Endpoints {
    pub authorization: Url,
    pub token: Url,
    pub jwks: Url,
    /// RFC 8628; `None` when the provider does not advertise the device grant.
    pub device_authorization: Option<Url>,
    /// RFC 7009; `None` when the provider cannot revoke tokens.
    pub revocation: Option<Url>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct DiscoveryDocument {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    device_authorization_endpoint: Option<String>,
    revocation_endpoint: Option<String>,
}

/// Fetches and checks `<issuer>/.well-known/openid-configuration`.
///
/// Plain `http://` endpoints are only accepted when the configured issuer itself is a loopback
/// `http://` one (a test provider); otherwise everything the provider names must be https. The
/// endpoints that receive credentials or decide who is trusted stay on the issuer's host unless
/// the policy lists others.
pub async fn discover<T: Transport>(
    transport: &T,
    issuer: &str,
    policy: &DiscoveryPolicy,
) -> Result<Endpoints, Error> {
    let fail = |reason: &str| Error::Discovery(reason.to_owned());
    let issuer_url = Url::parse(issuer).map_err(|_| fail("the issuer is not a URL"))?;
    let http_issuer = loopback_http(&issuer_url);
    let url = Url::parse(&format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    ))
    .map_err(|_| fail("the issuer is not a URL"))?;
    if !allowed(&url, http_issuer) {
        return Err(Error::Network("refusing a non-https URL".into()));
    }
    let body = get_ok(transport, &url).await?;
    let doc: DiscoveryDocument =
        serde_json::from_slice(&body).map_err(|_| fail("the document is not JSON"))?;
    // Byte for byte (OIDC Discovery 4.3): a mismatch means the document is not this issuer's.
    if doc.issuer != issuer {
        return Err(fail("the document's issuer is not the configured one"));
    }
    let parse = |raw: &str, what: &str| {
        Url::parse(raw)
            .ok()
            .filter(|u| allowed(u, http_issuer))
            .ok_or_else(|| fail(&format!("{what} is missing or not an https URL")))
    };
    let same_host = |url: Url, what: &str| {
        if host_allowed(&url, &issuer_url, policy) {
            Ok(url)
        } else {
            Err(fail(&format!(
                "{what} is on a host other than the issuer's"
            )))
        }
    };
    let optional = |raw: Option<&str>, what: &str| match raw.filter(|r| !r.is_empty()) {
        Some(raw) => same_host(parse(raw, what)?, what).map(Some),
        None => Ok(None),
    };
    Ok(Endpoints {
        authorization: parse(&doc.authorization_endpoint, "authorization_endpoint")?,
        token: same_host(
            parse(&doc.token_endpoint, "token_endpoint")?,
            "token_endpoint",
        )?,
        jwks: same_host(parse(&doc.jwks_uri, "jwks_uri")?, "jwks_uri")?,
        device_authorization: optional(
            doc.device_authorization_endpoint.as_deref(),
            "device_authorization_endpoint",
        )?,
        revocation: optional(doc.revocation_endpoint.as_deref(), "revocation_endpoint")?,
    })
}

fn allowed(url: &Url, http_issuer: bool) -> bool {
    let scheme_ok = url.scheme() == "https" || (http_issuer && loopback_http(url));
    scheme_ok && url.host_str().is_some() && url.username().is_empty() && url.fragment().is_none()
}

fn host_allowed(url: &Url, issuer: &Url, policy: &DiscoveryPolicy) -> bool {
    let origin = |u: &Url| {
        (
            u.host_str().map(str::to_ascii_lowercase),
            u.port_or_known_default(),
        )
    };
    origin(url) == origin(issuer)
        || url.host_str().is_some_and(|h| {
            policy
                .extra_hosts
                .iter()
                .any(|extra| extra.eq_ignore_ascii_case(h))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::Script;

    fn doc(extra: &str) -> String {
        format!(
            r#"{{"issuer":"https://auth.example.com",
            "authorization_endpoint":"https://auth.example.com/authorize",
            "token_endpoint":"https://auth.example.com/token",
            "jwks_uri":"https://auth.example.com/jwks.json"{extra}}}"#
        )
    }

    async fn run(body: String) -> Result<Endpoints, Error> {
        let script = Script::default();
        script.push(200, &body);
        discover(
            &script,
            "https://auth.example.com",
            &DiscoveryPolicy::default(),
        )
        .await
    }

    #[tokio::test]
    async fn reads_the_optional_device_and_revocation_endpoints() {
        let e = run(doc(
            r#","device_authorization_endpoint":"https://auth.example.com/device","revocation_endpoint":"https://auth.example.com/revoke""#,
        ))
        .await
        .unwrap();
        assert_eq!(
            e.device_authorization.unwrap().as_str(),
            "https://auth.example.com/device"
        );
        assert!(e.revocation.is_some());
        assert!(run(doc("")).await.unwrap().device_authorization.is_none());
    }

    #[tokio::test]
    async fn refuses_a_foreign_issuer_and_a_foreign_token_host() {
        let foreign = doc("").replace(
            "\"https://auth.example.com\"",
            "\"https://evil.example.org\"",
        );
        assert!(matches!(run(foreign).await, Err(Error::Discovery(_))));
        let moved = doc("").replace("auth.example.com/token", "evil.example.org/token");
        assert!(matches!(run(moved).await, Err(Error::Discovery(_))));
        let device = doc(r#","device_authorization_endpoint":"https://evil.example.org/d""#);
        assert!(matches!(run(device).await, Err(Error::Discovery(_))));
    }

    #[tokio::test]
    async fn plain_http_only_for_a_loopback_issuer() {
        let script = Script::default();
        assert!(matches!(
            discover(
                &script,
                "http://auth.example.com",
                &DiscoveryPolicy::default()
            )
            .await,
            Err(Error::Network(_))
        ));
    }
}
