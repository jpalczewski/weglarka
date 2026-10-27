//! `oidc-clients.yml` (#91): `identity_providers.oidc.{claims_policies,clients}`. Field names are the ones
//! Authelia 4.39 accepts; CI validates the output against the pinned image.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use weglarka_model::app::InstanceName;
use weglarka_model::identity::{
    AccessTokenFormat, AuthorizationPolicy, ClientId, DEFAULT_SCOPES, ExternalClientSpec,
    OidcClientSpec, Pkce, TokenEndpointAuthMethod, valid_secret_digest,
};

use crate::{RenderError, to_text};

/// An app's client plus the stored digest of its secret (`<instance>.oidc-client-digest`, P1). The
/// client id is the instance name. `secret_digest` is `None` exactly for a public client.
#[derive(Debug, Clone, Copy)]
pub struct AppClient<'a> {
    pub instance: &'a InstanceName,
    pub spec: &'a OidcClientSpec,
    pub secret_digest: Option<&'a str>,
}

#[derive(Serialize)]
struct Document<'a> {
    identity_providers: IdentityProviders<'a>,
}

#[derive(Serialize)]
struct IdentityProviders<'a> {
    oidc: Oidc<'a>,
}

#[derive(Serialize)]
struct Oidc<'a> {
    claims_policies: BTreeMap<String, ClaimsPolicy>,
    clients: Vec<Client<'a>>,
}

#[derive(Serialize)]
struct ClaimsPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<[&'static str; 1]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_token: Option<[&'static str; 1]>,
}

#[derive(Serialize)]
struct Client<'a> {
    client_id: &'a str,
    client_name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<&'a str>,
    public: bool,
    redirect_uris: &'a [String],
    scopes: Vec<&'a str>,
    authorization_policy: &'static str,
    token_endpoint_auth_method: &'static str,
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    audience: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    claims_policy: Option<String>,
    require_pkce: bool,
    pkce_challenge_method: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    access_token_signed_response_alg: Option<&'static str>,
}

/// The fields both kinds of client share, borrowed from either spec.
struct Common<'a> {
    redirect_uris: &'a [String],
    scopes: &'a Option<Vec<String>>,
    authorization_policy: AuthorizationPolicy,
    token_endpoint_auth_method: TokenEndpointAuthMethod,
    audience: &'a [String],
    groups_in_id_token: bool,
    groups_in_access_token: bool,
    access_token: AccessTokenFormat,
    pkce: Pkce,
    public: bool,
}

impl<'a> From<&'a OidcClientSpec> for Common<'a> {
    fn from(c: &'a OidcClientSpec) -> Self {
        Self {
            redirect_uris: &c.redirect_uris,
            scopes: &c.scopes,
            authorization_policy: c.authorization_policy,
            token_endpoint_auth_method: c.token_endpoint_auth_method,
            audience: &c.audience,
            groups_in_id_token: c.groups_in_id_token,
            groups_in_access_token: c.groups_in_access_token,
            access_token: c.access_token,
            pkce: c.pkce,
            public: c.public,
        }
    }
}

impl<'a> From<&'a ExternalClientSpec> for Common<'a> {
    fn from(c: &'a ExternalClientSpec) -> Self {
        Self {
            redirect_uris: &c.redirect_uris,
            scopes: &c.scopes,
            authorization_policy: c.authorization_policy,
            token_endpoint_auth_method: c.token_endpoint_auth_method,
            audience: &c.audience,
            groups_in_id_token: c.groups_in_id_token,
            groups_in_access_token: c.groups_in_access_token,
            access_token: c.access_token,
            pkce: c.pkce,
            public: c.public,
        }
    }
}

/// Renders `oidc-clients.yml` for the app clients and the external `[oidc_clients]` together. They share
/// one sorted list because the provider replaces its whole `clients` list with the last file's.
///
/// A confidential client's `client_secret` is the given digest; an app with a missing or malformed
/// digest, or an id used twice, is an error (the file is never partially rendered).
pub fn render_oidc_clients(
    apps: &[AppClient<'_>],
    external: &BTreeMap<ClientId, ExternalClientSpec>,
) -> Result<String, RenderError> {
    let mut entries: Vec<(&str, &str, Common<'_>, Option<&str>)> = Vec::new();
    for app in apps {
        let id = app.instance.as_str();
        entries.push((id, id, app.spec.into(), app.secret_digest));
    }
    for (id, client) in external {
        entries.push((
            id.as_str(),
            &client.name,
            client.into(),
            client.secret_digest.as_deref(),
        ));
    }
    entries.sort_by(|a, b| a.0.cmp(b.0));

    let mut seen = BTreeSet::new();
    let mut claims_policies = BTreeMap::new();
    let mut clients = Vec::with_capacity(entries.len());
    for (id, name, c, digest) in entries {
        if !seen.insert(id) {
            return Err(RenderError::DuplicateClient(id.to_owned()));
        }
        let client_secret = match (c.public, digest) {
            (true, None) => None,
            (true, Some(_)) => return Err(RenderError::UnexpectedDigest(id.to_owned())),
            (false, None) => return Err(RenderError::MissingDigest(id.to_owned())),
            (false, Some(d)) if valid_secret_digest(d) => Some(d),
            (false, Some(_)) => return Err(RenderError::InvalidDigest(id.to_owned())),
        };
        let claims_policy = (c.groups_in_id_token || c.groups_in_access_token).then(|| {
            // Namespaced so the operator's own policies in the base config survive the merge.
            let policy = format!("weglarka-{id}");
            claims_policies.insert(
                policy.clone(),
                ClaimsPolicy {
                    id_token: c.groups_in_id_token.then_some(["groups"]),
                    access_token: c.groups_in_access_token.then_some(["groups"]),
                },
            );
            policy
        });
        clients.push(Client {
            client_id: id,
            client_name: name,
            client_secret,
            public: c.public,
            redirect_uris: c.redirect_uris,
            scopes: match c.scopes {
                Some(list) => list.iter().map(String::as_str).collect(),
                None => DEFAULT_SCOPES.to_vec(),
            },
            authorization_policy: match c.authorization_policy {
                AuthorizationPolicy::OneFactor => "one_factor",
                AuthorizationPolicy::TwoFactor => "two_factor",
            },
            token_endpoint_auth_method: match (c.public, c.token_endpoint_auth_method) {
                (true, _) => "none",
                (false, TokenEndpointAuthMethod::ClientSecretBasic) => "client_secret_basic",
                (false, TokenEndpointAuthMethod::ClientSecretPost) => "client_secret_post",
            },
            audience: c.audience,
            claims_policy,
            // A public client cannot do without PKCE, whatever the spec says.
            require_pkce: c.public || c.pkce == Pkce::Required,
            pkce_challenge_method: "S256",
            access_token_signed_response_alg: (c.access_token == AccessTokenFormat::Jwt)
                .then_some("RS256"),
        });
    }
    Ok(to_text(&Document {
        identity_providers: IdentityProviders {
            oidc: Oidc {
                claims_policies,
                clients,
            },
        },
    }))
}
