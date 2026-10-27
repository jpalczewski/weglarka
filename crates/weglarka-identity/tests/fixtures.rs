//! Sample inputs shared by the snapshot tests and the `render` example (which feeds CI's
//! `authelia config validate`). Digests are format-valid placeholders, not real secrets.
#![allow(dead_code)]

use std::collections::BTreeMap;

use weglarka_identity::{AppClient, ForwardApp};
use weglarka_model::app::{AppSpec, InstanceName};
use weglarka_model::identity::{ClientId, ExternalClientSpec, OidcClientSpec};

pub const ISSUER: &str = "https://auth.example.com";
pub const DIGEST: &str = "$pbkdf2-sha512$310000$c2FsdHNhbHRzYWx0$Vk3dN5y0n2m4q1w8e7r6t5y4u3i2o1p0aSdFgHjKlZxCvBnMqWeRtYuIoPaSdFgHjKlZxCvBnMqWeRtYuIoPaA";

pub fn oidc(toml: &str) -> OidcClientSpec {
    toml::from_str(toml).unwrap()
}

pub fn external(toml: &str) -> ExternalClientSpec {
    toml::from_str(toml).unwrap()
}

pub fn app(toml: &str) -> AppSpec {
    toml::from_str(toml).unwrap()
}

pub fn name(n: &str) -> InstanceName {
    InstanceName::new(n).unwrap()
}

/// Owns the specs so tests can borrow `AppClient`s from it.
pub struct Clients {
    pub apps: Vec<(InstanceName, OidcClientSpec, Option<&'static str>)>,
    pub external: BTreeMap<ClientId, ExternalClientSpec>,
}

impl Clients {
    pub fn app_clients(&self) -> Vec<AppClient<'_>> {
        self.apps
            .iter()
            .map(|(instance, spec, digest)| AppClient {
                instance,
                spec,
                secret_digest: *digest,
            })
            .collect()
    }
}

/// Every client flavour at once: confidential with defaults, public, PKCE off with `client_secret_post`,
/// a JWT access token with groups in both tokens and an audience, plus an external client.
pub fn clients() -> Clients {
    Clients {
        apps: vec![
            (
                name("panel"),
                oidc(
                    r#"
                    redirect_uris = ["https://admin.example.com/auth/callback"]
                    client_secret = { kind = "env", var = "OIDC_CLIENT_SECRET" }
                    "#,
                ),
                Some(DIGEST),
            ),
            (
                name("spa"),
                oidc(
                    r#"
                    redirect_uris = ["https://spa.example.com/callback"]
                    public = true
                    "#,
                ),
                None,
            ),
            (
                name("legacy"),
                oidc(
                    r#"
                    redirect_uris = ["https://legacy.example.com/cb"]
                    authorization_policy = "one_factor"
                    token_endpoint_auth_method = "client_secret_post"
                    pkce = "off"
                    client_secret = { kind = "env", var = "OIDC_CLIENT_SECRET" }
                    "#,
                ),
                Some(DIGEST),
            ),
            (
                name("api"),
                oidc(
                    r#"
                    redirect_uris = ["https://api.example.com/auth/callback", "https://api.example.com/auth/silent"]
                    scopes = ["openid", "profile", "email", "groups", "offline_access"]
                    audience = ["https://api.example.com/v1/"]
                    access_token = "jwt"
                    groups_in_id_token = true
                    groups_in_access_token = true
                    client_secret = { kind = "env", var = "OIDC_CLIENT_SECRET" }
                    "#,
                ),
                Some(DIGEST),
            ),
        ],
        external: BTreeMap::from([(
            ClientId::new("forge").unwrap(),
            external(&format!(
                r#"
                name = "Forge"
                redirect_uris = ["https://git.example.com/user/oauth2/authelia/callback"]
                authorization_policy = "one_factor"
                groups_in_id_token = true
                scopes = ["openid", "profile", "email", "groups"]
                secret_digest = "{DIGEST}"
                "#
            )),
        )]),
    }
}

pub struct Forward {
    pub name: InstanceName,
    pub spec: AppSpec,
}

impl Forward {
    pub fn new(n: &str, toml: &str) -> Self {
        Self {
            name: name(n),
            spec: app(toml),
        }
    }

    pub fn forward(&self) -> ForwardApp<'_> {
        ForwardApp {
            instance: &self.name,
            domains: &self.spec.domains,
            paths: &self.spec.paths,
            policy: self.spec.ingress.auth_policy,
            groups: &self.spec.ingress.auth_groups,
        }
    }
}

/// A plain app, a two-domain app restricted to groups, and two prefix apps on a shared domain next to
/// a whole-domain one.
pub fn forward_apps() -> Vec<Forward> {
    vec![
        Forward::new(
            "wiki",
            r#"
            image = "ghcr.io/example/wiki:1"
            domains = ["wiki.example.com"]
            "#,
        ),
        Forward::new(
            "panel",
            r#"
            image = "ghcr.io/example/panel:1"
            domains = ["admin.example.com", "panel.example.com"]
            [ingress]
            auth = "forward"
            auth_policy = "one_factor"
            auth_groups = ["weglarka-admins", "ops.team"]
            "#,
        ),
        Forward::new(
            "docs",
            r#"
            image = "ghcr.io/example/docs:1"
            domains = ["tools.example.com"]
            paths = ["/docs", "/v1.2/ref"]
            [ingress]
            auth = "forward"
            "#,
        ),
        Forward::new(
            "home",
            r#"
            image = "ghcr.io/example/home:1"
            domains = ["tools.example.com"]
            [ingress]
            auth = "forward"
            "#,
        ),
    ]
}
