//! Identity provider integration, stage P0 (issue #42, ADR 0051/0052): the serde types of
//! `AppSpec.oidc`, `[oidc_clients]` and `AppIngress.auth*`, their lexical validation, and the gate
//! that rejects every non-default value until the stage that enforces it.
//!
//! **Little behaviour lives here.** Forward auth is enforced by the ingress generator (P5), so its
//! fields are accepted; nothing reads the OIDC fields yet, so accepting one would leave the app
//! without a client, and [`gate`] still refuses them. The gate is the one place a later stage edits
//! to switch a feature on. `[identity]` itself
//! ([`crate::config::IdentityConfig`]) stays in `config.rs` next to the other host sections.
//!
//! None of these fields is part of `spec_hash`.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::app::{
    AppSpec, AppsFile, InstanceName, SecretTarget, check_skip_path, valid_mount_target,
};

/// Scopes an OIDC client may request (#91); extending the list is how further scopes arrive later.
pub const ALLOWED_SCOPES: &[&str] = &["openid", "profile", "email", "groups", "offline_access"];

/// Longest redirect URI / audience entry accepted; they land in the provider's config.
const MAX_URL_LEN: usize = 2048;

/// Authelia's `authorization_policy` of a client and `ingress.auth_policy` of an app.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationPolicy {
    OneFactor,
    #[default]
    TwoFactor,
}

impl AuthorizationPolicy {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// How the client authenticates at the token endpoint. Authelia defaults to `client_secret_basic`,
/// while many relying parties send `client_secret_post` and then fail with "client authentication
/// failed". A public client has no secret and its method is implied (`none`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenEndpointAuthMethod {
    #[default]
    ClientSecretBasic,
    ClientSecretPost,
}

impl TokenEndpointAuthMethod {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// Format of issued access tokens: opaque (default) or a JWT (RFC 9068) for resource servers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessTokenFormat {
    #[default]
    Opaque,
    Jwt,
}

impl AccessTokenFormat {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// Whether the client must use PKCE. `Off` is for relying parties that cannot; a public client
/// cannot turn it off.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Pkce {
    #[default]
    Required,
    Off,
}

impl Pkce {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// `ingress.auth` of an app (#89).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IngressAuth {
    /// The ingress adds no authentication in front of the app (default).
    #[default]
    None,
    /// nginx asks the identity provider before proxying (`auth_request`).
    Forward,
}

impl IngressAuth {
    pub fn is_none(&self) -> bool {
        *self == Self::None
    }
}

/// Scopes of a client that sets none.
pub const DEFAULT_SCOPES: &[&str] = &["openid", "profile", "email"];
/// Default `client_id_env` of [`OidcClientSpec`].
pub const DEFAULT_CLIENT_ID_ENV: &str = "OIDC_CLIENT_ID";
/// Default `issuer_env` of [`OidcClientSpec`].
pub const DEFAULT_ISSUER_ENV: &str = "OIDC_ISSUER";

/// Where the provider's command must load the generated directory from, as its **last** `--config`
/// (#88): the provider merges sources in order, the last wins for scalars and replaces lists
/// wholesale, so anything loaded after ours could re-open `access_control.default_policy`.
pub const GENERATED_CONFIG: &str = "/weglarka/generated/current";

/// Every `--config` source of `command`, in load order. Understands the forms a `StringSlice` flag
/// accepts: `--config=a,b`, `--config a`, `-c a`, `-c=a` and `-ca`. Anything after a bare `--`
/// is a positional argument, not a source.
pub fn config_sources(command: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut args = command.iter();
    while let Some(arg) = args.next() {
        let value = if arg == "--" {
            break;
        } else if let Some(v) = arg.strip_prefix("--config=") {
            v
        } else if arg == "--config" || arg == "-c" {
            match args.next() {
                Some(v) => v,
                None => break,
            }
        } else if let Some(v) = arg.strip_prefix("-c")
            && !arg.starts_with("--")
        {
            v.strip_prefix('=').unwrap_or(v)
        } else {
            continue;
        };
        out.extend(
            value
                .split(',')
                .filter(|s| !s.is_empty())
                .map(str::to_owned),
        );
    }
    out
}

/// Whether `command` loads [`GENERATED_CONFIG`] as its last config source.
pub fn loads_generated_last(command: &[String]) -> bool {
    config_sources(command).last().map(String::as_str) == Some(GENERATED_CONFIG)
}

/// The spec as the container sees it: the app's own spec plus what the identity integration injects
/// (#91) — `<client_id_env>=<instance>`, `<issuer_env>=<issuer>` and a binding of
/// `<instance>.oidc-client-secret` at the declared target. The one place that overlay is computed;
/// the hash, secret materialisation, container creation and `weglarka run` all read the result, so
/// none of them can miss an injected value. Borrowed (identical hash) for an app without `oidc`,
/// or when the host has no `[identity]`. The overlay is never written back into `apps.toml`.
pub fn effective_spec<'a>(
    instance: &InstanceName,
    spec: &'a AppSpec,
    identity: Option<&crate::config::IdentityConfig>,
) -> std::borrow::Cow<'a, AppSpec> {
    use crate::app::SecretBinding;
    use std::borrow::Cow;

    let (Some(oidc), Some(identity)) = (&spec.oidc, identity) else {
        return Cow::Borrowed(spec);
    };
    let mut out = spec.clone();
    out.env.insert(
        oidc.client_id_env
            .clone()
            .unwrap_or_else(|| DEFAULT_CLIENT_ID_ENV.to_owned()),
        instance.to_string(),
    );
    out.env.insert(
        oidc.issuer_env
            .clone()
            .unwrap_or_else(|| DEFAULT_ISSUER_ENV.to_owned()),
        identity.issuer.clone(),
    );
    if let Some(target) = &oidc.client_secret {
        out.secrets
            .retain(|b| b.secret != crate::secret_store::OIDC_CLIENT_SECRET);
        out.secrets.push(SecretBinding {
            secret: crate::secret_store::OIDC_CLIENT_SECRET.to_owned(),
            target: target.clone(),
        });
    }
    Cow::Owned(out)
}

fn scopes_or_default(scopes: &Option<Vec<String>>) -> Vec<&str> {
    match scopes {
        Some(list) => list.iter().map(String::as_str).collect(),
        None => DEFAULT_SCOPES.to_vec(),
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// An OIDC client for an app Węglarka runs (`[apps.<name>.oidc]`, #91). The client id is the
/// instance name. Everything but the injected credentials is render-only: it will change the
/// provider's config, never the app's container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcClientSpec {
    /// Callback URLs: `https`, no fragment, host one of the app's `domains`. At least one.
    pub redirect_uris: Vec<String>,
    /// Unset means [`DEFAULT_SCOPES`]. `openid` is required; the rest comes from [`ALLOWED_SCOPES`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "AuthorizationPolicy::is_default")]
    pub authorization_policy: AuthorizationPolicy,
    #[serde(default, skip_serializing_if = "TokenEndpointAuthMethod::is_default")]
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    /// RFC 8707 audiences, matched byte for byte (a trailing slash counts).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audience: Vec<String>,
    /// Put the `groups` claim into the ID token (needs the `groups` scope).
    #[serde(default, skip_serializing_if = "is_false")]
    pub groups_in_id_token: bool,
    /// Put the `groups` claim into the access token (needs the `groups` scope).
    #[serde(default, skip_serializing_if = "is_false")]
    pub groups_in_access_token: bool,
    #[serde(default, skip_serializing_if = "AccessTokenFormat::is_default")]
    pub access_token: AccessTokenFormat,
    #[serde(default, skip_serializing_if = "Pkce::is_default")]
    pub pkce: Pkce,
    /// A public client: no secret, PKCE forced, auth method `none`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub public: bool,
    /// Environment variable that will carry the client id.
    /// Unset means [`DEFAULT_CLIENT_ID_ENV`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id_env: Option<String>,
    /// Environment variable that will carry the issuer URL.
    /// Unset means [`DEFAULT_ISSUER_ENV`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_env: Option<String>,
    /// Where the client secret reaches the container; required unless `public`, forbidden with it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<SecretTarget>,
}

/// Id of an external client: the same charset as an instance name (`[a-z0-9-]`, 1–63 chars), so it is
/// a subset of RFC 3986 unreserved characters and can never equal an instance's client id by accident
/// ([`validate_file`] rejects equality).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ClientId(String);

impl ClientId {
    pub fn new(id: impl Into<String>) -> Result<Self, String> {
        let id = id.into();
        match InstanceName::new(id.as_str()) {
            Ok(_) => Ok(Self(id)),
            Err(_) => Err(format!(
                "invalid OIDC client id {id:?}: expected 1-63 chars of [a-z0-9-], no leading/trailing '-'"
            )),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ClientId {
    type Error = String;

    fn try_from(value: String) -> Result<Self, String> {
        Self::new(value)
    }
}

impl From<ClientId> for String {
    fn from(value: ClientId) -> Self {
        value.0
    }
}

impl fmt::Display for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A client for an app Węglarka does not run (`[oidc_clients.<id>]`, #91). The provider replaces its
/// whole `clients` list with the last config file's, so Węglarka must own every client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalClientSpec {
    /// Display name (`client_name`).
    pub name: String,
    pub redirect_uris: Vec<String>,
    /// Unset means [`DEFAULT_SCOPES`]. `openid` is required; the rest comes from [`ALLOWED_SCOPES`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "AuthorizationPolicy::is_default")]
    pub authorization_policy: AuthorizationPolicy,
    /// Operator-supplied digest of the client secret (argon2id or pbkdf2); required unless
    /// `public`, forbidden with it. Plaintext and bare values are rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_digest: Option<String>,
    #[serde(default, skip_serializing_if = "TokenEndpointAuthMethod::is_default")]
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audience: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub groups_in_id_token: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub groups_in_access_token: bool,
    #[serde(default, skip_serializing_if = "AccessTokenFormat::is_default")]
    pub access_token: AccessTokenFormat,
    #[serde(default, skip_serializing_if = "Pkce::is_default")]
    pub pkce: Pkce,
    #[serde(default, skip_serializing_if = "is_false")]
    pub public: bool,
}

/// What the app-level and the external client share, borrowed so the checks exist once.
struct ClientCommon<'a> {
    redirect_uris: &'a [String],
    scopes: Vec<&'a str>,
    token_endpoint_auth_method: TokenEndpointAuthMethod,
    audience: &'a [String],
    groups_in_id_token: bool,
    groups_in_access_token: bool,
    access_token: AccessTokenFormat,
    pkce: Pkce,
    public: bool,
}

impl<'a> From<&'a OidcClientSpec> for ClientCommon<'a> {
    fn from(c: &'a OidcClientSpec) -> Self {
        Self {
            redirect_uris: &c.redirect_uris,
            scopes: scopes_or_default(&c.scopes),
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

impl<'a> From<&'a ExternalClientSpec> for ClientCommon<'a> {
    fn from(c: &'a ExternalClientSpec) -> Self {
        Self {
            redirect_uris: &c.redirect_uris,
            scopes: scopes_or_default(&c.scopes),
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

/// Splits an `https://` URL into its host, enforcing the shape every URL we hand to the provider has:
/// no whitespace/control characters, no userinfo, no IPv6 literal, optional numeric port, no fragment.
fn https_host(url: &str) -> Result<&str, &'static str> {
    if url.len() > MAX_URL_LEN {
        return Err("longer than 2048 bytes");
    }
    if url.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("must not contain whitespace or control characters");
    }
    if url.contains('#') {
        return Err("must not contain a fragment");
    }
    let Some(rest) = url.strip_prefix("https://") else {
        return Err("must be an https:// URL");
    };
    let authority = rest.split(['/', '?']).next().unwrap_or_default();
    if authority.contains('@') {
        return Err("must not contain userinfo");
    }
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if !valid_dns_name(host) {
        return Err(
            "host must be a DNS name of non-empty labels (at most 63 bytes of [A-Za-z0-9-], no leading or trailing '-')",
        );
    }
    if port.is_some_and(|p| !valid_port(p)) {
        return Err("port must be a number in 1..=65535");
    }
    Ok(host)
}

/// A DNS name of non-empty labels (at most 63 bytes of `[A-Za-z0-9-]`, no leading or trailing `-`).
pub fn valid_dns_name(host: &str) -> bool {
    !host.is_empty()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn valid_port(port: &str) -> bool {
    port.bytes().all(|b| b.is_ascii_digit()) && port.parse::<u16>().is_ok_and(|p| p != 0)
}

/// `https://host[:port]` with nothing after it — the shape of `[identity].issuer`.
pub fn check_issuer(issuer: &str) -> Result<(), &'static str> {
    https_host(issuer)?;
    if issuer["https://".len()..].contains(['/', '?']) {
        return Err("must not have a path, query or trailing slash");
    }
    Ok(())
}

/// `host:port` of `[identity].upstream`. It lands in `nginx.conf`, so the alphabet is strict.
pub fn check_upstream(upstream: &str) -> Result<(), &'static str> {
    let Some((host, port)) = upstream.rsplit_once(':') else {
        return Err("must be host:port");
    };
    if host.is_empty()
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return Err("host may only contain [A-Za-z0-9._-]");
    }
    if !valid_port(port) {
        return Err("port must be a number in 1..=65535");
    }
    Ok(())
}

/// Group name in `ingress.auth_groups`: `[A-Za-z0-9._-]+`, at most 128 bytes.
pub fn valid_auth_group(group: &str) -> bool {
    !group.is_empty()
        && group.len() <= 128
        && group
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// An environment variable name as the shell and libpod accept it.
fn valid_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    name.len() <= 128
        && bytes
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Authelia's digest format (`$argon2id$…` or `$pbkdf2[-sha256|-sha512]$…`): `$id$` followed by
/// `$`-separated non-empty parts from the PHC alphabet. `$plaintext$` and bare values do not match.
pub fn valid_secret_digest(digest: &str) -> bool {
    let Some(rest) = digest.strip_prefix('$') else {
        return false;
    };
    let mut parts = rest.split('$');
    let algorithm = parts.next().unwrap_or_default();
    let params: Vec<&str> = parts.collect();
    let algorithm_ok = algorithm == "argon2id"
        || matches!(
            algorithm,
            "pbkdf2"
                | "pbkdf2-sha1"
                | "pbkdf2-sha224"
                | "pbkdf2-sha256"
                | "pbkdf2-sha384"
                | "pbkdf2-sha512"
        );
    let min_parts = if algorithm == "argon2id" { 4 } else { 3 };
    algorithm_ok
        && digest.len() <= 1024
        && params.len() >= min_parts
        && params.iter().all(|p| {
            !p.is_empty()
                && p.bytes().all(|b| {
                    b.is_ascii_alphanumeric()
                        || matches!(b, b'.' | b'/' | b'+' | b'=' | b',' | b'-')
                })
        })
}

fn check_common(c: &ClientCommon<'_>) -> Result<(), String> {
    if c.redirect_uris.is_empty() {
        return Err("redirect_uris needs at least one entry".to_owned());
    }
    let mut seen = BTreeSet::new();
    for uri in c.redirect_uris {
        https_host(uri).map_err(|r| format!("invalid redirect URI {uri:?}: {r}"))?;
        if !seen.insert(uri) {
            return Err(format!("duplicate redirect URI {uri:?}"));
        }
    }
    let mut seen = BTreeSet::new();
    for &scope in &c.scopes {
        if !ALLOWED_SCOPES.contains(&scope) {
            return Err(format!(
                "scope {scope:?} is not allowed (allowed: {})",
                ALLOWED_SCOPES.join(", ")
            ));
        }
        if !seen.insert(scope) {
            return Err(format!("duplicate scope {scope:?}"));
        }
    }
    if !seen.contains("openid") {
        return Err("scopes must include \"openid\"".to_owned());
    }
    if (c.groups_in_id_token || c.groups_in_access_token) && !seen.contains("groups") {
        return Err(
            "groups_in_id_token / groups_in_access_token need the \"groups\" scope".to_owned(),
        );
    }
    if c.groups_in_access_token && c.access_token == AccessTokenFormat::Opaque {
        return Err(
            "groups_in_access_token needs access_token = \"jwt\": an opaque token carries no claims"
                .to_owned(),
        );
    }
    for aud in c.audience {
        https_host(aud).map_err(|r| format!("invalid audience {aud:?}: {r}"))?;
    }
    if c.public {
        if c.pkce == Pkce::Off {
            return Err("a public client cannot turn PKCE off".to_owned());
        }
        if !c.token_endpoint_auth_method.is_default() {
            return Err(
                "a public client has no secret, so token_endpoint_auth_method does not apply"
                    .to_owned(),
            );
        }
    }
    Ok(())
}

/// Lexical checks of `AppSpec.oidc` and `AppSpec.ingress.auth*` (no I/O, no host config). Host-aware
/// rules (`[identity]` exists, the provider's `command`, …) belong to a later stage.
pub fn validate_app(name: &InstanceName, spec: &AppSpec) -> Result<(), String> {
    if let Some(oidc) = &spec.oidc {
        validate_oidc(spec, oidc).map_err(|e| format!("{name}: oidc: {e}"))?;
    }
    validate_auth(spec).map_err(|e| format!("{name}: {e}"))
}

fn validate_oidc(spec: &AppSpec, oidc: &OidcClientSpec) -> Result<(), String> {
    if spec.domains.is_empty() {
        return Err("needs at least one domain on the app".to_owned());
    }
    check_common(&oidc.into())?;
    for uri in &oidc.redirect_uris {
        // Already shaped by `check_common`; an app may only register callbacks on its own hosts.
        let host = https_host(uri).map_err(str::to_owned)?;
        if !spec.domains.iter().any(|d| d.eq_ignore_ascii_case(host)) {
            return Err(format!(
                "redirect URI {uri:?}: host {host:?} is not one of the app's domains"
            ));
        }
    }
    let client_id_env = oidc
        .client_id_env
        .as_deref()
        .unwrap_or(DEFAULT_CLIENT_ID_ENV);
    let issuer_env = oidc.issuer_env.as_deref().unwrap_or(DEFAULT_ISSUER_ENV);
    for (field, var) in [("client_id_env", client_id_env), ("issuer_env", issuer_env)] {
        if !valid_env_name(var) {
            return Err(format!(
                "{field} {var:?} is not a valid environment variable name"
            ));
        }
    }
    if client_id_env == issuer_env {
        return Err("client_id_env and issuer_env must differ".to_owned());
    }
    match (&oidc.client_secret, oidc.public) {
        (Some(_), true) => return Err("a public client must not set client_secret".to_owned()),
        (None, false) => {
            return Err("client_secret is required unless the client is public".to_owned());
        }
        _ => {}
    }
    match &oidc.client_secret {
        Some(SecretTarget::Env { var }) => {
            if !valid_env_name(var) {
                return Err(format!(
                    "client_secret var {var:?} is not a valid environment variable name"
                ));
            }
            if [client_id_env, issuer_env].contains(&var.as_str()) {
                return Err(format!(
                    "client_secret var {var:?} collides with client_id_env/issuer_env"
                ));
            }
        }
        Some(SecretTarget::Mount { path, uid, gid, .. }) => {
            if !valid_mount_target(path) {
                return Err(
                    "client_secret path must be an absolute path (no '..', ':' or ',')".to_owned(),
                );
            }
            crate::state::check_mount_owner(*uid, *gid)
                .map_err(|e| format!("client_secret: {e}"))?;
            if spec.secrets.iter().any(|b| {
                matches!(&b.target, SecretTarget::Mount { path: p, .. }
                    if p.trim_end_matches('/') == path.trim_end_matches('/'))
            }) {
                return Err(format!(
                    "client_secret path {path:?} collides with a mounted secret of the app"
                ));
            }
        }
        None => {}
    }
    // The injected names must not shadow what the app already sets.
    let secret_var = match &oidc.client_secret {
        Some(SecretTarget::Env { var }) => Some(("client_secret var", var.as_str())),
        _ => None,
    };
    for (field, var) in [("client_id_env", client_id_env), ("issuer_env", issuer_env)]
        .into_iter()
        .chain(secret_var)
    {
        if spec.env.contains_key(var) {
            return Err(format!(
                "{field} {var:?} collides with a key of the app's env"
            ));
        }
        if spec
            .secrets
            .iter()
            .any(|b| matches!(&b.target, SecretTarget::Env { var: v } if v == var))
        {
            return Err(format!(
                "{field} {var:?} collides with an environment secret of the app"
            ));
        }
    }
    Ok(())
}

fn validate_auth(spec: &AppSpec) -> Result<(), String> {
    let ingress = &spec.ingress;
    if ingress.auth.is_none() {
        let dependent = [
            ("auth_policy", ingress.auth_policy.is_some()),
            ("auth_groups", !ingress.auth_groups.is_empty()),
            ("auth_exempt_paths", !ingress.auth_exempt_paths.is_empty()),
        ];
        if let Some((field, _)) = dependent.iter().find(|(_, set)| *set) {
            return Err(format!(
                "ingress.{field} requires ingress.auth = \"forward\""
            ));
        }
        return Ok(());
    }
    let mut seen = BTreeSet::new();
    for group in &ingress.auth_groups {
        if !valid_auth_group(group) {
            return Err(format!(
                "invalid ingress.auth_groups entry {group:?}: expected 1-128 chars of [A-Za-z0-9._-]"
            ));
        }
        if !seen.insert(group) {
            return Err(format!("duplicate ingress.auth_groups entry {group:?}"));
        }
    }
    let mut seen = BTreeSet::new();
    for path in &ingress.auth_exempt_paths {
        check_skip_path(path)
            .map_err(|r| format!("invalid ingress.auth_exempt_paths entry {path:?}: {r}"))?;
        if !seen.insert(path) {
            return Err(format!(
                "duplicate ingress.auth_exempt_paths entry {path:?}"
            ));
        }
    }
    // A static site's files are served by nginx itself; there is no upstream to attach identity to
    // and no provider-aware location for it, so the combination is refused rather than half-supported.
    if spec.kind == crate::app::AppKind::Static {
        return Err(
            "ingress.auth = \"forward\" is not supported on `kind = \"static\"` apps".to_owned(),
        );
    }
    // Like `streaming_paths`, exempt locations are carved out of the app's own catch-all; a prefix app
    // would need them nested below each of its prefixes. The health probe needs no entry here: it
    // arrives on the probe socket, which the authz location lets through (docs/decisions/0054).
    if !ingress.auth_exempt_paths.is_empty() && !spec.paths.is_empty() {
        return Err(
            "ingress.auth_exempt_paths cannot be combined with path prefixes in `paths`".to_owned(),
        );
    }
    Ok(())
}

/// Lexical checks of one `[oidc_clients.<id>]` entry.
pub fn validate_external_client(id: &ClientId, client: &ExternalClientSpec) -> Result<(), String> {
    let fail = |e: String| format!("oidc_clients.{id}: {e}");
    if client.name.trim().is_empty()
        || client.name.len() > 128
        || client.name.chars().any(char::is_control)
    {
        return Err(fail(
            "name must be 1-128 characters without control characters".to_owned(),
        ));
    }
    check_common(&ClientCommon::from(client)).map_err(fail)?;
    match (&client.secret_digest, client.public) {
        (Some(_), true) => {
            return Err(fail(
                "a public client must not set secret_digest".to_owned(),
            ));
        }
        (None, false) => {
            return Err(fail(
                "secret_digest is required unless the client is public".to_owned(),
            ));
        }
        (Some(digest), false) if !valid_secret_digest(digest) => {
            return Err(fail(
                "secret_digest must be an argon2id or pbkdf2 digest ($plaintext$ and bare values are not accepted)"
                    .to_owned(),
            ));
        }
        _ => {}
    }
    Ok(())
}

/// File-level checks of `apps.toml`: every external client is well-formed, and none shares an id
/// with any instance (with or without `oidc`, so adding `oidc` to an app later cannot collide).
pub fn validate_file(file: &AppsFile) -> Result<(), String> {
    for (id, client) in &file.oidc_clients {
        validate_external_client(id, client)?;
        if InstanceName::new(id.as_str()).is_ok_and(|n| file.apps.contains_key(&n)) {
            return Err(format!(
                "oidc_clients.{id}: the id equals the instance {id:?}, whose OIDC client id it would shadow"
            ));
        }
    }
    Ok(())
}

/// Host-aware rules of forward auth (docs/decisions/0052): an app with `ingress.auth = "forward"`
/// needs `[identity]` (whose provider answers the authz subrequests) and domains (nothing to protect
/// otherwise), and the provider's own instance can never be one — its login page would redirect to
/// itself. Run on every write (`app` only) and at startup (`apps`).
pub fn validate_host_app(
    host: &crate::config::HostConfig,
    name: &InstanceName,
    spec: &AppSpec,
) -> Result<(), String> {
    if spec.oidc.is_some() && host.identity.is_none() {
        return Err(format!(
            "{name}: `oidc` needs an `[identity]` section in weglarka.toml"
        ));
    }
    if spec.ingress.auth.is_none() {
        return Ok(());
    }
    let Some(identity) = &host.identity else {
        return Err(format!(
            "{name}: ingress.auth = \"forward\" needs an `[identity]` section in weglarka.toml"
        ));
    };
    if spec.domains.is_empty() {
        return Err(format!(
            "{name}: ingress.auth = \"forward\" needs `domains`: there is nothing to protect otherwise"
        ));
    }
    if &identity.instance == name {
        return Err(format!(
            "{name}: the identity provider instance cannot use ingress.auth = \"forward\" (its login page would redirect to itself)"
        ));
    }
    Ok(())
}

/// [`validate_host_app`] for every app of `apps.toml`, plus the file-level `[oidc_clients]` rule.
pub fn validate_host(host: &crate::config::HostConfig, apps: &AppsFile) -> Result<(), String> {
    if !apps.oidc_clients.is_empty() && host.identity.is_none() {
        return Err("`[oidc_clients]` needs an `[identity]` section in weglarka.toml".to_owned());
    }
    apps.apps
        .iter()
        .try_for_each(|(name, spec)| validate_host_app(host, name, spec))
}

/// Rules for the spec of the provider instance itself (`[identity].instance`, #88); `Ok` for any
/// other instance. Run on every write of that instance. At daemon start the same rules are only
/// *reported* (`doctor identity.provider`): a wrong provider degrades the integration, but the
/// admin API has to stay up to repair it.
pub fn validate_provider(
    host: &crate::config::HostConfig,
    name: &InstanceName,
    spec: &AppSpec,
) -> Result<(), String> {
    let Some(identity) = host.identity.as_ref().filter(|i| &i.instance == name) else {
        return Ok(());
    };
    if spec.auto_update {
        return Err(format!(
            "{name}: the identity provider must set `auto_update = false`; it is updated deliberately, never from a webhook"
        ));
    }
    // `IdentityConfig::validate` guarantees `https://host[:port]`.
    let issuer_host = identity
        .issuer
        .trim_start_matches("https://")
        .split(':')
        .next()
        .unwrap_or_default();
    if !spec.domains.iter().any(|d| d == issuer_host) {
        return Err(format!(
            "{name}: the issuer host {issuer_host:?} must be one of the provider's `domains`"
        ));
    }
    if !loads_generated_last(&spec.command) {
        return Err(format!(
            "{name}: the provider's `command` must load `--config={GENERATED_CONFIG}` as its last config source \
             (the generated access rules and OIDC clients replace anything a later file sets)"
        ));
    }
    Ok(())
}

/// The feature gate (#42 B4). A field that is accepted but not enforced leaves apps public, so until
/// the stage that implements a feature lands, any non-default value is an error. **To switch a
/// feature on, delete its line below** (and its test); nothing else gates these fields.
pub mod gate {
    use super::{AppSpec, InstanceName};

    const SUFFIX: &str = "is not enabled in this release";

    fn reject(used: bool, feature: &str) -> Result<(), String> {
        if used {
            Err(format!("{feature} {SUFFIX}"))
        } else {
            Ok(())
        }
    }

    /// Per-app fields (`ingress.auth_policy`/`auth_groups`; `oidc` was lifted by P4, `auth` and `auth_exempt_paths` by P5).
    pub fn app(name: &InstanceName, spec: &AppSpec) -> Result<(), String> {
        let ingress = &spec.ingress;
        // nginx enforces only *who is logged in*; the policy and groups become the provider's access
        // rules in #90. Until then accepting them would leave an app that asks for `two_factor` or a
        // group open to every authenticated user.
        let access_control = ingress.auth_policy.is_some() || !ingress.auth_groups.is_empty();
        reject(
            access_control,
            "forward auth access control (`ingress.auth_policy`, `ingress.auth_groups`)",
        ) // lifted by #90
        .map_err(|e| format!("{name}: {e}"))
    }
}

#[cfg(test)]
mod tests;
