//! Panel configuration, read from the environment and validated once at startup.
//!
//! The daemon injects `OIDC_CLIENT_ID`, `OIDC_ISSUER` and the client secret for an app with `oidc`
//! (docs/guides/identity-provider.md); the rest are panel settings with defaults. Parsing takes a
//! lookup function instead of reading the process environment, so tests never touch it.

use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use url::Url;

pub const ENV_CLIENT_ID: &str = "OIDC_CLIENT_ID";
pub const ENV_ISSUER: &str = "OIDC_ISSUER";
pub const ENV_CLIENT_SECRET: &str = "OIDC_CLIENT_SECRET";
pub const ENV_PUBLIC_URL: &str = "PANEL_PUBLIC_URL";
pub const ENV_LISTEN: &str = "PANEL_LISTEN";
pub const ENV_SOCKET: &str = "WEGLARKA_PANEL_SOCKET";
pub const ENV_TIMEOUT_SECS: &str = "PANEL_REQUEST_TIMEOUT_SECS";

/// Where the token listener's directory is mounted in a client (docs/decisions/0056, decision 2).
pub const DEFAULT_SOCKET: &str = "/run/weglarka-admin/api.sock";
pub const DEFAULT_LISTEN: &str = "0.0.0.0:8080";
/// How long the daemon may take to answer the head of a response.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REQUEST_TIMEOUT_SECS: u64 = 120;

/// A secret string. `Debug` never shows it and there is no `Display`, `Serialize` or `Clone`
/// into a loggable form: the only way out is [`Secret::expose`].
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("{0} is not set")]
    Missing(&'static str),
    /// The reason never contains the value: some variables hold secrets.
    #[error("{var} is invalid: {reason}")]
    Invalid { var: &'static str, reason: String },
}

fn invalid(var: &'static str, reason: impl Into<String>) -> ConfigError {
    ConfigError::Invalid {
        var,
        reason: reason.into(),
    }
}

/// The OIDC confidential client the panel logs users in with (docs/decisions/0057, decision 4).
#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub client_id: String,
    pub client_secret: Secret,
    /// The provider's public https URL, without a trailing slash.
    pub issuer: Url,
}

#[derive(Debug, Clone)]
pub struct PanelConfig {
    pub listen: SocketAddr,
    /// The panel's own public origin; the login redirect URI is derived from it.
    pub public_url: Url,
    /// The daemon's token socket (docs/decisions/0056).
    pub socket: PathBuf,
    /// Bounds how long the daemon may take to answer a request.
    pub request_timeout: Duration,
    pub oidc: OidcConfig,
}

impl PanelConfig {
    /// Reads and validates the configuration; `lookup` is the environment (empty values count as unset).
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let get = |var: &'static str| lookup(var).filter(|v| !v.trim().is_empty());
        let required = |var: &'static str| get(var).ok_or(ConfigError::Missing(var));

        let listen = get(ENV_LISTEN)
            .unwrap_or_else(|| DEFAULT_LISTEN.to_owned())
            .parse()
            .map_err(|_| invalid(ENV_LISTEN, "expected <address>:<port>"))?;

        let public_url = parse_url(ENV_PUBLIC_URL, &required(ENV_PUBLIC_URL)?, true)?;
        let issuer = parse_url(ENV_ISSUER, &required(ENV_ISSUER)?, false)?;

        let socket = get(ENV_SOCKET).unwrap_or_else(|| DEFAULT_SOCKET.to_owned());
        if !socket.starts_with('/') {
            return Err(invalid(ENV_SOCKET, "expected an absolute path"));
        }

        let request_timeout = match get(ENV_TIMEOUT_SECS) {
            None => DEFAULT_REQUEST_TIMEOUT,
            Some(raw) => match raw.parse::<u64>() {
                Ok(s) if (1..=MAX_REQUEST_TIMEOUT_SECS).contains(&s) => Duration::from_secs(s),
                _ => {
                    return Err(invalid(
                        ENV_TIMEOUT_SECS,
                        format!("expected 1..={MAX_REQUEST_TIMEOUT_SECS} seconds"),
                    ));
                }
            },
        };

        Ok(Self {
            listen,
            public_url,
            socket: socket.into(),
            request_timeout,
            oidc: OidcConfig {
                client_id: required(ENV_CLIENT_ID)?,
                client_secret: Secret::new(required(ENV_CLIENT_SECRET)?),
                issuer,
            },
        })
    }
}

/// An absolute `https` URL with no credentials, query or fragment and no trailing slash.
/// `allow_loopback_http` additionally accepts plain `http` for a loopback host (local development).
fn parse_url(var: &'static str, raw: &str, allow_loopback_http: bool) -> Result<Url, ConfigError> {
    let mut url = Url::parse(raw.trim()).map_err(|_| invalid(var, "not a valid URL"))?;
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    match url.scheme() {
        "https" => {}
        "http" if allow_loopback_http && loopback => {}
        _ => return Err(invalid(var, "expected an https URL")),
    }
    if url.host_str().is_none() {
        return Err(invalid(var, "expected a host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid(var, "must not contain credentials"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(invalid(var, "must not contain a query or fragment"));
    }
    let trimmed = url.path().trim_end_matches('/').to_owned();
    url.set_path(&trimmed);
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(extra: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let mut vars: Vec<(String, String)> = [
            (ENV_CLIENT_ID, "panel"),
            (ENV_CLIENT_SECRET, "s3cr3t-value"),
            (ENV_ISSUER, "https://auth.example.com"),
            (ENV_PUBLIC_URL, "https://panel.example.com/"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        for (k, v) in extra {
            vars.retain(|(name, _)| name != k);
            vars.push((k.to_string(), v.to_string()));
        }
        move |k| vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone())
    }

    #[test]
    fn defaults() {
        let c = PanelConfig::from_lookup(env(&[])).unwrap();
        assert_eq!(c.listen.to_string(), "0.0.0.0:8080");
        assert_eq!(c.socket, PathBuf::from(DEFAULT_SOCKET));
        assert_eq!(c.request_timeout, DEFAULT_REQUEST_TIMEOUT);
        assert_eq!(c.public_url.as_str(), "https://panel.example.com/");
    }

    #[test]
    fn debug_never_shows_the_secret() {
        let c = PanelConfig::from_lookup(env(&[])).unwrap();
        let shown = format!("{c:?}");
        assert!(!shown.contains("s3cr3t-value"), "{shown}");
        assert!(shown.contains("<redacted>"));
    }

    #[test]
    fn missing_variables_are_named() {
        let err = PanelConfig::from_lookup(|_| None).unwrap_err();
        assert_eq!(err, ConfigError::Missing(ENV_PUBLIC_URL));
        let err = PanelConfig::from_lookup(env(&[(ENV_CLIENT_SECRET, " ")])).unwrap_err();
        assert_eq!(err, ConfigError::Missing(ENV_CLIENT_SECRET));
    }

    #[test]
    fn urls_must_be_https_without_extras() {
        for (var, bad) in [
            (ENV_ISSUER, "http://auth.example.com"),
            (ENV_ISSUER, "http://localhost:9091"),
            (ENV_ISSUER, "https://user:pw@auth.example.com"),
            (ENV_PUBLIC_URL, "http://panel.example.com"),
            (ENV_PUBLIC_URL, "https://panel.example.com/?x=1"),
            (ENV_PUBLIC_URL, "not a url"),
        ] {
            let err = PanelConfig::from_lookup(env(&[(var, bad)])).unwrap_err();
            assert!(
                matches!(err, ConfigError::Invalid { var: v, .. } if v == var),
                "{bad}"
            );
            assert!(!err.to_string().contains("pw"), "{err}");
        }
        // plain http is only for the panel's own origin on loopback
        PanelConfig::from_lookup(env(&[(ENV_PUBLIC_URL, "http://localhost:8080")])).unwrap();
    }

    #[test]
    fn socket_listen_and_timeout_are_validated() {
        let c = PanelConfig::from_lookup(env(&[
            (ENV_SOCKET, "/tmp/api.sock"),
            (ENV_LISTEN, "127.0.0.1:9000"),
            (ENV_TIMEOUT_SECS, "3"),
        ]))
        .unwrap();
        assert_eq!(c.socket, PathBuf::from("/tmp/api.sock"));
        assert_eq!(c.request_timeout, Duration::from_secs(3));
        for (var, bad) in [
            (ENV_SOCKET, "relative.sock"),
            (ENV_LISTEN, "everywhere"),
            (ENV_TIMEOUT_SECS, "0"),
            (ENV_TIMEOUT_SECS, "soon"),
        ] {
            assert!(
                PanelConfig::from_lookup(env(&[(var, bad)])).is_err(),
                "{bad}"
            );
        }
    }
}
