//! Panel configuration, read from the environment and validated once at startup.
//!
//! The daemon injects `OIDC_CLIENT_ID`, `OIDC_ISSUER` and the client secret for an app with `oidc`
//! (docs/guides/identity-provider.md); the rest are panel settings with defaults. Parsing takes a
//! lookup function instead of reading the process environment, so tests never touch it.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use url::Url;

use crate::limit::ProxyNet;

pub const ENV_CLIENT_ID: &str = "OIDC_CLIENT_ID";
pub const ENV_ISSUER: &str = "OIDC_ISSUER";
pub const ENV_CLIENT_SECRET: &str = "OIDC_CLIENT_SECRET";
pub const ENV_PUBLIC_URL: &str = "PANEL_PUBLIC_URL";
pub const ENV_LISTEN: &str = "PANEL_LISTEN";
pub const ENV_SOCKET: &str = "WEGLARKA_PANEL_SOCKET";
pub const ENV_TIMEOUT_SECS: &str = "PANEL_REQUEST_TIMEOUT_SECS";
pub const ENV_CLIENT_SECRET_FILE: &str = "OIDC_CLIENT_SECRET_FILE";
pub const ENV_ENDPOINT_HOSTS: &str = "OIDC_ENDPOINT_HOSTS";
pub const ENV_API_AUDIENCE: &str = "PANEL_API_AUDIENCE";
pub const ENV_SESSION_IDLE_SECS: &str = "PANEL_SESSION_IDLE_SECS";
pub const ENV_SESSION_MAX_SECS: &str = "PANEL_SESSION_MAX_SECS";
pub const ENV_TRUSTED_PROXIES: &str = "PANEL_TRUSTED_PROXIES";

/// Where the token listener's directory is mounted in a client (docs/decisions/0056, decision 2).
pub const DEFAULT_SOCKET: &str = "/run/weglarka-admin/api.sock";
pub const DEFAULT_LISTEN: &str = "0.0.0.0:8080";
/// How long the daemon may take to answer the head of a response.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REQUEST_TIMEOUT_SECS: u64 = 120;
/// A session ends after this long without a request, and after [`DEFAULT_SESSION_MAX`] regardless.
pub const DEFAULT_SESSION_IDLE: Duration = Duration::from_secs(30 * 60);
pub const DEFAULT_SESSION_MAX: Duration = Duration::from_secs(8 * 60 * 60);
const SESSION_IDLE_BOUNDS: std::ops::RangeInclusive<u64> = 60..=24 * 60 * 60;
const SESSION_MAX_BOUNDS: std::ops::RangeInclusive<u64> = 300..=7 * 24 * 60 * 60;
/// A client secret file is a few dozen bytes; anything bigger is the wrong file.
const MAX_SECRET_FILE_BYTES: u64 = 4096;
const MAX_AUDIENCE_BYTES: usize = 512;

pub use weglarka_oidc::Secret;

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
#[derive(Debug)]
pub struct OidcConfig {
    pub client_id: String,
    pub client_secret: Secret,
    /// The provider's public https URL exactly as configured (whitespace trimmed, nothing else):
    /// the issuer identifier is compared byte for byte with the token's `iss`, so it is never
    /// normalized.
    pub issuer: String,
    /// The `aud` the daemon expects of an access token (`[admin.http] audience`); sent in the
    /// authorization request so the provider mints tokens the daemon accepts.
    pub audience: String,
    /// Hosts, besides the issuer's own, that the discovery document may name for `token_endpoint`
    /// and `jwks_uri` (`OIDC_ENDPOINT_HOSTS`). Empty by default: the client secret is sent to the
    /// token endpoint, so a discovery document must not be able to point it at another host.
    pub extra_endpoint_hosts: Vec<String>,
}

#[derive(Debug)]
pub struct PanelConfig {
    pub listen: SocketAddr,
    /// The panel's own public origin; the login redirect URI is derived from it.
    pub public_url: Url,
    /// The daemon's token socket (docs/decisions/0056).
    pub socket: PathBuf,
    /// Bounds how long the daemon may take to answer a request.
    pub request_timeout: Duration,
    /// A session with no request for this long ends.
    pub session_idle: Duration,
    /// A session ends this long after login, however active.
    pub session_max: Duration,
    /// Proxies whose `X-Forwarded-For` is believed (empty: the header is ignored).
    pub trusted_proxies: Vec<ProxyNet>,
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
        let issuer = required(ENV_ISSUER)?.trim().to_owned();
        // A loopback `http://` issuer is allowed for a test provider; everything else is https.
        let issuer_url = parse_url(ENV_ISSUER, &issuer, true)?;
        // The same rule the OIDC client applies to every endpoint: plain http only to a loopback IP
        // (`localhost` is a name, not an address, and would only fail later at discovery).
        if issuer_url.scheme() == "http" && !weglarka_http::transport_allowed(&issuer_url) {
            return Err(invalid(
                ENV_ISSUER,
                "plain http is only allowed to a loopback IP address",
            ));
        }

        let audience = required(ENV_API_AUDIENCE)?.trim().to_owned();
        if audience.len() > MAX_AUDIENCE_BYTES || audience.chars().any(|c| c.is_control()) {
            return Err(invalid(
                ENV_API_AUDIENCE,
                "expected a short single-line identifier",
            ));
        }
        let extra_endpoint_hosts = endpoint_hosts(get(ENV_ENDPOINT_HOSTS))?;
        let client_secret = client_secret(&get)?;

        let socket = get(ENV_SOCKET).unwrap_or_else(|| DEFAULT_SOCKET.to_owned());
        if !socket.starts_with('/') {
            return Err(invalid(ENV_SOCKET, "expected an absolute path"));
        }

        let session_idle = seconds(
            get(ENV_SESSION_IDLE_SECS),
            ENV_SESSION_IDLE_SECS,
            SESSION_IDLE_BOUNDS,
            DEFAULT_SESSION_IDLE,
        )?;
        let session_max = seconds(
            get(ENV_SESSION_MAX_SECS),
            ENV_SESSION_MAX_SECS,
            SESSION_MAX_BOUNDS,
            DEFAULT_SESSION_MAX,
        )?;
        if session_idle > session_max {
            return Err(invalid(
                ENV_SESSION_IDLE_SECS,
                format!("must not exceed {ENV_SESSION_MAX_SECS}"),
            ));
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
            session_idle,
            session_max,
            trusted_proxies: trusted_proxies(get(ENV_TRUSTED_PROXIES))?,
            oidc: OidcConfig {
                client_id: required(ENV_CLIENT_ID)?,
                client_secret,
                issuer,
                audience,
                extra_endpoint_hosts,
            },
        })
    }
}

/// `PANEL_TRUSTED_PROXIES`: comma-separated IP addresses or CIDR ranges.
fn trusted_proxies(raw: Option<String>) -> Result<Vec<ProxyNet>, ConfigError> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    raw.split(',')
        .map(|net| {
            net.trim()
                .parse()
                .map_err(|reason: String| invalid(ENV_TRUSTED_PROXIES, reason))
        })
        .collect()
}

/// `OIDC_ENDPOINT_HOSTS`: comma-separated host names (no scheme, port or path), lower-cased.
fn endpoint_hosts(raw: Option<String>) -> Result<Vec<String>, ConfigError> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    raw.split(',')
        .map(|host| {
            let host = host.trim().to_ascii_lowercase();
            let ok = !host.is_empty()
                && host.len() <= 253
                && host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
            if ok {
                Ok(host)
            } else {
                Err(invalid(
                    ENV_ENDPOINT_HOSTS,
                    "expected comma-separated host names",
                ))
            }
        })
        .collect()
}

/// The client secret: `OIDC_CLIENT_SECRET`, or the first line of the file `OIDC_CLIENT_SECRET_FILE`
/// names (a mounted secret). Setting both is ambiguous, so it is refused. Errors never carry the value.
fn client_secret(get: &impl Fn(&'static str) -> Option<String>) -> Result<Secret, ConfigError> {
    match (get(ENV_CLIENT_SECRET), get(ENV_CLIENT_SECRET_FILE)) {
        (Some(_), Some(_)) => Err(invalid(
            ENV_CLIENT_SECRET_FILE,
            format!("set either {ENV_CLIENT_SECRET} or this, not both"),
        )),
        (Some(value), None) => secret(&value, ENV_CLIENT_SECRET),
        (None, None) => Err(ConfigError::Missing(ENV_CLIENT_SECRET)),
        (None, Some(path)) => {
            let unreadable = || invalid(ENV_CLIENT_SECRET_FILE, "cannot read the file");
            let file = std::fs::File::open(&path).map_err(|_| unreadable())?;
            let mut text = String::new();
            std::io::Read::read_to_string(
                &mut std::io::Read::take(file, MAX_SECRET_FILE_BYTES + 1),
                &mut text,
            )
            .map_err(|_| unreadable())?;
            if text.len() as u64 > MAX_SECRET_FILE_BYTES {
                return Err(invalid(ENV_CLIENT_SECRET_FILE, "the file is too large"));
            }
            let value = text.lines().next().unwrap_or("").trim();
            if value.is_empty() {
                return Err(invalid(ENV_CLIENT_SECRET_FILE, "the file is empty"));
            }
            secret(value, ENV_CLIENT_SECRET_FILE)
        }
    }
}

/// A secret is one line of printable characters: anything else is a mangled mount or a pasted file.
fn secret(value: &str, var: &'static str) -> Result<Secret, ConfigError> {
    if value.chars().any(|c| c.is_control()) {
        return Err(invalid(
            var,
            "must be a single line without control characters",
        ));
    }
    Ok(Secret::new(value))
}

fn seconds(
    raw: Option<String>,
    var: &'static str,
    bounds: std::ops::RangeInclusive<u64>,
    default: Duration,
) -> Result<Duration, ConfigError> {
    match raw {
        None => Ok(default),
        Some(raw) => match raw.trim().parse::<u64>() {
            Ok(s) if bounds.contains(&s) => Ok(Duration::from_secs(s)),
            _ => Err(invalid(
                var,
                format!("expected {}..={} seconds", bounds.start(), bounds.end()),
            )),
        },
    }
}

/// An absolute `https` URL with no credentials, query or fragment; a trailing slash on the path
/// is dropped (a host-only URL still prints with its `/`, as [`Url`] always does).
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
            (ENV_API_AUDIENCE, "https://admin.example.com/api/"),
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
    fn the_issuer_is_kept_exactly_as_configured() {
        for raw in [
            "https://auth.example.com",
            "https://auth.example.com/tenant/",
        ] {
            let c = PanelConfig::from_lookup(env(&[(ENV_ISSUER, &format!(" {raw}\n"))])).unwrap();
            assert_eq!(c.oidc.issuer, raw);
        }
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
            (ENV_ISSUER, "http://auth.example.com:9091"),
            (ENV_ISSUER, "http://127.0.0.1.example.com"),
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
    fn a_loopback_http_issuer_is_allowed_everything_else_stays_https() {
        for ok in ["http://127.0.0.1:9091", "http://[::1]:9091"] {
            let c = PanelConfig::from_lookup(env(&[(ENV_ISSUER, ok)])).unwrap();
            assert_eq!(c.oidc.issuer, ok);
        }
        // `localhost` is a name: the OIDC client would refuse it, so startup does too.
        assert!(PanelConfig::from_lookup(env(&[(ENV_ISSUER, "http://localhost:9091")])).is_err());
    }

    #[test]
    fn extra_endpoint_hosts_are_host_names_only() {
        let with = |hosts: &str| {
            let hosts = hosts.to_owned();
            PanelConfig::from_lookup(move |var| match var {
                ENV_ENDPOINT_HOSTS => Some(hosts.clone()),
                ENV_CLIENT_ID => Some("panel".into()),
                ENV_CLIENT_SECRET => Some("s".into()),
                ENV_ISSUER => Some("https://auth.example.com".into()),
                ENV_PUBLIC_URL => Some("https://panel.example.com".into()),
                ENV_API_AUDIENCE => Some("https://admin.example.com/api/".into()),
                _ => None,
            })
        };
        assert_eq!(
            with("Tokens.Example.org, keys.example.org")
                .unwrap()
                .oidc
                .extra_endpoint_hosts,
            ["tokens.example.org", "keys.example.org"]
        );
        for bad in ["https://x.example.org", "x.example.org:443", "a,,b", "x/y"] {
            assert!(with(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_api_audience_is_required_and_a_single_line() {
        let err = PanelConfig::from_lookup(|k| env(&[])(k).filter(|_| k != ENV_API_AUDIENCE))
            .unwrap_err();
        assert_eq!(err, ConfigError::Missing(ENV_API_AUDIENCE));
        let c = PanelConfig::from_lookup(env(&[])).unwrap();
        assert_eq!(c.oidc.audience, "https://admin.example.com/api/");
        for bad in ["two\nlines", &"a".repeat(600)] {
            assert!(PanelConfig::from_lookup(env(&[(ENV_API_AUDIENCE, bad)])).is_err());
        }
    }

    #[test]
    fn session_lifetimes_have_defaults_and_bounds() {
        let c = PanelConfig::from_lookup(env(&[])).unwrap();
        assert_eq!(c.session_idle, DEFAULT_SESSION_IDLE);
        assert_eq!(c.session_max, DEFAULT_SESSION_MAX);
        let c = PanelConfig::from_lookup(env(&[
            (ENV_SESSION_IDLE_SECS, "120"),
            (ENV_SESSION_MAX_SECS, "600"),
        ]))
        .unwrap();
        assert_eq!(c.session_idle, Duration::from_secs(120));
        assert_eq!(c.session_max, Duration::from_secs(600));
        for (var, bad) in [
            (ENV_SESSION_IDLE_SECS, "5"),
            (ENV_SESSION_IDLE_SECS, "999999999"),
            (ENV_SESSION_IDLE_SECS, "soon"),
            (ENV_SESSION_MAX_SECS, "10"),
            (ENV_SESSION_MAX_SECS, "99999999"),
            // idle may not exceed max
            (ENV_SESSION_MAX_SECS, "600"),
        ] {
            let mut extra = vec![(var, bad)];
            if bad == "600" {
                extra.push((ENV_SESSION_IDLE_SECS, "1200"));
            }
            assert!(
                PanelConfig::from_lookup(env(&extra)).is_err(),
                "{var}={bad}"
            );
        }
    }

    #[test]
    fn the_secret_comes_from_a_variable_or_a_file_never_both_and_never_leaks() {
        let dir = std::env::temp_dir().join(format!("wgl-secret-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("secret");
        std::fs::write(&file, "from-the-file\n").unwrap();
        let file_arg = file.display().to_string();
        let only_file = |k: &str| match k {
            ENV_CLIENT_SECRET => None,
            ENV_CLIENT_SECRET_FILE => Some(file_arg.clone()),
            other => env(&[])(other),
        };
        let c = PanelConfig::from_lookup(only_file).unwrap();
        assert_eq!(c.oidc.client_secret.expose(), "from-the-file");

        let both = PanelConfig::from_lookup(env(&[(ENV_CLIENT_SECRET_FILE, &file_arg)]));
        assert!(matches!(both, Err(ConfigError::Invalid { .. })));

        let missing = |k: &str| match k {
            ENV_CLIENT_SECRET => None,
            ENV_CLIENT_SECRET_FILE => Some("/nonexistent/secret".to_owned()),
            other => env(&[])(other),
        };
        let err = PanelConfig::from_lookup(missing).unwrap_err().to_string();
        assert!(err.contains(ENV_CLIENT_SECRET_FILE), "{err}");

        std::fs::write(&file, "  \n").unwrap();
        assert!(PanelConfig::from_lookup(only_file).is_err());

        // A secret with a control character is refused without quoting it.
        let err = PanelConfig::from_lookup(env(&[(ENV_CLIENT_SECRET, "top\u{7}-secret")]))
            .unwrap_err()
            .to_string();
        assert!(!err.contains("top"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
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
