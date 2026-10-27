//! Where the notification endpoint lives: URL parsing and validation.
//!
//! The URL is deliberately restrictive (no query, credentials, IDN hosts or doubled slashes): the
//! daemon builds the request from these parts, and a token travels with it.

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EndpointError {
    #[error("URL must start with http:// or https://")]
    Scheme,
    #[error("URL must not contain a query or a fragment: use the base URL only")]
    Query,
    #[error("URL must not contain credentials (user:password@)")]
    Credentials,
    #[error("missing or invalid host in the URL")]
    Host,
    #[error("host must be ASCII (IDN host names are not supported)")]
    NonAsciiHost,
    #[error("invalid port in the URL")]
    Port,
    #[error("invalid path in the URL (whitespace and control characters are not allowed)")]
    Path,
    #[error("invalid Host override {0:?}")]
    HostOverride(String),
    #[error(
        "`host` can only be combined with an `http://` URL: over TLS the certificate is verified \
         against the host in the URL, so put the real name in `url` instead"
    )]
    HostOverrideTls,
}

/// Where to connect and what to send in the request line / headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub tls: bool,
    /// Address to connect to (`url` host, unless it is an internal service name).
    pub connect_host: String,
    pub connect_port: u16,
    /// `Host` header (differs from `connect_host` only on the plain-HTTP internal route).
    pub host: String,
    /// Request target: always starts and ends with `/` (the ntfy JSON-publish endpoint is the root).
    pub path: String,
}

/// Character-safe for a request line or a header value.
fn token_safe(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_graphic())
}

fn valid_host(host: &str) -> Result<(), EndpointError> {
    if host.is_empty() || host.contains(['/', '@', '?', '#', ' ', '\\']) {
        return Err(EndpointError::Host);
    }
    if !host.is_ascii() {
        return Err(EndpointError::NonAsciiHost);
    }
    if !token_safe(host) {
        return Err(EndpointError::Host);
    }
    Ok(())
}

impl Endpoint {
    /// Parses `url` (`scheme://host[:port][/base]`); `host_override` replaces the `Host` header and
    /// the TLS server name, for an endpoint reached by service name (e.g. through the ingress).
    pub fn parse(url: &str, host_override: Option<&str>) -> Result<Self, EndpointError> {
        let url = url.trim();
        let (scheme, rest) = url.split_once("://").ok_or(EndpointError::Scheme)?;
        let tls = match scheme.to_ascii_lowercase().as_str() {
            "http" => false,
            "https" => true,
            _ => return Err(EndpointError::Scheme),
        };
        if rest.contains(['?', '#']) {
            return Err(EndpointError::Query);
        }
        if rest.contains('@') {
            return Err(EndpointError::Credentials);
        }
        let (authority, path) = match rest.split_once('/') {
            Some((authority, path)) => (authority, format!("/{path}")),
            None => (rest, "/".to_owned()),
        };
        if !path.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(EndpointError::Path);
        }
        let (host, port) = split_authority(authority)?;
        let connect_host = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
            // Keep IPv6 literals bracketed for `getaddrinfo`; the Host header stays bracketed too.
            Some(inner) => format!("[{inner}]"),
            None => host.clone(),
        };
        let port = match port {
            Some(0) => return Err(EndpointError::Port),
            Some(port) => port,
            None if tls => 443,
            None => 80,
        };
        let host = match host_override {
            Some(override_host) => {
                if !token_safe(override_host) || override_host.contains(':') {
                    return Err(EndpointError::HostOverride(override_host.to_owned()));
                }
                override_host.to_owned()
            }
            None => host,
        };
        // The ntfy JSON publish endpoint is the server root; normalize to `/base/` with exactly one
        // leading and trailing slash (`//x` must not reach the server as a network-path reference).
        if tls && host_override.is_some() {
            return Err(EndpointError::HostOverrideTls);
        }
        let path = match path.trim_matches('/') {
            "" => "/".to_owned(),
            base => format!("/{base}/"),
        };
        Ok(Self {
            tls,
            connect_host,
            connect_port: port,
            host,
            path,
        })
    }
}

impl Endpoint {
    /// The request URL: scheme, connect address and path (the `Host` header is set separately).
    pub fn url(&self) -> String {
        let scheme = if self.tls { "https" } else { "http" };
        format!(
            "{scheme}://{}:{}{}",
            self.connect_host, self.connect_port, self.path
        )
    }
}

/// `host`, `host:port`, `[v6]` or `[v6]:port`.
fn split_authority(authority: &str) -> Result<(String, Option<u16>), EndpointError> {
    if authority.starts_with('[') {
        let end = authority.find(']').ok_or(EndpointError::Host)?;
        let host = &authority[..=end];
        let rest = &authority[end + 1..];
        let port = match rest.strip_prefix(':') {
            Some(port) => Some(port.parse().map_err(|_| EndpointError::Port)?),
            None if rest.is_empty() => None,
            None => return Err(EndpointError::Host),
        };
        valid_host(&host[1..host.len() - 1])?;
        return Ok((host.to_owned(), port));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port.parse().map_err(|_| EndpointError::Port)?)),
        None => (authority, None),
    };
    valid_host(host)?;
    Ok((host.to_owned(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_parsing() {
        let endpoint = Endpoint::parse("https://ntfy.example.com", None).unwrap();
        assert!(endpoint.tls);
        assert_eq!(endpoint.connect_host, "ntfy.example.com");
        assert_eq!(endpoint.connect_port, 443);
        assert_eq!(endpoint.host, "ntfy.example.com");
        assert_eq!(endpoint.path, "/");

        let endpoint =
            Endpoint::parse("http://weglarka-nginx:8080", Some("ntfy.example.com")).unwrap();
        assert!(!endpoint.tls);
        assert_eq!(endpoint.connect_host, "weglarka-nginx");
        assert_eq!(endpoint.connect_port, 8080);
        assert_eq!(endpoint.host, "ntfy.example.com");

        let endpoint = Endpoint::parse("https://example.com/ntfy", None).unwrap();
        assert_eq!(endpoint.path, "/ntfy/");
        let endpoint = Endpoint::parse("https://example.com/ntfy/", None).unwrap();
        assert_eq!(endpoint.path, "/ntfy/");
        // A doubled slash must not become a network-path reference (`//host`).
        let endpoint = Endpoint::parse("https://example.com//ntfy", None).unwrap();
        assert_eq!(endpoint.path, "/ntfy/");
        let endpoint = Endpoint::parse("http://[::1]:8080", None).unwrap();
        assert_eq!(endpoint.connect_host, "[::1]");
        assert_eq!(endpoint.connect_port, 8080);
        assert_eq!(endpoint.url(), "http://[::1]:8080/");
    }

    #[test]
    fn endpoint_rejects_unsafe_or_unsupported_urls() {
        for (url, host, expected) in [
            ("ftp://x", None, EndpointError::Scheme),
            ("ntfy.example.com", None, EndpointError::Scheme),
            (
                "https://ntfy.example.com/insecure?x=1",
                None,
                EndpointError::Query,
            ),
            (
                "https://user:pass@ntfy.example.com",
                None,
                EndpointError::Credentials,
            ),
            ("https://", None, EndpointError::Host),
            ("https://ntfy.example.com:0", None, EndpointError::Port),
            ("https://ntfy.example.com:99999", None, EndpointError::Port),
            ("https://ntfy.example.com:abc", None, EndpointError::Port),
            ("https://ntfy.example.com/a b", None, EndpointError::Path),
            (
                "http://weglarka-nginx:8080",
                Some("bad host"),
                EndpointError::HostOverride("bad host".into()),
            ),
            (
                "https://ntfy.example.com",
                Some("ntfy.example.org"),
                EndpointError::HostOverrideTls,
            ),
            (
                "http://weglarka-nginx:8080",
                Some("host:80"),
                EndpointError::HostOverride("host:80".into()),
            ),
        ] {
            assert_eq!(
                Endpoint::parse(url, host).unwrap_err(),
                expected,
                "{url} {host:?}"
            );
        }
        assert_eq!(
            Endpoint::parse("https://ntfy.例え.com", None).unwrap_err(),
            EndpointError::NonAsciiHost
        );
    }
}
