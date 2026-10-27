//! [`NginxOptions`]: generator settings and their validation.

use std::collections::BTreeSet;
use std::net::IpAddr;

use weglarka_model::app::InstanceName;
use weglarka_model::config::{IngressMode, wildcard_cert_stem, wildcard_covers};

use super::{ACME_CONTAINER_DIR, CERT_CONTAINER_DIR, PROBE_CONTAINER_DIR, PROBE_SOCKET};
use crate::cdn::CdnTrust;
use crate::plan::{Cidr, Domain, IngressError};

/// Generator settings that belong to neither `HostConfig` nor `AppSpec`.
#[derive(Debug, Clone)]
pub struct NginxOptions {
    /// Resolver addresses (aardvark-dns of the Podman network); at least one is required.
    pub resolvers: Vec<IpAddr>,
    /// Port nginx listens on *inside* the container for plain HTTP (published on `ingress.bind`).
    pub listen_port: u16,
    /// Port nginx listens on *inside* the container for TLS (`edge` only; published on
    /// `ingress.https_bind`).
    pub https_listen_port: u16,
    /// Peers we trust for `X-Forwarded-*` and `real_ip` (`behind` mode only: whoever connects to the
    /// published port — with rootless Podman that is the port forwarder, not Traefik itself, and it
    /// dials from one of nginx's own addresses, `docs/decisions/0032`).
    pub trusted_proxies: Vec<Cidr>,
    /// Webhook path prefixes (start and end with `/`); the rest of the domain → 404.
    pub webhook_paths: Vec<String>,
    /// Webhook request body limit.
    pub webhook_max_body_bytes: u32,
    /// App request body limit.
    pub app_max_body_bytes: u64,
    /// `edge`: domains with a certificate pair in [`Self::cert_dir`]. A routed domain missing here
    /// gets a plain-HTTP server (redirect + ACME) but no TLS server.
    pub certificates: Vec<Domain>,
    /// `edge`: apex domains with a wildcard pair (`_wildcard.<apex>.crt|key`, issue #97). A routed
    /// domain without a pair of its own is served with the wildcard of the apex that covers it (the
    /// apex itself or one label below, [`wildcard_covers`]); a domain's own pair always wins.
    pub wildcard_certificates: Vec<Domain>,
    /// `edge`: container path of the TLS material, mounted read-only (default [`CERT_CONTAINER_DIR`]).
    pub cert_dir: String,
    /// `edge`: container path of the ACME webroot (default [`ACME_CONTAINER_DIR`]).
    pub acme_webroot: String,
    /// `edge`: stable fingerprint of the TLS material on the host. It is rendered as a comment, so a
    /// renewed certificate changes `nginx.conf` (and therefore triggers `nginx -t` + reload) even
    /// though no route changed. The generator does not interpret it beyond its alphabet.
    pub tls_fingerprint: Option<String>,
    /// `edge`: container directory with the two unix sockets ([`PLAIN_SOCKET`], [`TLS_SOCKET`]) on
    /// which nginx also listens, with `proxy_protocol`, for the port forwarder (issue #162,
    /// docs/decisions/0043). The forwarder is the only peer on them; the client address it announces
    /// in the PROXY header becomes `$remote_addr`. `None` = TCP listeners only (nginx's own address is
    /// then what a published port shows as the client).
    pub proxy_socket_dir: Option<String>,
    /// Container path of the daemon's probe socket (docs/decisions/0054), both modes: a plain-HTTP
    /// `listen unix:` on every app server and on the default server. Its directory must be mounted
    /// into nginx only — never into [`Self::proxy_socket_dir`] (the forwarder's directory), because the
    /// socket skips TLS and authentication. Default: `PROBE_CONTAINER_DIR/PROBE_SOCKET`.
    pub probe_socket: String,
    /// `edge`: the peers that are a CDN and announce the visitor in a header (issue #159,
    /// docs/decisions/0044). Requires [`Self::proxy_socket_dir`]: only then `$remote_addr` is the
    /// real peer the ranges can be compared with.
    pub cdn: Option<CdnTrust>,
    /// Static sites without a release yet (a first deploy has not happened, or a promote-only
    /// environment has not been promoted into, issue #205): their routes answer `503` instead of a
    /// missing `current` directory.
    pub unreleased: BTreeSet<InstanceName>,
}

impl NginxOptions {
    /// File stem (`<domain>` or `_wildcard.<apex>`) of the certificate pair `domain` is served with
    /// in `edge`: its own pair first, else the wildcard of the longest covering apex. `None` = no
    /// TLS server for the domain (its handshake is refused, fail closed).
    pub fn certificate_stem(&self, domain: &Domain) -> Option<String> {
        if self.certificates.contains(domain) {
            return Some(domain.to_string());
        }
        self.wildcard_certificates
            .iter()
            .filter(|apex| wildcard_covers(apex.as_str(), domain.as_str()))
            .max_by_key(|apex| apex.as_str().len())
            .map(|apex| wildcard_cert_stem(apex.as_str()))
    }

    pub fn new(resolvers: Vec<IpAddr>) -> Self {
        Self {
            resolvers,
            listen_port: 8080,
            https_listen_port: 8443,
            trusted_proxies: Vec::new(),
            webhook_paths: vec!["/webhook/".to_owned()],
            webhook_max_body_bytes: 1024 * 1024,
            app_max_body_bytes: 64 * 1024 * 1024,
            certificates: Vec::new(),
            wildcard_certificates: Vec::new(),
            cert_dir: CERT_CONTAINER_DIR.to_owned(),
            acme_webroot: ACME_CONTAINER_DIR.to_owned(),
            tls_fingerprint: None,
            proxy_socket_dir: None,
            probe_socket: format!("{PROBE_CONTAINER_DIR}/{PROBE_SOCKET}"),
            cdn: None,
            unreleased: BTreeSet::new(),
        }
    }

    /// Sets the trusted peers (CIDRs or bare addresses). There is deliberately no default: trusting
    /// a whole Podman address range would let any app container forge `X-Forwarded-*`
    /// (`docs/decisions/0007`); callers pass nginx's own addresses or the configured list.
    pub fn with_trusted_proxies(mut self, entries: &[String]) -> Result<Self, IngressError> {
        self.trusted_proxies = entries
            .iter()
            .map(|e| e.parse())
            .collect::<Result<_, _>>()?;
        Ok(self)
    }

    pub(super) fn validate(&self, mode: IngressMode) -> Result<(), IngressError> {
        let bad = |name, reason: &str| IngressError::InvalidOption {
            name,
            reason: reason.to_owned(),
        };
        if self.resolvers.is_empty() {
            return Err(bad("resolvers", "at least one resolver required"));
        }
        if self.listen_port == 0 {
            return Err(bad("listen_port", "must not be 0"));
        }
        if self.https_listen_port == 0 {
            return Err(bad("https_listen_port", "must not be 0"));
        }
        if self.webhook_paths.is_empty() {
            return Err(bad("webhook_paths", "at least one path required"));
        }
        for p in &self.webhook_paths {
            let ok = p.len() <= 128
                && p.starts_with('/')
                && p.ends_with('/')
                && !p.contains("//")
                && !p.split('/').any(|seg| seg == "." || seg == "..")
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.'));
            if !ok {
                return Err(bad(
                    "webhook_paths",
                    "expected '/'-delimited prefix of [A-Za-z0-9_.-]",
                ));
            }
        }
        check_container_dir("probe_socket", &self.probe_socket)?;
        let probe_dir = self
            .probe_socket
            .rsplit_once('/')
            .map_or("", |(dir, _)| dir);
        let in_forwarder_dir = self
            .proxy_socket_dir
            .as_deref()
            .is_some_and(|dir| probe_dir == dir || probe_dir.starts_with(&format!("{dir}/")));
        if in_forwarder_dir {
            return Err(bad(
                "probe_socket",
                "must not live in proxy_socket_dir (the forwarder mounts that directory)",
            ));
        }
        match mode {
            IngressMode::Behind => {
                if self.proxy_socket_dir.is_some() {
                    return Err(bad(
                        "proxy_socket_dir",
                        "is an `edge`-mode option (Traefik is the client-facing hop in `behind`)",
                    ));
                }
                if self.cdn.is_some() {
                    return Err(bad(
                        "cdn",
                        "is an `edge`-mode option (Traefik is the client-facing hop in `behind`)",
                    ));
                }
                if self.trusted_proxies.is_empty() {
                    return Err(bad(
                        "trusted_proxies",
                        "at least one peer required (set [ingress] trusted_proxies)",
                    ));
                }
            }
            IngressMode::Edge => {
                // `behind` only: in `edge` nginx terminates TLS and no direct client may be trusted.
                if !self.trusted_proxies.is_empty() {
                    return Err(bad(
                        "trusted_proxies",
                        "is a `behind`-mode option; in `edge` no client is trusted (docs/decisions/0007)",
                    ));
                }
                check_container_dir("cert_dir", &self.cert_dir)?;
                check_container_dir("acme_webroot", &self.acme_webroot)?;
                if let Some(dir) = &self.proxy_socket_dir {
                    check_container_dir("proxy_socket_dir", dir)?;
                }
                if self.cdn.is_some() && self.proxy_socket_dir.is_none() {
                    // Without the forwarder `$remote_addr` is nginx's own address, so the CDN ranges
                    // would be compared with the wrong peer (an invariant: `edge` always sets it).
                    return Err(bad(
                        "cdn",
                        "requires proxy_socket_dir (the real peer address)",
                    ));
                }
                if self.cert_dir == self.acme_webroot {
                    return Err(bad("cert_dir", "must differ from acme_webroot"));
                }
                if self.listen_port == self.https_listen_port {
                    return Err(bad("https_listen_port", "must differ from listen_port"));
                }
                match self.tls_fingerprint.as_deref() {
                    Some(fingerprint) if is_tls_fingerprint(fingerprint) => {}
                    Some(fingerprint) => {
                        return Err(IngressError::InvalidOption {
                            name: "tls_fingerprint",
                            reason: format!("{fingerprint:?}: expected 8 lowercase hex characters"),
                        });
                    }
                    None => return Err(bad("tls_fingerprint", "required in `edge`")),
                }
            }
        }
        Ok(())
    }
}

/// An absolute container path made of the characters a config token can carry safely: it lands
/// verbatim in `alias`/`ssl_certificate`, so no whitespace, quotes or `;` (defence in depth — the
/// daemon passes its own constants).
fn check_container_dir(name: &'static str, path: &str) -> Result<(), IngressError> {
    let ok = path.starts_with('/')
        && path.len() > 1
        && !path.ends_with('/')
        && !path.contains("//")
        && !path.split('/').any(|seg| seg == "." || seg == "..")
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.'));
    if ok {
        Ok(())
    } else {
        Err(IngressError::InvalidOption {
            name,
            reason: format!(
                "{path:?}: expected an absolute container directory of [A-Za-z0-9/_.-]"
            ),
        })
    }
}

/// 8 lowercase hex characters: the daemon's truncated sha256 of the TLS material.
fn is_tls_fingerprint(value: &str) -> bool {
    value.len() == 8
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}
