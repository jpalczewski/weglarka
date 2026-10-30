//! Shared, validated route model — the only place where app data becomes "safe".

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use weglarka_model::admin_auth::RELAY_PREFIX;
use weglarka_model::app::{AppIngress, AppKind, AppSpec, InstanceName, check_path_prefix};
use weglarka_model::config::{HostConfig, IngressMode};
use weglarka_model::identity::{IngressAuth, check_issuer, check_upstream};

/// DNS name of Węglarka's container on the `net-weglarka` network (the `proxy_pass` target for webhooks).
/// An app instance name must not equal it (it would shadow the webhook upstream).
pub const WEBHOOK_UPSTREAM_HOST: &str = "weglarka";

/// The internal location every protected location asks (docs/decisions/0052); no app path may be it.
pub(crate) const AUTHZ_PATH: &str = "/internal/weglarka/authz";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IngressError {
    #[error("invalid domain {value:?}: {reason}")]
    InvalidDomain { value: String, reason: &'static str },
    #[error("domain {0:?} is used more than once")]
    DuplicateDomain(String),
    #[error("invalid path {value:?}: {reason}")]
    InvalidPath { value: String, reason: &'static str },
    #[error(
        "path conflict on {domain}: {path_a:?} of {a} and {path_b:?} of {b} overlap (paths of instances sharing a domain must be disjoint)"
    )]
    PathConflict {
        domain: String,
        a: InstanceName,
        path_a: String,
        b: InstanceName,
        path_b: String,
    },
    #[error("app {0} has domains but no port")]
    MissingPort(InstanceName),
    #[error("app {0} has invalid port 0")]
    InvalidPort(InstanceName),
    #[error("instance name {0} is reserved for the Węglarka webhook upstream")]
    ReservedName(InstanceName),
    #[error("ingress mode {0:?} is not supported by this generator yet")]
    UnsupportedMode(IngressMode),
    #[error("invalid option {name}: {reason}")]
    InvalidOption { name: &'static str, reason: String },
    #[error("app {0} uses forward auth, but weglarka.toml has no [identity] section")]
    ForwardWithoutIdentity(InstanceName),
    #[error(
        "app {0} is the identity provider and cannot use forward auth (its login page would redirect to itself)"
    )]
    ForwardProvider(InstanceName),
    #[error(
        "app {app}: auth_exempt_paths entry {exempt:?} overlaps streaming path {streaming:?} (their locations would collide)"
    )]
    ExemptOverlap {
        app: InstanceName,
        exempt: String,
        streaming: String,
    },
}

/// Domain name after strict validation: lowercase ASCII, digits and `-`, ≥2 labels,
/// no trailing dot, wildcards or special characters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Domain(String);

impl Domain {
    pub fn new(value: impl Into<String>) -> Result<Self, IngressError> {
        let value = value.into();
        match Self::check(&value) {
            Ok(()) => Ok(Self(value)),
            Err(reason) => Err(IngressError::InvalidDomain { value, reason }),
        }
    }

    fn check(v: &str) -> Result<(), &'static str> {
        if v.is_empty() || v.len() > 253 {
            return Err("length must be 1-253");
        }
        let mut labels = 0;
        let mut last = "";
        for label in v.split('.') {
            labels += 1;
            last = label;
            if !(1..=63).contains(&label.len()) {
                return Err("label length must be 1-63");
            }
            if !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return Err("only [a-z0-9-] and '.' allowed");
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err("label must not start or end with '-'");
            }
        }
        if labels < 2 {
            return Err("at least two labels required");
        }
        if last.bytes().all(|b| b.is_ascii_digit()) {
            return Err("last label must not be numeric");
        }
        Ok(())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Path prefix of a route (ADR 0031): `/` or `/seg[/seg…]`, validated by
/// [`weglarka_model::app::check_path_prefix`] because it lands in `nginx.conf`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathPrefix(String);

impl PathPrefix {
    pub fn new(value: impl Into<String>) -> Result<Self, IngressError> {
        let value = value.into();
        match check_path_prefix(&value) {
            Ok(()) => Ok(Self(value)),
            Err(reason) => Err(IngressError::InvalidPath { value, reason }),
        }
    }

    /// The catch-all prefix, i.e. the default of an app without `paths`.
    pub fn root() -> Self {
        Self("/".to_owned())
    }

    pub fn is_root(&self) -> bool {
        self.0 == "/"
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Two prefixes overlap when equal or when one is a segment-wise ancestor of the other
    /// (`/api` vs `/api/v2`, but not `/api` vs `/apiary`). The root is the designed catch-all and
    /// never counts as a conflict with a longer prefix.
    fn overlaps(&self, other: &Self) -> bool {
        if self == other {
            return true;
        }
        if self.is_root() || other.is_root() {
            return false;
        }
        let (short, long) = if self.0.len() <= other.0.len() {
            (&self.0, &other.0)
        } else {
            (&other.0, &self.0)
        };
        long.strip_prefix(short.as_str())
            .is_some_and(|rest| rest.starts_with('/'))
    }
}

impl fmt::Display for PathPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// IP network in CIDR notation (e.g. trusted Docker networks for `set_real_ip_from`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn new(addr: IpAddr, prefix: u8) -> Result<Self, IngressError> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(IngressError::InvalidOption {
                name: "cidr",
                reason: format!("prefix /{prefix} too long for {addr}"),
            });
        }
        Ok(Self { addr, prefix })
    }
}

impl Cidr {
    /// `true` when every address of `other` lies inside `self` (same family, shorter or equal prefix).
    pub fn covers(&self, other: &Cidr) -> bool {
        fn bits(addr: IpAddr) -> (u128, u8) {
            match addr {
                IpAddr::V4(a) => (u128::from(u32::from(a)), 32),
                IpAddr::V6(a) => (u128::from(a), 128),
            }
        }
        let (a, width) = bits(self.addr);
        let (b, other_width) = bits(other.addr);
        if width != other_width || self.prefix > other.prefix {
            return false;
        }
        let shift = u32::from(width - self.prefix);
        shift >= 128 || a >> shift == b >> shift
    }
}

impl FromStr for Cidr {
    type Err = IngressError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bad = |reason: &str| IngressError::InvalidOption {
            name: "cidr",
            reason: format!("{s:?}: {reason}"),
        };
        let Some((addr, prefix)) = s.split_once('/') else {
            // A bare address is a single host.
            let addr: IpAddr = s.parse().map_err(|_| bad("expected addr[/prefix]"))?;
            return Self::new(addr, if addr.is_ipv4() { 32 } else { 128 });
        };
        let addr: IpAddr = addr.parse().map_err(|_| bad("bad address"))?;
        let prefix: u8 = prefix.parse().map_err(|_| bad("bad prefix"))?;
        Self::new(addr, prefix)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// Directory inside the nginx container under which the daemon keeps one directory per static site
/// (`<nginx_conf_dir>/sites`, with `<nginx_conf_dir>` mounted at `/etc/nginx`, ADR 0036/0049).
pub const SITES_CONTAINER_DIR: &str = "/etc/nginx/sites";

/// Where the traffic of a route ends up (ADR 0049).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteBackend {
    /// A container: `instance:port` on the app network.
    Upstream { port: u16 },
    /// A static site: files below `root` inside the nginx container. It is the `current` symlink the
    /// daemon switches atomically, never a path taken from app data.
    Directory { root: String },
}

impl RouteBackend {
    /// Served root of the static site `instance`: `/etc/nginx/sites/<instance>/current`.
    pub fn site_root(instance: &InstanceName) -> String {
        format!("{SITES_CONTAINER_DIR}/{instance}/current")
    }

    /// The upstream port, `None` for a directory.
    pub fn port(&self) -> Option<u16> {
        match self {
            Self::Upstream { port } => Some(*port),
            Self::Directory { .. } => None,
        }
    }
}

impl fmt::Display for RouteBackend {
    /// `doctor`'s notation: `<port>` is rendered by the caller next to the instance; a directory
    /// shows as `static:<root>`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Upstream { port } => write!(f, "{port}"),
            Self::Directory { root } => write!(f, "static:{root}"),
        }
    }
}

/// Route of a single app: all its domains × paths → a container (`instance:port` on the app network)
/// or, for a static site, a directory served by nginx itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppRoute<'a> {
    pub instance: &'a InstanceName,
    pub backend: RouteBackend,
    /// Sorted, without duplicates.
    pub domains: Vec<Domain>,
    /// Path prefixes served on every domain; sorted, without duplicates, `["/"]` when the spec sets none.
    pub paths: Vec<PathPrefix>,
    /// `spec.start`: `false` means the app is provisioned only (no container), so it is validated
    /// and reserves its domains like any other app, but the generators render no route for it.
    pub active: bool,
    /// Per-app ingress behaviour (issue #64). Copied from the spec as-is: an app without a domain is
    /// not rendered at all, so the options never matter there.
    pub ingress: AppIngress,
    /// `auth_exempt_paths` (#89), normalized: empty unless the app uses forward auth. Sorted, one
    /// entry per path.
    pub auth_exempt: Vec<ExemptPath>,
    /// The app is an `[admin.http] clients` instance routed at `/`: its
    /// [`RELAY_PREFIX`](weglarka_model::admin_auth::RELAY_PREFIX) is carved out of the catch-all, without
    /// forward auth and with the long-lived stream settings and the upload body limit
    /// (docs/decisions/0060). Derived from the host config, never from the spec.
    pub admin_relay: bool,
}

impl AppRoute<'_> {
    /// Whether nginx asks the identity provider before serving this app.
    pub fn forward_auth(&self) -> bool {
        self.ingress.auth == IngressAuth::Forward
    }
}

/// One `auth_exempt_paths` entry: `/x` is the exact path, `/x/` the exact `/x` plus everything below
/// `/x/` (the pair `streaming_paths` renders, so `/x` itself is not left protected).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExemptPath {
    /// The path without its trailing slash.
    pub path: PathPrefix,
    /// `true` when the entry also covers everything below `path/`.
    pub prefix: bool,
}

/// The identity provider as the ingress needs it (docs/decisions/0052): where nginx sends the authz
/// subrequests and where an unauthenticated browser goes when the provider gave no `Location`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityRoute {
    /// `host:port` on the app network (`[identity] upstream`, else `<instance>:<port>`).
    pub upstream: String,
    /// `https://host[:port]` of the provider's portal.
    pub issuer: String,
}

/// One line of the effective route table (`doctor`, ADR 0031): a `(domain, path)` and where it goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRow {
    pub domain: Domain,
    pub path: PathPrefix,
    pub instance: InstanceName,
    pub backend: RouteBackend,
    pub strip_prefix: bool,
    pub streaming: bool,
    /// `false` for `start = false` apps: they reserve the route but nginx renders nothing for it.
    pub active: bool,
}

/// Webhook route: public domain → Węglarka's container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookRoute {
    pub domain: Domain,
    pub upstream_port: u16,
}

/// Validated generator input. App order = `BTreeMap` order (deterministic).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan<'a> {
    pub mode: IngressMode,
    pub bind: SocketAddr,
    pub apps: Vec<AppRoute<'a>>,
    pub webhook: WebhookRoute,
    /// The identity provider; `Some` exactly when an app uses forward auth, so a config without such
    /// an app renders no auth machinery at all.
    pub identity: Option<IdentityRoute>,
}

impl<'a> Plan<'a> {
    /// The provider, when an *active* app uses forward auth, i.e. when the config needs the authz
    /// machinery at all (a `start = false` app renders no route).
    pub fn forward_auth(&self) -> Option<&IdentityRoute> {
        self.identity
            .as_ref()
            .filter(|_| self.apps.iter().any(|app| app.active && app.forward_auth()))
    }

    /// Every `(domain, path)` of every app, sorted by domain then path.
    pub fn route_table(&self) -> Vec<RouteRow> {
        let mut rows: Vec<RouteRow> = self
            .apps
            .iter()
            .flat_map(|app| {
                app.domains.iter().flat_map(move |domain| {
                    app.paths.iter().map(move |path| RouteRow {
                        domain: domain.clone(),
                        path: path.clone(),
                        instance: app.instance.clone(),
                        backend: app.backend.clone(),
                        strip_prefix: app.ingress.strip_prefix,
                        streaming: app.ingress.streaming,
                        active: app.active,
                    })
                })
            })
            .collect();
        rows.sort_by(|a, b| (&a.domain, &a.path).cmp(&(&b.domain, &b.path)));
        rows
    }

    /// Apps without domains are skipped (nothing to route). A domain must not repeat
    /// within an app, between apps, or with the webhook domain. Apps with `start = false` are
    /// validated exactly like running ones and keep their domains reserved (a later start must not
    /// collide with, say, Coolify); only rendering skips them ([`AppRoute::active`]).
    pub fn build(
        host: &HostConfig,
        apps: &'a BTreeMap<InstanceName, AppSpec>,
    ) -> Result<Self, IngressError> {
        let webhook_domain = Domain::new(host.webhook.domain.clone())?;
        // Who claimed which prefix on a domain; the webhook domain is exclusive (no entry to share).
        let mut claimed: BTreeMap<Domain, Vec<(&InstanceName, PathPrefix)>> = BTreeMap::new();
        let mut routes = Vec::new();

        for (instance, spec) in apps {
            if spec.domains.is_empty() {
                continue;
            }
            if instance.as_str() == WEBHOOK_UPSTREAM_HOST {
                return Err(IngressError::ReservedName(instance.clone()));
            }
            // A static site has no container and therefore no port (whatever the spec carries).
            let backend = match spec.kind {
                AppKind::Static => RouteBackend::Directory {
                    root: RouteBackend::site_root(instance),
                },
                AppKind::Container => RouteBackend::Upstream {
                    port: match spec.port {
                        None => return Err(IngressError::MissingPort(instance.clone())),
                        Some(0) => return Err(IngressError::InvalidPort(instance.clone())),
                        Some(p) => p,
                    },
                },
            };
            let mut paths = spec
                .paths
                .iter()
                .map(PathPrefix::new)
                .collect::<Result<Vec<_>, _>>()?;
            if paths.is_empty() {
                paths.push(PathPrefix::root());
            }
            paths.sort();
            if let Some(w) = paths.windows(2).find(|w| w[0] == w[1]) {
                return Err(IngressError::InvalidPath {
                    value: w[0].to_string(),
                    reason: "listed more than once",
                });
            }
            // Streaming paths (issue #180) are carved out of the app's own catch-all, so they must not
            // shadow a prefix another app owns on the same domain.
            let streaming = spec
                .ingress
                .streaming_paths
                .iter()
                .map(PathPrefix::new)
                .collect::<Result<Vec<_>, _>>()?;
            if spec.ingress.streaming_paths.iter().any(|p| p == AUTHZ_PATH) {
                return Err(IngressError::InvalidPath {
                    value: AUTHZ_PATH.to_owned(),
                    reason: "is reserved for the forward-auth subrequest",
                });
            }
            let auth_exempt = exempt_paths(instance, &spec.ingress, &streaming)?;
            // Only an app served at `/` can carve a location out of its catch-all, like the
            // streaming and exempt paths above.
            let admin_relay = paths.len() == 1
                && paths[0].is_root()
                && host
                    .admin
                    .http
                    .as_ref()
                    .is_some_and(|http| http.clients.contains(instance));
            let relay = PathPrefix::new(RELAY_PREFIX)?;
            if admin_relay
                && let Some(other) = streaming
                    .iter()
                    .chain(auth_exempt.iter().map(|e| &e.path))
                    .find(|p| p.overlaps(&relay))
            {
                return Err(IngressError::InvalidPath {
                    value: other.to_string(),
                    reason: "overlaps the admin API relay path of an admin client",
                });
            }
            let mut domains = Vec::with_capacity(spec.domains.len());
            for raw in &spec.domains {
                let domain = Domain::new(raw.clone())?;
                if domain == webhook_domain || domains.contains(&domain) {
                    return Err(IngressError::DuplicateDomain(raw.clone()));
                }
                let others = claimed.entry(domain.clone()).or_default();
                for path in paths
                    .iter()
                    .chain(&streaming)
                    .chain(auth_exempt.iter().map(|e| &e.path))
                    .chain(admin_relay.then_some(&relay))
                {
                    if let Some((other, other_path)) = others.iter().find(|(_, q)| path.overlaps(q))
                    {
                        // Two catch-alls are the pre-#130 "domain already taken" case.
                        if path.is_root() && other_path.is_root() {
                            return Err(IngressError::DuplicateDomain(raw.clone()));
                        }
                        return Err(IngressError::PathConflict {
                            domain: raw.clone(),
                            a: (*other).clone(),
                            path_a: other_path.to_string(),
                            b: instance.clone(),
                            path_b: path.to_string(),
                        });
                    }
                }
                others.extend(
                    paths
                        .iter()
                        .chain(&streaming)
                        .chain(auth_exempt.iter().map(|e| &e.path))
                        .chain(admin_relay.then_some(&relay))
                        .map(|p| (instance, p.clone())),
                );
                domains.push(domain);
            }
            domains.sort();
            routes.push(AppRoute {
                instance,
                backend,
                domains,
                paths,
                active: spec.start,
                ingress: spec.ingress.clone(),
                auth_exempt,
                admin_relay,
            });
        }

        let identity = identity_route(host, apps, &routes)?;

        Ok(Self {
            mode: host.ingress.mode,
            bind: host.ingress.bind,
            apps: routes,
            webhook: WebhookRoute {
                domain: webhook_domain,
                upstream_port: host.webhook.listen.port(),
            },
            identity,
        })
    }
}

/// Normalized `auth_exempt_paths` of an app that uses forward auth, checked against its streaming
/// paths: both render `location = p` and `location ^~ p/`, so any overlap is a duplicate location or
/// an ambiguous carve-out. Empty for an app without forward auth (the model rejects the field there).
fn exempt_paths(
    instance: &InstanceName,
    ingress: &AppIngress,
    streaming: &[PathPrefix],
) -> Result<Vec<ExemptPath>, IngressError> {
    if ingress.auth != IngressAuth::Forward {
        return Ok(Vec::new());
    }
    let mut by_path: BTreeMap<PathPrefix, bool> = BTreeMap::new();
    for raw in &ingress.auth_exempt_paths {
        let (body, prefix) = match raw.strip_suffix('/') {
            Some(body) => (body, true),
            None => (raw.as_str(), false),
        };
        // `check_skip_path` (the model) already refuses `/`; `PathPrefix` would accept it.
        if body.is_empty() {
            return Err(IngressError::InvalidPath {
                value: raw.clone(),
                reason: "would exempt every request",
            });
        }
        if body == AUTHZ_PATH {
            return Err(IngressError::InvalidPath {
                value: raw.clone(),
                reason: "is reserved for the forward-auth subrequest",
            });
        }
        *by_path.entry(PathPrefix::new(body)?).or_default() |= prefix;
    }
    for path in by_path.keys() {
        if let Some(streaming) = streaming.iter().find(|s| path.overlaps(s)) {
            return Err(IngressError::ExemptOverlap {
                app: instance.clone(),
                exempt: path.to_string(),
                streaming: streaming.to_string(),
            });
        }
    }
    Ok(by_path
        .into_iter()
        .map(|(path, prefix)| ExemptPath { path, prefix })
        .collect())
}

/// The provider route, resolved only when an app asks for forward auth. Fail closed: a forward app
/// without `[identity]` (or the provider itself behind forward auth) refuses the whole plan, so the
/// last good `nginx.conf` stays instead of a config that serves the app unprotected.
fn identity_route(
    host: &HostConfig,
    apps: &BTreeMap<InstanceName, AppSpec>,
    routes: &[AppRoute<'_>],
) -> Result<Option<IdentityRoute>, IngressError> {
    let Some(first) = routes.iter().find(|r| r.forward_auth()) else {
        return Ok(None);
    };
    let identity = host
        .identity
        .as_ref()
        .ok_or_else(|| IngressError::ForwardWithoutIdentity(first.instance.clone()))?;
    if apps
        .get(&identity.instance)
        .is_some_and(|provider| provider.ingress.auth == IngressAuth::Forward)
    {
        return Err(IngressError::ForwardProvider(identity.instance.clone()));
    }
    let bad = |name, reason: String| IngressError::InvalidOption { name, reason };
    check_issuer(&identity.issuer).map_err(|r| bad("identity.issuer", r.to_owned()))?;
    let upstream = match &identity.upstream {
        Some(upstream) => {
            check_upstream(upstream).map_err(|r| bad("identity.upstream", r.to_owned()))?;
            upstream.clone()
        }
        None => {
            let port = apps
                .get(&identity.instance)
                .and_then(|provider| provider.port)
                .ok_or_else(|| {
                    bad(
                        "identity.upstream",
                        format!(
                            "unset, and instance {} has no port to default to",
                            identity.instance
                        ),
                    )
                })?;
            format!("{}:{port}", identity.instance)
        }
    };
    Ok(Some(IdentityRoute {
        upstream,
        issuer: identity.issuer.clone(),
    }))
}
