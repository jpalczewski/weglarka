//! Shared, validated route model — the only place where app data becomes "safe".

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use weglarka_core::app::{AppSpec, InstanceName};
use weglarka_core::config::{HostConfig, IngressMode};

/// DNS name of Węglarka's container on the `net-weglarka` network (the `proxy_pass` target for webhooks).
/// An app instance name must not equal it (it would shadow the webhook upstream).
pub const WEBHOOK_UPSTREAM_HOST: &str = "weglarka";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IngressError {
    #[error("invalid domain {value:?}: {reason}")]
    InvalidDomain { value: String, reason: &'static str },
    #[error("domain {0:?} is used more than once")]
    DuplicateDomain(String),
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

/// Route of a single app: all its domains → `instance:port` on the app network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppRoute<'a> {
    pub instance: &'a InstanceName,
    pub port: u16,
    /// Sorted, without duplicates.
    pub domains: Vec<Domain>,
    /// `spec.start`: `false` means the app is provisioned only (no container), so it is validated
    /// and reserves its domains like any other app, but the generators render no route for it.
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
}

impl<'a> Plan<'a> {
    /// Apps without domains are skipped (nothing to route). A domain must not repeat
    /// within an app, between apps, or with the webhook domain. Apps with `start = false` are
    /// validated exactly like running ones and keep their domains reserved (a later start must not
    /// collide with, say, Coolify); only rendering skips them ([`AppRoute::active`]).
    pub fn build(
        host: &HostConfig,
        apps: &'a BTreeMap<InstanceName, AppSpec>,
    ) -> Result<Self, IngressError> {
        let webhook_domain = Domain::new(host.webhook.domain.clone())?;
        let mut seen = BTreeSet::from([webhook_domain.clone()]);
        let mut routes = Vec::new();

        for (instance, spec) in apps {
            if spec.domains.is_empty() {
                continue;
            }
            if instance.as_str() == WEBHOOK_UPSTREAM_HOST {
                return Err(IngressError::ReservedName(instance.clone()));
            }
            let port = match spec.port {
                None => return Err(IngressError::MissingPort(instance.clone())),
                Some(0) => return Err(IngressError::InvalidPort(instance.clone())),
                Some(p) => p,
            };
            let mut domains = Vec::with_capacity(spec.domains.len());
            for raw in &spec.domains {
                let domain = Domain::new(raw.clone())?;
                if !seen.insert(domain.clone()) {
                    return Err(IngressError::DuplicateDomain(raw.clone()));
                }
                domains.push(domain);
            }
            domains.sort();
            routes.push(AppRoute {
                instance,
                port,
                domains,
                active: spec.start,
            });
        }

        Ok(Self {
            mode: host.ingress.mode,
            bind: host.ingress.bind,
            apps: routes,
            webhook: WebhookRoute {
                domain: webhook_domain,
                upstream_port: host.webhook.listen.port(),
            },
        })
    }
}
