//! Cross-app validation of `internal_hosts` (issue #303,
//! `docs/decisions/0071-internal-hosts-host-gateway.md`): the domains an app resolves through Podman's
//! `host-gateway` instead of the public internet.
//!
//! `state::validate_app` covers what an app can break on its own (domain syntax, duplicates). The rule
//! that needs the host — "this host serves that domain" — lives here and is checked wherever the daemon
//! loads `apps.toml` or writes it, next to [`crate::host_ports::validate`]. The field is deliberately
//! not a general hosts-file override: a container that could name any domain would let `apps.toml`
//! point an app at an address outside the ingress.

use std::collections::BTreeSet;

use crate::app::AppsFile;
use crate::config::HostConfig;

/// An `internal_hosts` entry this host does not serve.
#[derive(Debug, thiserror::Error)]
pub enum InternalHostsError {
    #[error(
        "{app}: internal_hosts entry {domain:?} is not a domain this host serves; list a `domains` \
         entry of some app, the `[webhook] domain` or the `[identity]` issuer"
    )]
    NotServed { app: String, domain: String },
}

/// Every entry of every app's `internal_hosts` must be a domain this host serves.
///
/// `apps.toml` is a `BTreeMap`, so the first reported failure is deterministic, like
/// [`crate::host_ports::validate`].
pub fn validate(host: &HostConfig, apps: &AppsFile) -> Result<(), InternalHostsError> {
    let served = served_domains(host, apps);
    for (name, spec) in &apps.apps {
        for domain in &spec.internal_hosts {
            if !served.contains(domain.as_str()) {
                return Err(InternalHostsError::NotServed {
                    app: name.to_string(),
                    domain: domain.clone(),
                });
            }
        }
    }
    Ok(())
}

/// The domains this host answers for: `domains` of every instance (started or not, like the ingress
/// route table reserves them), the webhook domain and the identity issuer's host.
pub fn served_domains<'a>(host: &'a HostConfig, apps: &'a AppsFile) -> BTreeSet<&'a str> {
    let mut served: BTreeSet<&str> = apps
        .apps
        .values()
        .flat_map(|s| s.domains.iter().map(String::as_str))
        .collect();
    served.insert(host.webhook.domain.as_str());
    if let Some(issuer) = host
        .identity
        .as_ref()
        .and_then(|identity| issuer_host(&identity.issuer))
    {
        served.insert(issuer);
    }
    served
}

/// Host part of the `[identity] issuer` URL (`https://host[:port]`, validated by
/// [`crate::config::IdentityConfig::validate`]), borrowed from `issuer`.
fn issuer_host(issuer: &str) -> Option<&str> {
    issuer
        .strip_prefix("https://")
        .and_then(|rest| rest.split(':').next())
        .filter(|host| !host.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{AppSpec, InstanceName};

    fn host(webhook_domain: &str) -> HostConfig {
        HostConfig::from_toml_str(&format!(
            "[ingress]\nmode = \"behind\"\nbind = \"0.0.0.0:8080\"\n\n[admin]\nsocket = \"/tmp/a.sock\"\n\n\
             [webhook]\nlisten = \"0.0.0.0:9000\"\ndomain = \"{webhook_domain}\"\n"
        ))
        .expect("minimal host config")
    }

    fn apps(entries: &[(&str, &[&str], &[&str])]) -> AppsFile {
        let mut file = AppsFile::default();
        for (name, domains, internal_hosts) in entries {
            let spec: AppSpec = toml::from_str(&format!(
                "image = \"i:1\"\ndomains = {domains:?}\ninternal_hosts = {internal_hosts:?}\n"
            ))
            .expect("spec parses");
            file.apps.insert(InstanceName::new(*name).unwrap(), spec);
        }
        file
    }

    #[test]
    fn a_served_domain_is_accepted() {
        let apps = apps(&[
            (
                "git",
                &["git.example.org"],
                &["auth.example.org", "git.example.org"],
            ),
            ("auth", &["auth.example.org"], &[]),
        ]);
        validate(&host("hooks.example.org"), &apps).unwrap();
    }

    #[test]
    fn the_webhook_and_issuer_domains_are_served() {
        let mut host = host("hooks.example.org");
        host.identity = Some(crate::config::IdentityConfig {
            provider: crate::config::IdentityProvider::Authelia,
            instance: InstanceName::new("auth").unwrap(),
            issuer: "https://auth.example.org:8443".to_owned(),
            upstream: None,
        });
        let apps = apps(&[(
            "git",
            &["git.example.org"],
            &["hooks.example.org", "auth.example.org"],
        )]);
        validate(&host, &apps).unwrap();
        assert_eq!(
            served_domains(&host, &apps),
            BTreeSet::from(["auth.example.org", "git.example.org", "hooks.example.org"])
        );
    }

    #[test]
    fn a_domain_this_host_does_not_serve_is_refused() {
        let apps = apps(&[("git", &["git.example.org"], &["elsewhere.example.net"])]);
        let err = validate(&host("hooks.example.org"), &apps).unwrap_err();
        assert_eq!(
            err.to_string(),
            "git: internal_hosts entry \"elsewhere.example.net\" is not a domain this host serves; \
             list a `domains` entry of some app, the `[webhook] domain` or the `[identity]` issuer"
        );
    }
}
