//! `access-control.yml` (#90): the whole `access_control` section. Whatever the number of forward apps
//! the shape is the same — `default_policy: deny` and a constant first rule that lets the portal itself
//! through — so no policy flips with the app count and the rule list is never empty. A rule that
//! names groups is followed by a `deny` for the same domain and resources, because the provider
//! skips it for non-members instead of stopping there.

use serde::Serialize;
use weglarka_model::app::{InstanceName, check_path_prefix};
use weglarka_model::identity::{
    AuthorizationPolicy, issuer_host, valid_auth_group, valid_dns_name,
};

use crate::{RenderError, to_text};

/// An app with `ingress.auth = "forward"`, reduced to what the rule needs.
#[derive(Debug, Clone, Copy)]
pub struct ForwardApp<'a> {
    pub instance: &'a InstanceName,
    pub domains: &'a [String],
    /// `paths` of the app; empty or containing `/` means the whole domain.
    pub paths: &'a [String],
    /// `ingress.auth_policy`; `None` is `two_factor`.
    pub policy: Option<AuthorizationPolicy>,
    /// `ingress.auth_groups`: membership of any one is enough.
    pub groups: &'a [String],
}

#[derive(Serialize)]
struct Document<'a> {
    access_control: AccessControl<'a>,
}

#[derive(Serialize)]
struct AccessControl<'a> {
    default_policy: &'static str,
    rules: Vec<Rule<'a>>,
}

#[derive(Serialize)]
struct Rule<'a> {
    domain: &'a [String],
    policy: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    subject: Vec<[String; 1]>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    resources: Vec<String>,
}

/// Renders `access-control.yml`. `issuer` is `[identity].issuer`; its host gets the constant `bypass`
/// rule (the portal must be reachable to log in). Rules with `resources` precede the whole-domain ones
/// (Authelia takes the first match, so a prefix app wins over an app on `/` of the same domain), each
/// group sorted by instance.
pub fn render_access_control(issuer: &str, apps: &[ForwardApp<'_>]) -> Result<String, RenderError> {
    let portal = vec![
        issuer_host(issuer)
            .map_err(|e| RenderError::Issuer(issuer.to_owned(), e))?
            .to_owned(),
    ];

    let mut sorted: Vec<&ForwardApp<'_>> = apps.iter().collect();
    sorted.sort_by_key(|a| a.instance.as_str());
    let mut scoped = Vec::new();
    let mut whole = Vec::new();
    for app in sorted {
        let name = app.instance.as_str();
        if app.domains.is_empty() {
            return Err(RenderError::NoDomains(name.to_owned()));
        }
        if let Some(d) = app.domains.iter().find(|d| !valid_domain(d)) {
            return Err(RenderError::InvalidDomain(name.to_owned(), d.clone()));
        }
        // The portal's `bypass` rule comes first, so an app on the portal's host (or a wildcard over it)
        // would be served without authentication.
        if let Some(d) = app.domains.iter().find(|d| covers(d, &portal[0])) {
            return Err(RenderError::PortalDomain(name.to_owned(), d.clone()));
        }
        if let Some(g) = app.groups.iter().find(|g| !valid_auth_group(g)) {
            return Err(RenderError::InvalidGroup(name.to_owned(), g.clone()));
        }
        for path in app.paths {
            check_path_prefix(path)
                .map_err(|e| RenderError::InvalidPath(name.to_owned(), path.clone(), e))?;
        }
        let whole_domain = app.paths.is_empty() || app.paths.iter().any(|p| p == "/");
        let rule = Rule {
            domain: app.domains,
            policy: match app.policy.unwrap_or_default() {
                AuthorizationPolicy::OneFactor => "one_factor",
                AuthorizationPolicy::TwoFactor => "two_factor",
            },
            subject: app.groups.iter().map(|g| [format!("group:{g}")]).collect(),
            resources: if whole_domain {
                Vec::new()
            } else {
                app.paths.iter().map(|p| prefix_regex(p)).collect()
            },
        };
        if whole_domain {
            whole.push(rule);
        } else {
            let longest = app.paths.iter().map(String::len).max().unwrap_or(0);
            scoped.push((longest, rule));
        }
    }

    // Most specific prefix first (stable, so ties stay in instance order): the first match wins, and `/docs`
    // must not shadow `/docs/internal`.
    scoped.sort_by_key(|(longest, _)| std::cmp::Reverse(*longest));
    let scoped = scoped.into_iter().map(|(_, rule)| rule);
    let mut rules = vec![Rule {
        domain: &portal,
        policy: "bypass",
        subject: Vec::new(),
        resources: Vec::new(),
    }];
    for rule in scoped.chain(whole) {
        // Authelia skips a rule whose `subject` does not match the user and carries on with the next
        // one, so a later, laxer rule (another app on the same domain) would admit a non-member.
        // Closing each group rule with a `deny` over the same domain and resources makes it final.
        let closing = (!rule.subject.is_empty()).then(|| Rule {
            domain: rule.domain,
            policy: "deny",
            subject: Vec::new(),
            resources: rule.resources.clone(),
        });
        rules.push(rule);
        rules.extend(closing);
    }
    Ok(to_text(&Document {
        access_control: AccessControl {
            default_policy: "deny",
            rules,
        },
    }))
}

/// Domains land in the rule verbatim, so the alphabet is the hostname one (a leading `*.` wildcard is
/// what Authelia understands too).
fn valid_domain(domain: &str) -> bool {
    valid_dns_name(domain.strip_prefix("*.").unwrap_or(domain))
}

/// Whether a rule domain matches `host`: equal, or a `*.suffix` wildcard over it.
fn covers(domain: &str, host: &str) -> bool {
    domain == host
        || domain
            .strip_prefix('*')
            .is_some_and(|suffix| host.ends_with(suffix))
}

/// `^/prefix([/?].*)?$`: the prefix itself, anything below it, or its query string — but not `/prefixx`.
/// The prefix alphabet (`[A-Za-z0-9_.-]` and `/`) needs only `.` escaped.
fn prefix_regex(prefix: &str) -> String {
    format!("^{}([/?].*)?$", prefix.replace('.', "\\."))
}
