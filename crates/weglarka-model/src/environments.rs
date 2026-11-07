//! Sites with environments (issue #205, `docs/decisions/0050-site-environments.md`).
//!
//! `[sites.<site>.env.<env>]` in `apps.toml` is sugar: at load every environment expands into the
//! ordinary static instance `<site>-<env>`, so reconcile, deploy, webhook matching, `state.toml` and
//! ingress keep working on instances. The expansion is never written back; [`AppsFile`] remembers each
//! expanded instance's [`SiteOrigin`] only in memory.
//!
//! [`AppsFile`]: crate::app::AppsFile

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::app::{AppKind, AppSpec, InstanceName, Robots, StaticIngress};
use crate::identity::IngressAuth;

/// Defines a lowercase `[a-z0-9-]` name newtype (1–63 chars, no leading/trailing hyphen) — the same
/// alphabet as [`InstanceName`], because `<site>-<env>` has to be a valid instance name.
macro_rules! label_name {
    ($(#[$doc:meta])* $name:ident, $error:ident, $what:literal) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        #[derive(Debug, thiserror::Error)]
        #[error("invalid {what} name {0:?}: use 1-63 characters of [a-z0-9-], no leading or trailing hyphen", what = $what)]
        pub struct $error(pub String);

        impl $name {
            pub fn new(name: impl Into<String>) -> Result<Self, $error> {
                let name = name.into();
                match InstanceName::new(name.clone()) {
                    Ok(_) => Ok(Self(name)),
                    Err(_) => Err($error(name)),
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = $error;
            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

label_name!(
    /// Key of `[sites.<site>]`.
    SiteName,
    InvalidSiteName,
    "site"
);
label_name!(
    /// Key of `[sites.<site>.env.<env>]`.
    EnvName,
    InvalidEnvName,
    "environment"
);

/// `[sites.<site>]`: what the environments of one site have in common.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteSpec {
    /// v1 supports `static` only (container environments are a follow-up, issue #205).
    pub kind: AppKind,
    /// Image repository **without** tag or digest; each environment picks its release.
    pub image: String,
    /// Static-site options shared by every environment (#548, ADR 0075): each environment's instance
    /// gets them, so `not_found_page`, cache headers and the rest are declared once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress: Option<SiteIngress>,
    pub env: BTreeMap<EnvName, EnvSpec>,
}

/// `[sites.<site>.ingress]`: the [`StaticIngress`] options every environment of the site shares.
/// Deliberately not [`crate::app::AppIngress`]: streaming, body limits and auth configure a proxy to a
/// container, which a site environment never has (the same allowlist rule as ADR 0069).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteIngress {
    /// `[sites.<site>.ingress.static]`, renamed like `AppIngress::static_` (`static` is a keyword).
    #[serde(default, rename = "static", skip_serializing_if = "Option::is_none")]
    pub static_: Option<StaticIngress>,
}

/// `[sites.<site>.env.<env>]`: exactly one of `track` and `promote_from`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvSpec {
    /// Tag of the site's repository this environment follows (a webhook for it deploys here).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub track: Option<String>,
    /// Environment whose digest this one receives, only through `weglarka promote`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promote_from: Option<EnvName>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    /// The one per-environment override of the site's shared static options (#545, ADR 0075): a
    /// preview must not be indexed while the same digest is production.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub robots: Option<Robots>,
    /// Auth of this environment (ADR 0081): protection is a property of an environment, not of the
    /// artifact, so a preview can sit behind a password while production stays open. Unset (default)
    /// leaves the instance without auth.
    #[serde(default, skip_serializing_if = "IngressAuth::is_none")]
    pub auth: IngressAuth,
    /// Name of the secret (instance scope, `<site>-<env>.<name>`) holding the `user:password` lines.
    /// Required by `auth = "basic"`, rejected otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_secret: Option<String>,
    /// Paths that skip auth structurally; needs `auth = "forward"` or `auth = "basic"`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auth_exempt_paths: Vec<String>,
}

/// Where an expanded instance comes from. Kept next to `apps.toml`'s instances, never serialized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteOrigin {
    pub site: SiteName,
    pub env: EnvName,
    /// `Some` for a promote-only environment.
    pub promote_from: Option<EnvName>,
}

/// The instance an environment expands into.
pub fn instance_name(site: &SiteName, env: &EnvName) -> Result<InstanceName, String> {
    InstanceName::new(format!("{site}-{env}")).map_err(|e| {
        format!("site {site}, environment {env}: the instance name {e} is not valid (too long?)")
    })
}

/// A repository reference has no tag and no digest.
fn repository_only(image: &str) -> bool {
    let last = image.rsplit('/').next().unwrap_or(image);
    !image.is_empty()
        && !image.contains(char::is_whitespace)
        && !image.contains('@')
        && !last.contains(':')
}

/// Invariants of one site, independent of the rest of the file.
fn validate_site(site: &SiteName, spec: &SiteSpec) -> Result<(), String> {
    if spec.kind != AppKind::Static {
        return Err(format!(
            "site {site}: only kind = \"static\" is supported for sites"
        ));
    }
    if !repository_only(&spec.image) {
        return Err(format!(
            "site {site}: image must be a repository without tag or digest (environments pick the release), got {:?}",
            spec.image
        ));
    }
    if spec.env.is_empty() {
        return Err(format!("site {site}: declare at least one environment"));
    }
    for (env, e) in &spec.env {
        match (&e.track, &e.promote_from) {
            (Some(_), Some(_)) => {
                return Err(format!(
                    "site {site}, environment {env}: set `track` or `promote_from`, not both"
                ));
            }
            (None, None) => {
                return Err(format!(
                    "site {site}, environment {env}: set `track` (follows a tag) or `promote_from` (changes only by promotion)"
                ));
            }
            (Some(tag), None)
                if tag.is_empty()
                    || tag.contains(|c: char| c.is_whitespace() || c == '@' || c == ':') =>
            {
                return Err(format!(
                    "site {site}, environment {env}: invalid tag {tag:?}"
                ));
            }
            (None, Some(from)) => {
                if from == env {
                    return Err(format!(
                        "site {site}, environment {env}: promote_from points at itself"
                    ));
                }
                if !spec.env.contains_key(from) {
                    return Err(format!(
                        "site {site}, environment {env}: promote_from names unknown environment {from}"
                    ));
                }
            }
            _ => {}
        }
    }
    // Every promote chain has to end in a `track` environment, i.e. have no cycle.
    for (env, e) in &spec.env {
        let mut seen = BTreeSet::from([env]);
        let mut at = e;
        while let Some(from) = &at.promote_from {
            if !seen.insert(from) {
                return Err(format!(
                    "site {site}: promote_from forms a cycle through environment {from}"
                ));
            }
            at = &spec.env[from];
        }
    }
    Ok(())
}

/// Expands every environment of `sites` into an instance. Fails on an invalid site or when an
/// expanded name collides with `existing` (`[apps]`) or with another expansion.
pub fn expand(
    sites: &BTreeMap<SiteName, SiteSpec>,
    existing: &BTreeMap<InstanceName, AppSpec>,
) -> Result<BTreeMap<InstanceName, (AppSpec, SiteOrigin)>, String> {
    let mut out: BTreeMap<InstanceName, (AppSpec, SiteOrigin)> = BTreeMap::new();
    for (site, spec) in sites {
        validate_site(site, spec)?;
        for (env, e) in &spec.env {
            let name = instance_name(site, env)?;
            if existing.contains_key(&name) {
                return Err(format!(
                    "site {site}, environment {env} expands to instance {name}, which is already declared in [apps]"
                ));
            }
            if let Some((_, other)) = out.get(&name) {
                return Err(format!(
                    "site {site}, environment {env} expands to instance {name}, which site {}, environment {} already expands to",
                    other.site, other.env
                ));
            }
            out.insert(
                name,
                (
                    expanded_spec(spec, e),
                    SiteOrigin {
                        site: site.clone(),
                        env: env.clone(),
                        promote_from: e.promote_from.clone(),
                    },
                ),
            );
        }
    }
    Ok(out)
}

fn expanded_spec(site: &SiteSpec, env: &EnvSpec) -> AppSpec {
    let mut spec: AppSpec = toml::from_str("image = \"i\"").expect("minimal spec parses");
    spec.kind = site.kind;
    spec.domains = env.domains.clone();
    spec.paths = env.paths.clone();
    match &env.track {
        Some(tag) => spec.image = format!("{}:{tag}", site.image),
        // No tag: nothing may resolve one, so the instance never auto-updates (the engine also
        // refuses a tag-sourced deploy of it).
        None => {
            spec.image = site.image.clone();
            spec.auto_update = false;
        }
    }
    // The site's static options are shared by every environment (#548); `robots` is the only
    // per-environment override (#545), and an environment that sets it without any shared options
    // still gets a `StaticIngress` carrying just that one (ADR 0075).
    spec.ingress.static_ = site.ingress.as_ref().and_then(|i| i.static_.clone());
    if let Some(robots) = env.robots {
        spec.ingress
            .static_
            .get_or_insert_with(StaticIngress::default)
            .robots = Some(robots);
    }
    // Auth belongs to the environment (ADR 0081), so the secret is the instance's own
    // `<site>-<env>.<name>` and a preview can be protected while production is not.
    spec.ingress.auth = env.auth;
    spec.ingress.auth_secret = env.auth_secret.clone();
    spec.ingress.auth_exempt_paths = env.auth_exempt_paths.clone();
    spec
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sites(src: &str) -> Result<BTreeMap<SiteName, SiteSpec>, toml::de::Error> {
        #[derive(Deserialize)]
        struct F {
            sites: BTreeMap<SiteName, SiteSpec>,
        }
        toml::from_str::<F>(src).map(|f| f.sites)
    }

    const BLOG: &str = r#"
[sites.blog]
kind = "static"
image = "ghcr.io/me/blog"

[sites.blog.env.dev]
track = "main"
domains = ["dev.example.com"]

[sites.blog.env.prod]
promote_from = "dev"
domains = ["example.com"]
"#;

    #[test]
    fn expands_into_instances() {
        let out = expand(&sites(BLOG).unwrap(), &BTreeMap::new()).unwrap();
        let dev = &out[&InstanceName::new("blog-dev").unwrap()];
        assert_eq!(dev.0.image, "ghcr.io/me/blog:main");
        assert!(dev.0.auto_update && dev.1.promote_from.is_none());
        let prod = &out[&InstanceName::new("blog-prod").unwrap()];
        assert_eq!(prod.0.image, "ghcr.io/me/blog");
        assert!(!prod.0.auto_update);
        assert_eq!(prod.0.kind, AppKind::Static);
        assert_eq!(prod.0.domains, ["example.com"]);
        assert_eq!(prod.1.promote_from.as_ref().unwrap().as_str(), "dev");
    }

    fn rejects(src: &str, needle: &str) {
        let err = expand(&sites(src).unwrap(), &BTreeMap::new()).unwrap_err();
        assert!(err.contains(needle), "{err}");
    }

    #[test]
    fn rejects_invalid_sites() {
        rejects(
            &BLOG.replace("ghcr.io/me/blog\"", "ghcr.io/me/blog:x\""),
            "without tag",
        );
        rejects(&BLOG.replace("static", "container"), "static");
        rejects(
            &BLOG.replace(
                "promote_from = \"dev\"",
                "track = \"v\"\npromote_from = \"dev\"",
            ),
            "not both",
        );
        rejects(
            &BLOG.replace("promote_from = \"dev\"", "promote_from = \"nope\""),
            "unknown environment",
        );
        rejects(
            &BLOG.replace("promote_from = \"dev\"", "promote_from = \"prod\""),
            "itself",
        );
        rejects(
            &BLOG.replace("track = \"main\"", "promote_from = \"prod\""),
            "cycle",
        );
        rejects(&BLOG.replace("promote_from = \"dev\"", ""), "set `track`");
    }

    #[test]
    fn rejects_name_collisions() {
        // a + b-c against a-b + c
        let src = r#"
[sites.a]
kind = "static"
image = "r/a"
[sites.a.env.b-c]
track = "t"
[sites.a-b]
kind = "static"
image = "r/b"
[sites.a-b.env.c]
track = "t"
"#;
        rejects(src, "already expands");
        let apps: BTreeMap<InstanceName, AppSpec> = BTreeMap::from([(
            InstanceName::new("blog-dev").unwrap(),
            toml::from_str("image = \"x\"").unwrap(),
        )]);
        let err = expand(&sites(BLOG).unwrap(), &apps).unwrap_err();
        assert!(err.contains("[apps]"), "{err}");
    }

    /// `[sites.<site>.ingress.static]` (shared options) and `robots` per environment (#545/#548,
    /// ADR 0075).
    const BLOG_WITH_OPTIONS: &str = r#"
[sites.blog]
kind = "static"
image = "ghcr.io/me/blog"

[sites.blog.ingress.static]
not_found_page = "/404.html"
cache_immutable_paths = ["/_astro"]

[sites.blog.env.dev]
track = "main"
domains = ["dev.example.com"]
robots = "noindex"

[sites.blog.env.prod]
promote_from = "dev"
domains = ["example.com"]
"#;

    fn static_ingress(spec: &AppSpec) -> &StaticIngress {
        spec.ingress
            .static_
            .as_ref()
            .expect("the instance carries static options")
    }

    #[test]
    fn the_sites_static_options_are_shared_and_robots_is_per_environment() {
        let out = expand(&sites(BLOG_WITH_OPTIONS).unwrap(), &BTreeMap::new()).unwrap();
        let dev = &out[&InstanceName::new("blog-dev").unwrap()].0;
        let prod = &out[&InstanceName::new("blog-prod").unwrap()].0;
        for spec in [dev, prod] {
            assert_eq!(spec.kind, AppKind::Static);
            assert_eq!(
                static_ingress(spec).not_found_page.as_deref(),
                Some("/404.html")
            );
            assert_eq!(static_ingress(spec).cache_immutable_paths, ["/_astro"]);
        }
        assert_eq!(static_ingress(dev).robots, Some(Robots::Noindex));
        assert_eq!(static_ingress(prod).robots, None, "not inherited from dev");
    }

    #[test]
    fn an_environment_robots_alone_creates_a_static_ingress() {
        let out = expand(&sites(BLOG_WITH_OPTIONS).unwrap(), &BTreeMap::new()).unwrap();
        let src = BLOG_WITH_OPTIONS.replace(
            "[sites.blog.ingress.static]\nnot_found_page = \"/404.html\"\ncache_immutable_paths = [\"/_astro\"]\n",
            "",
        );
        let out_without = expand(&sites(&src).unwrap(), &BTreeMap::new()).unwrap();
        assert!(!src.contains("[sites.blog.ingress.static]"), "{src}");
        let dev = &out_without[&InstanceName::new("blog-dev").unwrap()].0;
        assert_eq!(static_ingress(dev).robots, Some(Robots::Noindex));
        assert!(!static_ingress(dev).clean_urls);
        // Nothing shared and no per-environment override: no table at all.
        assert!(
            out[&InstanceName::new("blog-prod").unwrap()]
                .0
                .ingress
                .static_
                .is_some()
        );
        assert!(
            out_without[&InstanceName::new("blog-prod").unwrap()]
                .0
                .ingress
                .static_
                .is_none(),
            "a site without shared options and without robots renders nothing"
        );
    }

    #[test]
    fn the_shared_robots_applies_to_an_environment_without_an_override() {
        let src = BLOG_WITH_OPTIONS.replace(
            "not_found_page = \"/404.html\"",
            "not_found_page = \"/404.html\"\nrobots = \"noindex\"",
        );
        let out = expand(&sites(&src).unwrap(), &BTreeMap::new()).unwrap();
        let prod = &out[&InstanceName::new("blog-prod").unwrap()].0;
        assert_eq!(static_ingress(prod).robots, Some(Robots::Noindex));
    }

    #[test]
    fn the_environment_auth_is_copied_into_the_instance() {
        // ADR 0081: protection belongs to the environment, so a preview can sit behind a password
        // while production (the same digest) stays open.
        let src = r#"
[sites.blog]
kind = "static"
image = "ghcr.io/me/blog"

[sites.blog.env.dev]
track = "main"
domains = ["dev.example.com"]
auth = "basic"
auth_secret = "basic-auth"
auth_exempt_paths = ["/robots.txt"]

[sites.blog.env.prod]
promote_from = "dev"
domains = ["example.com"]
"#;
        let out = expand(&sites(src).unwrap(), &BTreeMap::new()).unwrap();
        let dev = &out[&InstanceName::new("blog-dev").unwrap()].0;
        assert_eq!(dev.ingress.auth, crate::identity::IngressAuth::Basic);
        assert_eq!(dev.ingress.auth_secret.as_deref(), Some("basic-auth"));
        assert_eq!(dev.ingress.auth_exempt_paths, ["/robots.txt"]);
        let prod = &out[&InstanceName::new("blog-prod").unwrap()].0;
        assert_eq!(prod.ingress.auth, crate::identity::IngressAuth::None);
        assert_eq!(prod.ingress.auth_secret, None);
        assert!(prod.ingress.auth_exempt_paths.is_empty());
    }

    #[test]
    fn an_environment_auth_round_trips_through_toml() {
        #[derive(Serialize, Deserialize)]
        struct F {
            sites: BTreeMap<SiteName, SiteSpec>,
        }
        let src = BLOG.replace(
            "domains = [\"dev.example.com\"]",
            "domains = [\"dev.example.com\"]\nauth = \"basic\"\nauth_secret = \"basic-auth\"",
        );
        let parsed: F = toml::from_str(&src).unwrap();
        let text = toml::to_string(&parsed).unwrap();
        assert!(text.contains("auth = \"basic\""), "{text}");
        assert!(text.contains("auth_secret = \"basic-auth\""), "{text}");
        assert_eq!(toml::from_str::<F>(&text).unwrap().sites, parsed.sites);
        // An environment without auth writes neither key.
        assert!(
            !toml::to_string(&toml::from_str::<F>(BLOG).unwrap())
                .unwrap()
                .contains("auth")
        );
    }

    #[test]
    fn a_site_with_options_round_trips_through_toml() {
        #[derive(Serialize, Deserialize)]
        struct F {
            sites: BTreeMap<SiteName, SiteSpec>,
        }
        let parsed: F = toml::from_str(BLOG_WITH_OPTIONS).unwrap();
        let text = toml::to_string(&parsed).unwrap();
        assert!(text.contains("[sites.blog.ingress.static]"), "{text}");
        assert!(text.contains("robots = \"noindex\""), "{text}");
        let again: F = toml::from_str(&text).unwrap();
        assert_eq!(again.sites, parsed.sites);
        // A site without options stays without them: no empty table is written.
        let plain: F = toml::from_str(BLOG).unwrap();
        let text = toml::to_string(&plain).unwrap();
        assert!(!text.contains("ingress"), "{text}");
        assert!(!text.contains("robots"), "{text}");
    }

    #[test]
    fn unknown_static_option_names_are_rejected() {
        // `deny_unknown_fields` on `SiteIngress`, `StaticIngress` and `EnvSpec`: a typo is a parse
        // error, not a silently ignored option.
        for (src, needle) in [
            (
                BLOG_WITH_OPTIONS.replace("robots = \"noindex\"", "robots = \"nofollow\""),
                "unknown variant",
            ),
            (
                BLOG_WITH_OPTIONS.replace("robots = \"noindex\"", "robot = \"noindex\""),
                "unknown field",
            ),
            (
                BLOG_WITH_OPTIONS.replace(
                    "not_found_page = \"/404.html\"",
                    "not_found_page = \"/404.html\"\nnot_found = \"x\"",
                ),
                "unknown field",
            ),
            (
                BLOG_WITH_OPTIONS.replace(
                    "[sites.blog.ingress.static]",
                    "[sites.blog.ingress.container]",
                ),
                "unknown field",
            ),
        ] {
            #[derive(Debug, Deserialize)]
            struct F {
                #[allow(dead_code)]
                sites: BTreeMap<SiteName, SiteSpec>,
            }
            let err = toml::from_str::<F>(&src).unwrap_err().to_string();
            assert!(err.contains(needle), "{needle:?} not in {err}");
        }
    }
}
