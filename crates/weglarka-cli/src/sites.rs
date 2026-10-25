//! `weglarka sites list|show|declare|remove` and `weglarka promote` (API: `SITES_*`, issue #205,
//! `docs/decisions/0050-site-environments.md`). A site declares environments that expand into the
//! instances `<site>-<env>`; `promote` moves the exact digest one environment runs into another.

use std::path::PathBuf;

use clap::{Args, Subcommand};
use serde::Serialize;
use weglarka_api::{
    DeclareSiteRequest, ListSitesResponse, PromoteRequest, PromoteResponse, SiteSummary, endpoints,
};
use weglarka_core::app::Digest;
use weglarka_core::environments::{EnvName, SiteName, SiteSpec};

use crate::commands::{DryRun, client, report_deploy};
use crate::error::{CliError, Kind, exit};
use crate::output::{emit, table};
use crate::settings::Overrides;

#[derive(Debug, Subcommand)]
pub enum SitesCommand {
    /// List the declared sites with the digest each environment serves.
    List,
    /// Show one site.
    Show { site: String },
    /// Declare or replace a site from a TOML file (`kind`, `image`, `[env.<name>]` tables — the body
    /// of `[sites.<site>]` in apps.toml).
    Declare(DeclareArgs),
    /// Remove a site. Refused while an environment serves a release unless `--purge`.
    Remove(RemoveArgs),
}

#[derive(Debug, Args)]
pub struct DeclareArgs {
    /// Site name ([a-z0-9-], 1–63 characters).
    pub site: String,
    /// TOML file with the site (`-` reads stdin).
    #[arg(long, value_name = "FILE")]
    pub spec: PathBuf,
    /// Send nothing; show the request.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct RemoveArgs {
    pub site: String,
    /// Also forget the state of environments that still serve a release.
    #[arg(long)]
    pub purge: bool,
    /// Send nothing; show the request.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct PromoteArgs {
    pub site: String,
    /// Environment to promote into (it must have `promote_from`).
    pub env: String,
    /// Promote this digest of the site's repository instead of the source environment's current one.
    #[arg(long, value_name = "sha256:…", conflicts_with = "rollback")]
    pub digest: Option<String>,
    /// Return the environment to its previous digest.
    #[arg(long)]
    pub rollback: bool,
    /// Show the digests on both sides and change nothing.
    #[arg(long)]
    pub dry_run: bool,
}

pub async fn run(json: bool, o: &Overrides, cmd: SitesCommand) -> Result<i32, CliError> {
    match cmd {
        SitesCommand::List => list(json, o).await,
        SitesCommand::Show { site } => show(json, o, &site).await,
        SitesCommand::Declare(a) => declare(json, o, a).await,
        SitesCommand::Remove(a) => remove(json, o, a).await,
    }
}

fn site_name(raw: &str) -> Result<SiteName, CliError> {
    SiteName::new(raw)
        .map_err(|e| CliError::usage(e.to_string()).with_hint("site names look like `blog`"))
}

fn env_name(raw: &str) -> Result<EnvName, CliError> {
    EnvName::new(raw).map_err(|e| {
        CliError::usage(e.to_string()).with_hint("environment names look like `dev` or `prod`")
    })
}

fn short(d: &Option<Digest>) -> String {
    d.as_ref().map_or("-".to_owned(), |d| {
        d.as_str().chars().take(19).collect::<String>()
    })
}

fn sites_table(sites: &[SiteSummary]) -> String {
    if sites.is_empty() {
        return "no sites declared (see `weglarka sites declare --help`)\n".to_owned();
    }
    let rows: Vec<Vec<String>> = sites
        .iter()
        .flat_map(|s| {
            s.envs.iter().map(move |e| {
                let source = match (&e.track, &e.promote_from) {
                    (Some(tag), _) => format!("tracks :{tag}"),
                    (None, Some(from)) => format!("promoted from {from}"),
                    (None, None) => "-".to_owned(),
                };
                vec![
                    s.name.to_string(),
                    e.env.to_string(),
                    source,
                    e.domains.join(","),
                    short(&e.current),
                    short(&e.previous),
                ]
            })
        })
        .collect();
    table(
        &["SITE", "ENV", "SOURCE", "DOMAINS", "CURRENT", "PREVIOUS"],
        &rows,
    )
}

async fn list(json: bool, o: &Overrides) -> Result<i32, CliError> {
    let resp: ListSitesResponse = client(o)?
        .call(endpoints::SITES_LIST, &[], None::<&()>)
        .await?;
    emit(json, &resp, || sites_table(&resp.sites));
    Ok(exit::OK)
}

async fn show(json: bool, o: &Overrides, site: &str) -> Result<i32, CliError> {
    let name = site_name(site)?;
    let resp: SiteSummary = client(o)?
        .call(
            endpoints::SITES_SHOW,
            &[("site", name.as_str())],
            None::<&()>,
        )
        .await
        .map_err(|e| match e.kind {
            Kind::NotFound => e.with_hint("declared sites: `weglarka sites list`"),
            _ => e,
        })?;
    emit(json, &resp, || {
        format!(
            "image: {}\n\n{}",
            resp.image,
            sites_table(std::slice::from_ref(&resp))
        )
    });
    Ok(exit::OK)
}

async fn declare(json: bool, o: &Overrides, a: DeclareArgs) -> Result<i32, CliError> {
    let name = site_name(&a.site)?;
    let src = if a.spec.as_os_str() == "-" {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut s)
            .map_err(|e| CliError::usage(format!("cannot read the site from stdin: {e}")))?;
        s
    } else {
        std::fs::read_to_string(&a.spec)
            .map_err(|e| CliError::usage(format!("cannot read {}: {e}", a.spec.display())))?
    };
    let spec: SiteSpec = toml::from_str(&src).map_err(|e| {
        CliError::usage(format!("invalid site: {e}")).with_hint(
            "format: the body of `[sites.<site>]` — kind = \"static\", image = \"repo\" and \
             [env.<name>] tables with `track` or `promote_from`",
        )
    })?;
    let req = DeclareSiteRequest { spec };
    let params = [("site", name.as_str())];
    if a.dry_run {
        let body = serde_json::to_value(&req).map_err(|e| CliError::internal(e.to_string()))?;
        DryRun::new(endpoints::SITES_DECLARE, &params, Some(body)).print(json);
        return Ok(exit::OK);
    }
    client(o)?
        .call_empty_json(endpoints::SITES_DECLARE, &params, &req)
        .await?;
    #[derive(Serialize)]
    struct Declared {
        declared: String,
    }
    emit(
        json,
        &Declared {
            declared: name.to_string(),
        },
        || format!("declared site {name}\n"),
    );
    Ok(exit::OK)
}

async fn remove(json: bool, o: &Overrides, a: RemoveArgs) -> Result<i32, CliError> {
    let name = site_name(&a.site)?;
    let params = [("site", name.as_str())];
    let query = if a.purge { "purge=true" } else { "" };
    if a.dry_run {
        DryRun::new(endpoints::SITES_REMOVE, &params, None)
            .with_query(query)
            .print(json);
        return Ok(exit::OK);
    }
    client(o)?
        .call_empty_query(endpoints::SITES_REMOVE, &params, query)
        .await
        .map_err(|e| match e.kind {
            Kind::NotFound => e.with_hint("declared sites: `weglarka sites list`"),
            Kind::Conflict => e.with_hint("`weglarka sites remove --purge` drops the releases"),
            _ => e,
        })?;
    #[derive(Serialize)]
    struct Removed {
        removed: String,
    }
    emit(
        json,
        &Removed {
            removed: name.to_string(),
        },
        || format!("removed site {name}\n"),
    );
    Ok(exit::OK)
}

/// `weglarka promote <site> <env>`.
pub async fn promote(json: bool, o: &Overrides, a: PromoteArgs) -> Result<i32, CliError> {
    let (site, env) = (site_name(&a.site)?, env_name(&a.env)?);
    let digest = a
        .digest
        .as_deref()
        .map(|d| {
            Digest::new(d).map_err(|e| {
                CliError::usage(e.to_string())
                    .with_hint("`weglarka sites show <site>` lists digests")
            })
        })
        .transpose()?;
    let req = PromoteRequest {
        digest,
        rollback: a.rollback,
        dry_run: a.dry_run,
    };
    let params = [("site", site.as_str()), ("env", env.as_str())];
    let resp: PromoteResponse = client(o)?
        .call(endpoints::SITES_PROMOTE, &params, Some(&req))
        .await
        .map_err(|e| match e.kind {
            Kind::NotFound => e.with_hint("declared sites: `weglarka sites list`"),
            Kind::Conflict => {
                e.with_hint("`weglarka sites show <site>` shows what each environment serves")
            }
            _ => e,
        })?;
    match &resp.deploy {
        Some(deploy) => Ok(report_deploy(json, &resp.instance, deploy)),
        None => {
            emit(json, &resp, || dry_run_text(&site, &env, &resp));
            Ok(exit::OK)
        }
    }
}

fn dry_run_text(site: &SiteName, env: &EnvName, r: &PromoteResponse) -> String {
    let side = |d: &Option<Digest>| d.as_ref().map_or("-", |d| d.as_str()).to_owned();
    let from = r
        .source
        .as_ref()
        .map_or("previous release".to_owned(), |s| {
            format!("{s} serves {}", side(&r.source_current))
        });
    format!(
        "dry run: nothing changed\n\
         {site}/{env} ({}) serves {}\n\
         would serve {} ({from})\n",
        r.instance,
        side(&r.target_current),
        r.digest,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use weglarka_api::SiteEnvSummary;
    use weglarka_core::app::InstanceName;

    #[test]
    fn table_shows_the_source_and_digests_of_each_environment() {
        let d = Digest::new(format!("sha256:{}", "a".repeat(64))).unwrap();
        let sites = vec![SiteSummary {
            name: SiteName::new("blog").unwrap(),
            image: "ghcr.io/me/blog".into(),
            envs: vec![
                SiteEnvSummary {
                    env: env_name("dev").unwrap(),
                    instance: InstanceName::new("blog-dev").unwrap(),
                    track: Some("main".into()),
                    promote_from: None,
                    domains: vec!["dev.example.com".into()],
                    current: Some(d.clone()),
                    previous: None,
                },
                SiteEnvSummary {
                    env: env_name("prod").unwrap(),
                    instance: InstanceName::new("blog-prod").unwrap(),
                    track: None,
                    promote_from: Some(env_name("dev").unwrap()),
                    domains: vec!["example.com".into()],
                    current: None,
                    previous: None,
                },
            ],
        }];
        let t = sites_table(&sites);
        assert!(t.contains("tracks :main"), "{t}");
        assert!(t.contains("promoted from dev"), "{t}");
        assert!(t.contains("sha256:aaaaaaaaaaaa"), "{t}");
        assert!(sites_table(&[]).contains("no sites declared"));
    }

    #[test]
    fn names_are_validated_before_they_reach_a_url() {
        assert!(site_name("Blog").is_err());
        assert!(env_name("pr_1").is_err());
        assert!(site_name("blog").is_ok());
    }
}
