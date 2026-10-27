//! `weglarka promote` (issue #205, docs/decisions/0050): move the exact digest one environment of a
//! site runs into another.
//!
//! A promotion is a deploy of the target instance whose digest comes from state instead of from a
//! tag: it goes through the same `DigestSource::Local` path as `weglarka push`, so the release is
//! built from the image that is already in the local store (no second pull) and `current` /
//! `previous` / `failed` behave as for any deploy.

use std::collections::BTreeMap;

use crate::deploy::{DeployOutcome, DigestSource};
use crate::reconcile::{EngineError, Reconciler};
use weglarka_model::app::{AppsFile, Digest, InstanceName};
use weglarka_model::environments::{EnvName, SiteName, SiteSpec, instance_name};
use weglarka_model::podman::PodmanClient;
use weglarka_model::state;

/// Where the digest to promote comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromoteSource {
    /// The `current` digest of the environment named by `promote_from`.
    FromEnv,
    /// An explicit digest of the site's repository.
    Digest(Digest),
    /// The target's own `previous` digest.
    Rollback,
}

/// What a promotion does (or, for `--dry-run`, would do).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotePlan {
    pub target: InstanceName,
    /// The environment the digest comes from (`None` for `--rollback`).
    pub source: Option<InstanceName>,
    /// Digests the source environment and the target serve now.
    pub source_current: Option<Digest>,
    pub target_current: Option<Digest>,
    pub target_previous: Option<Digest>,
    /// The digest the target will serve afterwards.
    pub digest: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromoteReport {
    pub plan: PromotePlan,
    /// `None` for a dry run.
    pub outcome: Option<DeployOutcome>,
}

impl<P: PodmanClient> Reconciler<P> {
    /// Promotes into `site`'s `env`. With `dry_run` only the plan is computed and nothing changes.
    pub async fn promote(
        &self,
        site: &SiteName,
        env: &EnvName,
        source: PromoteSource,
        dry_run: bool,
    ) -> Result<PromoteReport, EngineError> {
        let _g = self.lock.lock().await;
        let apps = state::load_apps(&self.paths.apps)?;
        let label = format!("{site}/{env}");
        let target =
            instance_name(site, env).map_err(|_| EngineError::UnknownSite(label.clone()))?;
        let origin = apps
            .origin(&target)
            .filter(|o| &o.site == site && &o.env == env)
            .ok_or_else(|| EngineError::UnknownSite(label.clone()))?;
        let Some(from_env) = origin.promote_from.clone() else {
            return Err(EngineError::PromoteInvalid(format!(
                "environment {label} tracks a tag and is deployed by the webhook; only a promote_from environment can be promoted into"
            )));
        };
        let source_instance =
            instance_name(site, &from_env).map_err(EngineError::PromoteInvalid)?;
        let spec = apps
            .apps
            .get(&target)
            .ok_or_else(|| EngineError::UnknownInstance(target.clone()))?
            .clone();

        let st = state::load_state(&self.paths.state)?;
        let target_state = st.apps.get(&target).cloned().unwrap_or_default();
        let source_state = st.apps.get(&source_instance).cloned().unwrap_or_default();

        let (digest, from) = match &source {
            PromoteSource::FromEnv => (
                source_state.current.clone().ok_or_else(|| {
                    EngineError::PromoteInvalid(format!(
                        "{site}/{from_env} has no release yet; deploy it first"
                    ))
                })?,
                Some(source_instance.clone()),
            ),
            PromoteSource::Digest(d) => (d.clone(), Some(source_instance.clone())),
            PromoteSource::Rollback => (
                target_state.previous.clone().ok_or_else(|| {
                    EngineError::PromoteInvalid(format!(
                        "{label} has no previous release to return to"
                    ))
                })?,
                None,
            ),
        };
        if !matches!(source, PromoteSource::Rollback)
            && source_state
                .failed
                .as_ref()
                .is_some_and(|f| f.digest == digest)
        {
            return Err(EngineError::PromoteRefused(format!(
                "{digest} failed to deploy in {site}/{from_env}; fix it there first"
            )));
        }
        let plan = PromotePlan {
            target: target.clone(),
            source: from,
            source_current: source_state.current.clone(),
            target_current: target_state.current.clone(),
            target_previous: target_state.previous.clone(),
            digest: digest.clone(),
        };
        if dry_run {
            return Ok(PromoteReport {
                plan,
                outcome: None,
            });
        }

        // The image is normally local already (it is `current` or `previous` somewhere); only an
        // explicit digest of a pruned release pulls, with the target's registry credentials.
        self.ensure_image(&target, &spec, &digest, None).await?;
        let mut outcome = self
            .deploy_locked_from(&target, false, DigestSource::Local(&digest))
            .await?;
        // An explicit promotion is the operator's will: retry a digest that failed here before.
        if matches!(outcome, DeployOutcome::KnownBad { .. }) {
            outcome = self
                .deploy_locked_from(&target, true, DigestSource::Local(&digest))
                .await?;
        }
        Ok(PromoteReport {
            plan,
            outcome: Some(outcome),
        })
    }
}

/// Refuses to edit an instance that a site owns: the edit would be lost, because expanded instances
/// are never written back to `apps.toml`.
pub(crate) fn ensure_unmanaged(apps: &AppsFile, name: &InstanceName) -> Result<(), EngineError> {
    match apps.origin(name) {
        Some(o) => Err(EngineError::ManagedBySite {
            instance: name.clone(),
            site: o.site.to_string(),
        }),
        None => Ok(()),
    }
}

impl<P: PodmanClient> Reconciler<P> {
    /// Declares or replaces `site` (`PUT /v1/sites/{site}`). Environments that disappear from a
    /// replaced site are dropped from the desired state like a removed app (their releases and state
    /// entries stay until pruned, as for `apps remove`).
    pub async fn declare_site(&self, site: SiteName, spec: SiteSpec) -> Result<(), EngineError> {
        let _g = self.lock.lock().await;
        let mut apps = state::load_apps(&self.paths.apps)?;
        let mut sites: BTreeMap<SiteName, SiteSpec> = apps.sites.clone();
        sites.insert(site, spec);
        apps.set_sites(sites).map_err(EngineError::PromoteInvalid)?;
        for (name, spec) in &apps.apps {
            state::validate_app(name, spec).map_err(EngineError::PromoteInvalid)?;
        }
        weglarka_model::depends::validate(&apps).map_err(EngineError::PromoteInvalid)?;
        Ok(state::save_apps(&self.paths.apps, &apps)?)
    }

    /// Removes `site` (`DELETE /v1/sites/{site}`). Refused while any of its environments has a release
    /// unless `purge`, which also forgets their state entries.
    pub async fn remove_site(&self, site: &SiteName, purge: bool) -> Result<(), EngineError> {
        let _g = self.lock.lock().await;
        let mut apps = state::load_apps(&self.paths.apps)?;
        if !apps.sites.contains_key(site) {
            return Err(EngineError::UnknownSite(site.to_string()));
        }
        let members: Vec<InstanceName> = apps
            .origins
            .iter()
            .filter(|(_, o)| &o.site == site)
            .map(|(n, _)| n.clone())
            .collect();
        let mut st = state::load_state(&self.paths.state)?;
        let pinned: Vec<String> = members
            .iter()
            .filter(|n| st.apps.get(*n).is_some_and(|s| s.current.is_some()))
            .map(ToString::to_string)
            .collect();
        if !pinned.is_empty() && !purge {
            return Err(EngineError::PromoteRefused(format!(
                "site {site} still serves releases in {}; remove it with --purge to drop them",
                pinned.join(", ")
            )));
        }
        let mut sites = apps.sites.clone();
        sites.remove(site);
        apps.set_sites(sites).map_err(EngineError::PromoteInvalid)?;
        weglarka_model::depends::validate(&apps).map_err(EngineError::PromoteInvalid)?;
        state::save_apps(&self.paths.apps, &apps)?;
        if purge {
            let mut changed = false;
            for n in &members {
                changed |= st.apps.remove(n).is_some();
            }
            if changed {
                state::save_state(&self.paths.state, &st)?;
            }
        }
        Ok(())
    }
}
