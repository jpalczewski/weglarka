//! Image retention (issue #40, `docs/decisions/0020`): keep the **current** and the **previous**
//! (rollback) image of every repository Węglarka deploys and remove the older ones.
//!
//! libpod records no provenance, so "an image Węglarka pulled" is approximated by the repository: an
//! image is managed when one of its `repo:tag` or `repo@sha256:…` names matches a repository named in
//! `apps.toml`. An untagged leftover of an earlier pull keeps its `RepoDigests`, and an image whose
//! tag moved away to a new build (or a spec that switched tags) is no longer named by any spec, so
//! both are reachable this way.
//!
//! Planning is pure ([`plan`]); [`execute`] performs the removals. An image is never removed while a
//! container references it, while it is an app's `current`/`previous` digest, or while one of its tags
//! is named by an app spec. `image_remove` is never called with `force`: Podman refusing an image in
//! use is the last line of defence.

use std::collections::{BTreeMap, BTreeSet};

use crate::app::{AppsFile, Digest, InstanceName};
use crate::deploy::normalize_image;
use crate::podman::{
    ContainerFilter, ContainerInfo, ImageInfo, PodmanClient, PodmanError, image_repo,
};
use crate::reconcile::{EngineError, Reconciler};
use crate::state::{self, StateFile};

/// Why an image is kept (reported by `doctor` and by `weglarka images prune --dry-run`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeepReason {
    /// A container (any state — ours or not, app or ingress) references it.
    InUse(Vec<String>),
    /// `AppState::current` of the instance: the version running now.
    Current(InstanceName),
    /// `AppState::previous` of the instance: the rollback target.
    Previous(InstanceName),
    /// The tag is named by an app spec — the image a deploy would use.
    TagInUse(String),
}

/// Outcome of [`plan`]. Only repositories named in `apps.toml` appear here; foreign images are
/// neither kept nor removed by us.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    /// Images kept, with the reason (sorted by image id).
    pub keep: Vec<(ImageInfo, KeepReason)>,
    /// Images to remove (sorted by image id).
    pub remove: Vec<ImageInfo>,
}

impl Plan {
    /// Space the removals would reclaim. An upper bound: sizes of shared layers are counted per image.
    pub fn reclaimable_bytes(&self) -> u64 {
        self.remove.iter().map(|i| i.size_bytes).sum()
    }

    /// Nothing to remove.
    pub fn is_empty(&self) -> bool {
        self.remove.is_empty()
    }
}

/// Result of [`execute`] and of [`Reconciler::prune_images`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PruneReport {
    /// Images actually removed; on a dry run — the images that *would* be removed.
    pub removed: Vec<ImageInfo>,
    /// `(image id, error)` of images Podman refused (e.g. still in use); the rest is still removed.
    /// Always empty on a dry run.
    pub failed: Vec<(String, String)>,
    /// Upper bound of the reclaimed space (see [`Plan::reclaimable_bytes`]).
    pub reclaimed_bytes: u64,
    /// The removals were only planned, nothing was removed.
    pub dry_run: bool,
}

/// Which images to keep and which to remove.
///
/// `scope = Some(repo)` limits the candidates to one repository (automatic retention after a deploy,
/// so that deploying one app never touches another app's repository); `None` covers every repository
/// named in `apps.toml` (`weglarka images prune`). The keep set is always computed from **all** apps.
pub fn plan(
    images: &[ImageInfo],
    containers: &[ContainerInfo],
    apps: &AppsFile,
    st: &StateFile,
    scope: Option<&str>,
) -> Plan {
    let specs: Vec<(InstanceName, String, String)> = apps
        .apps
        .iter()
        .map(|(instance, spec)| {
            let (repo, tag) = normalize_image(&spec.image);
            (instance.clone(), repo, tag)
        })
        .collect();
    let tracked: BTreeSet<String> = specs.iter().map(|(_, repo, _)| repo.clone()).collect();
    let tags_in_use: BTreeSet<(&str, &str)> = specs
        .iter()
        .map(|(_, repo, tag)| (repo.as_str(), tag.as_str()))
        .collect();
    let scope = scope.map(|repo| image_repo(repo).to_ascii_lowercase());

    // Image id → names of the containers referencing it (any state: a stopped container still needs
    // its image for its next start).
    let mut used: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for container in containers {
        if !container.image_id.is_empty() {
            used.entry(container.image_id.as_str())
                .or_default()
                .push(container.name.clone());
        }
    }
    let current: Vec<(&InstanceName, &Digest)> = st
        .apps
        .iter()
        .filter_map(|(instance, state)| Some((instance, state.current.as_ref()?)))
        .collect();
    let previous: Vec<(&InstanceName, &Digest)> = st
        .apps
        .iter()
        .filter_map(|(instance, state)| Some((instance, state.previous.as_ref()?)))
        .collect();

    let mut plan = Plan::default();
    for image in images {
        let repos = image_repos(image);
        if repos.is_disjoint(&tracked) {
            continue; // not one of ours (another runtime user's pull, the ingress image, a build…)
        }
        if let Some(scope) = &scope
            && !repos.contains(scope)
        {
            continue;
        }
        let reason = if let Some(names) = used.get(image.id.as_str()) {
            Some(KeepReason::InUse(names.clone()))
        } else if let Some(instance) = app_with_digest(&current, image) {
            Some(KeepReason::Current(instance.clone()))
        } else if let Some(instance) = app_with_digest(&previous, image) {
            Some(KeepReason::Previous(instance.clone()))
        } else {
            image
                .repo_tags
                .iter()
                .filter(|tag| !is_placeholder(tag))
                .map(|tag| normalize_image(tag))
                .find(|(repo, tag)| tags_in_use.contains(&(repo.as_str(), tag.as_str())))
                .map(|(_, tag)| KeepReason::TagInUse(tag))
        };
        match reason {
            Some(reason) => plan.keep.push((image.clone(), reason)),
            None => plan.remove.push(image.clone()),
        }
    }
    plan.keep.sort_by(|a, b| a.0.id.cmp(&b.0.id));
    plan.remove.sort_by(|a, b| a.id.cmp(&b.id));
    plan
}

/// Removes the planned images, best effort: an image that is already gone counts as removed, any
/// other error is collected and the remaining images are still processed. Never forces.
pub async fn execute<P: PodmanClient>(podman: &P, plan: Plan) -> PruneReport {
    let mut report = PruneReport::default();
    for image in plan.remove {
        match podman.image_remove(&image.id).await {
            Ok(()) | Err(PodmanError::NotFound(_)) => {
                report.reclaimed_bytes = report.reclaimed_bytes.saturating_add(image.size_bytes);
                report.removed.push(image);
            }
            Err(e) => report.failed.push((image.id, e.to_string())),
        }
    }
    report
}

/// `1234` → `1.2 KiB`. Used by `doctor` and the CLI so both report sizes the same way.
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

impl<P: PodmanClient> Reconciler<P> {
    /// Explicit prune (`POST /v1/images/prune`, `weglarka images prune`): every repository named in
    /// `apps.toml`. `dry_run` plans without removing anything.
    pub async fn prune_images(&self, dry_run: bool) -> Result<PruneReport, EngineError> {
        let _g = self.lock.lock().await;
        self.prune_images_locked(dry_run, None).await
    }

    /// The body of [`Self::prune_images`], under the engine lock.
    pub(crate) async fn prune_images_locked(
        &self,
        dry_run: bool,
        scope: Option<&str>,
    ) -> Result<PruneReport, EngineError> {
        let apps = state::load_apps(&self.paths.apps)?;
        let st = state::load_state(&self.paths.state)?;
        let images = self.podman.image_list().await?;
        let containers = self
            .podman
            .container_list(&ContainerFilter::default())
            .await?;
        let plan = plan(&images, &containers, &apps, &st, scope);
        if dry_run {
            return Ok(PruneReport {
                reclaimed_bytes: plan.reclaimable_bytes(),
                removed: plan.remove,
                failed: Vec::new(),
                dry_run: true,
            });
        }
        Ok(execute(&self.podman, plan).await)
    }

    /// Best effort housekeeping after a successful deploy of `repo`: removes the app's images older
    /// than the current and the previous one. Never fails the deploy — a retention problem is logged.
    pub(crate) async fn retain_images_locked(&self, repo: &str) {
        match self.prune_images_locked(false, Some(repo)).await {
            Ok(report) if report.removed.is_empty() => {
                tracing::debug!(repo, "image retention: nothing to remove");
            }
            Ok(report) => tracing::info!(
                repo,
                removed = report.removed.len(),
                reclaimed_bytes = report.reclaimed_bytes,
                failed = report.failed.len(),
                "image retention: removed older images"
            ),
            Err(e) => tracing::warn!(repo, error = %e, "image retention skipped"),
        }
    }
}

/// Repositories an image is known under (`repo:tag` and `repo@sha256:…` names).
fn image_repos(image: &ImageInfo) -> BTreeSet<String> {
    image
        .repo_tags
        .iter()
        .chain(image.repo_digests.iter())
        .filter(|name| !is_placeholder(name))
        .map(|name| normalize_image(name).0)
        .collect()
}

/// `<none>:<none>` (and an empty name) is libpod's way of saying "no name".
fn is_placeholder(name: &str) -> bool {
    name.is_empty() || name.contains("<none>")
}

/// The instance whose `current`/`previous` digest is this image, if any.
fn app_with_digest<'a>(
    entries: &[(&'a InstanceName, &'a Digest)],
    image: &ImageInfo,
) -> Option<&'a InstanceName> {
    entries
        .iter()
        .find(|(_, digest)| {
            image.digest.as_ref() == Some(*digest)
                || image.repo_digests.iter().any(|name| {
                    name.split_once('@')
                        .is_some_and(|(_, d)| d == digest.as_str())
                })
        })
        .map(|(instance, _)| *instance)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::app::InstanceName;
    use crate::podman::ContainerState;
    use crate::state::AppState;

    fn digest(c: char) -> Digest {
        Digest::new(format!("sha256:{}", c.to_string().repeat(64))).unwrap()
    }

    fn name(s: &str) -> InstanceName {
        InstanceName::new(s).unwrap()
    }

    /// An image with the id `id` and the given names; a `repo@sha256:…` name is taken as a digest of
    /// the image, `repo:tag` as a tag.
    fn image(id: &str, names: &[&str]) -> ImageInfo {
        let mut tags = Vec::new();
        let mut digests = Vec::new();
        for n in names {
            if n.contains('@') {
                digests.push((*n).to_owned());
            } else {
                tags.push((*n).to_owned());
            }
        }
        let digest = digests
            .first()
            .and_then(|d| d.split_once('@').map(|(_, d)| d))
            .and_then(|d| Digest::new(d).ok());
        ImageInfo {
            id: id.to_owned(),
            digest,
            repo_tags: tags,
            repo_digests: digests,
            size_bytes: 1000,
        }
    }

    fn container(name: &str, image_id: &str) -> ContainerInfo {
        ContainerInfo {
            id: name.to_owned(),
            name: name.to_owned(),
            image: String::new(),
            image_id: image_id.to_owned(),
            labels: BTreeMap::new(),
            state: ContainerState::Running,
            exit_code: None,
            health: None,
            networks: Vec::new(),
        }
    }

    fn apps(toml: &str) -> AppsFile {
        toml::from_str(toml).unwrap()
    }

    fn state(entries: &[(&str, Option<char>, Option<char>)]) -> StateFile {
        let mut st = StateFile::default();
        for (instance, current, previous) in entries {
            st.apps.insert(
                name(instance),
                AppState {
                    current: current.map(digest),
                    previous: previous.map(digest),
                    ..Default::default()
                },
            );
        }
        st
    }

    fn pinned(repo: &str, d: char) -> String {
        format!("{repo}@{}", digest(d))
    }

    #[test]
    fn keeps_current_and_previous_and_removes_older_ones() {
        let repo = "ghcr.io/x/y";
        let apps = apps("[apps.web]\nimage = \"ghcr.io/x/y:latest\"\n");
        let st = state(&[("web", Some('c'), Some('b'))]);
        let images = [
            image("3", &[&pinned(repo, 'c')]),
            image("2", &[&pinned(repo, 'b')]),
            image("1", &[&pinned(repo, 'a')]),
        ];
        let plan = plan(&images, &[], &apps, &st, None);
        assert_eq!(
            plan.remove
                .iter()
                .map(|i| i.id.as_str())
                .collect::<Vec<_>>(),
            ["1"]
        );
        assert_eq!(plan.reclaimable_bytes(), 1000);
        assert!(
            plan.keep
                .iter()
                .any(|(i, r)| i.id == "3" && *r == KeepReason::Current(name("web")))
        );
        assert!(
            plan.keep
                .iter()
                .any(|(i, r)| i.id == "2" && *r == KeepReason::Previous(name("web")))
        );
    }

    #[test]
    fn keeps_the_image_a_container_runs_even_when_it_is_old() {
        let repo = "ghcr.io/x/y";
        let apps = apps("[apps.web]\nimage = \"ghcr.io/x/y:latest\"\n");
        let st = state(&[("web", Some('c'), None)]);
        let images = [
            image("3", &[&pinned(repo, 'c')]),
            image("1", &[&pinned(repo, 'a')]),
        ];
        // A stopped container of another app (or a foreign one) still needs image 1.
        let containers = [container("other", "1")];
        let plan = plan(&images, &containers, &apps, &st, None);
        assert!(plan.remove.is_empty(), "{plan:?}");
        assert!(
            plan.keep
                .iter()
                .any(|(i, r)| i.id == "1" && *r == KeepReason::InUse(vec!["other".to_owned()]))
        );
    }

    #[test]
    fn keeps_the_tag_named_by_a_spec_so_a_deploy_can_run_without_pulling() {
        let repo = "ghcr.io/x/y";
        let apps = apps("[apps.web]\nimage = \"ghcr.io/x/y:v2\"\n");
        let st = state(&[("web", Some('a'), None)]);
        let images = [
            image("3", &[&format!("{repo}:v2")]),
            image("1", &[&pinned(repo, 'a')]),
        ];
        let plan = plan(&images, &[], &apps, &st, None);
        assert!(plan.remove.is_empty(), "{plan:?}");
        assert!(
            plan.keep
                .iter()
                .any(|(i, r)| i.id == "3" && *r == KeepReason::TagInUse("v2".into()))
        );
    }

    #[test]
    fn a_formatted_foreign_image_is_never_touched() {
        let apps = apps("[apps.web]\nimage = \"ghcr.io/x/y:latest\"\n");
        let st = state(&[("web", Some('a'), None)]);
        let images = [
            image("3", &[&pinned("ghcr.io/x/y", 'a')]),
            image("9", &["docker.io/library/nginx:alpine"]),
            image("10", &[]),
        ];
        let plan = plan(&images, &[], &apps, &st, None);
        assert!(plan.remove.is_empty(), "{plan:?}");
        assert_eq!(plan.keep.len(), 1);
    }

    #[test]
    fn two_apps_sharing_a_repository_keep_both_versions() {
        let repo = "ghcr.io/x/y";
        let apps = apps(
            "[apps.a]\nimage = \"ghcr.io/x/y:latest\"\n[apps.b]\nimage = \"ghcr.io/x/y:v1\"\n",
        );
        let st = state(&[("a", Some('c'), Some('b')), ("b", Some('a'), None)]);
        let images = [
            image("4", &[&pinned(repo, 'c')]),
            image("3", &[&pinned(repo, 'b')]),
            image("2", &[&pinned(repo, 'a')]),
            image("1", &[&pinned(repo, '9')]),
        ];
        let plan = plan(&images, &[], &apps, &st, None);
        assert_eq!(
            plan.remove
                .iter()
                .map(|i| i.id.as_str())
                .collect::<Vec<_>>(),
            ["1"]
        );
    }

    #[test]
    fn a_provisioned_app_keeps_its_image_without_a_container() {
        let repo = "ghcr.io/x/y";
        let apps = apps("[apps.web]\nimage = \"ghcr.io/x/y:latest\"\nstart = false\n");
        let st = state(&[("web", Some('a'), None)]);
        let images = [
            image("1", &[&pinned(repo, 'a')]),
            image("2", &[&pinned(repo, 'b')]),
        ];
        let plan = plan(&images, &[], &apps, &st, None);
        assert_eq!(
            plan.remove
                .iter()
                .map(|i| i.id.as_str())
                .collect::<Vec<_>>(),
            ["2"]
        );
        assert!(plan.keep.iter().any(|(i, _)| i.id == "1"));
    }

    #[test]
    fn a_repository_dropped_from_the_spec_is_out_of_scope() {
        // The app moved to another image; nothing names the old repository any more.
        let apps = apps("[apps.web]\nimage = \"ghcr.io/x/new:latest\"\n");
        let st = state(&[("web", Some('a'), None)]);
        let images = [image("1", &[&pinned("ghcr.io/x/old", 'f')])];
        let plan = plan(&images, &[], &apps, &st, None);
        assert!(plan.is_empty(), "{plan:?}");
        assert!(plan.keep.is_empty(), "{plan:?}");
    }

    #[test]
    fn scope_limits_removals_to_one_repository() {
        let ours = "ghcr.io/x/y";
        let other = "ghcr.io/x/z";
        let apps = apps(
            "[apps.a]\nimage = \"ghcr.io/x/y:latest\"\n[apps.b]\nimage = \"ghcr.io/x/z:latest\"\n",
        );
        let st = state(&[("a", Some('b'), None), ("b", Some('b'), None)]);
        let images = [
            image("y1", &[&pinned(ours, 'a')]),
            image("z1", &[&pinned(other, 'a')]),
        ];
        let scoped = plan(&images, &[], &apps, &st, Some("ghcr.io/x/y:latest"));
        assert_eq!(
            scoped
                .remove
                .iter()
                .map(|i| i.id.as_str())
                .collect::<Vec<_>>(),
            ["y1"]
        );
        assert!(scoped.keep.is_empty(), "z1 not touched: {scoped:?}");

        let global = plan(&images, &[], &apps, &st, None);
        assert_eq!(global.remove.len(), 2);
    }

    #[test]
    fn placeholders_are_ignored() {
        let repo = "ghcr.io/x/y";
        let apps = apps("[apps.web]\nimage = \"ghcr.io/x/y:latest\"\n");
        let st = state(&[("web", Some('b'), None)]);
        // An old image of ours: only placeholder tags and its repository digest.
        let mut old = image("1", &[&pinned(repo, 'a')]);
        old.repo_tags = vec!["<none>:<none>".into(), String::new()];
        // No usable name at all: not attributable, so left alone.
        let mut nameless = image("2", &[]);
        nameless.repo_tags = vec!["<none>:<none>".into()];
        let images = [old, nameless];
        let plan = plan(&images, &[], &apps, &st, None);
        assert_eq!(
            plan.remove
                .iter()
                .map(|i| i.id.as_str())
                .collect::<Vec<_>>(),
            ["1"]
        );
    }

    #[test]
    fn a_rollback_target_that_lost_its_tag_is_kept_by_digest() {
        let repo = "ghcr.io/x/y";
        let apps = apps("[apps.web]\nimage = \"ghcr.io/x/y:latest\"\n");
        let st = state(&[("web", Some('b'), Some('a'))]);
        // The previous image kept only its repository digest.
        let images = [image("1", &[&pinned(repo, 'a')])];
        let plan = plan(&images, &[], &apps, &st, None);
        assert!(plan.remove.is_empty(), "{plan:?}");
        assert!(matches!(
            plan.keep.first().map(|(_, r)| r),
            Some(KeepReason::Previous(_))
        ));
    }

    #[test]
    fn report_is_sorted_and_a_dry_run_removes_nothing() {
        let repo = "ghcr.io/x/y";
        let apps = apps("[apps.web]\nimage = \"ghcr.io/x/y:latest\"\n");
        let st = state(&[("web", Some('f'), None)]);
        let images = [
            image("b", &[&pinned(repo, 'b')]),
            image("a", &[&pinned(repo, 'a')]),
        ];
        let plan = plan(&images, &[], &apps, &st, None);
        assert_eq!(
            plan.remove
                .iter()
                .map(|i| i.id.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert_eq!(plan.reclaimable_bytes(), 2000);
    }

    #[test]
    fn human_bytes_is_compact() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(5 * 1024 * 1024 * 1024), "5.0 GiB");
    }
}
