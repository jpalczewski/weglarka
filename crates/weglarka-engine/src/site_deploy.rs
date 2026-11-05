//! Deploy of a `kind = "static"` instance (ADR 0049): pull → export → extract into a release directory →
//! atomic `current` symlink switch. There is no container, no secrets and no health gate; the gate is the
//! release itself (it extracted cleanly and has the files its gate names), so a failed deploy never
//! touches the release that is being served.

use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::Path;

use bytes::Bytes;
use futures_util::StreamExt;

use crate::deploy::{AcquisitionSlot, DeployOutcome, DigestSource, pinned_ref};
use crate::images::ImageGuard;
use crate::reconcile::{ActivityKind, EngineError, Reconciler, SitesOptions};
use crate::sites::{ReleaseError, ReleaseGate, SiteReleases, extract_release, release_id};
use weglarka_model::app::{AppKind, AppSpec, Digest, InstanceName};
use weglarka_model::events::Event;
use weglarka_model::podman::{PodmanClient, TarStream};
use weglarka_model::state::{self, FailedDeploy, StateFile};

/// Releases kept per site: the one being served and the previous one (retention 1, like images).
const KEPT_RELEASES: usize = 2;

/// What `weglarka apps rollback` did (issue #103): the site now serves `to` instead of `from`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackReport {
    /// The digest `current` pointed at before the rollback.
    pub from: Digest,
    /// The digest `current` points at afterwards (`state.toml`'s `previous`).
    pub to: Digest,
    /// The release for `to` was complete on disk, so only `current` moved: no image was exported.
    pub reused_release: bool,
}

impl<P: PodmanClient> Reconciler<P> {
    /// Whether `digest`'s release of the static site `instance` is complete on disk, so deploying it
    /// only switches `current` and needs neither the local image nor the registry (ADR 0049).
    pub(crate) fn has_complete_release(
        &self,
        instance: &InstanceName,
        spec: &AppSpec,
        digest: &Digest,
    ) -> bool {
        spec.kind == AppKind::Static
            && self.options.sites.as_ref().is_some_and(|sites| {
                SiteReleases::new(sites.root.join(instance.as_str()))
                    .is_complete(&release_id(digest), &ReleaseGate::for_spec(spec))
            })
    }

    fn sites(&self) -> Result<&SitesOptions, EngineError> {
        self.options.sites.as_ref().ok_or_else(|| {
            EngineError::Site(
                "static sites need a sites root and a scratch directory; the daemon configures none"
                    .into(),
            )
        })
    }

    /// `weglarka apps rollback` (issue #103, ADR 0049): return a static site to its `previous` release.
    ///
    /// A complete release for `previous` is switched without touching the image store or the registry;
    /// otherwise the image is ensured locally (pulled only when it is gone) and the release is
    /// extracted again. The digest that is left becomes `failed`, so a webhook redelivery or a plain
    /// deploy does not immediately undo the rollback — `weglarka deploy <app> --force` moves forward.
    pub async fn rollback_site(
        &self,
        instance: &InstanceName,
    ) -> Result<RollbackReport, EngineError> {
        let guard = self.acquire().await;
        let apps = state::load_apps(&self.paths.apps)?;
        let spec = apps
            .apps
            .get(instance)
            .cloned()
            .ok_or_else(|| EngineError::UnknownInstance(instance.clone()))?;
        if spec.kind != AppKind::Static {
            return Err(EngineError::RollbackUnsupported(format!(
                "{instance} is not a static site: container apps roll back automatically when the health gate fails, or manually with `weglarka apps update {instance} <image>:<tag>` (see docs/guides/verify-and-rollback.md)"
            )));
        }
        if let Some(origin) = apps.origin(instance) {
            return Err(EngineError::RollbackUnsupported(format!(
                "{instance} is managed by site {site}, environment {env}; roll it back with `weglarka promote {site} {env} --rollback`",
                site = origin.site,
                env = origin.env,
            )));
        }

        let st = state::load_state(&self.paths.state)?;
        let cur = st.apps.get(instance).cloned().unwrap_or_default();
        let previous = cur.previous.clone().ok_or_else(|| {
            EngineError::RollbackRefused(format!("{instance} has no previous release to return to"))
        })?;
        let from = cur.current.clone().ok_or_else(|| {
            EngineError::RollbackRefused(format!(
                "{instance} has no current release to roll back from"
            ))
        })?;
        let gate = ReleaseGate::for_spec(&spec);
        let releases = SiteReleases::new(self.sites()?.root.join(instance.as_str()));
        let reused_release = releases.is_complete(&release_id(&previous), &gate);

        // Same guard/slot/retention sequence as `promote`: `ensure_image` only matters when the
        // release has to be built again, and the deploy itself reuses a complete release.
        let image_guard = ImageGuard::new(&guard);
        let mut slot = AcquisitionSlot::default();
        let result = async {
            if !reused_release {
                self.ensure_image(&image_guard, instance, &spec, &previous, None, &mut slot)
                    .await?;
            }
            self.deploy_locked_from(&guard, instance, true, DigestSource::Local(&previous))
                .await
        }
        .await;
        slot.finish(self, &image_guard).await;
        let outcome = result?;
        self.retain_for_outcome(Some(&guard), instance, &outcome)
            .await;
        if let DeployOutcome::Failed { reason, .. } = &outcome {
            return Err(EngineError::RollbackFailed(format!(
                "cannot roll back {instance} to {previous}: {reason}"
            )));
        }

        // The tag still points at `from`: without this a webhook redelivery or a plain deploy would
        // undo the rollback at once. `failed` is skipped as `KnownBad` unless forced, while a newly
        // pushed digest is not marked and deploys normally.
        let mut st: StateFile = state::load_state(&self.paths.state)?;
        st.apps.entry(instance.clone()).or_default().failed = Some(FailedDeploy {
            digest: from.clone(),
            reason: "rolled back by the operator".into(),
        });
        state::save_state(&self.paths.state, &st)?;
        Ok(RollbackReport {
            from,
            to: previous,
            reused_release,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn deploy_static_from(
        &self,
        image_guard: &ImageGuard<'_>,
        instance: &InstanceName,
        spec: &AppSpec,
        force: bool,
        source: DigestSource<'_>,
        slot: &mut AcquisitionSlot,
    ) -> Result<DeployOutcome, EngineError> {
        let sites = self.sites()?.clone();
        // Older versions kept the exported archive under the nginx-mounted sites root; a deploy is
        // the first chance to remove that leftover when the daemon was not restarted after upgrading.
        let _ = std::fs::remove_dir_all(sites.root.join(".tmp"));
        let _activity = self.begin_activity(instance, ActivityKind::Deploy);
        let mut st: StateFile = state::load_state(&self.paths.state)?;
        let cur = st.apps.get(instance).cloned().unwrap_or_default();

        let digest = match self
            .digest_from(image_guard, instance, spec, source, slot)
            .await
        {
            Ok(d) => d,
            Err(e) => {
                self.events.emit(Event::DeployFailed {
                    instance: instance.clone(),
                    digest: None,
                    reason: e.to_string(),
                });
                return Err(e);
            }
        };
        let site_dir = sites.root.join(instance.as_str());
        let releases = SiteReleases::new(site_dir.clone());
        let gate = ReleaseGate::for_spec(spec);
        let id = release_id(&digest);
        if !force {
            if cur.failed.as_ref().is_some_and(|f| f.digest == digest) {
                return Ok(DeployOutcome::KnownBad { digest });
            }
            if cur.current.as_ref() == Some(&digest) && releases.serves(&id, &gate) {
                return Ok(DeployOutcome::Unchanged { digest });
            }
        }

        let generation = cur.generation + 1;
        let released = self
            .release(&sites, &site_dir, &id, instance, spec, &digest)
            .await;
        let entry = st.apps.entry(instance.clone()).or_default();
        entry.generation = generation;
        if let Err(reason) = released {
            let reason = reason.to_string();
            entry.failed = Some(FailedDeploy {
                digest: digest.clone(),
                reason: reason.clone(),
            });
            state::save_state(&self.paths.state, &st)?;
            self.events.emit(Event::DeployFailed {
                instance: instance.clone(),
                digest: Some(digest.clone()),
                reason: reason.clone(),
            });
            return Ok(DeployOutcome::Failed { digest, reason });
        }
        if cur.current.as_ref() != Some(&digest) {
            entry.previous = cur.current.clone().or(cur.previous.clone());
        }
        entry.current = Some(digest.clone());
        entry.failed = None;
        let keep: Vec<String> = [entry.current.as_ref(), entry.previous.as_ref()]
            .into_iter()
            .flatten()
            .map(release_id)
            .take(KEPT_RELEASES)
            .collect();
        state::save_state(&self.paths.state, &st)?;
        self.events.emit(Event::DeployOk {
            instance: instance.clone(),
            digest: digest.clone(),
            generation,
        });
        let _ = tokio::task::spawn_blocking(move || releases.prune(&keep)).await;
        Ok(DeployOutcome::Deployed { digest, generation })
    }

    /// Exports the image, unpacks it and switches `current`. `Err` carries the operator-facing reason; the
    /// served release is untouched unless the switch itself succeeded.
    ///
    /// A complete release for `id` is reused as-is: redeploying a retained release (the previous one, or
    /// a rollback) needs neither the image store nor the registry.
    async fn release(
        &self,
        sites: &SitesOptions,
        site_dir: &Path,
        id: &str,
        instance: &InstanceName,
        spec: &AppSpec,
        digest: &Digest,
    ) -> Result<(), ReleaseError> {
        let releases = SiteReleases::new(site_dir.to_owned());
        let gate = ReleaseGate::for_spec(spec);
        if releases.is_complete(id, &gate) {
            let (releases, id) = (releases, id.to_owned());
            return tokio::task::spawn_blocking(move || releases.switch_to(&id, &gate))
                .await
                .map_err(|source| ReleaseError::Blocking {
                    context: "switch task",
                    source,
                })?;
        }

        let scratch = sites.scratch.clone();
        let archive = scratch.join(format!("{instance}-{id}.tar"));
        let result = async {
            let stream = self
                .podman
                .image_save(&pinned_ref(&spec.image, digest))
                .await
                .map_err(|e| ReleaseError::Export(e.to_string()))?;
            write_archive(&scratch, &archive, stream).await?;
            let (a, extract_store, check_gate, extract_id, limits) = (
                archive.clone(),
                releases.clone(),
                gate.clone(),
                id.to_owned(),
                sites.limits,
            );
            tokio::task::spawn_blocking(move || {
                let releases_dir = extract_store.releases_dir();
                std::fs::create_dir_all(&releases_dir).map_err(|source| ReleaseError::Io {
                    path: releases_dir.clone(),
                    source,
                })?;
                let partial = extract_store.partial_dir(&extract_id);
                // A leftover from a crashed deploy.
                let _ = std::fs::remove_dir_all(&partial);
                extract_release(&a, &partial, &limits)?;
                if let Err(e) = check_gate.check(&partial) {
                    let _ = std::fs::remove_dir_all(&partial);
                    return Err(e);
                }
                Ok(())
            })
            .await
            .map_err(|source| ReleaseError::Blocking {
                context: "extraction task",
                source,
            })??;
            let (publish_store, publish_id) = (releases, id.to_owned());
            tokio::task::spawn_blocking(move || publish_store.publish(&publish_id, &gate))
                .await
                .map_err(|source| ReleaseError::Blocking {
                    context: "switch task",
                    source,
                })?
        }
        .await;
        let _ = std::fs::remove_file(&archive);
        result
    }
}

/// Streams the exported image into a private scratch file: the archive is never held in memory, and a
/// blocking writer keeps the async runtime free.
async fn write_archive(
    scratch: &Path,
    archive: &Path,
    mut stream: TarStream,
) -> Result<(), ReleaseError> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(4);
    let (dir, file) = (scratch.to_owned(), archive.to_owned());
    let writer = tokio::task::spawn_blocking(move || -> Result<(), ReleaseError> {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .map_err(|source| ReleaseError::Io {
                path: dir.clone(),
                source,
            })?;
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&file)
            .map_err(|source| ReleaseError::Io {
                path: file.clone(),
                source,
            })?;
        while let Some(chunk) = rx.blocking_recv() {
            out.write_all(&chunk).map_err(|source| ReleaseError::Io {
                path: file.clone(),
                source,
            })?;
        }
        out.flush()
            .map_err(|source| ReleaseError::Io { path: file, source })
    });
    let mut export = Ok(());
    while let Some(chunk) = stream.next().await {
        match chunk {
            // A closed channel means the writer failed; its error is reported below.
            Ok(bytes) => {
                if tx.send(bytes).await.is_err() {
                    break;
                }
            }
            Err(e) => {
                export = Err(ReleaseError::Export(e.to_string()));
                break;
            }
        }
    }
    drop(tx);
    let written = writer.await.map_err(|source| ReleaseError::Blocking {
        context: "archive writer",
        source,
    })?;
    export.and(written)
}
