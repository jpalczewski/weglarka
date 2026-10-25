//! Deploy of a `kind = "static"` instance (ADR 0049): pull → export → extract into a release directory →
//! atomic `current` symlink switch. There is no container, no secrets and no health gate; the gate is the
//! release itself (it extracted cleanly and has an `index.html`), so a failed deploy never touches the
//! release that is being served.

use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::Path;

use bytes::Bytes;
use futures_util::StreamExt;

use crate::app::{AppSpec, Digest, InstanceName};
use crate::deploy::{DeployOutcome, DigestSource, pinned_ref};
use crate::events::Event;
use crate::podman::{PodmanClient, TarStream, image_repo};
use crate::reconcile::{ActivityKind, EngineError, Reconciler};
use crate::sites::{ExtractLimits, extract_release};
use crate::state::{self, FailedDeploy, StateFile};

/// Subdirectory of the sites root for exported archives that are being unpacked.
const SCRATCH_DIR: &str = ".tmp";
/// Releases kept per site: the one being served and the previous one (retention 1, like images).
const KEPT_RELEASES: usize = 2;

/// Directory name of a release: the leading hex of its digest.
pub(crate) fn release_id(digest: &Digest) -> String {
    digest
        .as_str()
        .trim_start_matches("sha256:")
        .chars()
        .take(20)
        .collect()
}

impl<P: PodmanClient> Reconciler<P> {
    fn sites_root(&self) -> Result<&Path, EngineError> {
        self.options.sites_root.as_deref().ok_or_else(|| {
            EngineError::Site(
                "static sites need a sites directory; the daemon configures none".into(),
            )
        })
    }

    pub(crate) async fn deploy_static_from(
        &self,
        instance: &InstanceName,
        spec: &AppSpec,
        force: bool,
        source: DigestSource<'_>,
    ) -> Result<DeployOutcome, EngineError> {
        let sites_root = self.sites_root()?.to_owned();
        let _activity = self.begin_activity(instance, ActivityKind::Deploy);
        let mut st: StateFile = state::load_state(&self.paths.state)?;
        let cur = st.apps.get(instance).cloned().unwrap_or_default();

        let digest = match self.digest_from(instance, spec, source).await {
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
        let site_dir = sites_root.join(instance.as_str());
        let id = release_id(&digest);
        if !force {
            if cur.failed.as_ref().is_some_and(|f| f.digest == digest) {
                return Ok(DeployOutcome::KnownBad { digest });
            }
            if cur.current.as_ref() == Some(&digest) && serves(&site_dir, &id) {
                return Ok(DeployOutcome::Unchanged { digest });
            }
        }

        let generation = cur.generation + 1;
        let released = self
            .release(&sites_root, &site_dir, &id, instance, spec, &digest)
            .await;
        let entry = st.apps.entry(instance.clone()).or_default();
        entry.generation = generation;
        if let Err(reason) = released {
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
            .collect();
        state::save_state(&self.paths.state, &st)?;
        self.events.emit(Event::DeployOk {
            instance: instance.clone(),
            digest: digest.clone(),
            generation,
        });
        prune_releases(&site_dir, &keep).await;
        // The files are on disk now; the image only has to stay while it is `current`/`previous`.
        self.retain_images_locked(image_repo(&spec.image)).await;
        Ok(DeployOutcome::Deployed { digest, generation })
    }

    /// Exports the image, unpacks it and switches `current`. `Err` carries the operator-facing reason; the
    /// served release is untouched unless the switch itself succeeded.
    async fn release(
        &self,
        sites_root: &Path,
        site_dir: &Path,
        id: &str,
        instance: &InstanceName,
        spec: &AppSpec,
        digest: &Digest,
    ) -> Result<(), String> {
        let scratch = sites_root.join(SCRATCH_DIR);
        let archive = scratch.join(format!("{instance}-{id}.tar"));
        let result = async {
            let stream = self
                .podman
                .image_save(&pinned_ref(&spec.image, digest))
                .await
                .map_err(|e| format!("cannot export the image: {e}"))?;
            write_archive(&scratch, &archive, stream).await?;
            let releases = site_dir.join("releases");
            let partial = releases.join(format!("{id}.partial"));
            let (a, p, r) = (archive.clone(), partial.clone(), releases.clone());
            tokio::task::spawn_blocking(move || {
                std::fs::create_dir_all(&r).map_err(|e| format!("{}: {e}", r.display()))?;
                // A leftover from a crashed deploy.
                let _ = std::fs::remove_dir_all(&p);
                extract_release(&a, &p, &ExtractLimits::default()).map_err(|e| e.to_string())?;
                if !p.join("index.html").is_file() {
                    let _ = std::fs::remove_dir_all(&p);
                    return Err("the site has no index.html at its root".to_owned());
                }
                Ok(())
            })
            .await
            .map_err(|e| format!("extraction task failed: {e}"))??;
            let (site, id) = (site_dir.to_owned(), id.to_owned());
            tokio::task::spawn_blocking(move || publish(&site, &id))
                .await
                .map_err(|e| format!("switch task failed: {e}"))?
        }
        .await;
        let _ = std::fs::remove_file(&archive);
        result
    }
}

/// Whether `current` already points at a complete release `id`.
fn serves(site_dir: &Path, id: &str) -> bool {
    std::fs::read_link(site_dir.join("current")).is_ok_and(|t| t == Path::new("releases").join(id))
        && site_dir
            .join("releases")
            .join(id)
            .join("index.html")
            .is_file()
}

/// Streams the exported image into a private scratch file: the archive is never held in memory, and a
/// blocking writer keeps the async runtime free.
async fn write_archive(
    scratch: &Path,
    archive: &Path,
    mut stream: TarStream,
) -> Result<(), String> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(4);
    let (dir, file) = (scratch.to_owned(), archive.to_owned());
    let writer = tokio::task::spawn_blocking(move || -> Result<(), String> {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?;
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&file)
            .map_err(|e| format!("{}: {e}", file.display()))?;
        while let Some(chunk) = rx.blocking_recv() {
            out.write_all(&chunk)
                .map_err(|e| format!("{}: {e}", file.display()))?;
        }
        out.flush().map_err(|e| format!("{}: {e}", file.display()))
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
                export = Err(format!("cannot export the image: {e}"));
                break;
            }
        }
    }
    drop(tx);
    let written = writer
        .await
        .map_err(|e| format!("archive writer failed: {e}"))?;
    export.and(written)
}

/// Moves the unpacked `releases/<id>.partial` into place and points `current` at it with one `rename(2)`,
/// so a request sees either the old site or the new one, never a mixture.
fn publish(site_dir: &Path, id: &str) -> Result<(), String> {
    let releases = site_dir.join("releases");
    let (partial, release) = (releases.join(format!("{id}.partial")), releases.join(id));
    if release.join("index.html").is_file() {
        // Same digest deployed again (`--force`): the content is identical, keep what is served.
        let _ = std::fs::remove_dir_all(&partial);
    } else {
        let _ = std::fs::remove_dir_all(&release);
        std::fs::rename(&partial, &release).map_err(|e| format!("{}: {e}", release.display()))?;
    }
    let tmp = site_dir.join("current.tmp");
    let _ = std::fs::remove_file(&tmp);
    std::os::unix::fs::symlink(Path::new("releases").join(id), &tmp)
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, site_dir.join("current"))
        .map_err(|e| format!("{}: {e}", site_dir.join("current").display()))
}

/// Removes every release directory except those in `keep` (and any `.partial` leftovers). Best effort.
async fn prune_releases(site_dir: &Path, keep: &[String]) {
    let (releases, keep) = (site_dir.join("releases"), keep.to_vec());
    let _ = tokio::task::spawn_blocking(move || {
        let Ok(entries) = std::fs::read_dir(&releases) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if keep.len() <= KEPT_RELEASES && !keep.contains(&name) {
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
    })
    .await;
}
