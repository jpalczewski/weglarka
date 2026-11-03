//! `weglarka push` (issue #109, docs/decisions/0042): deploy an image that did not arrive through the
//! webhook — either a reference in the app's registry repository, or an archive built on the
//! operator's machine and streamed in.
//!
//! Both end in the ordinary deploy (health gate, `current`/`previous`/`failed`, rollback), with the
//! digest taken from somewhere other than `spec.image`'s tag. `apps.toml` is never touched: the pin
//! lives in `state.toml` only, so the next webhook for the tag replaces a pushed image.
//!
//! An archive upload is an acquisition: it publishes a durable reservation (phase `loading`) before
//! `image_load`, advances it to `loaded` with the loaded ID/digest before `image_tag`, and holds the
//! image guard through the deploy. A disconnect at any point leaves a recoverable reservation instead
//! of a tagged but unrecorded image (contract, "Runtime interfaces and locks").

use crate::deploy::{DeployOutcome, DigestSource, normalize_image};
use crate::images::{ImageGuard, inventory_repository};
use crate::reconcile::{EngineError, Reconciler};
use weglarka_model::app::InstanceName;
use weglarka_model::image_inventory::Owner;
use weglarka_model::podman::{PodmanClient, TarStream, image_repo};
use weglarka_model::state;

/// Tag a pushed image gets in the app's repository, so that `repo@digest` resolves for every source
/// (an archive saved by id has no name at all). It moves to the newest push, like any tag.
pub const PUSHED_TAG: &str = "pushed";

/// A reference must stay in the repository of the app's image: the pin is `repo@digest` and the
/// registry credentials are per instance, so another repository could not be pulled again after a
/// rollback.
fn check_same_repository(spec_image: &str, reference: &str) -> Result<(), EngineError> {
    if reference.is_empty() || reference.contains(char::is_whitespace) {
        return Err(EngineError::PushInvalid(format!(
            "invalid image reference {reference:?}"
        )));
    }
    if normalize_image(reference).0 != normalize_image(spec_image).0 {
        return Err(EngineError::PushInvalid(format!(
            "{reference} is not in the repository of the app's image ({}); push an image of the \
             same repository or change `image` in the spec",
            image_repo(spec_image)
        )));
    }
    Ok(())
}

impl<P: PodmanClient> Reconciler<P> {
    /// Deploys `reference` (a tag or digest of the app's image repository), pulled now.
    pub async fn push_reference(
        &self,
        instance: &InstanceName,
        reference: &str,
    ) -> Result<DeployOutcome, EngineError> {
        let spec = self.load_spec(instance)?;
        check_same_repository(&spec.image, reference)?;
        let outcome = {
            let guard = self.acquire().await;
            self.deploy_pushed_locked(&guard, instance, DigestSource::Reference(reference))
                .await
        };
        if matches!(&outcome, Ok(o) if is_deployed(o)) {
            self.retain_after_deploy(instance, image_repo(&spec.image))
                .await;
        }
        outcome
    }

    /// Loads the archive in `tar` into the image store and deploys the image it holds.
    ///
    /// The upload holds the image/engine guard from the reservation through the deploy. That
    /// serializes it with prune (the first implementation in ADR 0067: acquisition and pruning are
    /// serialized for simplicity) and closes the old tag-before-reservation window.
    pub async fn push_archive(
        &self,
        instance: &InstanceName,
        tar: TarStream,
    ) -> Result<DeployOutcome, EngineError> {
        let spec = self.load_spec(instance)?;
        // One upload at a time bounds the disk and I/O a client can take.
        let _slot = self
            .uploads
            .clone()
            .try_acquire_owned()
            .map_err(|_| EngineError::PushBusy)?;
        let outcome = {
            let guard = self.acquire().await;
            let image_guard = ImageGuard::new(&guard);
            let owner = Owner::App {
                instance: instance.clone(),
            };
            let repository = inventory_repository(&spec.image)?;
            let operation = self
                .begin_acquisition(&image_guard, owner.clone(), repository.clone())
                .await?;

            let loaded = match self.podman.image_load(tar).await {
                Ok(loaded) => loaded,
                Err(e) => {
                    // Nothing was loaded: a failed acquisition releases its reservation.
                    self.finish_acquisition(&image_guard, operation).await;
                    return Err(EngineError::PushLoad(e.to_string()));
                }
            };
            let Some(digest) = loaded.digest else {
                self.finish_acquisition(&image_guard, operation).await;
                return Err(EngineError::PushLoad(
                    "podman reports no digest for the loaded image".into(),
                ));
            };
            // Advance **before** `image_tag`: from here a cancelled upload leaves a `loaded`
            // reservation that protects the image, never a tag without a record.
            self.advance_acquisition(&image_guard, &operation, Some(&loaded.id), &digest)
                .await?;
            let recorded = match self
                .record_acquisition(&image_guard, owner, repository, Some(&loaded.id), &digest)
                .await
            {
                Ok(()) => true,
                Err(e) => {
                    // Keep the reservation: it is the only protection for an image whose provenance
                    // could not be written. The deploy itself is not failed by bookkeeping.
                    tracing::warn!(
                        %instance,
                        error = %e,
                        "cannot record image provenance; image cleanup is disabled for this push"
                    );
                    false
                }
            };
            if let Err(e) = self
                .podman
                .image_tag(&loaded.id, image_repo(&spec.image), PUSHED_TAG)
                .await
            {
                // Keep the loaded reservation: the operation is recoverable and the image protected.
                return Err(e.into());
            }

            let outcome = self
                .deploy_pushed_locked(&guard, instance, DigestSource::Local(&digest))
                .await;
            if recorded {
                self.finish_acquisition(&image_guard, operation).await;
            }
            outcome
        };

        if matches!(&outcome, Ok(o) if is_deployed(o))
            && spec.kind != weglarka_model::app::AppKind::Static
        {
            self.retain_after_deploy(instance, image_repo(&spec.image))
                .await;
        }
        outcome
    }

    /// Deploys under an already held engine/image guard. A manual push is the operator's explicit
    /// will: it retries a digest marked known-bad, like `apps deploy --force`.
    async fn deploy_pushed_locked(
        &self,
        guard: &crate::reconcile::EngineGuard<'_>,
        instance: &InstanceName,
        source: DigestSource<'_>,
    ) -> Result<DeployOutcome, EngineError> {
        // A promote-only environment changes only through `weglarka promote` (issue #205).
        if state::load_apps(&self.paths.apps)?.is_promote_only(instance) {
            return Err(EngineError::PromoteOnly(instance.clone()));
        }
        let outcome = self
            .deploy_locked_from(guard, instance, false, source)
            .await?;
        if matches!(outcome, DeployOutcome::KnownBad { .. }) {
            return self.deploy_locked_from(guard, instance, true, source).await;
        }
        Ok(outcome)
    }
}

fn is_deployed(outcome: &DeployOutcome) -> bool {
    matches!(
        outcome,
        DeployOutcome::Deployed { .. }
            | DeployOutcome::RolledBack { .. }
            | DeployOutcome::Provisioned { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reference_has_to_stay_in_the_apps_repository() {
        let image = "ghcr.io/me/app:latest";
        for ok in [
            "ghcr.io/me/app:sha-1",
            "ghcr.io/me/app",
            "GHCR.io/me/app:x",
            "ghcr.io/me/app@sha256:aaaa",
        ] {
            assert!(check_same_repository(image, ok).is_ok(), "{ok}");
        }
        for bad in [
            "ghcr.io/me/other:latest",
            "docker.io/me/app:latest",
            "",
            "ghcr.io/me/app :x",
        ] {
            assert!(
                matches!(
                    check_same_repository(image, bad),
                    Err(EngineError::PushInvalid(_))
                ),
                "{bad}"
            );
        }
    }
}
