//! `weglarka push` (issue #109, docs/decisions/0042): deploy an image that did not arrive through the
//! webhook — either a reference in the app's registry repository, or an archive built on the
//! operator's machine and streamed in.
//!
//! Both end in the ordinary deploy (health gate, `current`/`previous`/`failed`, rollback), with the
//! digest taken from somewhere other than `spec.image`'s tag. `apps.toml` is never touched: the pin
//! lives in `state.toml` only, so the next webhook for the tag replaces a pushed image.

use crate::deploy::{DeployOutcome, DigestSource, normalize_image};
use crate::reconcile::{EngineError, Reconciler};
use weglarka_model::app::InstanceName;
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
        self.deploy_pushed(instance, DigestSource::Reference(reference))
            .await
    }

    /// Loads the archive in `tar` into the image store and deploys the image it holds.
    ///
    /// The upload runs outside the engine lock — it can be gigabytes, and deploys of other apps must
    /// not wait for it — and only the deploy takes the lock. In the narrow window between the two, a
    /// deploy of another app of the same repository could prune the new image as unused; the deploy
    /// then fails on a pull of `repo@digest` and the push has to be repeated.
    pub async fn push_archive(
        &self,
        instance: &InstanceName,
        tar: TarStream,
    ) -> Result<DeployOutcome, EngineError> {
        let spec = self.load_spec(instance)?;
        let digest = {
            let _slot = self
                .uploads
                .clone()
                .try_acquire_owned()
                .map_err(|_| EngineError::PushBusy)?;
            let loaded = self
                .podman
                .image_load(tar)
                .await
                .map_err(|e| EngineError::PushLoad(e.to_string()))?;
            let digest = loaded.digest.ok_or_else(|| {
                EngineError::PushLoad("podman reports no digest for the loaded image".into())
            })?;
            self.podman
                .image_tag(&loaded.id, image_repo(&spec.image), PUSHED_TAG)
                .await?;
            digest
        };
        self.deploy_pushed(instance, DigestSource::Local(&digest))
            .await
    }

    async fn deploy_pushed(
        &self,
        instance: &InstanceName,
        source: DigestSource<'_>,
    ) -> Result<DeployOutcome, EngineError> {
        let _g = self.lock.lock().await;
        // A promote-only environment changes only through `weglarka promote` (issue #205).
        if state::load_apps(&self.paths.apps)?.is_promote_only(instance) {
            return Err(EngineError::PromoteOnly(instance.clone()));
        }
        let outcome = self.deploy_locked_from(instance, false, source).await?;
        // A manual push is the operator's explicit will: retry a known-bad digest, as `apps deploy`.
        if matches!(outcome, DeployOutcome::KnownBad { .. }) {
            return self.deploy_locked_from(instance, true, source).await;
        }
        Ok(outcome)
    }
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
