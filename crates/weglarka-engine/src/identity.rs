//! The identity integration's desired-state operations (#91): external OIDC clients in `apps.toml`
//! and rotation of an app's client secret. Rendering and applying the provider's files is the
//! generated config pipeline ([`crate::generated`]); this module only changes inputs.

use std::sync::Arc;

use weglarka_model::app::{AppsFile, InstanceName};
use weglarka_model::identity::{ClientId, ExternalClientSpec};
use weglarka_model::podman::PodmanClient;
use weglarka_model::state;

use crate::generated::{GeneratedOutcome, GeneratedWiring};
use crate::oidc_credentials;
use crate::reconcile::{EngineError, Reconciler};

impl<P: PodmanClient> Reconciler<P> {
    /// Adds or replaces `[oidc_clients.<id>]`. The file rules (lexical checks, the id not equal to
    /// an instance) run on save.
    pub async fn set_oidc_client(
        &self,
        id: ClientId,
        spec: ExternalClientSpec,
    ) -> Result<(), EngineError> {
        let _guard = self.acquire().await;
        if self.identity.is_none() {
            return Err(EngineError::IdentityInvalid(
                "`[oidc_clients]` needs an `[identity]` section in weglarka.toml".to_owned(),
            ));
        }
        let mut apps = state::load_apps(&self.paths.apps)?;
        apps.oidc_clients.insert(id, spec);
        state::save_apps(&self.paths.apps, &apps)
            .map_err(|e| EngineError::IdentityInvalid(e.to_string()))
    }

    /// Removes `[oidc_clients.<id>]`; the provider loses the client at the next apply.
    pub async fn remove_oidc_client(&self, id: &ClientId) -> Result<(), EngineError> {
        let _guard = self.acquire().await;
        let mut apps = state::load_apps(&self.paths.apps)?;
        if apps.oidc_clients.remove(id).is_none() {
            return Err(EngineError::UnknownOidcClient(id.to_string()));
        }
        Ok(state::save_apps(&self.paths.apps, &apps)?)
    }

    /// Rotates the client secret (and its digest) of `instance` without ever leaving the app and the
    /// provider disagreeing about the live pair: the new pair is staged under a pending name, the
    /// provider's files are rendered with the pending digest and applied, and only a successful
    /// apply promotes the pair to the live name. A failure discards it, so nothing changed. The
    /// whole sequence holds the engine lock, so no reconcile pass renders the old digest in between.
    /// The caller then recreates the app, which mounts the new secret.
    pub async fn rotate_oidc_secret(
        self: &Arc<Self>,
        instance: &InstanceName,
        wiring: Option<&GeneratedWiring>,
    ) -> Result<(), EngineError> {
        let guard = self.acquire().await;
        let apps = state::load_apps(&self.paths.apps)?;
        let spec = apps
            .apps
            .get(instance)
            .ok_or_else(|| EngineError::UnknownInstance(instance.clone()))?;
        if self.identity.is_none() {
            return Err(EngineError::IdentityInvalid(
                "`oidc` needs an `[identity]` section in weglarka.toml".to_owned(),
            ));
        }
        if !spec.oidc.as_ref().is_some_and(|oidc| !oidc.public) {
            return Err(EngineError::IdentityInvalid(format!(
                "{instance} has no confidential OIDC client to rotate"
            )));
        }
        let name = instance.clone();
        let staged = crate::secrets::blocking(&self.secrets, move |store| {
            oidc_credentials::stage_rotation(store, &name)
        })
        .await?;

        let applied = match wiring {
            Some(wiring) => {
                let (base, owner, staged) =
                    (wiring.digests.clone(), instance.clone(), staged.clone());
                let digests = move |apps: &AppsFile| {
                    let mut digests = base(apps);
                    digests.insert(owner.clone(), staged.clone());
                    digests
                };
                let mut result = Ok(());
                for generator in &wiring.generators {
                    let outcome = self
                        .apply_generated_locked(&guard, &**generator, &digests, true)
                        .await;
                    // Invalid and rolled-back renders are outcomes, not errors: the provider still
                    // runs the old files, so for a rotation they are failures all the same.
                    let failure = match outcome {
                        Ok(GeneratedOutcome::Applied { .. } | GeneratedOutcome::Unchanged) => {
                            continue;
                        }
                        Ok(GeneratedOutcome::Invalid { output }) => {
                            format!("the provider rejected the new config: {output}")
                        }
                        Ok(GeneratedOutcome::RolledBack { reason, .. }) => {
                            format!("the provider was unhealthy on the new config: {reason}")
                        }
                        Ok(GeneratedOutcome::Skipped { .. }) => {
                            "the provider config was not applied".to_owned()
                        }
                        Err(e) => {
                            result = Err(e);
                            break;
                        }
                    };
                    result = Err(EngineError::Generated {
                        consumer: generator.consumer().clone(),
                        message: failure,
                    });
                    break;
                }
                result
            }
            None => Ok(()),
        };

        let name = instance.clone();
        match applied {
            Ok(()) => {
                crate::secrets::blocking(&self.secrets, move |store| {
                    oidc_credentials::promote_rotation(store, &name)
                })
                .await
            }
            Err(e) => {
                // Best effort: a pending pair that stays is overwritten by the next rotation.
                let _ = crate::secrets::blocking(&self.secrets, move |store| {
                    oidc_credentials::discard_rotation(store, &name)
                })
                .await;
                Err(e)
            }
        }
    }
}
