//! The identity integration's desired-state operations (#91): external OIDC clients in `apps.toml`
//! and rotation of an app's client secret. Rendering and applying the provider's files is the
//! generated config pipeline ([`crate::generated`]); this module only changes inputs.

use weglarka_model::app::InstanceName;
use weglarka_model::identity::{ClientId, ExternalClientSpec};
use weglarka_model::podman::PodmanClient;
use weglarka_model::state;

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

    /// Replaces the client secret (and its digest) of `instance`. The caller then applies the
    /// provider's files and recreates the app — in that order, or the app holds a stale secret
    /// while the provider still knows the old digest (a window the guide documents).
    pub async fn rotate_oidc_secret(&self, instance: &InstanceName) -> Result<(), EngineError> {
        let _guard = self.acquire().await;
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
        let instance = instance.clone();
        crate::secrets::blocking(&self.secrets, move |store| {
            crate::oidc_credentials::rotate(store, &instance).map(drop)
        })
        .await
    }
}
