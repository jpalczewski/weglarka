//! Shared networks at run time (issue #128, `docs/decisions/0030-shared-networks.md`): declaring and
//! removing the declaration. The pure desired-state checks and lookups live in
//! [`weglarka_model::shared_networks`]; creating the Podman network is in [`crate::deploy`] (it needs
//! the engine lock and Podman).

use weglarka_model::app::SharedNetworkName;
use weglarka_model::labels;
use weglarka_model::podman::PodmanClient;
use weglarka_model::shared_networks::members;
use weglarka_model::state;

use crate::reconcile::{EngineError, Reconciler};

impl<P: PodmanClient> Reconciler<P> {
    /// Declares a shared network (idempotent, issue #128). Apps join it through `shared_networks`;
    /// the Podman network is created lazily by the first member's deploy.
    pub async fn declare_shared_network(&self, name: SharedNetworkName) -> Result<(), EngineError> {
        let _guard = self.acquire().await;
        let mut apps = state::load_apps(&self.paths.apps)?;
        if apps.shared_networks.contains_key(&name) {
            return Ok(());
        }
        apps.shared_networks.insert(name, Default::default());
        Ok(state::save_apps(&self.paths.apps, &apps)?)
    }

    /// Removes a shared network declaration (issue #128). Refused while any app joins it. The
    /// Podman network goes with it when nothing is attached; otherwise reconcile removes the empty
    /// network once the last container is gone (best effort, like per-app networks).
    pub async fn remove_shared_network(&self, name: &SharedNetworkName) -> Result<(), EngineError> {
        let _guard = self.acquire().await;
        let mut apps = state::load_apps(&self.paths.apps)?;
        if !apps.shared_networks.contains_key(name) {
            return Err(EngineError::UnknownSharedNetwork(name.clone()));
        }
        let members = members(&apps, name);
        if !members.is_empty() {
            return Err(EngineError::SharedNetworkInUse {
                network: name.clone(),
                members: members
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
            });
        }
        apps.shared_networks.remove(name);
        state::save_apps(&self.paths.apps, &apps)?;
        // Best effort and idempotent: a network still attached (a stopped member that was removed
        // from the spec but whose container lingers) is picked up by `prune_networks` later.
        if let Err(e) = self
            .podman
            .network_remove(&labels::shared_network_name(name))
            .await
        {
            tracing::debug!(network = %name, error = %e, "shared network not removed yet");
        }
        Ok(())
    }
}
