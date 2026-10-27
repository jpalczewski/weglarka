//! "Waiting for secret" (iteration 2, session 3): a spec that binds secrets which are not set yet is
//! not an error. The deploy is not attempted; the missing names are recorded in
//! `AppState::waiting_for_secrets` and the next reconcile (triggered by `secrets set`) deploys.

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::reconcile::{EngineError, Reconciler};
use crate::secrets::blocking;
use weglarka_model::app::{AppSpec, InstanceName};
use weglarka_model::events::Event;
use weglarka_model::podman::PodmanClient;
use weglarka_model::secret_store::{SecretStore, scoped_name};
use weglarka_model::state::{self, StateFile};

/// Secret names (binding names, as passed to `secrets set`) the spec binds but the store lacks.
/// Sorted and deduplicated.
pub(crate) async fn missing_secrets(
    store: &Arc<dyn SecretStore>,
    instance: &InstanceName,
    spec: &AppSpec,
) -> Result<Vec<String>, EngineError> {
    if spec.secrets.is_empty() {
        return Ok(vec![]);
    }
    let have: BTreeSet<String> = blocking(store, |s| s.list())
        .await?
        .into_iter()
        .map(|m| m.name)
        .collect();
    let missing: BTreeSet<String> = spec
        .secrets
        .iter()
        .filter(|b| !have.contains(&scoped_name(instance, &b.secret)))
        .map(|b| b.secret.clone())
        .collect();
    Ok(missing.into_iter().collect())
}

/// Records `missing` in the instance's state entry. Returns `true` when the state changed.
/// Creates an entry only when there is something to record.
pub(crate) fn apply_waiting(
    st: &mut StateFile,
    instance: &InstanceName,
    missing: &[String],
) -> bool {
    match st.apps.get_mut(instance) {
        Some(entry) if entry.waiting_for_secrets != missing => {
            entry.waiting_for_secrets = missing.to_vec();
            true
        }
        Some(_) => false,
        None if missing.is_empty() => false,
        None => {
            st.apps
                .entry(instance.clone())
                .or_default()
                .waiting_for_secrets = missing.to_vec();
            true
        }
    }
}

impl<P: PodmanClient> Reconciler<P> {
    /// Gate in front of a deploy (under `lock`): fails with [`EngineError::MissingSecrets`] after
    /// recording the wait; clears a stale wait when everything is set.
    pub(crate) async fn secrets_gate(
        &self,
        instance: &InstanceName,
        spec: &AppSpec,
        st: &mut StateFile,
    ) -> Result<(), EngineError> {
        let missing = missing_secrets(&self.secrets, instance, spec).await?;
        if apply_waiting(st, instance, &missing) {
            state::save_state(&self.paths.state, st)?;
            if !missing.is_empty() {
                self.events.emit(Event::WaitingForSecret {
                    instance: instance.clone(),
                    missing: missing.clone(),
                });
            }
        }
        if missing.is_empty() {
            Ok(())
        } else {
            Err(EngineError::MissingSecrets(missing))
        }
    }
}
