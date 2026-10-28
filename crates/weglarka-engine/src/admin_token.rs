//! The token admin API socket for the `[admin.http] clients` (docs/decisions/0056): the directory
//! that holds the listener's socket is bind-mounted read-only into exactly those instances. A
//! read-only mount is enough — `connect(2)` on a unix socket does not write to its filesystem.
//!
//! The opt-in is host policy (`weglarka.toml`), never an `AppSpec` field, so an app cannot grant
//! itself the API; like the generated config mount it enters the spec hash only for its clients.

use std::collections::BTreeSet;
use std::path::PathBuf;

use weglarka_model::admin_auth::CONTAINER_SOCKET_DIR;
use weglarka_model::app::InstanceName;

use crate::config_mounts::Resolved;
use crate::reconcile::{EngineError, Reconciler};
use weglarka_model::podman::PodmanClient;

/// Which instances get the socket directory, and where it lives on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminTokenMount {
    /// Host directory of the socket (`Paths::admin_token_dir`).
    pub dir: PathBuf,
    pub clients: BTreeSet<InstanceName>,
}

impl<P: PodmanClient> Reconciler<P> {
    pub(crate) fn is_admin_token_client(&self, instance: &InstanceName) -> bool {
        self.options
            .admin_token
            .as_ref()
            .is_some_and(|m| m.clients.contains(instance))
    }

    /// The read-only bind of the socket directory at [`CONTAINER_SOCKET_DIR`] for a client (none for
    /// any other app). The canonical path is what mounts, like every host-side mount (ADR 0028).
    pub(crate) fn admin_token_mounts(
        &self,
        instance: &InstanceName,
    ) -> Result<Vec<Resolved>, EngineError> {
        let Some(mount) = self
            .options
            .admin_token
            .as_ref()
            .filter(|m| m.clients.contains(instance))
        else {
            return Ok(vec![]);
        };
        let source = std::fs::canonicalize(&mount.dir).map_err(|e| {
            EngineError::Configs(format!(
                "admin token socket directory {}: {e} (is [admin.http] served by this daemon?)",
                mount.dir.display()
            ))
        })?;
        Ok(vec![Resolved {
            source,
            target: CONTAINER_SOCKET_DIR.to_owned(),
        }])
    }
}
