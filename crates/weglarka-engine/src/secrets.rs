//! Delivering secrets to containers: the `Arc<dyn SecretStore>` helpers the engine uses off the async
//! thread, and Podman secrets (types `env` and `mount`). The file-backed store itself is
//! [`weglarka_model::secrets::FileSecretStore`]. Values never reach logs or `Debug`.

use std::collections::BTreeMap;
use std::sync::Arc;

use weglarka_model::app::{AppSpec, InstanceName};
use weglarka_model::podman::{PodmanClient, RegistryAuth, SecretAttachment};
use weglarka_model::secret_store::{
    REGISTRY_AUTH_SECRET, SecretError, SecretStore, scoped_name, split_scoped,
};

use crate::reconcile::EngineError;

/// Calls the synchronous `SecretStore` off the async thread (ADR 0001).
pub(crate) async fn blocking<T: Send + 'static>(
    store: &Arc<dyn SecretStore>,
    f: impl FnOnce(&dyn SecretStore) -> Result<T, SecretError> + Send + 'static,
) -> Result<T, EngineError> {
    let store = Arc::clone(store);
    tokio::task::spawn_blocking(move || f(store.as_ref()))
        .await
        .map_err(|e| SecretError::Io(e.to_string()))?
        .map_err(EngineError::from)
}

/// Instance secret fingerprints as `binding name → fingerprint` (for `spec_hash`).
/// A missing secret = [`SecretError::NotFound`].
pub(crate) async fn binding_fingerprints(
    store: &Arc<dyn SecretStore>,
    instance: &InstanceName,
    spec: &AppSpec,
) -> Result<BTreeMap<String, String>, EngineError> {
    if spec.secrets.is_empty() {
        return Ok(BTreeMap::new());
    }
    let all = blocking(store, |s| s.list()).await?;
    let mut out = BTreeMap::new();
    for b in &spec.secrets {
        let scoped = scoped_name(instance, &b.secret);
        let meta = all
            .iter()
            .find(|m| m.name == scoped)
            .ok_or(SecretError::NotFound(scoped))?;
        out.insert(b.secret.clone(), meta.fingerprint.clone());
    }
    Ok(out)
}

/// Registry credentials for `instance`'s image pulls: the reserved `<instance>.registry-auth`
/// secret (`<username>:<password>`), `None` when it is not set (anonymous pull / `auth.json`).
/// A malformed value is [`SecretError::Malformed`] — a pull must not silently fall back to anonymous.
pub(crate) async fn registry_auth(
    store: &Arc<dyn SecretStore>,
    instance: &InstanceName,
) -> Result<Option<RegistryAuth>, EngineError> {
    let scoped = scoped_name(instance, REGISTRY_AUTH_SECRET);
    let key = scoped.clone();
    let Some(value) = blocking(store, move |s| s.get(&key)).await? else {
        return Ok(None);
    };
    RegistryAuth::parse(value.expose())
        .map(Some)
        .ok_or_else(|| {
            SecretError::Malformed {
                name: scoped,
                reason: "expected <username>:<password>",
            }
            .into()
        })
}

/// Removes every secret of `instance` from the store — the whole `<instance>.*` scope (issue #80:
/// `apps remove --purge-secrets`). Returns the removed scoped names; a missing entry is tolerated
/// (the store is the single writer, but a concurrent removal is not an error). One `spawn_blocking`
/// for the whole scope, so the read-modify-write cycles of the file store are not interleaved.
pub(crate) async fn remove_instance_secrets(
    store: &Arc<dyn SecretStore>,
    instance: &InstanceName,
) -> Result<Vec<String>, EngineError> {
    let instance = instance.clone();
    blocking(store, move |s| {
        let mut removed = Vec::new();
        for meta in s.list()? {
            let owner = match split_scoped(&meta.name) {
                Ok((owner, _)) => owner,
                // Unreachable for a store that validates its names; skip instead of failing the purge.
                Err(_) => continue,
            };
            if owner != instance {
                continue;
            }
            match s.remove(&meta.name) {
                Ok(()) => removed.push(meta.name),
                Err(SecretError::NotFound(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(removed)
    })
    .await
}

/// Writes the instance's secrets as Podman secrets (`create` overwrites) and returns the attachments
/// for `ContainerSpec`.
pub(crate) async fn materialize<P: PodmanClient>(
    podman: &P,
    store: &Arc<dyn SecretStore>,
    instance: &InstanceName,
    spec: &AppSpec,
) -> Result<Vec<SecretAttachment>, EngineError> {
    let mut out = Vec::with_capacity(spec.secrets.len());
    for b in &spec.secrets {
        let scoped = scoped_name(instance, &b.secret);
        let key = scoped.clone();
        let value = blocking(store, move |s| s.get(&key))
            .await?
            .ok_or_else(|| SecretError::NotFound(scoped.clone()))?;
        podman.secret_create(&scoped, value.expose()).await?;
        out.push(SecretAttachment {
            secret: scoped,
            target: b.target.clone(),
        });
    }
    Ok(out)
}
