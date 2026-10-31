//! OIDC client credentials (#213): a thin layer over [`SecretOps`]. The plain client secret is
//! minted into the store and never returned; callers get the PBKDF2 digest the identity provider
//! stores. Nothing here takes a `SecretStore`, so a vault-backed `SecretOps` (#200) drops in.
//!
//! Called by the engine before an `oidc` app is reconciled, deployed or run (`ensure_oidc_credential`),
//! and by the generated config pipeline for the digests it renders.
//! Callers must hold the engine mutex — minting is a read-then-write on the store.

use weglarka_model::app::InstanceName;
use weglarka_model::secret_ops::{Alphabet, MintSpec, Pbkdf2Digest, SecretOps, digest_name};
use weglarka_model::secret_store::{
    OIDC_CLIENT_SECRET, SecretError, SecretStore, SecretValue, scoped_name,
};

/// Where a rotation keeps the new secret (and `<this>-digest` its digest) until the provider has
/// applied it. Both are ordinary entries of the secret store: no schema change, and a pending pair
/// left by a crash is overwritten by the next rotation.
const PENDING_SECRET: &str = "oidc-client-secret-pending";

/// 72 characters of the RFC 3986 unreserved set.
pub const CLIENT_SECRET_SPEC: MintSpec = MintSpec {
    len: 72,
    alphabet: Alphabet::Rfc3986Unreserved,
};

/// Mints `<instance>.oidc-client-secret` (and its digest) when absent; returns the digest.
pub fn ensure(
    ops: &(impl SecretOps + ?Sized),
    instance: &InstanceName,
) -> Result<Pbkdf2Digest, SecretError> {
    ops.mint_hashed(
        &scoped_name(instance, OIDC_CLIENT_SECRET),
        &CLIENT_SECRET_SPEC,
    )
}

/// Replaces the client secret and its digest; returns the new digest.
pub fn rotate(
    ops: &(impl SecretOps + ?Sized),
    instance: &InstanceName,
) -> Result<Pbkdf2Digest, SecretError> {
    ops.rotate_hashed(
        &scoped_name(instance, OIDC_CLIENT_SECRET),
        &CLIENT_SECRET_SPEC,
    )
}

fn pending_name(instance: &InstanceName) -> String {
    scoped_name(instance, PENDING_SECRET)
}

/// Draws a new secret under the pending name, leaving the live pair alone; returns the new digest.
/// A stale pending pair is replaced.
pub fn stage_rotation(
    store: &(impl SecretStore + ?Sized),
    instance: &InstanceName,
) -> Result<Pbkdf2Digest, SecretError> {
    store.rotate_hashed(&pending_name(instance), &CLIENT_SECRET_SPEC)
}

/// The pending pair becomes the live one. Same order of writes as [`rotate`]: the old digest goes
/// first, so a crash leaves "value, no digest" (repaired on the next mint), never a new value next
/// to a stale digest.
pub fn promote_rotation(
    store: &(impl SecretStore + ?Sized),
    instance: &InstanceName,
) -> Result<(), SecretError> {
    let pending = pending_name(instance);
    let live = scoped_name(instance, OIDC_CLIENT_SECRET);
    let value = store
        .get(&pending)?
        .ok_or_else(|| SecretError::NotFound(pending.clone()))?;
    let digest = store
        .digest(&pending)?
        .ok_or_else(|| SecretError::NotFound(digest_name(&pending).unwrap_or_default()))?;
    let live_digest = digest_name(&live)?;
    forgive_missing(store.remove(&live_digest))?;
    store.set(&live, value)?;
    store.set(&live_digest, SecretValue::new(digest.to_string()))?;
    discard_rotation(store, instance)
}

/// Drops the pending pair (a rotation that failed, or one that was promoted). Idempotent.
pub fn discard_rotation(
    store: &(impl SecretStore + ?Sized),
    instance: &InstanceName,
) -> Result<(), SecretError> {
    let pending = pending_name(instance);
    forgive_missing(store.remove(&digest_name(&pending)?))?;
    forgive_missing(store.remove(&pending))
}

fn forgive_missing(result: Result<(), SecretError>) -> Result<(), SecretError> {
    match result {
        Err(SecretError::NotFound(_)) => Ok(()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use weglarka_model::secret_store::SecretStore;
    use weglarka_model::secrets::FileSecretStore;

    #[test]
    fn ensure_is_stable_and_rotate_changes_it() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileSecretStore::new(dir.path().join("secrets.toml"));
        let app = InstanceName::new("blog").unwrap();
        let a = ensure(&store, &app).unwrap();
        assert_eq!(ensure(&store, &app).unwrap(), a);
        let plain = store.get("blog.oidc-client-secret").unwrap().unwrap();
        assert_eq!(plain.expose().len(), 72);
        let b = rotate(&store, &app).unwrap();
        assert_ne!(a, b);
        assert_ne!(
            store.get("blog.oidc-client-secret").unwrap().unwrap(),
            plain
        );
        // Also usable as a trait object.
        let dynstore: &dyn SecretStore = &store;
        assert_eq!(ensure(dynstore, &app).unwrap(), b);
    }

    #[test]
    fn a_staged_rotation_changes_nothing_until_it_is_promoted() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileSecretStore::new(dir.path().join("secrets.toml"));
        let app = InstanceName::new("blog").unwrap();
        let live = ensure(&store, &app).unwrap();
        let live_value = store.get("blog.oidc-client-secret").unwrap().unwrap();

        let staged = stage_rotation(&store, &app).unwrap();
        assert_ne!(staged, live);
        assert_eq!(ensure(&store, &app).unwrap(), live, "the live digest stays");
        assert_eq!(
            store.get("blog.oidc-client-secret").unwrap().unwrap(),
            live_value
        );

        // Discarding (a failed apply) leaves the live pair and no pending entries.
        discard_rotation(&store, &app).unwrap();
        discard_rotation(&store, &app).unwrap();
        assert!(promote_rotation(&store, &app).is_err());
        assert_eq!(ensure(&store, &app).unwrap(), live);
        assert!(
            store
                .list()
                .unwrap()
                .iter()
                .all(|m| !m.name.contains("pending")),
            "no pending entry is left"
        );

        let staged = stage_rotation(&store, &app).unwrap();
        promote_rotation(&store, &app).unwrap();
        assert_eq!(ensure(&store, &app).unwrap(), staged);
        assert_ne!(
            store.get("blog.oidc-client-secret").unwrap().unwrap(),
            live_value
        );
        assert!(
            store
                .get("blog.oidc-client-secret-pending")
                .unwrap()
                .is_none()
        );
    }
}
