//! OIDC client credentials (#213): a thin layer over [`SecretOps`]. The plain client secret is
//! minted into the store and never returned; callers get the PBKDF2 digest the identity provider
//! stores. Nothing here takes a `SecretStore`, so a vault-backed `SecretOps` (#200) drops in.
//!
//! Called by the engine before an `oidc` app is reconciled, deployed or run (`ensure_oidc_credential`),
//! and by the generated config pipeline for the digests it renders.
//! Callers must hold the engine mutex — minting is a read-then-write on the store.

use weglarka_model::app::InstanceName;
use weglarka_model::secret_ops::{Alphabet, MintSpec, Pbkdf2Digest, SecretOps};
use weglarka_model::secret_store::{OIDC_CLIENT_SECRET, SecretError, scoped_name};

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
}
