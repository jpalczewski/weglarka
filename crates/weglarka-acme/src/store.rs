use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use weglarka_core::state::write_atomic;

use crate::cert::{CertId, Issued};
use crate::error::AcmeError;

const KEY_MODE: u32 = 0o600;
const CERT_MODE: u32 = 0o644;
const DIR_MODE: u32 = 0o700;

/// The `tls/` directory of the edge ingress: `<id>.crt` (chain, leaf first) and `<id>.key`.
///
/// The ingress fingerprints both files and reloads nginx when it changes, so [`CertStore::write`]
/// stores the **key first, then the certificate**: a reader that sees the new certificate always
/// finds its key, and a crash in between leaves the old certificate with a new key at worst — which
/// `nginx -t` rejects, so the ingress keeps the last good config and the next pass repairs it.
#[derive(Debug, Clone)]
pub struct CertStore {
    dir: PathBuf,
}

impl CertStore {
    pub fn new(tls_dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: tls_dir.into(),
        }
    }

    pub fn cert_path(&self, id: &CertId) -> PathBuf {
        self.dir.join(format!("{id}.crt"))
    }

    pub fn key_path(&self, id: &CertId) -> PathBuf {
        self.dir.join(format!("{id}.key"))
    }

    /// The chain on disk, or `None` when this certificate has not been issued yet.
    pub fn read_chain(&self, id: &CertId) -> Result<Option<Vec<u8>>, AcmeError> {
        let path = self.cert_path(id);
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(AcmeError::Io { path, source }),
        }
    }

    pub fn write(&self, id: &CertId, issued: &Issued) -> Result<(), AcmeError> {
        self.ensure_dir()?;
        let key = self.key_path(id);
        write_atomic(&key, issued.key.expose(), KEY_MODE)
            .map_err(|source| AcmeError::Io { path: key, source })?;
        let cert = self.cert_path(id);
        write_atomic(&cert, &issued.chain_pem, CERT_MODE)
            .map_err(|source| AcmeError::Io { path: cert, source })
    }

    fn ensure_dir(&self) -> Result<(), AcmeError> {
        if Path::new(&self.dir).is_dir() {
            return Ok(());
        }
        DirBuilder::new()
            .recursive(true)
            .mode(DIR_MODE)
            .create(&self.dir)
            .map_err(|source| AcmeError::Io {
                path: self.dir.clone(),
                source,
            })
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::time::SystemTime;

    use super::*;
    use crate::cert::PrivateKeyPem;

    fn issued() -> Issued {
        Issued {
            chain_pem: b"chain".to_vec(),
            key: PrivateKeyPem::new(b"key".to_vec()),
            not_after: SystemTime::UNIX_EPOCH,
        }
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn writes_pair_with_expected_modes_and_creates_a_private_dir() {
        let root = tempfile::tempdir().unwrap();
        let tls = root.path().join("tls");
        let store = CertStore::new(&tls);
        let id = CertId::new("app.example.eu").unwrap();
        assert_eq!(store.read_chain(&id).unwrap(), None);

        store.write(&id, &issued()).unwrap();
        assert_eq!(mode(&tls), 0o700);
        assert_eq!(mode(&store.key_path(&id)), 0o600);
        assert_eq!(mode(&store.cert_path(&id)), 0o644);
        assert_eq!(fs::read(store.key_path(&id)).unwrap(), b"key");
        assert_eq!(store.read_chain(&id).unwrap().unwrap(), b"chain");
    }

    #[test]
    fn overwrite_keeps_modes_and_leaves_no_temp_files() {
        let root = tempfile::tempdir().unwrap();
        let store = CertStore::new(root.path());
        let id = CertId::new("a.example.eu").unwrap();
        store.write(&id, &issued()).unwrap();
        store.write(&id, &issued()).unwrap();
        assert_eq!(mode(&store.key_path(&id)), 0o600);
        let mut names: Vec<_> = fs::read_dir(root.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, ["a.example.eu.crt", "a.example.eu.key"]);
    }
}
