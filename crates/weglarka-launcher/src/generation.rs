//! Generation directories: verify-and-reuse, atomic install and garbage collection.
//!
//! A generation lives at `<host-dir>/generations/<sha256 hex>/` and contains exactly the two host
//! tools plus a `manifest.toml` recording their sizes and SHA-256 digests. Names are digest hex, not
//! arbitrary paths. An existing directory is reused only after the manifest and every file verify;
//! a mismatch is an error, never a silent overwrite. Installation renames a complete staging
//! directory into place and fsyncs the parent.
//!
//! GC deletes only directories that are unreferenced by the selector (`active`, `previous`,
//! `candidate`) or by the caller's extra references (an unfinished journal). The recovery generation
//! and the running generation are therefore never removed.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use weglarka_model::fsutil::write_atomic;
use weglarka_model::release_set::StrictDigest;

use crate::host::{
    GENERATION_MANIFEST, GENERATIONS_DIR, HOST_CLI_FILE, HOST_DAEMON_FILE, HostError,
    generation_name, parse_generation_name, read_bounded,
};
use crate::selector::HostSelector;

/// Format of a generation manifest.
pub const MANIFEST_FORMAT_VERSION: u32 = 1;
/// Largest accepted manifest.
pub const MANIFEST_MAX_BYTES: usize = 8 * 1024;
/// Largest accepted host tool file (contract: files over 64 MiB reject the set).
pub const MAX_TOOL_BYTES: u64 = 64 * 1024 * 1024;
/// The only accepted host tool names and their order.
/// Mode of `generations/` and of every generation directory. World-readable and executable so the
/// runtime-user launcher can open and run a generation; only the owner (root, see the daemon's
/// `ownership` module) can change it. Never group- or world-writable.
const GENERATION_DIR_MODE: u32 = 0o755;

/// Mode of a generation manifest (readable by the runtime user, writable by its owner only).
const MANIFEST_MODE: u32 = 0o644;

pub const HOST_TOOL_NAMES: [&str; 2] = [HOST_DAEMON_FILE, HOST_CLI_FILE];

/// One expected file from the descriptor / bootstrap source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedFile {
    pub name: String,
    pub size: u64,
    pub digest: StrictDigest,
}

impl ExpectedFile {
    pub fn new(name: impl Into<String>, size: u64, digest: StrictDigest) -> Self {
        Self {
            name: name.into(),
            size,
            digest,
        }
    }
}

/// One verified file in a generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationFile {
    pub name: String,
    pub size: u64,
    pub digest: StrictDigest,
}

/// `manifest.toml` inside a generation directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationManifest {
    pub format_version: u32,
    pub generation: StrictDigest,
    pub files: Vec<GenerationFile>,
}

#[derive(Debug, thiserror::Error)]
pub enum GenerationError {
    #[error(transparent)]
    Host(#[from] HostError),
    #[error("invalid generation manifest in {path}: {message}")]
    Manifest { path: PathBuf, message: String },
    #[error("generation {digest} is missing")]
    Missing { digest: StrictDigest },
    #[error("generation {digest} has an unexpected directory entry {name:?}")]
    UnexpectedEntry { digest: StrictDigest, name: String },
    #[error("generation {digest} is missing {name}")]
    MissingFile { digest: StrictDigest, name: String },
    #[error(
        "generation {digest} has unexpected file {name:?} (expected exactly the two host tools)"
    )]
    UnexpectedFile { digest: StrictDigest, name: String },
    #[error("generation file {path} does not match its manifest (size or SHA-256)")]
    Mismatch { path: PathBuf },
    #[error("cannot rename {from} to {to}: {source}")]
    Rename {
        from: PathBuf,
        to: PathBuf,
        source: io::Error,
    },
    #[error("cannot create {path}: {source}")]
    Dir { path: PathBuf, source: io::Error },
    #[error("cannot remove {path}: {source}")]
    Remove { path: PathBuf, source: io::Error },
    #[error(transparent)]
    Selector(#[from] crate::selector::SelectorError),
}

/// A verified generation directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Generation {
    dir: PathBuf,
    manifest: GenerationManifest,
}

impl Generation {
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn digest(&self) -> &StrictDigest {
        &self.manifest.generation
    }

    pub fn manifest(&self) -> &GenerationManifest {
        &self.manifest
    }

    /// Path of one of the two host tools. Names outside the fixed set are rejected.
    pub fn binary(&self, name: &str) -> Result<PathBuf, GenerationError> {
        if !HOST_TOOL_NAMES.contains(&name) {
            return Err(GenerationError::MissingFile {
                digest: self.digest().clone(),
                name: name.to_owned(),
            });
        }
        Ok(self.dir.join(name))
    }
}

/// The generation store rooted at the host-only directory.
#[derive(Debug, Clone)]
pub struct GenerationStore {
    root: PathBuf,
}

impl GenerationStore {
    pub fn new(host_dir: impl Into<PathBuf>) -> Self {
        Self {
            root: host_dir.into(),
        }
    }

    fn generations_dir(&self) -> PathBuf {
        self.root.join(GENERATIONS_DIR)
    }

    fn generation_dir(&self, digest: &StrictDigest) -> PathBuf {
        self.generations_dir().join(generation_name(digest))
    }

    /// Creates the host-only generations directory.
    pub fn ensure(&self) -> Result<(), GenerationError> {
        let dir = self.generations_dir();
        fs::create_dir_all(&dir).map_err(|source| GenerationError::Dir {
            path: dir.clone(),
            source,
        })?;
        // `symlink_metadata`, not `metadata`: a `generations` that is a symlink (or anything but a
        // plain directory) is never accepted, so the mode below cannot land on another target.
        let meta = fs::symlink_metadata(&dir).map_err(|source| GenerationError::Dir {
            path: dir.clone(),
            source,
        })?;
        if !meta.is_dir() {
            return Err(GenerationError::Dir {
                path: dir.clone(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "not a plain directory",
                ),
            });
        }
        if meta.permissions().mode() & 0o777 != GENERATION_DIR_MODE {
            fs::set_permissions(&dir, fs::Permissions::from_mode(GENERATION_DIR_MODE)).map_err(
                |source| GenerationError::Dir {
                    path: dir.clone(),
                    source,
                },
            )?;
        }
        Ok(())
    }

    /// Creates a fresh staging directory under `generations/` (same filesystem as the target, so
    /// the final rename is atomic).
    pub fn staging_dir(&self) -> Result<PathBuf, GenerationError> {
        self.ensure()?;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let dir = self
            .generations_dir()
            .join(format!(".staging-{}-{nanos}", std::process::id()));
        fs::create_dir(&dir).map_err(|source| GenerationError::Dir {
            path: dir.clone(),
            source,
        })?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(GENERATION_DIR_MODE)).map_err(
            |source| GenerationError::Dir {
                path: dir.clone(),
                source,
            },
        )?;
        Ok(dir)
    }

    /// Verifies a generation directory and returns its handle.
    pub fn open(&self, digest: &StrictDigest) -> Result<Generation, GenerationError> {
        let dir = self.generation_dir(digest);
        if !dir.is_dir() {
            return Err(GenerationError::Missing {
                digest: digest.clone(),
            });
        }
        let manifest_path = dir.join(GENERATION_MANIFEST);
        let text = read_bounded(&manifest_path, GENERATION_MANIFEST, MANIFEST_MAX_BYTES)?
            .ok_or_else(|| GenerationError::Manifest {
                path: manifest_path.clone(),
                message: "manifest is missing".into(),
            })?;
        let manifest: GenerationManifest =
            toml::from_str(&text).map_err(|e| GenerationError::Manifest {
                path: manifest_path.clone(),
                message: e.to_string(),
            })?;
        if manifest.format_version != MANIFEST_FORMAT_VERSION {
            return Err(GenerationError::Manifest {
                path: manifest_path,
                message: format!("unsupported format_version {}", manifest.format_version),
            });
        }
        if manifest.generation != *digest {
            return Err(GenerationError::Manifest {
                path: dir.join(GENERATION_MANIFEST),
                message: format!(
                    "manifest names {} but the directory is {}",
                    manifest.generation, digest
                ),
            });
        }
        verify_files(&dir, digest, &manifest)?;
        Ok(Generation { dir, manifest })
    }

    /// Installs a complete staging directory.
    ///
    /// The staging directory must already contain exactly the expected files with mode 0755. This
    /// writes the manifest, verifies everything, then either reuses an identical existing
    /// generation or atomically renames the staging directory into place.
    pub fn install(
        &self,
        staging: &Path,
        digest: &StrictDigest,
        expected: &[ExpectedFile],
    ) -> Result<Generation, GenerationError> {
        validate_expected(digest, expected)?;
        self.ensure()?;

        let mut entries = BTreeSet::new();
        for entry in fs::read_dir(staging).map_err(|source| GenerationError::Dir {
            path: staging.to_owned(),
            source,
        })? {
            let entry = entry.map_err(|source| GenerationError::Dir {
                path: staging.to_owned(),
                source,
            })?;
            entries.insert(entry.file_name().to_string_lossy().into_owned());
        }
        for expected_file in expected {
            if !entries.remove(&expected_file.name) {
                return Err(GenerationError::MissingFile {
                    digest: digest.clone(),
                    name: expected_file.name.clone(),
                });
            }
        }
        if let Some(extra) = entries.into_iter().next() {
            return Err(GenerationError::UnexpectedFile {
                digest: digest.clone(),
                name: extra,
            });
        }

        let mut files = Vec::with_capacity(expected.len());
        for expected_file in expected {
            let path = staging.join(&expected_file.name);
            verify_one(&path, expected_file)?;
            files.push(GenerationFile {
                name: expected_file.name.clone(),
                size: expected_file.size,
                digest: expected_file.digest.clone(),
            });
        }

        let manifest = GenerationManifest {
            format_version: MANIFEST_FORMAT_VERSION,
            generation: digest.clone(),
            files,
        };
        let text = toml::to_string(&manifest).map_err(|e| GenerationError::Manifest {
            path: staging.join(GENERATION_MANIFEST),
            message: e.to_string(),
        })?;
        write_atomic(
            &staging.join(GENERATION_MANIFEST),
            text.as_bytes(),
            MANIFEST_MODE,
        )
        .map_err(|source| HostError::Write {
            path: staging.join(GENERATION_MANIFEST),
            source,
        })?;
        sync_dir(staging)?;

        let target = self.generation_dir(digest);
        if target.exists() {
            // Replay: never overwrite a verified directory. Reuse it only when its file manifest
            // names exactly the files we just verified; the same digest with different content is a
            // mismatch, not a reason to keep the old directory silently.
            let generation = self.open(digest)?;
            let same = generation.manifest().files == manifest.files;
            remove_dir(staging)?;
            if !same {
                return Err(GenerationError::Mismatch {
                    path: target.join(GENERATION_MANIFEST),
                });
            }
            return Ok(generation);
        }
        fs::rename(staging, &target).map_err(|source| GenerationError::Rename {
            from: staging.to_owned(),
            to: target.clone(),
            source,
        })?;
        sync_dir(&self.generations_dir())?;
        self.open(digest)
    }

    /// Installs from files that already live outside the store (bootstrap generation 0), copying
    /// them into a staging directory first.
    pub fn install_from_files(
        &self,
        digest: &StrictDigest,
        sources: &[(&str, PathBuf)],
    ) -> Result<Generation, GenerationError> {
        let mut expected = Vec::new();
        for (name, source) in sources {
            if !HOST_TOOL_NAMES.contains(name) {
                return Err(GenerationError::UnexpectedFile {
                    digest: digest.clone(),
                    name: (*name).to_owned(),
                });
            }
            let metadata = fs::symlink_metadata(source).map_err(|source_err| HostError::Read {
                path: source.clone(),
                source: source_err,
            })?;
            if metadata.file_type().is_symlink() {
                return Err(HostError::Symlink {
                    path: source.clone(),
                }
                .into());
            }
            if !metadata.is_file() {
                return Err(HostError::NotRegular {
                    path: source.clone(),
                }
                .into());
            }
            if metadata.len() > MAX_TOOL_BYTES {
                return Err(HostError::TooLarge {
                    file: "host tool",
                    size: usize::try_from(metadata.len()).unwrap_or(usize::MAX),
                    limit: usize::try_from(MAX_TOOL_BYTES).unwrap_or(usize::MAX),
                }
                .into());
            }
            let digest_hex = file_digest(source)?;
            expected.push(ExpectedFile::new(
                (*name).to_owned(),
                metadata.len(),
                digest_hex,
            ));
        }
        let staging = self.staging_dir()?;
        for (name, source) in sources {
            let target = staging.join(name);
            fs::copy(source, &target).map_err(|source_err| GenerationError::Dir {
                path: target.clone(),
                source: source_err,
            })?;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).map_err(
                |source_err| GenerationError::Dir {
                    path: target.clone(),
                    source: source_err,
                },
            )?;
            let file = fs::File::open(&target).map_err(|source_err| GenerationError::Dir {
                path: target.clone(),
                source: source_err,
            })?;
            file.sync_all().map_err(|source_err| GenerationError::Dir {
                path: target.clone(),
                source: source_err,
            })?;
        }
        self.install(&staging, digest, &expected)
    }

    /// All valid generation directories, sorted.
    pub fn list(&self) -> Result<Vec<StrictDigest>, GenerationError> {
        let dir = self.generations_dir();
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => {
                return Err(GenerationError::Dir { path: dir, source });
            }
        };
        let mut digests = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| GenerationError::Dir {
                path: self.generations_dir(),
                source,
            })?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Ok(digest) = parse_generation_name(&name) {
                digests.push(digest);
            }
        }
        digests.sort();
        Ok(digests)
    }

    /// Removes every generation unreferenced by the selector or by `extra` (for example a
    /// nonterminal journal) under the host-selection lock. Staging directories are left alone:
    /// another process may be filling one.
    pub fn gc(
        &self,
        selector: &HostSelector,
        extra: &[StrictDigest],
    ) -> Result<Vec<StrictDigest>, GenerationError> {
        let _guard = crate::selector::lock_host_selection(&self.root)?;
        self.gc_locked(selector, extra)
    }

    /// [`gc`](Self::gc) without taking the lock; the caller must hold the host-selection lock.
    pub fn gc_locked(
        &self,
        selector: &HostSelector,
        extra: &[StrictDigest],
    ) -> Result<Vec<StrictDigest>, GenerationError> {
        let mut removed = Vec::new();
        for digest in self.list()? {
            if selector.references(&digest) || extra.contains(&digest) {
                continue;
            }
            let dir = self.generation_dir(&digest);
            remove_dir(&dir)?;
            removed.push(digest);
        }
        if !removed.is_empty() {
            sync_dir(&self.generations_dir())?;
        }
        Ok(removed)
    }
}

fn validate_expected(
    digest: &StrictDigest,
    expected: &[ExpectedFile],
) -> Result<(), GenerationError> {
    if expected.len() != HOST_TOOL_NAMES.len() {
        return Err(GenerationError::Manifest {
            path: PathBuf::from(generation_name(digest)),
            message: "exactly the two host tools are required".into(),
        });
    }
    let mut names = BTreeSet::new();
    for file in expected {
        if !HOST_TOOL_NAMES.contains(&file.name.as_str()) {
            return Err(GenerationError::UnexpectedFile {
                digest: digest.clone(),
                name: file.name.clone(),
            });
        }
        if !names.insert(file.name.as_str()) {
            return Err(GenerationError::UnexpectedFile {
                digest: digest.clone(),
                name: format!("{} (duplicate)", file.name),
            });
        }
        if file.size == 0 || file.size > MAX_TOOL_BYTES {
            return Err(GenerationError::Manifest {
                path: PathBuf::from(generation_name(digest)),
                message: format!("{} has an invalid size {}", file.name, file.size),
            });
        }
    }
    Ok(())
}

fn verify_files(
    dir: &Path,
    digest: &StrictDigest,
    manifest: &GenerationManifest,
) -> Result<(), GenerationError> {
    if manifest.files.len() != HOST_TOOL_NAMES.len() {
        return Err(GenerationError::Manifest {
            path: dir.join(GENERATION_MANIFEST),
            message: "exactly the two host tools are required".into(),
        });
    }
    let mut seen = BTreeSet::new();
    for file in &manifest.files {
        if !HOST_TOOL_NAMES.contains(&file.name.as_str()) {
            return Err(GenerationError::UnexpectedFile {
                digest: digest.clone(),
                name: file.name.clone(),
            });
        }
        if !seen.insert(file.name.as_str()) {
            return Err(GenerationError::Manifest {
                path: dir.join(GENERATION_MANIFEST),
                message: format!("duplicate file {}", file.name),
            });
        }
        verify_one(
            &dir.join(&file.name),
            &ExpectedFile::new(file.name.clone(), file.size, file.digest.clone()),
        )?;
    }
    for name in HOST_TOOL_NAMES {
        if !seen.contains(name) {
            return Err(GenerationError::MissingFile {
                digest: digest.clone(),
                name: name.to_owned(),
            });
        }
    }
    let mut entries = BTreeSet::new();
    for entry in fs::read_dir(dir).map_err(|source| GenerationError::Dir {
        path: dir.to_owned(),
        source,
    })? {
        let entry = entry.map_err(|source| GenerationError::Dir {
            path: dir.to_owned(),
            source,
        })?;
        entries.insert(entry.file_name().to_string_lossy().into_owned());
    }
    entries.remove(GENERATION_MANIFEST);
    for name in HOST_TOOL_NAMES {
        entries.remove(name);
    }
    if let Some(extra) = entries.into_iter().next() {
        return Err(GenerationError::UnexpectedEntry {
            digest: digest.clone(),
            name: extra,
        });
    }
    Ok(())
}

fn verify_one(path: &Path, expected: &ExpectedFile) -> Result<(), GenerationError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| HostError::Read {
        path: path.to_owned(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Err(HostError::Symlink {
            path: path.to_owned(),
        }
        .into());
    }
    if !metadata.is_file() {
        return Err(HostError::NotRegular {
            path: path.to_owned(),
        }
        .into());
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o755 {
        return Err(HostError::Mode {
            path: path.to_owned(),
            mode,
            expected: 0o755,
        }
        .into());
    }
    if metadata.len() != expected.size {
        return Err(GenerationError::Mismatch {
            path: path.to_owned(),
        });
    }
    if file_digest(path)? != expected.digest {
        return Err(GenerationError::Mismatch {
            path: path.to_owned(),
        });
    }
    Ok(())
}

/// SHA-256 of a file read through a fixed buffer, so hashing a tool binary of tens of MiB (done for
/// both binaries on every launcher call) never holds the file in memory.
fn file_digest(path: &Path) -> Result<StrictDigest, GenerationError> {
    let read_error = |source| HostError::Read {
        path: path.to_owned(),
        source,
    };
    let mut file = fs::File::open(path).map_err(read_error)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = std::io::Read::read(&mut file, &mut buffer).map_err(read_error)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    StrictDigest::new(format!("sha256:{}", hex::encode(hasher.finalize()))).map_err(|_| {
        GenerationError::Mismatch {
            path: path.to_owned(),
        }
    })
}

fn sync_dir(dir: &Path) -> Result<(), GenerationError> {
    let file = fs::File::open(dir).map_err(|source| GenerationError::Dir {
        path: dir.to_owned(),
        source,
    })?;
    file.sync_all().map_err(|source| GenerationError::Dir {
        path: dir.to_owned(),
        source,
    })
}

fn remove_dir(path: &Path) -> Result<(), GenerationError> {
    fs::remove_dir_all(path).map_err(|source| GenerationError::Remove {
        path: path.to_owned(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> StrictDigest {
        StrictDigest::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn staging_with(store: &GenerationStore, daemon: &[u8], cli: &[u8]) -> PathBuf {
        let dir = store.staging_dir().unwrap();
        for (name, bytes) in [(HOST_DAEMON_FILE, daemon), (HOST_CLI_FILE, cli)] {
            let path = dir.join(name);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        dir
    }

    fn expected(daemon: &[u8], cli: &[u8]) -> Vec<ExpectedFile> {
        let mut out = Vec::new();
        for (name, bytes) in [(HOST_DAEMON_FILE, daemon), (HOST_CLI_FILE, cli)] {
            out.push(ExpectedFile::new(
                name,
                bytes.len() as u64,
                StrictDigest::new(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
                    .unwrap(),
            ));
        }
        out
    }

    #[test]
    fn install_verifies_and_reuses_the_same_directory() {
        let dir = tempfile::tempdir().unwrap();
        let store = GenerationStore::new(dir.path());
        let d = digest('a');
        let staging = staging_with(&store, b"daemon", b"cli");
        let generation = store
            .install(&staging, &d, &expected(b"daemon", b"cli"))
            .unwrap();
        assert_eq!(generation.digest(), &d);
        assert!(generation.binary(HOST_DAEMON_FILE).unwrap().is_file());
        assert!(generation.binary("../escape").is_err());

        // Replay: a second identical install reuses the verified directory.
        let staging = staging_with(&store, b"daemon", b"cli");
        let again = store
            .install(&staging, &d, &expected(b"daemon", b"cli"))
            .unwrap();
        assert_eq!(again, generation);
        assert!(!staging.exists());
        assert_eq!(store.list().unwrap(), vec![d]);
    }

    #[test]
    fn the_same_digest_with_different_files_is_a_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let store = GenerationStore::new(dir.path());
        let d = digest('d');
        let staging = staging_with(&store, b"one", b"cli");
        store
            .install(&staging, &d, &expected(b"one", b"cli"))
            .unwrap();
        let staging = staging_with(&store, b"two", b"cli");
        assert!(matches!(
            store.install(&staging, &d, &expected(b"two", b"cli")),
            Err(GenerationError::Mismatch { .. })
        ));
    }

    #[test]
    fn a_tampered_generation_is_rejected_not_reused() {
        let dir = tempfile::tempdir().unwrap();
        let store = GenerationStore::new(dir.path());
        let d = digest('b');
        let staging = staging_with(&store, b"daemon", b"cli");
        store
            .install(&staging, &d, &expected(b"daemon", b"cli"))
            .unwrap();
        fs::write(store.generation_dir(&d).join(HOST_DAEMON_FILE), b"tampered").unwrap();
        assert!(matches!(
            store.open(&d),
            Err(GenerationError::Mismatch { .. })
        ));
        // The tampered directory is not overwritten by a fresh replay either.
        let staging = staging_with(&store, b"daemon", b"cli");
        assert!(
            store
                .install(&staging, &d, &expected(b"daemon", b"cli"))
                .is_err()
        );
    }

    #[test]
    fn symlinks_and_wrong_modes_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store = GenerationStore::new(dir.path());
        let d = digest('c');
        let staging = staging_with(&store, b"daemon", b"cli");
        fs::set_permissions(
            staging.join(HOST_CLI_FILE),
            fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        assert!(matches!(
            store.install(&staging, &d, &expected(b"daemon", b"cli")),
            Err(GenerationError::Host(HostError::Mode { .. }))
        ));

        let staging = staging_with(&store, b"daemon", b"cli");
        fs::remove_file(staging.join(HOST_CLI_FILE)).unwrap();
        std::os::unix::fs::symlink("/bin/sh", staging.join(HOST_CLI_FILE)).unwrap();
        assert!(matches!(
            store.install(&staging, &d, &expected(b"daemon", b"cli")),
            Err(GenerationError::Host(HostError::Symlink { .. }))
        ));
    }

    #[test]
    fn gc_keeps_active_previous_candidate_and_extra_references() {
        let dir = tempfile::tempdir().unwrap();
        let store = GenerationStore::new(dir.path());
        let mut digests = Vec::new();
        for byte in ['a', 'b', 'c', 'd', 'e'] {
            let d = digest(byte);
            let staging = staging_with(&store, byte.to_string().as_bytes(), b"cli");
            store
                .install(&staging, &d, &expected(byte.to_string().as_bytes(), b"cli"))
                .unwrap();
            digests.push(d);
        }
        let selector = HostSelector {
            format_version: crate::selector::FORMAT_VERSION,
            epoch: 2,
            active: digests[0].clone(),
            previous: Some(digests[1].clone()),
            candidate: Some(digests[2].clone()),
        };
        let extra = vec![digests[3].clone()];
        let removed = store.gc(&selector, &extra).unwrap();
        assert_eq!(removed, vec![digests[4].clone()]);
        let left = store.list().unwrap();
        for d in &digests[..4] {
            assert!(left.contains(d));
        }
    }

    #[test]
    fn bootstrap_copy_uses_the_same_verification() {
        let dir = tempfile::tempdir().unwrap();
        let store = GenerationStore::new(dir.path());
        let daemon = dir.path().join("src-daemon");
        let cli = dir.path().join("src-cli");
        fs::write(&daemon, b"daemon").unwrap();
        fs::write(&cli, b"cli").unwrap();
        let d = digest('f');
        let generation = store
            .install_from_files(&d, &[(HOST_DAEMON_FILE, daemon), (HOST_CLI_FILE, cli)])
            .unwrap();
        let mode = fs::metadata(generation.binary(HOST_CLI_FILE).unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755);
    }
}
