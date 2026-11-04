//! Generation directories: verify-and-reuse, atomic install and garbage collection.
//!
//! A generation lives at `<host-dir>/generations/<sha256 hex>/` and contains exactly the two host
//! tools plus a `manifest.toml` recording their sizes and SHA-256 digests. Names are digest hex, not
//! arbitrary paths. An existing directory is reused only after the manifest and every file verify;
//! a mismatch is an error, never a silent overwrite. Installation renames a complete staging
//! directory into place and fsyncs the parent.
//!
//! Hashing both binaries on every launcher call is the expensive part, so a generation also has a
//! `<digest>.verified` record next to it (inside `generations/`, hence root-owned): the
//! `(dev, ino, mtime, size)` of each binary at the moment its SHA-256 last matched the manifest.
//! [`GenerationStore::open_cached`] skips the hash of a binary whose metadata still matches;
//! [`GenerationStore::open`] always hashes (bootstrap, update and preflight use it). A record is
//! only ever written after a full hash matched the manifest, and only the root-owned directory
//! keeps it trustworthy: a process that cannot write `generations/` can neither forge a record nor
//! rewrite a binary without changing its metadata.
//!
//! GC deletes only directories that are unreferenced by the selector (`active`, `previous`,
//! `candidate`) or by the caller's extra references (an unfinished journal). The recovery generation
//! and the running generation are therefore never removed.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use weglarka_model::fsutil::write_atomic;
use weglarka_model::release_set::{StrictDigest, sha256_reader};

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

/// Suffix of the verified-metadata record beside a generation directory. It is not a 64-character
/// digest name, so [`GenerationStore::list`] never mistakes it for a generation.
const VERIFIED_SUFFIX: &str = ".verified";
/// Format of a verified-metadata record.
const VERIFIED_FORMAT_VERSION: u32 = 1;
/// Largest accepted verified-metadata record.
const VERIFIED_MAX_BYTES: usize = 4 * 1024;

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

/// What identifies the bytes of a file without reading them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileStamp {
    dev: u64,
    ino: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
    size: u64,
}

impl FileStamp {
    fn of(metadata: &fs::Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            mtime_sec: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            size: metadata.len(),
        }
    }
}

/// One binary's stamp, bound to the manifest entry it was verified against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifiedFile {
    name: String,
    digest: StrictDigest,
    stamp: FileStamp,
}

/// `<digest>.verified`: the stamps of both binaries when their SHA-256 last matched the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifiedRecord {
    format_version: u32,
    generation: StrictDigest,
    files: Vec<VerifiedFile>,
}

/// Outcome of checking one file: its stamp when it was stable while being hashed (or trusted from
/// the record), and whether the content was actually read.
struct Checked {
    stamp: Option<FileStamp>,
    hashed: bool,
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

    fn record_path(&self, digest: &StrictDigest) -> PathBuf {
        self.generations_dir()
            .join(format!("{}{VERIFIED_SUFFIX}", generation_name(digest)))
    }

    /// The stored record for `digest`, or `None` when it is absent, unreadable or not about this
    /// generation: a record is only ever an optimisation.
    fn read_record(&self, digest: &StrictDigest) -> Option<VerifiedRecord> {
        let text = read_bounded(
            &self.record_path(digest),
            "verified record",
            VERIFIED_MAX_BYTES,
        )
        .ok()??;
        let record: VerifiedRecord = toml::from_str(&text).ok()?;
        (record.format_version == VERIFIED_FORMAT_VERSION && record.generation == *digest)
            .then_some(record)
    }

    /// Best effort: the runtime user cannot write `generations/`, so only a root caller (bootstrap,
    /// an update) leaves a record behind, and a failure just means the next open hashes again.
    fn write_record(&self, digest: &StrictDigest, files: Vec<VerifiedFile>) {
        let record = VerifiedRecord {
            format_version: VERIFIED_FORMAT_VERSION,
            generation: digest.clone(),
            files,
        };
        if let Ok(text) = toml::to_string(&record) {
            let _ = write_atomic(&self.record_path(digest), text.as_bytes(), MANIFEST_MODE);
        }
    }

    /// Verifies a generation directory, hashing every binary, and returns its handle.
    ///
    /// This is the check bootstrap, update and preflight rely on. When every hash matches the
    /// manifest the verified-metadata record is refreshed (see the module docs).
    pub fn open(&self, digest: &StrictDigest) -> Result<Generation, GenerationError> {
        self.open_with(digest, false)
    }

    /// Like [`open`](Self::open), but a binary whose `(dev, ino, mtime, size)` still equals the
    /// record written after its last full verification is not hashed again. Anything else falls
    /// back to the full check, which refreshes the record only when the hash matches.
    pub fn open_cached(&self, digest: &StrictDigest) -> Result<Generation, GenerationError> {
        self.open_with(digest, true)
    }

    fn open_with(
        &self,
        digest: &StrictDigest,
        use_record: bool,
    ) -> Result<Generation, GenerationError> {
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
        let record = if use_record {
            self.read_record(digest)
        } else {
            None
        };
        let checked = verify_files(&dir, digest, &manifest, record.as_ref())?;
        if checked.iter().any(|(_, c)| c.hashed) {
            let stamps: Option<Vec<VerifiedFile>> = checked
                .iter()
                .map(|(file, c)| {
                    c.stamp.map(|stamp| VerifiedFile {
                        name: file.name.clone(),
                        digest: file.digest.clone(),
                        stamp,
                    })
                })
                .collect();
            if let Some(files) = stamps {
                self.write_record(digest, files);
            }
        }
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
            let _ = fs::remove_file(self.record_path(&digest));
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

fn verify_files<'m>(
    dir: &Path,
    digest: &StrictDigest,
    manifest: &'m GenerationManifest,
    record: Option<&VerifiedRecord>,
) -> Result<Vec<(&'m GenerationFile, Checked)>, GenerationError> {
    if manifest.files.len() != HOST_TOOL_NAMES.len() {
        return Err(GenerationError::Manifest {
            path: dir.join(GENERATION_MANIFEST),
            message: "exactly the two host tools are required".into(),
        });
    }
    let mut seen = BTreeSet::new();
    let mut checked = Vec::with_capacity(manifest.files.len());
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
        // Trusted only for the very manifest entry the record was written against.
        let trusted = record
            .and_then(|r| r.files.iter().find(|v| v.name == file.name))
            .filter(|v| v.digest == file.digest && v.stamp.size == file.size)
            .map(|v| v.stamp);
        let result = verify_file(
            &dir.join(&file.name),
            &ExpectedFile::new(file.name.clone(), file.size, file.digest.clone()),
            trusted,
        )?;
        checked.push((file, result));
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
    Ok(checked)
}

/// Full verification of a file outside the record (a staged file about to be installed).
fn verify_one(path: &Path, expected: &ExpectedFile) -> Result<(), GenerationError> {
    verify_file(path, expected, None).map(|_| ())
}

/// Checks type, mode and size, then the SHA-256 unless `trusted` equals the file's current stamp.
fn verify_file(
    path: &Path,
    expected: &ExpectedFile,
    trusted: Option<FileStamp>,
) -> Result<Checked, GenerationError> {
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
    if trusted == Some(FileStamp::of(&metadata)) {
        return Ok(Checked {
            stamp: trusted,
            hashed: false,
        });
    }
    let (actual, before, after) = file_digest_with_stamps(path)?;
    if actual != expected.digest {
        return Err(GenerationError::Mismatch {
            path: path.to_owned(),
        });
    }
    // A file that changed while it was being read is not recorded: the next open hashes it again.
    Ok(Checked {
        stamp: (before == after).then_some(before),
        hashed: true,
    })
}

/// SHA-256 of a file read through a fixed buffer, so hashing a tool binary of tens of MiB (done for
/// both binaries on every launcher call) never holds the file in memory.
fn file_digest(path: &Path) -> Result<StrictDigest, GenerationError> {
    file_digest_with_stamps(path).map(|(digest, _, _)| digest)
}

/// [`file_digest`] plus the open file's stamp before and after the read.
fn file_digest_with_stamps(
    path: &Path,
) -> Result<(StrictDigest, FileStamp, FileStamp), GenerationError> {
    let read_error = |source| HostError::Read {
        path: path.to_owned(),
        source,
    };
    let file = fs::File::open(path).map_err(read_error)?;
    let before = FileStamp::of(&file.metadata().map_err(read_error)?);
    let streamed = sha256_reader(&file).map_err(read_error)?;
    let after = FileStamp::of(&file.metadata().map_err(read_error)?);
    Ok((StrictDigest::from_sha256(streamed.sha256), before, after))
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
    use sha2::{Digest as _, Sha256};

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

    fn installed(dir: &Path, byte: char) -> (GenerationStore, StrictDigest) {
        let store = GenerationStore::new(dir);
        let d = digest(byte);
        let staging = staging_with(&store, b"daemon", b"cli");
        store
            .install(&staging, &d, &expected(b"daemon", b"cli"))
            .unwrap();
        (store, d)
    }

    /// Rewrites a binary in place (same inode), with `mtime` restored to what it was.
    fn rewrite_in_place(path: &Path, bytes: &[u8], mtime: Option<std::time::SystemTime>) {
        let before = fs::metadata(path).unwrap();
        let file = fs::OpenOptions::new().write(true).open(path).unwrap();
        file.set_len(0).unwrap();
        io::Write::write_all(&mut &file, bytes).unwrap();
        file.set_modified(mtime.unwrap_or(before.modified().unwrap()))
            .unwrap();
        assert_eq!(fs::metadata(path).unwrap().ino(), before.ino());
    }

    #[test]
    fn install_leaves_a_record_that_is_not_mistaken_for_a_generation() {
        let dir = tempfile::tempdir().unwrap();
        let (store, d) = installed(dir.path(), 'a');
        let record = store.record_path(&d);
        assert!(record.is_file());
        assert_eq!(
            fs::metadata(&record).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert_eq!(store.list().unwrap(), vec![d]);
    }

    #[test]
    fn a_cached_open_of_an_unchanged_generation_does_not_read_the_binaries() {
        let dir = tempfile::tempdir().unwrap();
        let (store, d) = installed(dir.path(), 'a');
        let daemon = store.generation_dir(&d).join(HOST_DAEMON_FILE);
        let mtime = fs::metadata(&daemon).unwrap().modified().unwrap();

        // Same size, same inode, same mtime: the only way to tell is to read the bytes. The cached
        // open trusts the record and succeeds; the full check reads them and refuses.
        rewrite_in_place(&daemon, b"DAEMON", Some(mtime));
        store.open_cached(&d).unwrap();
        assert!(matches!(
            store.open(&d),
            Err(GenerationError::Mismatch { .. })
        ));
    }

    #[test]
    fn an_in_place_rewrite_is_detected_and_does_not_touch_the_record() {
        let dir = tempfile::tempdir().unwrap();
        let (store, d) = installed(dir.path(), 'b');
        let daemon = store.generation_dir(&d).join(HOST_DAEMON_FILE);
        let record = fs::read(store.record_path(&d)).unwrap();

        let later =
            fs::metadata(&daemon).unwrap().modified().unwrap() + std::time::Duration::from_secs(5);
        rewrite_in_place(&daemon, b"DAEMON", Some(later));
        assert!(matches!(
            store.open_cached(&d),
            Err(GenerationError::Mismatch { .. })
        ));
        // A hash that does not match the manifest never refreshes the record.
        assert_eq!(fs::read(store.record_path(&d)).unwrap(), record);
        assert!(matches!(
            store.open_cached(&d),
            Err(GenerationError::Mismatch { .. })
        ));
    }

    #[test]
    fn a_missing_or_stale_record_falls_back_to_hashing_and_is_rewritten() {
        let dir = tempfile::tempdir().unwrap();
        let (store, d) = installed(dir.path(), 'c');
        let record = store.record_path(&d);
        let original = fs::read(&record).unwrap();
        let daemon = store.generation_dir(&d).join(HOST_DAEMON_FILE);

        fs::remove_file(&record).unwrap();
        store.open_cached(&d).unwrap();
        assert_eq!(fs::read(&record).unwrap(), original);

        // The same bytes with a new mtime: hashed again (it still matches), then recorded.
        let later =
            fs::metadata(&daemon).unwrap().modified().unwrap() + std::time::Duration::from_secs(5);
        daemon_touch(&daemon, later);
        store.open_cached(&d).unwrap();
        assert_ne!(fs::read(&record).unwrap(), original);
        // ... and the next cached open trusts the refreshed record.
        rewrite_in_place(&daemon, b"DAEMON", Some(later));
        store.open_cached(&d).unwrap();

        // Garbage in the record is ignored, not trusted (the rewrite above is now caught).
        fs::write(&record, b"not toml").unwrap();
        assert!(matches!(
            store.open_cached(&d),
            Err(GenerationError::Mismatch { .. })
        ));
    }

    fn daemon_touch(path: &Path, mtime: std::time::SystemTime) {
        fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(mtime)
            .unwrap();
    }

    #[test]
    fn a_record_for_another_manifest_entry_is_not_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let (store, d) = installed(dir.path(), 'd');
        let daemon = store.generation_dir(&d).join(HOST_DAEMON_FILE);
        let mtime = fs::metadata(&daemon).unwrap().modified().unwrap();
        rewrite_in_place(&daemon, b"DAEMON", Some(mtime));

        // The stamps still match, but the record vouches for a different digest than the manifest's.
        let mut record = store.read_record(&d).unwrap();
        record.files[0].digest = digest('0');
        fs::write(store.record_path(&d), toml::to_string(&record).unwrap()).unwrap();
        assert!(matches!(
            store.open_cached(&d),
            Err(GenerationError::Mismatch { .. })
        ));
    }

    #[test]
    fn gc_removes_the_record_with_its_generation() {
        let dir = tempfile::tempdir().unwrap();
        let (store, keep) = installed(dir.path(), 'a');
        let staging = staging_with(&store, b"other", b"cli");
        let drop = digest('b');
        store
            .install(&staging, &drop, &expected(b"other", b"cli"))
            .unwrap();
        assert!(store.record_path(&drop).is_file());
        let selector = HostSelector {
            format_version: crate::selector::FORMAT_VERSION,
            epoch: 1,
            active: keep.clone(),
            previous: None,
            candidate: None,
        };
        store.gc(&selector, &[]).unwrap();
        assert!(!store.record_path(&drop).exists());
        assert!(store.record_path(&keep).is_file());
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
