//! `platform-service.toml` and `runtime-jobs.toml`.
//!
//! The service selection is the host adapter's immutable intent: the desired daemon digest, the
//! activation epoch and the exact rendered `podman` argument vector. It lives in the host-only
//! directory, is written atomically under the service-selection lock, and never contains shell text.
//! The launcher re-hashes the vector before executing it, so a damaged or hand-edited file cannot
//! smuggle in a different command.
//!
//! `runtime-jobs.toml` holds the runtime enable flags. Cron/systemd entries are installer-owned and
//! are never rewritten to toggle a job.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use weglarka_model::fsutil::write_atomic;
use weglarka_model::release_set::StrictDigest;

use crate::host::{
    HostError, RUNTIME_JOBS_FILE, RUNTIME_JOBS_LOCK, RUNTIME_JOBS_MAX_BYTES,
    SERVICE_SELECTION_FILE, SERVICE_SELECTION_LOCK, SERVICE_SELECTION_MAX_BYTES, read_bounded,
};
use crate::lock::{self, LockError};

/// Format version of both files.
pub const FORMAT_VERSION: u32 = 1;
/// Label carrying the activation epoch on the daemon container.
pub const LABEL_ACTIVATION_EPOCH: &str = "io.weglarka.activation-epoch";
/// Label carrying the selected daemon digest on the daemon container.
pub const LABEL_DAEMON_DIGEST: &str = "io.weglarka.daemon-digest";

/// `platform-service.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformService {
    pub format_version: u32,
    pub service: String,
    /// Pinned `repository@sha256:…` reference; must agree with `digest`.
    pub image: String,
    pub digest: StrictDigest,
    /// Monotonic activation epoch.
    pub epoch: u64,
    /// Complete argument vector for `podman`, without the program name.
    pub argv: Vec<String>,
    /// SHA-256 over the fields above and the argument vector.
    pub argv_sha256: StrictDigest,
}

#[derive(Debug, thiserror::Error)]
pub enum SelectionError {
    #[error(transparent)]
    Host(#[from] HostError),
    #[error("invalid {SERVICE_SELECTION_FILE}: {0}")]
    Parse(String),
    #[error("unsupported {SERVICE_SELECTION_FILE} format_version {0}")]
    UnsupportedFormat(u32),
    #[error("invalid service selection: {0}")]
    Invalid(String),
    #[error("cannot encode {SERVICE_SELECTION_FILE}: {0}")]
    Encode(String),
    #[error("the argument vector hash does not match the selection")]
    HashMismatch,
    /// A write that would move the activation epoch backwards, or change what an epoch names. The
    /// stored selection is left as it was; the request is obsolete.
    #[error(
        "stale activation: the stored selection is at epoch {stored}, the request is for epoch {requested}"
    )]
    Stale { stored: u64, requested: u64 },
    #[error(transparent)]
    Lock(#[from] LockError),
}

#[derive(Deserialize)]
struct FormatProbe {
    #[serde(default)]
    format_version: Option<u32>,
}

impl PlatformService {
    pub fn path(host_dir: &Path) -> PathBuf {
        host_dir.join(SERVICE_SELECTION_FILE)
    }

    /// Builds a selection from the desired identity and its rendered argument vector.
    pub fn build(
        service: impl Into<String>,
        image: impl Into<String>,
        digest: StrictDigest,
        epoch: u64,
        argv: Vec<String>,
    ) -> Result<Self, SelectionError> {
        let mut selection = Self {
            format_version: FORMAT_VERSION,
            service: service.into(),
            image: image.into(),
            digest,
            epoch,
            argv,
            // Replaced below; a placeholder lets `hash()` see the final fields.
            argv_sha256: StrictDigest::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
        };
        selection.argv_sha256 = selection.hash()?;
        selection.validate()?;
        Ok(selection)
    }

    /// SHA-256 of the selection identity and the argument vector (length-prefixed, unambiguous).
    pub fn hash(&self) -> Result<StrictDigest, SelectionError> {
        let mut hasher = Sha256::new();
        feed(&mut hasher, b"weglarka-platform-service-v1");
        feed(&mut hasher, &self.format_version.to_le_bytes());
        feed(&mut hasher, self.service.as_bytes());
        feed(&mut hasher, self.image.as_bytes());
        feed(&mut hasher, self.digest.as_str().as_bytes());
        feed(&mut hasher, &self.epoch.to_le_bytes());
        feed(&mut hasher, &(self.argv.len() as u64).to_le_bytes());
        for arg in &self.argv {
            feed(&mut hasher, arg.as_bytes());
        }
        StrictDigest::new(format!("sha256:{}", hex::encode(hasher.finalize())))
            .map_err(|_| SelectionError::Invalid("cannot encode the argument-vector hash".into()))
    }

    pub fn validate(&self) -> Result<(), SelectionError> {
        if self.format_version != FORMAT_VERSION {
            return Err(SelectionError::UnsupportedFormat(self.format_version));
        }
        if self.service.is_empty() || self.service.len() > 255 {
            return Err(SelectionError::Invalid(
                "service name must be 1-255 characters".into(),
            ));
        }
        let digest = self.digest.as_str();
        if !self.image.ends_with(&format!("@{digest}")) || self.image.matches('@').count() != 1 {
            return Err(SelectionError::Invalid(format!(
                "image {:?} is not pinned to {}",
                self.image, self.digest
            )));
        }
        if self.epoch == 0 {
            return Err(SelectionError::Invalid(
                "activation epoch is zero; it is monotonic and starts at 1".into(),
            ));
        }
        if self.argv.is_empty() || self.argv.len() > 4096 {
            return Err(SelectionError::Invalid(
                "the argument vector must have 1-4096 entries".into(),
            ));
        }
        let mut total = 0usize;
        for arg in &self.argv {
            if arg.len() > 8192 || arg.chars().any(|c| c == '\n' || c == '\r' || c == '\0') {
                return Err(SelectionError::Invalid(
                    "argument contains a newline, NUL or is too long".into(),
                ));
            }
            total += arg.len();
        }
        if total > SERVICE_SELECTION_MAX_BYTES {
            return Err(SelectionError::Invalid(
                "the argument vector is larger than the service-selection limit".into(),
            ));
        }
        // The fixed Podman shape: name first, exactly one pinned image token.
        if self.argv.first().map(String::as_str) != Some("--name")
            || self.argv.get(1) != Some(&self.service)
        {
            return Err(SelectionError::Invalid(
                "the argument vector must start with `--name <service>`".into(),
            ));
        }
        let images = self
            .argv
            .iter()
            .filter(|arg| arg.as_str() == self.image)
            .count();
        if images != 1 {
            return Err(SelectionError::Invalid(
                "the argument vector must contain the pinned image exactly once".into(),
            ));
        }
        let epoch = self.epoch.to_string();
        if label(&self.argv, LABEL_ACTIVATION_EPOCH) != Some(epoch.as_str()) {
            return Err(SelectionError::Invalid(format!(
                "the argument vector must carry {LABEL_ACTIVATION_EPOCH}={}",
                self.epoch
            )));
        }
        if label(&self.argv, LABEL_DAEMON_DIGEST) != Some(digest) {
            return Err(SelectionError::Invalid(format!(
                "the argument vector must carry {LABEL_DAEMON_DIGEST}={digest}"
            )));
        }
        if self.hash()? != self.argv_sha256 {
            return Err(SelectionError::HashMismatch);
        }
        Ok(())
    }

    pub fn load(host_dir: &Path) -> Result<Option<Self>, SelectionError> {
        let path = Self::path(host_dir);
        let Some(text) = read_bounded(&path, SERVICE_SELECTION_FILE, SERVICE_SELECTION_MAX_BYTES)?
        else {
            return Ok(None);
        };
        let probe: FormatProbe =
            toml::from_str(&text).map_err(|e| SelectionError::Parse(e.to_string()))?;
        match probe.format_version {
            Some(FORMAT_VERSION) => {}
            Some(other) => return Err(SelectionError::UnsupportedFormat(other)),
            None => return Err(SelectionError::Parse("missing format_version".into())),
        }
        let selection: Self =
            toml::from_str(&text).map_err(|e| SelectionError::Parse(e.to_string()))?;
        selection.validate()?;
        Ok(Some(selection))
    }

    pub fn to_toml(&self) -> Result<String, SelectionError> {
        self.validate()?;
        toml::to_string(self).map_err(|e| SelectionError::Encode(e.to_string()))
    }

    /// Writes the selection atomically. The caller must hold [`lock_service_selection`].
    ///
    /// Forward only: a lower `epoch` than the stored one, or the same `epoch` naming another image,
    /// digest or argument vector, is refused with [`SelectionError::Stale`] and the file is left as
    /// it was. Writing exactly the stored selection again is a no-op success. Order is by epoch,
    /// never by wall clock or by who arrives last.
    pub fn save(&self, host_dir: &Path) -> Result<(), SelectionError> {
        if let Some(stored) = Self::load(host_dir)?
            && (self.epoch < stored.epoch || (self.epoch == stored.epoch && *self != stored))
        {
            return Err(SelectionError::Stale {
                stored: stored.epoch,
                requested: self.epoch,
            });
        }
        let text = self.to_toml()?;
        write_atomic(&Self::path(host_dir), text.as_bytes(), 0o600).map_err(|source| {
            SelectionError::Host(HostError::Write {
                path: Self::path(host_dir),
                source,
            })
        })
    }

    /// Reads the selection under the service-selection lock (the contract's re-read before a stop).
    pub fn read_locked(host_dir: &Path) -> Result<Option<Self>, SelectionError> {
        let _guard = lock_service_selection(host_dir)?;
        Self::load(host_dir)
    }

    /// Writes a selection under the service-selection lock (forward only, see [`Self::save`]).
    ///
    /// The host directory is created by bootstrap with its ownership model (`1770`, root-owned code);
    /// this never changes its mode.
    pub fn write_locked(
        host_dir: &Path,
        selection: &PlatformService,
    ) -> Result<(), SelectionError> {
        create_host_dir(host_dir)?;
        let _guard = lock_service_selection(host_dir)?;
        selection.save(host_dir)
    }
}

fn label<'a>(argv: &'a [String], key: &str) -> Option<&'a str> {
    let prefix = format!("{key}=");
    for (index, arg) in argv.iter().enumerate() {
        if arg == "--label"
            && let Some(value) = argv
                .get(index + 1)
                .and_then(|value| value.strip_prefix(&prefix))
        {
            return Some(value);
        }
        if let Some(value) = arg.strip_prefix("--label=")
            && let Some(value) = value.strip_prefix(&prefix)
        {
            return Some(value);
        }
    }
    None
}

fn feed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// Creates the host directory when it is missing (a no-op on an installed host). Its mode is never
/// changed here: bootstrap owns the ownership model.
pub fn create_host_dir(host_dir: &Path) -> Result<(), SelectionError> {
    std::fs::create_dir_all(host_dir).map_err(|source| {
        SelectionError::Host(HostError::Write {
            path: host_dir.to_owned(),
            source,
        })
    })
}

/// Takes the service-selection lock.
pub fn lock_service_selection(host_dir: &Path) -> Result<lock::HostLock, SelectionError> {
    Ok(lock::lock(&host_dir.join(SERVICE_SELECTION_LOCK))?)
}

/// Typed runtime job. Kept free of the engine's `JobId` so this crate stays a leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Job {
    Update,
    Watchdog,
}

impl Job {
    pub const fn as_str(self) -> &'static str {
        match self {
            Job::Update => "update",
            Job::Watchdog => "watchdog",
        }
    }
}

/// `runtime-jobs.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeJobs {
    pub format_version: u32,
    #[serde(default = "default_true")]
    pub update: bool,
    #[serde(default = "default_true")]
    pub watchdog: bool,
}

fn default_true() -> bool {
    true
}

impl Default for RuntimeJobs {
    fn default() -> Self {
        Self {
            format_version: FORMAT_VERSION,
            update: true,
            watchdog: true,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeJobsError {
    #[error(transparent)]
    Host(#[from] HostError),
    #[error("invalid {RUNTIME_JOBS_FILE}: {0}")]
    Parse(String),
    #[error("unsupported {RUNTIME_JOBS_FILE} format_version {0}")]
    UnsupportedFormat(u32),
    #[error("cannot encode {RUNTIME_JOBS_FILE}: {0}")]
    Encode(String),
    #[error(transparent)]
    Lock(#[from] LockError),
}

impl RuntimeJobs {
    pub fn path(state_dir: &Path) -> PathBuf {
        state_dir.join(RUNTIME_JOBS_FILE)
    }

    pub fn load(state_dir: &Path) -> Result<Self, RuntimeJobsError> {
        let path = Self::path(state_dir);
        let Some(text) = read_bounded(&path, RUNTIME_JOBS_FILE, RUNTIME_JOBS_MAX_BYTES)? else {
            return Ok(Self::default());
        };
        let probe: FormatProbe =
            toml::from_str(&text).map_err(|e| RuntimeJobsError::Parse(e.to_string()))?;
        match probe.format_version {
            Some(FORMAT_VERSION) => {}
            Some(other) => return Err(RuntimeJobsError::UnsupportedFormat(other)),
            None => return Err(RuntimeJobsError::Parse("missing format_version".into())),
        }
        let jobs: Self =
            toml::from_str(&text).map_err(|e| RuntimeJobsError::Parse(e.to_string()))?;
        Ok(jobs)
    }

    pub fn enabled(&self, job: Job) -> bool {
        match job {
            Job::Update => self.update,
            Job::Watchdog => self.watchdog,
        }
    }

    pub fn set(&mut self, job: Job, enabled: bool) {
        match job {
            Job::Update => self.update = enabled,
            Job::Watchdog => self.watchdog = enabled,
        }
    }

    pub fn to_toml(&self) -> Result<String, RuntimeJobsError> {
        if self.format_version != FORMAT_VERSION {
            return Err(RuntimeJobsError::UnsupportedFormat(self.format_version));
        }
        toml::to_string(self).map_err(|e| RuntimeJobsError::Encode(e.to_string()))
    }

    pub fn save(&self, state_dir: &Path) -> Result<(), RuntimeJobsError> {
        let text = self.to_toml()?;
        write_atomic(&Self::path(state_dir), text.as_bytes(), 0o600).map_err(|source| {
            RuntimeJobsError::Host(HostError::Write {
                path: Self::path(state_dir),
                source,
            })
        })
    }

    /// Read-modify-write under the runtime-jobs lock, so two toggles cannot lose each other.
    pub fn set_enabled(state_dir: &Path, job: Job, enabled: bool) -> Result<(), RuntimeJobsError> {
        std::fs::create_dir_all(state_dir).map_err(|source| {
            RuntimeJobsError::Host(HostError::Write {
                path: state_dir.to_owned(),
                source,
            })
        })?;
        let _guard = lock::lock(&state_dir.join(RUNTIME_JOBS_LOCK))?;
        let mut jobs = Self::load(state_dir)?;
        jobs.set(job, enabled);
        jobs.save(state_dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn digest(byte: char) -> StrictDigest {
        StrictDigest::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn argv(service: &str, image: &str, epoch: u64, digest: &StrictDigest) -> Vec<String> {
        vec![
            "--name".into(),
            service.into(),
            "--label".into(),
            format!("{LABEL_ACTIVATION_EPOCH}={epoch}"),
            format!("--label={LABEL_DAEMON_DIGEST}={digest}"),
            image.into(),
        ]
    }

    fn selection() -> PlatformService {
        let d = digest('a');
        let image = format!("ghcr.io/example/weglarka@{d}");
        PlatformService::build(
            "weglarka",
            image.clone(),
            d.clone(),
            7,
            argv("weglarka", &image, 7, &d),
        )
        .unwrap()
    }

    #[test]
    fn the_selection_round_trips_and_hashes_the_vector() {
        let s = selection();
        let text = s.to_toml().unwrap();
        let parsed: PlatformService = toml::from_str(&text).unwrap();
        parsed.validate().unwrap();
        assert_eq!(parsed, s);

        let mut tampered = parsed;
        tampered.argv.push("--privileged".into());
        assert!(matches!(
            tampered.validate(),
            Err(SelectionError::HashMismatch)
        ));
    }

    fn selection_at(epoch: u64, byte: char) -> PlatformService {
        let d = digest(byte);
        let image = format!("ghcr.io/example/weglarka@{d}");
        PlatformService::build(
            "weglarka",
            image.clone(),
            d.clone(),
            epoch,
            argv("weglarka", &image, epoch, &d),
        )
        .unwrap()
    }

    #[test]
    fn the_selection_epoch_only_moves_forward() {
        let dir = tempfile::tempdir().unwrap();
        let host = dir.path();
        PlatformService::write_locked(host, &selection_at(4, 'a')).unwrap();
        let stored = std::fs::read_to_string(PlatformService::path(host)).unwrap();

        // Epoch 3 after epoch 4 is stale; so is epoch 4 naming another digest.
        for stale in [selection_at(3, 'b'), selection_at(4, 'b')] {
            assert!(matches!(
                PlatformService::write_locked(host, &stale),
                Err(SelectionError::Stale { stored: 4, .. })
            ));
        }
        assert_eq!(
            std::fs::read_to_string(PlatformService::path(host)).unwrap(),
            stored,
            "a refused write leaves the file untouched"
        );
        // The same selection again is idempotent; a higher epoch moves forward.
        PlatformService::write_locked(host, &selection_at(4, 'a')).unwrap();
        PlatformService::write_locked(host, &selection_at(5, 'b')).unwrap();
        assert_eq!(PlatformService::load(host).unwrap().unwrap().epoch, 5);
    }

    #[test]
    fn a_missing_epoch_label_or_unpinned_image_is_rejected() {
        let d = digest('b');
        let image = format!("ghcr.io/example/weglarka@{d}");
        let mut bad = argv("weglarka", &image, 7, &d);
        bad.retain(|a| !a.starts_with(LABEL_ACTIVATION_EPOCH));
        assert!(PlatformService::build("weglarka", image.clone(), d.clone(), 7, bad).is_err());

        let floating = vec![
            "--name".into(),
            "weglarka".into(),
            "ghcr.io/example/weglarka:latest".into(),
        ];
        assert!(
            PlatformService::build(
                "weglarka",
                "ghcr.io/example/weglarka:latest",
                d,
                7,
                floating
            )
            .is_err()
        );
    }

    #[test]
    fn atomic_write_is_mode_0600_and_absent_means_none() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(PlatformService::load(dir.path()).unwrap(), None);
        let s = selection();
        s.save(dir.path()).unwrap();
        assert_eq!(PlatformService::load(dir.path()).unwrap(), Some(s));
        let mode = std::fs::metadata(PlatformService::path(dir.path()))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn runtime_jobs_default_on_and_toggle_independently() {
        let dir = tempfile::tempdir().unwrap();
        let jobs = RuntimeJobs::load(dir.path()).unwrap();
        assert!(jobs.update && jobs.watchdog);
        RuntimeJobs::set_enabled(dir.path(), Job::Update, false).unwrap();
        RuntimeJobs::set_enabled(dir.path(), Job::Watchdog, false).unwrap();
        let jobs = RuntimeJobs::load(dir.path()).unwrap();
        assert!(!jobs.update && !jobs.watchdog);
        RuntimeJobs::set_enabled(dir.path(), Job::Update, true).unwrap();
        let jobs = RuntimeJobs::load(dir.path()).unwrap();
        assert!(jobs.update && !jobs.watchdog);
    }
}
