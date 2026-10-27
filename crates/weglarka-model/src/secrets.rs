//! `secrets.toml` (0600) as a [`SecretStore`] implementation. Values never reach logs or `Debug`.
//! Delivering secrets to containers is the engine's job (`weglarka_engine::secrets`).

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::fsutil::write_atomic;
use crate::secret_store::{
    SecretError, SecretMeta, SecretStore, SecretValue, fingerprint, split_scoped,
};

#[derive(Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct SecretsFile {
    #[serde(default)]
    secrets: BTreeMap<String, Entry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    value: String,
    updated_at: String,
}

/// Store in a TOML file with 0600 permissions. Values must be UTF-8 (API keys, JSON configs).
/// A file with looser permissions is rejected on every read ([`SecretError::Permissions`]).
pub struct FileSecretStore {
    path: PathBuf,
    clock: Box<dyn Fn() -> SystemTime + Send + Sync>,
    /// Serializes the read-modify-write cycle within the process (sole writer: the daemon).
    write_lock: Mutex<()>,
}

fn io_err(e: io::Error) -> SecretError {
    SecretError::Io(e.to_string())
}

impl FileSecretStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self::with_clock(path, SystemTime::now)
    }

    pub fn with_clock(
        path: impl Into<PathBuf>,
        clock: impl Fn() -> SystemTime + Send + Sync + 'static,
    ) -> Self {
        Self {
            path: path.into(),
            clock: Box::new(clock),
            write_lock: Mutex::new(()),
        }
    }

    /// Creates an empty file with 0600 permissions if missing; leaves an existing one alone.
    pub fn init(&self) -> Result<(), SecretError> {
        if self.path.exists() {
            return Ok(());
        }
        write_atomic(&self.path, b"", 0o600).map_err(io_err)
    }

    /// Sets 0600 permissions on an existing file (repair after `doctor`).
    pub fn restrict_permissions(&self) -> Result<(), SecretError> {
        fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600)).map_err(io_err)
    }

    /// Checks the file's permissions (missing file = OK, it will be created with 0600).
    pub fn check_permissions(&self) -> Result<(), SecretError> {
        match fs::metadata(&self.path) {
            Ok(m) if m.permissions().mode() & 0o077 != 0 => Err(SecretError::Permissions {
                path: self.path.display().to_string(),
                reason: format!("mode {:o}, expected 600", m.permissions().mode() & 0o777),
            }),
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io_err(e)),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read(&self) -> Result<SecretsFile, SecretError> {
        self.check_permissions()?;
        let src = match fs::read_to_string(&self.path) {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(SecretsFile::default()),
            Err(e) => return Err(io_err(e)),
        };
        // Only `message()`: the full `Display` of a TOML error quotes a source fragment, i.e. values.
        let file: SecretsFile =
            toml::from_str(&src).map_err(|e| SecretError::Corrupt(e.message().to_owned()))?;
        for name in file.secrets.keys() {
            split_scoped(name).map_err(|_| SecretError::Corrupt("invalid secret name".into()))?;
        }
        Ok(file)
    }

    fn write(&self, file: &SecretsFile) -> Result<(), SecretError> {
        let text = toml::to_string(file).map_err(|e| SecretError::Io(e.to_string()))?;
        write_atomic(&self.path, text.as_bytes(), 0o600).map_err(io_err)
    }
}

impl SecretStore for FileSecretStore {
    fn get(&self, name: &str) -> Result<Option<SecretValue>, SecretError> {
        split_scoped(name)?;
        Ok(self
            .read()?
            .secrets
            .remove(name)
            .map(|e| SecretValue::new(e.value.into_bytes())))
    }

    fn set(&self, name: &str, value: SecretValue) -> Result<(), SecretError> {
        split_scoped(name)?;
        let text = String::from_utf8(value.expose().to_vec())
            .map_err(|_| SecretError::NotUtf8(name.to_owned()))?;
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut file = self.read()?;
        file.secrets.insert(
            name.to_owned(),
            Entry {
                value: text,
                updated_at: rfc3339_utc((self.clock)()),
            },
        );
        self.write(&file)
    }

    fn remove(&self, name: &str) -> Result<(), SecretError> {
        split_scoped(name)?;
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut file = self.read()?;
        file.secrets
            .remove(name)
            .ok_or_else(|| SecretError::NotFound(name.to_owned()))?;
        self.write(&file)
    }

    fn list(&self) -> Result<Vec<SecretMeta>, SecretError> {
        Ok(self
            .read()?
            .secrets
            .into_iter()
            .map(|(name, e)| SecretMeta {
                fingerprint: fingerprint(&SecretValue::new(e.value.into_bytes())),
                name,
                updated_at: e.updated_at,
            })
            .collect())
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ` without depending on `chrono` (Howard Hinnant's civil-from-days algorithm).
pub fn rfc3339_utc(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()) as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn store(dir: &Path) -> FileSecretStore {
        FileSecretStore::with_clock(dir.join("secrets.toml"), || {
            UNIX_EPOCH + Duration::from_secs(1_792_000_000)
        })
    }

    #[test]
    fn rfc3339_known_values() {
        assert_eq!(rfc3339_utc(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        assert_eq!(
            rfc3339_utc(UNIX_EPOCH + Duration::from_secs(1_709_164_800 + 86_399)),
            "2024-02-29T23:59:59Z"
        );
    }

    #[test]
    fn set_get_list_remove_with_0600() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        assert!(s.list().unwrap().is_empty());
        s.set("ntfy.config", SecretValue::new("{\"k\":1}")).unwrap();
        s.set("ntfy.token", SecretValue::new("s3cr3t")).unwrap();

        let mode = fs::metadata(s.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(s.get("ntfy.token").unwrap().unwrap().expose(), b"s3cr3t");
        assert!(s.get("ntfy.nope").unwrap().is_none());

        let metas = s.list().unwrap();
        assert_eq!(metas.len(), 2);
        assert_eq!(metas[0].name, "ntfy.config");
        assert_eq!(metas[0].updated_at, "2026-10-14T17:46:40Z");
        assert_eq!(metas[0].fingerprint.len(), 8);
        let dbg = format!("{metas:?}");
        assert!(!dbg.contains("s3cr3t") && !dbg.contains("\"k\""));

        s.remove("ntfy.token").unwrap();
        assert!(matches!(
            s.remove("ntfy.token"),
            Err(SecretError::NotFound(_))
        ));
    }

    #[test]
    fn fingerprint_changes_with_value() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        s.set("a.k", SecretValue::new("one")).unwrap();
        let f1 = s.list().unwrap()[0].fingerprint.clone();
        s.set("a.k", SecretValue::new("two")).unwrap();
        assert_ne!(f1, s.list().unwrap()[0].fingerprint);
    }

    #[test]
    fn rejects_loose_permissions_and_can_fix_them() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        s.set("a.k", SecretValue::new("v")).unwrap();
        fs::set_permissions(s.path(), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(s.get("a.k"), Err(SecretError::Permissions { .. })));
        assert!(matches!(
            s.set("a.k", SecretValue::new("w")),
            Err(SecretError::Permissions { .. })
        ));
        s.restrict_permissions().unwrap();
        assert!(s.get("a.k").unwrap().is_some());
    }

    #[test]
    fn rejects_bad_names_and_non_utf8_and_corrupt_never_leaks() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        for bad in ["nodot", "A.k", "a.", "a.b.c", "a.k k", ".k"] {
            assert!(matches!(
                s.set(bad, SecretValue::new("v")),
                Err(SecretError::InvalidName(_))
            ));
        }
        assert!(matches!(
            s.set("a.k", SecretValue::new(vec![0xff, 0xfe])),
            Err(SecretError::NotUtf8(_))
        ));
        s.init().unwrap();
        fs::write(
            s.path(),
            "[secrets.\"a.k\"]\nvalue = \"TOPSECRET\"\nbogus = 1\n",
        )
        .unwrap();
        fs::set_permissions(s.path(), fs::Permissions::from_mode(0o600)).unwrap();
        let err = s.list().unwrap_err();
        assert!(matches!(err, SecretError::Corrupt(_)));
        assert!(!err.to_string().contains("TOPSECRET"));
    }

    #[test]
    fn init_creates_0600_and_does_not_touch_existing() {
        let dir = tempfile::tempdir().unwrap();
        let s = store(dir.path());
        s.init().unwrap();
        assert_eq!(
            fs::metadata(s.path()).unwrap().permissions().mode() & 0o777,
            0o600
        );
        s.set("a.k", SecretValue::new("v")).unwrap();
        s.init().unwrap();
        assert!(s.get("a.k").unwrap().is_some());
    }
}
