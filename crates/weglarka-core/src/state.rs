//! Stan na dysku: `apps.toml` (stan pożądany) i `state.toml` (stan runtime'owy).
//!
//! Oba pliki pisze wyłącznie demon, zawsze atomowo (tmp w tym samym katalogu + `fsync` + `rename`
//! + `fsync` katalogu). Odczyt waliduje zawartość (`deny_unknown_fields` + niezmienniki).
//!
//! Decyzja o podziale na dwa pliki: `docs/decisions/0003-state-toml.md`.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::app::{AppSpec, AppsFile, Digest, InstanceName};
use crate::hash::SpecHash;

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("i/o error on {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("cannot parse {path}: {message}")]
    Parse { path: PathBuf, message: String },
    #[error("invalid {path}: {reason}")]
    Invalid { path: PathBuf, reason: String },
}

/// Ostatni nieudany deploy — oznaczenie, żeby webhook/reconcile nie próbowały w kółko tego samego.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailedDeploy {
    pub digest: Digest,
    pub reason: String,
}

/// Stan jednej instancji. `previous` to retencja 1 do rollbacku.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppState {
    /// Numer generacji kontenera (rośnie przy każdym odtworzeniu).
    #[serde(default)]
    pub generation: u64,
    /// Aktualnie przypięty digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<Digest>,
    /// Poprzedni (znany dobry) digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<Digest>,
    /// Hash specyfikacji, z którym uruchomiono `current`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec_hash: Option<SpecHash>,
    /// Ostatni nieudany deploy (czyszczony po udanym).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<FailedDeploy>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateFile {
    #[serde(default)]
    pub apps: BTreeMap<InstanceName, AppState>,
}

/// Lokalizacja plików stanu (jeden katalog danych demona).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatePaths {
    pub apps: PathBuf,
    pub state: PathBuf,
}

impl StatePaths {
    pub fn in_dir(dir: impl AsRef<Path>) -> Self {
        let dir = dir.as_ref();
        Self {
            apps: dir.join("apps.toml"),
            state: dir.join("state.toml"),
        }
    }
}

fn io_err(path: &Path) -> impl FnOnce(io::Error) -> StateError + '_ {
    move |source| StateError::Io {
        path: path.to_owned(),
        source,
    }
}

/// Atomowy zapis: tmp w tym samym katalogu (tworzony z `mode`) → `fsync` → `rename` → `fsync` katalogu.
pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), io::Error> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let dir = dir.unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let tmp = dir.join(format!(".{}.tmp", file_name.to_string_lossy()));
    let result = (|| {
        // `create_new` + zawsze świeży plik: tmp nigdy nie dziedziczy cudzych praw/zawartości.
        let _ = fs::remove_file(&tmp);
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn read_optional(path: &Path) -> Result<Option<String>, StateError> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_err(path)(e)),
    }
}

fn invalid(path: &Path, reason: impl Into<String>) -> StateError {
    StateError::Invalid {
        path: path.to_owned(),
        reason: reason.into(),
    }
}

/// Niezmienniki `apps.toml`, których nie wyraża serde.
pub fn validate_app(name: &InstanceName, spec: &AppSpec) -> Result<(), String> {
    if spec.image.is_empty() || spec.image.chars().any(char::is_whitespace) {
        return Err(format!("{name}: image must be a non-empty reference"));
    }
    if spec.port == Some(0) {
        return Err(format!("{name}: port must be non-zero"));
    }
    if spec.health.attempts == 0 || spec.health.window_secs == 0 {
        return Err(format!("{name}: health attempts and window must be > 0"));
    }
    for b in &spec.secrets {
        if !crate::secret_store::valid_secret_name(&b.secret) {
            return Err(format!("{name}: invalid secret name {:?}", b.secret));
        }
    }
    Ok(())
}

pub fn load_apps(path: &Path) -> Result<AppsFile, StateError> {
    let Some(src) = read_optional(path)? else {
        return Ok(AppsFile::default());
    };
    let apps: AppsFile = toml::from_str(&src).map_err(|e| StateError::Parse {
        path: path.to_owned(),
        message: e.to_string(),
    })?;
    for (name, spec) in &apps.apps {
        validate_app(name, spec).map_err(|r| invalid(path, r))?;
    }
    Ok(apps)
}

pub fn save_apps(path: &Path, apps: &AppsFile) -> Result<(), StateError> {
    for (name, spec) in &apps.apps {
        validate_app(name, spec).map_err(|r| invalid(path, r))?;
    }
    let text = toml::to_string(apps).map_err(|e| invalid(path, e.to_string()))?;
    write_atomic(path, text.as_bytes(), 0o644).map_err(io_err(path))
}

fn validate_state(path: &Path, state: &StateFile) -> Result<(), StateError> {
    for (name, s) in &state.apps {
        if s.spec_hash.is_some() && s.current.is_none() {
            return Err(invalid(path, format!("{name}: spec_hash without current")));
        }
        if s.previous.is_some() && s.previous == s.current {
            return Err(invalid(path, format!("{name}: previous equals current")));
        }
    }
    Ok(())
}

pub fn load_state(path: &Path) -> Result<StateFile, StateError> {
    let Some(src) = read_optional(path)? else {
        return Ok(StateFile::default());
    };
    let state: StateFile = toml::from_str(&src).map_err(|e| StateError::Parse {
        path: path.to_owned(),
        message: e.to_string(),
    })?;
    validate_state(path, &state)?;
    Ok(state)
}

pub fn save_state(path: &Path, state: &StateFile) -> Result<(), StateError> {
    validate_state(path, state)?;
    let text = toml::to_string(state).map_err(|e| invalid(path, e.to_string()))?;
    write_atomic(path, text.as_bytes(), 0o644).map_err(io_err(path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn digest(c: char) -> Digest {
        Digest::new(format!("sha256:{}", c.to_string().repeat(64))).unwrap()
    }

    fn name(s: &str) -> InstanceName {
        InstanceName::new(s).unwrap()
    }

    #[test]
    fn state_roundtrip_and_missing_file_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let paths = StatePaths::in_dir(dir.path());
        assert_eq!(load_state(&paths.state).unwrap(), StateFile::default());

        let mut st = StateFile::default();
        st.apps.insert(
            name("ntfy"),
            AppState {
                generation: 3,
                current: Some(digest('a')),
                previous: Some(digest('b')),
                spec_hash: None,
                failed: Some(FailedDeploy {
                    digest: digest('c'),
                    reason: "unhealthy".into(),
                }),
            },
        );
        save_state(&paths.state, &st).unwrap();
        assert_eq!(load_state(&paths.state).unwrap(), st);
        insta::assert_snapshot!(fs::read_to_string(&paths.state).unwrap());
    }

    #[test]
    fn atomic_write_leaves_no_tmp_and_replaces_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.toml");
        write_atomic(&path, b"one", 0o600).unwrap();
        write_atomic(&path, b"two", 0o600).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "two");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let names: Vec<_> = fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(names.len(), 1);
    }

    #[test]
    fn rejects_unknown_fields_and_broken_invariants() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("state.toml");
        fs::write(&p, "[apps.a]\nbogus = 1\n").unwrap();
        assert!(matches!(load_state(&p), Err(StateError::Parse { .. })));

        let hash = "0".repeat(64);
        fs::write(&p, format!("[apps.a]\nspec_hash = \"{hash}\"\n")).unwrap();
        assert!(matches!(load_state(&p), Err(StateError::Invalid { .. })));

        let d = digest('a');
        fs::write(
            &p,
            format!("[apps.a]\ncurrent = \"{d}\"\nprevious = \"{d}\"\n"),
        )
        .unwrap();
        assert!(matches!(load_state(&p), Err(StateError::Invalid { .. })));

        fs::write(&p, "[apps.A_b]\n").unwrap();
        assert!(matches!(load_state(&p), Err(StateError::Parse { .. })));
    }

    #[test]
    fn apps_validation() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("apps.toml");
        fs::write(&p, "[apps.a]\nimage = \"x y\"\n").unwrap();
        assert!(matches!(load_apps(&p), Err(StateError::Invalid { .. })));
        fs::write(&p, "[apps.a]\nimage = \"x:1\"\nhealth = { attempts = 0 }\n").unwrap();
        assert!(matches!(load_apps(&p), Err(StateError::Invalid { .. })));
        fs::write(&p, "[apps.a]\nimage = \"x:1\"\n").unwrap();
        let apps = load_apps(&p).unwrap();
        save_apps(&p, &apps).unwrap();
        assert_eq!(load_apps(&p).unwrap(), apps);
    }
}
