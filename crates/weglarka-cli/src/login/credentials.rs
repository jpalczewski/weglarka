//! `credentials.toml`: the tokens `weglarka login` obtained, one entry per host, next to `cli.toml`
//! (mode 0600, its directory 0700). Reads and read-modify-writes go through [`Store::update`],
//! which holds an advisory lock so two CLI processes cannot race a rotating refresh token.
//! Nothing here is ever printed, logged or put in an error (docs/decisions/0060).

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use weglarka_model::fsutil::write_atomic;
use weglarka_oidc::Url;

use crate::error::{CliError, Kind};

const FILE_MODE: u32 = 0o600;
const DIR_MODE: u32 = 0o700;

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    #[serde(default)]
    pub hosts: BTreeMap<String, HostEntry>,
}

/// What `login` stored for one host.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostEntry {
    pub issuer: String,
    pub client_id: String,
    pub audience: String,
    pub access_token: String,
    /// Unix seconds.
    pub access_expires: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

impl fmt::Debug for HostEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostEntry")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("access_expires", &self.access_expires)
            .field("tokens", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.hosts.keys()).finish()
    }
}

/// `https://host[:port]` (or `http://` on loopback), lower-cased, with nothing after the authority:
/// the key under which a host's tokens are stored and the base of every API call.
pub fn normalize_host(raw: &str) -> Result<String, CliError> {
    let bad = |why: &str| {
        CliError::usage(format!("invalid --host {raw:?}: {why}"))
            .with_hint("pass the panel's address, e.g. `--host https://panel.example.com`")
    };
    let url = Url::parse(raw).map_err(|_| bad("not a URL"))?;
    let host = url.host_str().ok_or_else(|| bad("no host"))?;
    let loopback = host
        .trim_matches(['[', ']'])
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback());
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(bad("must be an https:// URL"));
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(bad("must be just a scheme, host and optional port"));
    }
    Ok(url.origin().ascii_serialization())
}

pub struct Store {
    path: PathBuf,
}

impl Store {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// `credentials.toml` beside `cli.toml`; no home directory means no place to keep tokens.
    pub fn default_location() -> Result<Self, CliError> {
        let cli_toml = crate::user_config::default_path(
            std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
            std::env::var_os("HOME").map(PathBuf::from),
        )
        .ok_or_else(|| {
            CliError::new(
                Kind::Config,
                "cannot tell where to keep credentials: HOME is not set",
            )
            .with_hint("set HOME or XDG_CONFIG_HOME")
        })?;
        Ok(Self::new(cli_toml.with_file_name("credentials.toml")))
    }

    /// Takes the advisory lock; it is held until the guard is dropped.
    pub fn lock(&self) -> Result<Locked<'_>, CliError> {
        let dir = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::DirBuilder::new()
            .recursive(true)
            .mode(DIR_MODE)
            .create(dir)
            .map_err(|e| self.io("create the directory of", e))?;
        let file = open_lock(&self.path).map_err(|e| self.io("lock", e))?;
        file.lock().map_err(|e| self.io("lock", e))?;
        Ok(Locked {
            store: self,
            _lock: file,
        })
    }

    /// Runs `f` on the current contents under the lock and stores what it leaves behind.
    pub fn update<R>(&self, f: impl FnOnce(&mut Credentials) -> R) -> Result<R, CliError> {
        let locked = self.lock()?;
        let mut credentials = locked.read()?;
        let out = f(&mut credentials);
        locked.write(&credentials)?;
        Ok(out)
    }

    fn io(&self, what: &str, e: std::io::Error) -> CliError {
        CliError::new(
            Kind::Config,
            format!("cannot {what} {}: {e}", self.path.display()),
        )
    }

    /// The stored credentials without taking the lock (the file is replaced atomically).
    pub fn read(&self) -> Result<Credentials, CliError> {
        match fs::read_to_string(&self.path) {
            Ok(text) => toml::from_str(&text).map_err(|_| {
                CliError::new(
                    Kind::Config,
                    format!("{} is not a valid credentials file", self.path.display()),
                )
                .with_hint("remove it and run `weglarka login` again")
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Credentials::default()),
            Err(e) => Err(CliError::new(
                Kind::Config,
                format!("cannot read {}: {e}", self.path.display()),
            )),
        }
    }
}

/// The store while its lock is held.
pub struct Locked<'a> {
    store: &'a Store,
    _lock: File,
}

impl Locked<'_> {
    pub fn read(&self) -> Result<Credentials, CliError> {
        self.store.read()
    }

    pub fn write(&self, credentials: &Credentials) -> Result<(), CliError> {
        let text = toml::to_string(credentials)
            .map_err(|e| CliError::internal(format!("cannot serialize credentials: {e}")))?;
        write_atomic(&self.store.path, text.as_bytes(), FILE_MODE)
            .map_err(|e| self.store.io("write", e))
    }
}

fn open_lock(path: &Path) -> std::io::Result<File> {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".lock");
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(FILE_MODE)
        .open(path.with_file_name(name))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn entry() -> HostEntry {
        HostEntry {
            issuer: "https://auth.example.com".into(),
            client_id: "weglarka-cli".into(),
            audience: "https://admin.example.com/api/".into(),
            access_token: "the-access-token".into(),
            access_expires: 1_900_000_000,
            refresh_token: Some("the-refresh-token".into()),
        }
    }

    #[test]
    fn hosts_are_reduced_to_an_origin_and_nothing_else_is_accepted() {
        assert_eq!(
            normalize_host("https://Panel.Example.com/").unwrap(),
            "https://panel.example.com"
        );
        assert_eq!(
            normalize_host("https://panel.example.com:8443").unwrap(),
            "https://panel.example.com:8443"
        );
        assert_eq!(
            normalize_host("http://127.0.0.1:9000").unwrap(),
            "http://127.0.0.1:9000"
        );
        for bad in [
            "panel.example.com",
            "http://panel.example.com",
            "https://panel.example.com/api",
            "https://u:p@panel.example.com",
            "https://panel.example.com/?x=1",
        ] {
            assert!(normalize_host(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_file_is_private_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().join("weglarka").join("credentials.toml"));
        store
            .update(|c| {
                c.hosts.insert("https://panel.example.com".into(), entry());
            })
            .unwrap();
        let path = dir.path().join("weglarka").join("credentials.toml");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let read = store.read().unwrap();
        let e = &read.hosts["https://panel.example.com"];
        assert_eq!(e.access_token, "the-access-token");
        assert_eq!(e.refresh_token.as_deref(), Some("the-refresh-token"));
    }

    #[test]
    fn debug_output_never_shows_a_token() {
        let mut c = Credentials::default();
        c.hosts.insert("https://panel.example.com".into(), entry());
        let shown = format!("{c:?} {:?}", entry());
        assert!(!shown.contains("the-access-token") && !shown.contains("the-refresh-token"));
    }

    #[test]
    fn a_missing_file_is_empty_and_a_broken_one_is_an_error_without_its_contents() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().join("credentials.toml"));
        assert!(store.read().unwrap().hosts.is_empty());
        fs::write(
            dir.path().join("credentials.toml"),
            "access = \"leaky-secret\"",
        )
        .unwrap();
        let err = store.read().unwrap_err();
        assert!(!err.message.contains("leaky-secret"));
    }
}
