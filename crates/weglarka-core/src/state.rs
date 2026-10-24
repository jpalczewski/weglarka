//! On-disk state: `apps.toml` (desired state) and `state.toml` (runtime state).
//!
//! Both files are written only by the daemon, always atomically (tmp in the same directory + `fsync`
//! + `rename` + directory `fsync`). Reading validates the contents (`deny_unknown_fields` + invariants).
//!
//! Decision on the two-file split: `docs/decisions/0003-state-toml.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::app::{AppSpec, AppsFile, Digest, HostPort, InstanceName, valid_volume_name};
use crate::hash::SpecHash;
use crate::uid_range::UidRange;

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("i/o error on {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("cannot parse {path}: {message}")]
    Parse { path: PathBuf, message: String },
    #[error("invalid {path}: {reason}")]
    Invalid { path: PathBuf, reason: String },
}

/// Last failed deploy — a marker so webhook/reconcile do not retry the same thing endlessly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailedDeploy {
    pub digest: Digest,
    pub reason: String,
}

/// State of a single instance. `previous` is retention 1, for rollback.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppState {
    /// Container generation number (increments on every recreate).
    #[serde(default)]
    pub generation: u64,
    /// Currently pinned digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<Digest>,
    /// Previous (known-good) digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<Digest>,
    /// Spec hash that `current` was started with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec_hash: Option<SpecHash>,
    /// Last failed deploy (cleared after a successful one).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<FailedDeploy>,
    /// Secrets the instance is waiting for (iteration 2, session 3): a deploy that cannot start
    /// because bound secrets are not set records their names here instead of failing; setting the
    /// last one triggers the deploy. Empty = not waiting.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub waiting_for_secrets: Vec<String>,
    /// Fixed uid/gid range of the instance (iteration 2, path (a) of docs/decisions/0009); allocated
    /// when the first container with volumes is created and kept for the instance's lifetime.
    /// `None` = the instance runs with `--userns=auto`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid_range: Option<UidRange>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateFile {
    #[serde(default)]
    pub apps: BTreeMap<InstanceName, AppState>,
    /// Fixed uid/gid range of the ingress nginx container (iteration 2, docs/decisions/0009): like
    /// instances, it must not stay on libpod's default map.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress_uid_range: Option<UidRange>,
}

/// Location of the state files (the daemon's single data directory).
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

/// Atomic write: tmp in the same directory (created with `mode`) → `fsync` → `rename` → directory `fsync`.
pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), io::Error> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let dir = dir.unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let tmp = dir.join(format!(".{}.tmp", file_name.to_string_lossy()));
    let result = (|| {
        // `create_new` + always a fresh file: tmp never inherits foreign permissions/contents.
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

/// `apps.toml` invariants that serde cannot express.
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
    validate_depends_on(name, spec)?;
    validate_iteration2(name, spec)
}

/// `depends_on` rules an app can break on its own. The cross-app rules (an unknown target, a cycle)
/// live in [`crate::depends::validate`], which needs the whole `apps.toml`.
fn validate_depends_on(name: &InstanceName, spec: &AppSpec) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for dep in &spec.depends_on {
        if dep == name {
            return Err(format!("{name}: depends_on must not list the app itself"));
        }
        if !seen.insert(dep) {
            return Err(format!("{name}: duplicate depends_on entry \"{dep}\""));
        }
    }
    Ok(())
}

/// Hardening values end up in the container spec verbatim, so they are checked strictly.
fn validate_security(name: &InstanceName, sec: &crate::app::Security) -> Result<(), String> {
    for cap in sec.cap_drop.iter().chain(&sec.cap_add) {
        if !crate::app::valid_capability(cap) {
            return Err(format!(
                "{name}: invalid capability {cap:?} (expected ALL or e.g. NET_BIND_SERVICE)"
            ));
        }
    }
    if sec.cap_add.iter().any(|c| c == "ALL") {
        return Err(format!("{name}: cap_add must not be ALL"));
    }
    let mut seen = BTreeSet::new();
    for path in &sec.tmpfs {
        let ok = path.starts_with('/')
            && path.len() > 1
            && !path.split('/').any(|s| s == "." || s == "..")
            && !path.chars().any(|c| c.is_control() || c == ',' || c == ':');
        if !ok {
            return Err(format!(
                "{name}: tmpfs path {path:?} must be absolute (no '..', ':' or ',')"
            ));
        }
        if !seen.insert(path.trim_end_matches('/')) {
            return Err(format!("{name}: duplicate tmpfs path {path:?}"));
        }
    }
    Ok(())
}

/// Rules for the iteration 2 fields (volumes, resources, health probes).
fn validate_iteration2(name: &InstanceName, spec: &AppSpec) -> Result<(), String> {
    let mut seen_names = BTreeSet::new();
    let mut seen_targets = BTreeSet::new();
    for v in &spec.volumes {
        if !valid_volume_name(&v.name) {
            return Err(format!("{name}: invalid volume name {:?}", v.name));
        }
        let target_ok = v.target.starts_with('/')
            && v.target.len() > 1
            && !v.target.split('/').any(|s| s == "." || s == "..")
            && !v
                .target
                .chars()
                .any(|c| c.is_control() || c == ',' || c == ':');
        if !target_ok {
            return Err(format!(
                "{name}: volume {:?} target must be an absolute path (no '..', ':' or ',')",
                v.name
            ));
        }
        if !seen_names.insert(&v.name) {
            return Err(format!("{name}: duplicate volume name {:?}", v.name));
        }
        if !seen_targets.insert(v.target.trim_end_matches('/')) {
            return Err(format!("{name}: duplicate volume target {:?}", v.target));
        }
    }
    validate_security(name, &spec.security)?;
    if spec.resources.pids_limit == Some(0) {
        return Err(format!(
            "{name}: pids_limit must be > 0 (omit it for no limit)"
        ));
    }
    if let Some(cmd) = &spec.health.command
        && (cmd.is_empty() || cmd[0].is_empty())
    {
        return Err(format!("{name}: health.command must not be empty"));
    }
    if let Some(http) = &spec.health.http {
        if spec.port.is_none() {
            return Err(format!("{name}: health.http requires port"));
        }
        // The probe goes through nginx, which routes by `Host` (docs/decisions/0010).
        if spec.domains.is_empty() {
            return Err(format!("{name}: health.http requires at least one domain"));
        }
        if !http.path.starts_with('/') {
            return Err(format!("{name}: health.http.path must start with '/'"));
        }
        if !(100..=599).contains(&http.expect_status) {
            return Err(format!("{name}: health.http.expect_status must be 100-599"));
        }
        if http.timeout_secs == 0 {
            return Err(format!("{name}: health.http.timeout_secs must be > 0"));
        }
    }
    validate_host_ports(name, &spec.host_ports)?;
    Ok(())
}

/// Rules an app can break on its own for ports published directly on the host. The host-dependent
/// ones (privileged ports, conflicts between apps, the ingress bind) are in
/// [`crate::host_ports::validate`], which needs `weglarka.toml`.
fn validate_host_ports(name: &InstanceName, ports: &[HostPort]) -> Result<(), String> {
    let mut seen: Vec<(u16, std::net::IpAddr)> = Vec::new();
    for entry in ports {
        if entry.host == 0 || entry.container == 0 {
            return Err(format!(
                "{name}: host_ports need non-zero host and container ports"
            ));
        }
        let bind = entry.bind_ip().parse::<std::net::IpAddr>().map_err(|_| {
            format!(
                "{name}: host_ports bind address {:?} is not an IP literal",
                entry.bind_ip()
            )
        })?;
        if seen.iter().any(|(port, other)| {
            *port == entry.host && crate::host_ports::bind_overlaps(bind, *other)
        }) {
            return Err(format!(
                "{name}: host port {} is published twice on the same address",
                entry.host
            ));
        }
        seen.push((entry.host, bind));
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
    crate::depends::validate(&apps).map_err(|r| invalid(path, r))?;
    Ok(apps)
}

pub fn save_apps(path: &Path, apps: &AppsFile) -> Result<(), StateError> {
    for (name, spec) in &apps.apps {
        validate_app(name, spec).map_err(|r| invalid(path, r))?;
    }
    crate::depends::validate(apps).map_err(|r| invalid(path, r))?;
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
    let ingress = "ingress".to_owned();
    let ranges: Vec<_> = state
        .apps
        .iter()
        .filter_map(|(n, s)| s.uid_range.map(|r| (n.to_string(), r)))
        .chain(state.ingress_uid_range.map(|r| (ingress, r)))
        .collect();
    for (i, (a, ra)) in ranges.iter().enumerate() {
        if ra.start == 0 || ra.size == 0 {
            return Err(invalid(
                path,
                format!("{a}: uid_range must start at >= 1 and be non-empty"),
            ));
        }
        if let Some((b, _)) = ranges[i + 1..].iter().find(|(_, rb)| ra.overlaps(*rb)) {
            return Err(invalid(path, format!("{a} and {b}: uid ranges overlap")));
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
    fn depends_on_self_and_duplicates_are_rejected() {
        let spec = |deps: &str| -> AppSpec {
            toml::from_str(&format!("image = \"i\"\ndepends_on = [{deps}]")).unwrap()
        };
        assert!(
            validate_app(&name("a"), &spec("\"a\""))
                .unwrap_err()
                .contains("app itself")
        );
        assert!(
            validate_app(&name("a"), &spec("\"b\", \"b\""))
                .unwrap_err()
                .contains("duplicate depends_on")
        );
        assert!(validate_app(&name("a"), &spec("\"b\"")).is_ok());
    }

    #[test]
    fn security_values_are_validated() {
        let ok = |sec: crate::app::Security| {
            let spec = AppSpec {
                security: sec,
                ..toml::from_str("image = \"i\"").unwrap()
            };
            validate_app(&name("a"), &spec)
        };
        let sec = |f: &dyn Fn(&mut crate::app::Security)| {
            let mut s = crate::app::Security::default();
            f(&mut s);
            s
        };
        assert!(
            ok(sec(&|s| {
                s.read_only = true;
                s.tmpfs = vec!["/cache".into()];
                s.cap_drop = vec!["ALL".into()];
                s.cap_add = vec!["NET_BIND_SERVICE".into()];
                s.no_new_privileges = true;
            }))
            .is_ok()
        );
        assert!(
            ok(sec(&|s| s.cap_drop = vec!["all".into()])).is_err(),
            "upper case only"
        );
        assert!(ok(sec(&|s| s.cap_drop = vec!["NET_ADMIN,SYS".into()])).is_err());
        assert!(ok(sec(&|s| s.cap_add = vec!["ALL".into()])).is_err());
        assert!(ok(sec(&|s| s.tmpfs = vec!["cache".into()])).is_err());
        assert!(ok(sec(&|s| s.tmpfs = vec!["/a,mode=777".into()])).is_err());
        assert!(ok(sec(&|s| s.tmpfs = vec!["/a/../b".into()])).is_err());
        assert!(ok(sec(&|s| s.tmpfs = vec!["/a".into(), "/a/".into()])).is_err());
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
                waiting_for_secrets: vec![],
                uid_range: Some(UidRange {
                    start: 1,
                    size: 65_536,
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

        fs::write(
            &p,
            "[apps.a]\nuid_range = { start = 1, size = 100 }\n[apps.b]\nuid_range = { start = 100, size = 100 }\n",
        )
        .unwrap();
        assert!(matches!(load_state(&p), Err(StateError::Invalid { .. })));

        fs::write(&p, "[apps.A_b]\n").unwrap();
        assert!(matches!(load_state(&p), Err(StateError::Parse { .. })));
    }

    #[test]
    fn iteration2_validation() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("apps.toml");
        let check = |extra: &str| {
            fs::write(
                &p,
                format!(
                    "[apps.a]\nimage = \"x:1\"\nport = 80\ndomains = [\"a.example.com\"]\n{extra}\n"
                ),
            )
            .unwrap();
            load_apps(&p).is_ok()
        };
        assert!(check("volumes = [{ name = \"data\", target = \"/data\" }]"));
        assert!(check(
            "health = { http = { path = \"/up\", expect_status = 204 } }"
        ));
        assert!(check("resources = { pids_limit = 10 }"));
        for bad in [
            "volumes = [{ name = \"Data\", target = \"/data\" }]",
            "volumes = [{ name = \"d\", target = \"data\" }]",
            "volumes = [{ name = \"d\", target = \"/a/../b\" }]",
            "volumes = [{ name = \"d\", target = \"/a:ro\" }]",
            "volumes = [{ name = \"d\", target = \"/a\" }, { name = \"d\", target = \"/b\" }]",
            "volumes = [{ name = \"d\", target = \"/a\" }, { name = \"e\", target = \"/a/\" }]",
            "resources = { pids_limit = 0 }",
            "resources = { memory = \"0\" }",
            "health = { command = [] }",
            "health = { http = { path = \"up\" } }",
            "health = { http = { expect_status = 99 } }",
            "health = { http = { timeout_secs = 0 } }",
        ] {
            assert!(!check(bad), "{bad}");
        }
        // The HTTP probe needs a port and a domain to go through the ingress.
        for no_route in [
            "image = \"x:1\"\ndomains = [\"a.example.com\"]",
            "image = \"x:1\"\nport = 80",
        ] {
            fs::write(
                &p,
                format!("[apps.a]\n{no_route}\nhealth = {{ http = {{}} }}\n"),
            )
            .unwrap();
            assert!(matches!(load_apps(&p), Err(StateError::Invalid { .. })));
        }
    }

    #[test]
    fn host_ports_are_validated_per_app() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("apps.toml");
        let check = |extra: &str| {
            fs::write(&p, format!("[apps.a]\nimage = \"x:1\"\n{extra}\n")).unwrap();
            load_apps(&p).is_ok()
        };
        assert!(check("host_ports = [{ host = 2222, container = 22 }]"));
        assert!(check(
            "host_ports = [{ host = 2222, container = 22, ip = \"0.0.0.0\" }]"
        ));
        // The same host port on two different, specific addresses is two distinct sockets.
        assert!(check(
            "host_ports = [\
             { host = 2222, container = 22, ip = \"10.0.0.5\" }, \
             { host = 2222, container = 23, ip = \"10.0.0.6\" }]"
        ));
        for bad in [
            "host_ports = [{ host = 0, container = 22 }]",
            "host_ports = [{ host = 2222, container = 0 }]",
            "host_ports = [{ host = 2222, container = 22, ip = \"nope\" }]",
            "host_ports = [{ host = 2222, container = 22 }, { host = 2222, container = 22 }]",
            "host_ports = [{ host = 2222, container = 22 }, \
             { host = 2222, container = 23, ip = \"0.0.0.0\" }]",
        ] {
            assert!(!check(bad), "{bad}");
        }
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
