//! Host config mounts (`configs`, issue #118, `docs/decisions/0027-config-root-mounts.md`).
//!
//! There is one `config_root` in `weglarka.toml` and one rule for everything below it: the source is
//! resolved (symlinks included), must stay inside the **canonical** root and must be a regular file
//! or a directory. The canonical path is what gets bind-mounted, so a symlink swapped between the
//! check and the mount cannot redirect it.
//!
//! The content is deliberately outside `spec_hash`; [`fingerprint`] only tells the operator what the
//! app currently sees (`apps show`/`doctor`). [`describe`] never fails: a broken mount is a status.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

use crate::app::{AppSpec, AppsFile, InstanceName};
use crate::config::HostConfig;

/// Most entries a directory fingerprint walks; a larger tree is not fingerprinted.
const MAX_FINGERPRINT_ENTRIES: usize = 4096;
/// Most file bytes a fingerprint reads; more content is not fingerprinted.
const MAX_FINGERPRINT_BYTES: u64 = 8 * 1024 * 1024;
/// Length of the short content fingerprint (a prefix of the sha256 hex).
const FINGERPRINT_HEX_LEN: usize = 16;

/// A config mount that cannot be mounted.
///
/// `Display`/`Error` are implemented by hand instead of `#[derive(thiserror::Error)]`: the variants
/// carry the offending spec `source` (a string, as the rest of the engine expects), and `thiserror`
/// reserves the field name `source` for the underlying error.
#[derive(Debug)]
pub enum ConfigError {
    NoRoot,
    NoRootFor { instance: InstanceName },
    RootUnavailable { root: PathBuf, reason: String },
    NotFound { source: String },
    OutsideRoot { source: String },
    NotFileOrDir { source: String },
    Io { path: PathBuf, source: io::Error },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoRoot => f.write_str("config mounts need `config_root` in weglarka.toml"),
            Self::NoRootFor { instance } => write!(
                f,
                "{instance}: config mounts need `config_root` in weglarka.toml"
            ),
            Self::RootUnavailable { root, reason } => {
                write!(f, "config_root {root:?} is unavailable: {reason}")
            }
            Self::NotFound { source } => {
                write!(
                    f,
                    "config source {source:?} does not exist under config_root"
                )
            }
            Self::OutsideRoot { source } => {
                write!(f, "config source {source:?} resolves outside config_root")
            }
            Self::NotFileOrDir { source } => {
                write!(
                    f,
                    "config source {source:?} is not a regular file or a directory"
                )
            }
            Self::Io { path, source } => write!(f, "i/o error on {}: {source}", path.display()),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// A config mount resolved against the canonical `config_root`: the path libpod binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// Canonical host path — what goes into the container's `BindMount::source`.
    pub source: PathBuf,
    /// Absolute path in the container, verbatim from the spec.
    pub target: String,
}

/// State of one declared config mount as the operator sees it (`apps show`/`doctor`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountStatus {
    Ok,
    /// The source does not exist under the root.
    Missing,
    /// The app declares configs but the host sets no `config_root` (or it is unusable).
    NoRoot,
    /// The source resolves outside the root (symlink escape, absolute path…).
    OutsideRoot,
    /// The source exists but is neither a regular file nor a directory.
    NotFileOrDir,
    /// The source cannot be inspected (permissions, i/o error).
    Unreadable,
}

/// One declared config mount with its status and (when readable) a content fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountView {
    pub source: String,
    pub target: String,
    pub status: MountStatus,
    /// Short sha256 of the content; `None` unless the mount is readable and within the caps.
    pub fingerprint: Option<String>,
    /// Why the mount is not usable (permission hint, escape target…), for the user-facing report.
    pub detail: Option<String>,
}

/// Resolves every config mount of `spec` against `root` (the host's `config_root`).
///
/// Fails on the first unresolvable mount: a deploy must not start with a partially mounted config.
pub fn resolve_all(root: Option<&Path>, spec: &AppSpec) -> Result<Vec<Resolved>, ConfigError> {
    if spec.configs.is_empty() {
        return Ok(Vec::new());
    }
    let root = root.ok_or(ConfigError::NoRoot)?;
    let root = canonical_root(root)?;
    spec.configs
        .iter()
        .map(|mount| {
            Ok(Resolved {
                source: canonical_source(&root, &mount.source)?,
                target: mount.target.clone(),
            })
        })
        .collect()
}

/// [`resolve_all`] as a never-failing report, one entry per declared mount and in spec order.
pub fn describe(root: Option<&Path>, spec: &AppSpec) -> Vec<MountView> {
    let (root, root_detail) = match root {
        None => (
            None,
            Some("config_root is not set in weglarka.toml".to_owned()),
        ),
        Some(root) => match canonical_root(root) {
            Ok(canonical) => (Some(canonical), None),
            Err(e) => (None, Some(e.to_string())),
        },
    };
    spec.configs
        .iter()
        .map(|mount| {
            let unresolved = MountView {
                source: mount.source.clone(),
                target: mount.target.clone(),
                status: MountStatus::NoRoot,
                fingerprint: None,
                detail: root_detail.clone(),
            };
            let Some(root) = &root else {
                return unresolved;
            };
            match canonical_source(root, &mount.source) {
                Ok(path) => MountView {
                    status: MountStatus::Ok,
                    fingerprint: fingerprint(&path),
                    detail: None,
                    ..unresolved
                },
                Err(e) => MountView {
                    status: match &e {
                        ConfigError::NotFound { .. } => MountStatus::Missing,
                        ConfigError::OutsideRoot { .. } => MountStatus::OutsideRoot,
                        ConfigError::NotFileOrDir { .. } => MountStatus::NotFileOrDir,
                        ConfigError::NoRoot
                        | ConfigError::NoRootFor { .. }
                        | ConfigError::RootUnavailable { .. } => MountStatus::NoRoot,
                        ConfigError::Io { .. } => MountStatus::Unreadable,
                    },
                    detail: Some(e.to_string()),
                    ..unresolved
                },
            }
        })
        .collect()
}

/// Validates the **host** side of `configs`: a configured `config_root` must be a usable directory
/// (checked even before an app uses it — a typo or a missing mount is a host misconfiguration), and
/// declaring `configs` without a `config_root` is an error naming the app. Individual sources are
/// deliberately **not** resolved here: a file the operator has not created yet must not keep the
/// daemon from starting. An unresolvable source blocks only the app (reconcile), is refused when the
/// container is about to be created (`launch`) and is reported by `doctor`.
pub fn validate_host(host: &HostConfig, apps: &AppsFile) -> Result<(), ConfigError> {
    if let Some(root) = host.config_root.as_deref() {
        canonical_root(root)?;
    }
    if host.config_root.is_none()
        && let Some((instance, _)) = apps.apps.iter().find(|(_, spec)| !spec.configs.is_empty())
    {
        return Err(ConfigError::NoRootFor {
            instance: instance.clone(),
        });
    }
    Ok(())
}

/// Short content fingerprint: sha256 over the file bytes, or over the sorted walk of a directory
/// (`relative_path\0kind\0content`). `.git` is skipped, directory symlinks are not followed (a
/// symlink contributes its target string) and the whole thing gives up (`None`) above the caps or on
/// an i/o error — a fingerprint is a convenience, never a correctness input.
pub fn fingerprint(path: &Path) -> Option<String> {
    let meta = fs::metadata(path).ok()?;
    let mut hasher = Sha256::new();
    if meta.is_file() {
        if meta.len() > MAX_FINGERPRINT_BYTES {
            return None;
        }
        hasher.update(fs::read(path).ok()?);
    } else if meta.is_dir() {
        let mut entries = Vec::new();
        collect_entries(path, "", &mut entries)?;
        let mut bytes = 0u64;
        for entry in &entries {
            hasher.update(entry.relative.as_bytes());
            hasher.update(b"\0");
            match entry.kind {
                Kind::Dir => hasher.update(b"dir\0"),
                Kind::Symlink => {
                    hasher.update(b"symlink\0");
                    hasher.update(
                        fs::read_link(&entry.path)
                            .ok()?
                            .as_os_str()
                            .as_encoded_bytes(),
                    );
                }
                Kind::File => {
                    hasher.update(b"file\0");
                    bytes = bytes.checked_add(fs::metadata(&entry.path).ok()?.len())?;
                    if bytes > MAX_FINGERPRINT_BYTES {
                        return None;
                    }
                    hasher.update(fs::read(&entry.path).ok()?);
                }
            }
        }
    } else {
        return None;
    }
    let hex = hex::encode(hasher.finalize());
    Some(hex[..FINGERPRINT_HEX_LEN].to_owned())
}

fn canonical_root(root: &Path) -> Result<PathBuf, ConfigError> {
    let canonical = root
        .canonicalize()
        .map_err(|e| ConfigError::RootUnavailable {
            root: root.to_owned(),
            reason: e.to_string(),
        })?;
    if !canonical.is_dir() {
        return Err(ConfigError::RootUnavailable {
            root: root.to_owned(),
            reason: "not a directory".to_owned(),
        });
    }
    Ok(canonical)
}

fn canonical_source(root: &Path, source: &str) -> Result<PathBuf, ConfigError> {
    let joined = root.join(source);
    match fs::metadata(&joined) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(ConfigError::NotFound {
                source: source.to_owned(),
            });
        }
        Err(e) => {
            return Err(ConfigError::Io {
                path: joined,
                source: e,
            });
        }
    }
    let canonical = joined.canonicalize().map_err(|e| ConfigError::Io {
        path: joined.clone(),
        source: e,
    })?;
    if !canonical.starts_with(root) {
        return Err(ConfigError::OutsideRoot {
            source: source.to_owned(),
        });
    }
    let meta = fs::metadata(&canonical).map_err(|e| ConfigError::Io {
        path: canonical.clone(),
        source: e,
    })?;
    if !(meta.is_file() || meta.is_dir()) {
        return Err(ConfigError::NotFileOrDir {
            source: source.to_owned(),
        });
    }
    Ok(canonical)
}

/// Kind of a walked directory entry, as it enters the fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    File,
    Dir,
    Symlink,
}

struct WalkEntry {
    path: PathBuf,
    relative: String,
    kind: Kind,
}

/// Collects the entries of `dir` in a deterministic order (byte-wise sorted names). `file_type()` is
/// taken from the directory entry, so symlinks are recorded as symlinks and never recursed into.
fn collect_entries(dir: &Path, prefix: &str, out: &mut Vec<WalkEntry>) -> Option<()> {
    let mut children = Vec::new();
    for entry in fs::read_dir(dir).ok()? {
        let entry = entry.ok()?;
        children.push((entry.file_name(), entry.file_type().ok()?));
    }
    children.sort_by(|(a, _), (b, _)| a.cmp(b));
    for (name, file_type) in children {
        let name = name.to_str()?.to_owned();
        // The operator's checkout metadata is not config the app sees.
        if name == ".git" {
            continue;
        }
        let relative = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        let kind = if file_type.is_symlink() {
            Kind::Symlink
        } else if file_type.is_dir() {
            Kind::Dir
        } else if file_type.is_file() {
            Kind::File
        } else {
            // A socket/FIFO/device in the tree makes the content unstable: do not fingerprint it.
            return None;
        };
        out.push(WalkEntry {
            path: dir.join(&name),
            relative: relative.clone(),
            kind,
        });
        if out.len() > MAX_FINGERPRINT_ENTRIES {
            return None;
        }
        if kind == Kind::Dir {
            collect_entries(&dir.join(&name), &relative, out)?;
        }
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;

    use super::*;
    use crate::app::ConfigMount;

    fn spec(configs: &[(&str, &str)]) -> AppSpec {
        let mut spec: AppSpec = toml::from_str("image = \"i\"").unwrap();
        spec.configs = configs
            .iter()
            .map(|(source, target)| ConfigMount {
                source: (*source).to_owned(),
                target: (*target).to_owned(),
            })
            .collect();
        spec
    }

    fn write(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    #[test]
    fn resolves_to_the_canonical_path_inside_the_root() {
        let root = tempfile::tempdir().unwrap();
        write(&root.path().join("prometheus/prometheus.yml"), "global: {}");
        fs::create_dir_all(root.path().join("prometheus/rules")).unwrap();
        let root_canon = root.path().canonicalize().unwrap();

        let resolved = resolve_all(
            Some(root.path()),
            &spec(&[
                (
                    "prometheus/prometheus.yml",
                    "/etc/prometheus/prometheus.yml",
                ),
                ("prometheus/rules", "/etc/prometheus/rules"),
            ]),
        )
        .unwrap();
        assert_eq!(
            resolved,
            vec![
                Resolved {
                    source: root_canon.join("prometheus/prometheus.yml"),
                    target: "/etc/prometheus/prometheus.yml".into(),
                },
                Resolved {
                    source: root_canon.join("prometheus/rules"),
                    target: "/etc/prometheus/rules".into(),
                },
            ]
        );
        // An app without configs needs no root at all.
        assert_eq!(resolve_all(None, &spec(&[])).unwrap(), vec![]);
    }

    #[test]
    fn no_root_relative_root_and_missing_sources_are_reported() {
        let root = tempfile::tempdir().unwrap();
        assert!(matches!(
            resolve_all(None, &spec(&[("a.yml", "/a.yml")])),
            Err(ConfigError::NoRoot)
        ));
        // An app without configs never touches the root, so a missing one is harmless.
        let missing_root = root.path().join("nope");
        assert!(resolve_all(Some(&missing_root), &spec(&[])).is_ok());
        assert!(matches!(
            resolve_all(Some(&missing_root), &spec(&[("a.yml", "/a")])),
            Err(ConfigError::RootUnavailable { .. })
        ));
        // The root must be a directory, not a file.
        let root_file = root.path().join("root.txt");
        write(&root_file, "x");
        assert!(matches!(
            resolve_all(Some(&root_file), &spec(&[("a.yml", "/a")])),
            Err(ConfigError::RootUnavailable { .. })
        ));
        assert!(matches!(
            resolve_all(Some(root.path()), &spec(&[("missing.yml", "/a")])),
            Err(ConfigError::NotFound { .. })
        ));
    }

    #[test]
    fn symlinks_cannot_escape_the_root() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        write(&outside.path().join("secret.yml"), "secret");
        write(&root.path().join("real.yml"), "ok");
        symlink(outside.path(), root.path().join("escape-dir")).unwrap();
        symlink(
            outside.path().join("secret.yml"),
            root.path().join("escape-file"),
        )
        .unwrap();
        symlink("/etc/passwd", root.path().join("passwd")).unwrap();
        symlink("real.yml", root.path().join("inside-link")).unwrap();

        for source in ["escape-dir", "escape-file", "passwd"] {
            let err = resolve_all(Some(root.path()), &spec(&[(source, "/x")])).unwrap_err();
            assert!(
                matches!(err, ConfigError::OutsideRoot { .. }),
                "{source}: {err}"
            );
        }
        // An in-root symlink is fine and resolves to the target: the canonical path is what mounts.
        let resolved = resolve_all(Some(root.path()), &spec(&[("inside-link", "/x")])).unwrap();
        assert_eq!(
            resolved[0].source,
            root.path().canonicalize().unwrap().join("real.yml")
        );
    }

    #[test]
    fn a_socket_is_not_a_file_or_dir() {
        let root = tempfile::tempdir().unwrap();
        let _listener = UnixListener::bind(root.path().join("sock")).unwrap();
        assert!(matches!(
            resolve_all(Some(root.path()), &spec(&[("sock", "/sock")])),
            Err(ConfigError::NotFileOrDir { .. })
        ));
    }

    #[test]
    fn describe_reports_statuses_and_never_fails() {
        let root = tempfile::tempdir().unwrap();
        write(&root.path().join("ok.yml"), "a: 1");
        let outside = tempfile::tempdir().unwrap();
        write(&outside.path().join("secret"), "s");
        symlink(outside.path(), root.path().join("escape")).unwrap();
        let _listener = UnixListener::bind(root.path().join("sock")).unwrap();
        let spec = spec(&[
            ("ok.yml", "/ok.yml"),
            ("missing.yml", "/missing.yml"),
            ("escape", "/escape"),
            ("sock", "/sock"),
        ]);

        let views = describe(Some(root.path()), &spec);
        let statuses: Vec<_> = views.iter().map(|v| v.status).collect();
        assert_eq!(
            statuses,
            vec![
                MountStatus::Ok,
                MountStatus::Missing,
                MountStatus::OutsideRoot,
                MountStatus::NotFileOrDir,
            ]
        );
        assert!(views[0].fingerprint.is_some());
        assert!(views[0].detail.is_none());
        assert!(views[1].fingerprint.is_none());
        assert!(views[1].detail.is_some());

        // Without a root every mount is reported as such instead of panicking.
        let views = describe(None, &spec);
        assert_eq!(views.len(), 4);
        assert!(views.iter().all(|v| v.status == MountStatus::NoRoot));
        // A root that does not exist is the same status, with the reason in `detail`.
        let views = describe(Some(&root.path().join("gone")), &spec);
        assert!(views.iter().all(|v| v.status == MountStatus::NoRoot));
        assert!(views[0].detail.as_deref().unwrap().contains("unavailable"));
    }

    #[test]
    fn fingerprint_is_deterministic_and_tracks_content() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("app.yml");
        write(&file, "a: 1");
        let first = fingerprint(&file).unwrap();
        assert_eq!(first.len(), FINGERPRINT_HEX_LEN);
        assert_eq!(fingerprint(&file).unwrap(), first);
        write(&file, "a: 2");
        assert_ne!(fingerprint(&file).unwrap(), first);

        // Directories: content and names matter, creation order does not.
        let one = tempfile::tempdir().unwrap();
        let two = tempfile::tempdir().unwrap();
        for (dir, order) in [
            (&one, ["a.yml", "sub/b.yml"]),
            (&two, ["sub/b.yml", "a.yml"]),
        ] {
            for name in order {
                write(&dir.path().join(name), name);
            }
        }
        let fp = fingerprint(one.path()).unwrap();
        assert_eq!(fingerprint(two.path()).unwrap(), fp);
        write(&two.path().join("sub/b.yml"), "changed");
        assert_ne!(fingerprint(two.path()).unwrap(), fp);

        // Neither a file nor a directory.
        assert_eq!(fingerprint(&dir.path().join("nope")), None);
    }

    #[test]
    fn fingerprint_skips_git_and_does_not_follow_directory_symlinks() {
        let with_git_dir = tempfile::tempdir().unwrap();
        let with_git_file = tempfile::tempdir().unwrap();
        let without_git = tempfile::tempdir().unwrap();
        for dir in [
            with_git_dir.path(),
            with_git_file.path(),
            without_git.path(),
        ] {
            write(&dir.join("a.yml"), "a: 1");
        }
        write(&with_git_dir.path().join(".git/config"), "[core]");
        write(&with_git_file.path().join(".git"), "");
        assert_eq!(
            fingerprint(with_git_dir.path()).unwrap(),
            fingerprint(without_git.path()).unwrap()
        );
        assert_eq!(
            fingerprint(with_git_file.path()).unwrap(),
            fingerprint(without_git.path()).unwrap()
        );

        let root = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        write(&target.path().join("inside.yml"), "x");
        symlink(target.path(), root.path().join("link")).unwrap();
        let before = fingerprint(root.path()).unwrap();
        write(&target.path().join("inside.yml"), "changed");
        assert_eq!(
            fingerprint(root.path()).unwrap(),
            before,
            "a directory symlink contributes its target string, not its content"
        );
        let other = tempfile::tempdir().unwrap();
        symlink(other.path(), root.path().join("link2")).unwrap();
        let with_two = fingerprint(root.path()).unwrap();
        fs::remove_file(root.path().join("link2")).unwrap();
        assert_ne!(fingerprint(root.path()).unwrap(), with_two);
    }

    #[test]
    fn fingerprint_gives_up_above_the_caps() {
        let dir = tempfile::tempdir().unwrap();
        let big = dir.path().join("big.bin");
        fs::write(&big, vec![0u8; MAX_FINGERPRINT_BYTES as usize + 1]).unwrap();
        assert_eq!(fingerprint(&big), None);

        let tree = tempfile::tempdir().unwrap();
        for i in 0..=MAX_FINGERPRINT_ENTRIES {
            fs::write(tree.path().join(format!("{i:05}.yml")), "").unwrap();
        }
        assert_eq!(fingerprint(tree.path()), None);

        // Just under the limit is fingerprinted.
        let small = tempfile::tempdir().unwrap();
        for i in 0..MAX_FINGERPRINT_ENTRIES - 1 {
            fs::write(small.path().join(format!("{i:05}.yml")), "").unwrap();
        }
        assert!(fingerprint(small.path()).is_some());
    }

    #[test]
    fn validate_host_checks_the_root_but_not_the_sources() {
        const HOST: &str = r#"
[ingress]
mode = "behind"
bind = "172.17.0.1:8080"

[admin]
socket = "/run/user/1001/weglarka/admin.sock"

[webhook]
listen = "0.0.0.0:9180"
domain = "weglarka.example.eu"
"#;
        let root = tempfile::tempdir().unwrap();
        write(&root.path().join("app.yml"), "a: 1");
        let apps = |configs: &str| -> AppsFile {
            toml::from_str(&format!("[apps.a]\nimage = \"i\"\n{configs}\n")).unwrap()
        };
        let host = |root: Option<&Path>| -> HostConfig {
            let extra = root.map_or_else(String::new, |r| format!("config_root = {r:?}\n"));
            HostConfig::from_toml_str(&format!("{extra}{HOST}")).unwrap()
        };

        // No configs anywhere: no root needed.
        validate_host(&host(None), &apps("")).unwrap();
        // A configured root is checked even before an app uses it: a missing directory is a typo or
        // a missing mount, not something to discover at the first deploy.
        let err =
            validate_host(&host(Some(&root.path().join("missing-dir"))), &apps("")).unwrap_err();
        assert!(matches!(err, ConfigError::RootUnavailable { .. }), "{err}");
        // A declared mount without a root is an error that names the app.
        let err = validate_host(
            &host(None),
            &apps("configs = [{ source = \"app.yml\", target = \"/app.yml\" }]"),
        )
        .unwrap_err();
        assert!(
            matches!(&err, ConfigError::NoRootFor { instance } if instance.as_str() == "a"),
            "{err}"
        );
        // With the root the same mount is valid...
        validate_host(
            &host(Some(root.path())),
            &apps("configs = [{ source = \"app.yml\", target = \"/app.yml\" }]"),
        )
        .unwrap();
        // A source that does not exist yet is not a host error: the app is blocked in reconcile and
        // `doctor` reports it (`launch` refuses it when a container is about to be created).
        validate_host(
            &host(Some(root.path())),
            &apps("configs = [{ source = \"missing.yml\", target = \"/app.yml\" }]"),
        )
        .unwrap();
        // A configured root that is not a directory is a host error.
        let err = validate_host(
            &host(Some(&root.path().join("missing-dir"))),
            &apps("configs = [{ source = \"app.yml\", target = \"/app.yml\" }]"),
        )
        .unwrap_err();
        assert!(matches!(err, ConfigError::RootUnavailable { .. }), "{err}");
    }
}
