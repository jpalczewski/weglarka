//! The description of Węglarka's own service, shared by `platform install` and the host-side
//! self-update switcher (`weglarka-daemon self-update`): both must render exactly the same unit, only
//! with a different image.
//!
//! The switcher runs on the host — the container has no `systemctl`, no `/etc/passwd` and no write
//! access to its own unit — so it also resolves the Podman socket here (`docs/decisions/0027`).

use std::path::PathBuf;

use weglarka_engine::platform::{Hardening, Platform, Result, ServiceSpec};

use crate::ingress::WEBHOOK_NETWORK;
use crate::settings::Settings;

/// Name of the service and of its container (`ContainerName=` in the quadlet).
pub const SERVICE_NAME: &str = "weglarka";
/// Image installed when the operator does not name one.
pub const DEFAULT_IMAGE: &str = "ghcr.io/jpalczewski/weglarka:latest";
/// Env var carrying the Podman socket path resolved on the host: the (`scratch`) container has no
/// `/etc/passwd`, so `platform install` resolves the socket and passes it in the quadlet.
pub const SOCKET_ENV: &str = "WEGLARKA_PODMAN_SOCKET";

/// All paths are mounted under the same name as on the host so that `weglarka.toml` is valid on both
/// sides (the host CLI reads the same file).
pub fn service_spec(settings: &Settings, podman_socket: PathBuf, image: String) -> ServiceSpec {
    let s = |p: &std::path::Path| p.display().to_string();
    let same = |p: &std::path::Path| (s(p), s(p));
    let mut mounts = vec![same(&podman_socket), same(&settings.paths.state_dir)];
    if let Some(dir) = settings.host.admin.socket.parent() {
        mounts.push(same(dir));
    }
    let conf = &settings.config_path;
    mounts.push((s(conf), format!("{}:ro", s(conf))));
    // `config_root` is what `apps show`, `doctor` and every deploy read (issue #118): the daemon
    // mounts it read-only at the same path, like `weglarka.toml`. Existing installs need a
    // `platform install` re-run to gain it (ADR 0028).
    if let Some(root) = &settings.paths.config_root {
        let root = s(root);
        let already_mounted = mounts.iter().any(|(_, target)| {
            target == &root || target.strip_suffix(":ro") == Some(root.as_str())
        });
        if !already_mounted {
            mounts.push((root.clone(), format!("{root}:ro")));
        }
    }
    // Allowlisted `host_mounts` (issue #178): the daemon must see each path to canonicalize it before
    // an app's bind, so every entry is mounted read-only at the same path. Existing installs need a
    // `platform install` re-run after changing the list (ADR 0045).
    for entry in &settings.host.runtime.host_mounts {
        let entry = s(entry);
        let already_mounted = mounts.iter().any(|(_, target)| {
            target == &entry || target.strip_suffix(":ro") == Some(entry.as_str())
        });
        if !already_mounted {
            mounts.push((entry.clone(), format!("{entry}:ro")));
        }
    }
    if !settings
        .paths
        .nginx_conf_dir
        .starts_with(&settings.paths.state_dir)
    {
        mounts.push(same(&settings.paths.nginx_conf_dir));
    }
    if let Some(f) = &settings.host.ingress.traefik_dynamic_file {
        // A single file: an in-place write preserves the inode, so Traefik sees the change.
        mounts.push(same(f));
    }
    ServiceSpec {
        name: SERVICE_NAME.to_owned(),
        image,
        run_as_user: settings.host.runtime.user.clone(),
        env: vec![
            ("RUST_LOG".to_owned(), "info".to_owned()),
            (SOCKET_ENV.to_owned(), s(&podman_socket)),
        ],
        mounts,
        networks: vec![WEBHOOK_NETWORK.to_owned()],
        args: vec!["run".to_owned(), "--config".to_owned(), s(conf)],
        hardening: Hardening {
            memory: Some(settings.host.platform.memory.clone()),
            pids_limit: Some(settings.host.platform.pids_limit),
            ..Hardening::default()
        },
    }
}

/// One `[runtime] host_mounts` entry that collides with a path the daemon container mounts writable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostMountOverlap {
    /// The allowlist entry.
    pub entry: PathBuf,
    /// The writable daemon mount it collides with.
    pub daemon_mount: PathBuf,
    pub relation: OverlapRelation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlapRelation {
    Equal,
    /// The entry is inside the writable mount.
    Inside,
    /// The entry contains the writable mount.
    Ancestor,
}

impl OverlapRelation {
    fn of(entry: &std::path::Path, mount: &std::path::Path) -> Option<Self> {
        // `Path::starts_with` compares whole components, so `/var/lib/weglarka2` is not inside
        // `/var/lib/weglarka`.
        if entry == mount {
            Some(Self::Equal)
        } else if entry.starts_with(mount) {
            Some(Self::Inside)
        } else if mount.starts_with(entry) {
            Some(Self::Ancestor)
        } else {
            None
        }
    }
}

impl std::fmt::Display for HostMountOverlap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (entry, mount) = (self.entry.display(), self.daemon_mount.display());
        let how = match self.relation {
            OverlapRelation::Equal => format!("is the same path as {mount}"),
            OverlapRelation::Inside => format!("is inside {mount}"),
            OverlapRelation::Ancestor => format!("contains {mount}"),
        };
        write!(
            f,
            "[runtime] host_mounts entry {entry} {how}, which the daemon container mounts writable; a \
             read-only mount of it would make the daemon's own writes fail with `Read-only file system` \
             (ingress apply, log rotation). Remove the entry from host_mounts"
        )
    }
}

/// The paths [`service_spec`] mounts writable (everything without `:ro`), derived from `service_spec`
/// itself so the two cannot drift apart. `host_mounts` are dropped first: they are the thing being
/// checked. A podman socket that is not configured is left out (it is resolved at install time).
pub fn daemon_writable_mounts(settings: &Settings) -> Vec<PathBuf> {
    let mut bare = settings.clone();
    bare.host.runtime.host_mounts.clear();
    let socket = settings.host.runtime.socket.clone().unwrap_or_default();
    service_spec(&bare, socket, String::new())
        .mounts
        .into_iter()
        .filter(|(_, target)| !target.ends_with(":ro"))
        .map(|(_, target)| PathBuf::from(target))
        .filter(|p| !p.as_os_str().is_empty())
        .collect()
}

/// Every allowlisted `host_mounts` entry that equals, lies inside or contains a writable daemon mount
/// (lexical comparison: entries are validated as normalized absolute paths).
pub fn host_mount_overlaps(settings: &Settings) -> Vec<HostMountOverlap> {
    let writable = daemon_writable_mounts(settings);
    let mut out = Vec::new();
    for entry in &settings.host.runtime.host_mounts {
        for mount in &writable {
            if let Some(relation) = OverlapRelation::of(entry, mount) {
                out.push(HostMountOverlap {
                    entry: entry.clone(),
                    daemon_mount: mount.clone(),
                    relation,
                });
                break;
            }
        }
    }
    out
}

/// The libpod socket of the runtime user: `[runtime] socket` when set, otherwise derived from the
/// platform (a host-side operation: `/etc/passwd` is available there).
pub async fn host_socket<P: Platform>(settings: &Settings, platform: &P) -> Result<PathBuf> {
    Ok(match &settings.host.runtime.socket {
        Some(socket) => socket.clone(),
        None => platform.runtime_socket(&settings.host.runtime.user).await?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use weglarka_model::config::HostConfig;

    const HOST: &str = r#"
[ingress]
mode = "behind"
bind = "172.17.0.1:8080"
[admin]
socket = "/run/user/1001/weglarka/admin.sock"
[webhook]
listen = "0.0.0.0:9180"
domain = "w.example.eu"
"#;

    fn spec(config_root: Option<&str>) -> ServiceSpec {
        let extra = config_root
            .map(|root| format!("config_root = {root:?}\n"))
            .unwrap_or_default();
        let host = HostConfig::from_toml_str(&format!("{extra}{HOST}")).unwrap();
        let settings = Settings::from_host(host, PathBuf::from("/etc/weglarka/weglarka.toml"));
        service_spec(
            &settings,
            PathBuf::from("/run/user/1001/podman/podman.sock"),
            "image:1".to_owned(),
        )
    }

    #[test]
    fn config_root_is_mounted_read_only_at_the_same_path() {
        let spec = spec(Some("/srv/weglarka/config"));
        let mount = (
            "/srv/weglarka/config".to_owned(),
            "/srv/weglarka/config:ro".to_owned(),
        );
        assert!(spec.mounts.contains(&mount), "{:?}", spec.mounts);
        // Existing mounts keep their shape (the config file itself is read-only already).
        assert!(
            spec.mounts.contains(&(
                "/etc/weglarka/weglarka.toml".to_owned(),
                "/etc/weglarka/weglarka.toml:ro".to_owned()
            )),
            "{:?}",
            spec.mounts
        );
    }

    #[test]
    fn without_config_root_the_mounts_are_unchanged() {
        let plain = spec(None);
        assert!(
            !plain
                .mounts
                .iter()
                .any(|(_, target)| target.contains("config")),
            "{:?}",
            plain.mounts
        );
        // Same mount set as before the feature existed: the socket, state dir, admin dir, config file.
        assert_eq!(plain.mounts.len(), 4, "{:?}", plain.mounts);
    }

    #[test]
    fn host_mounts_are_mounted_read_only_at_the_same_path() {
        let host = HostConfig::from_toml_str(&format!(
            "{HOST}\n[runtime]\nhost_mounts = [\"/var/log/journal\", \"/etc/machine-id\"]\n"
        ))
        .unwrap();
        let settings = Settings::from_host(host, PathBuf::from("/etc/weglarka/weglarka.toml"));
        let spec = service_spec(
            &settings,
            PathBuf::from("/run/user/1001/podman/podman.sock"),
            "image:1".to_owned(),
        );
        for path in ["/var/log/journal", "/etc/machine-id"] {
            assert!(
                spec.mounts
                    .contains(&(path.to_owned(), format!("{path}:ro"))),
                "{:?}",
                spec.mounts
            );
        }
    }

    fn settings_with(extra: &str) -> Settings {
        let host = HostConfig::from_toml_str(&format!(
            "{extra}\n[state]\ndir = \"/var/lib/weglarka\"\n{HOST}"
        ))
        .unwrap();
        Settings::from_host(host, PathBuf::from("/etc/weglarka/weglarka.toml"))
    }

    fn overlap_of(entry: &str) -> Vec<OverlapRelation> {
        let settings = settings_with(&format!("[runtime]\nhost_mounts = [{entry:?}]\n"));
        host_mount_overlaps(&settings)
            .into_iter()
            .map(|o| o.relation)
            .collect()
    }

    #[test]
    fn overlap_rule_covers_equal_inside_and_ancestor() {
        assert_eq!(overlap_of("/var/lib/weglarka"), [OverlapRelation::Equal]);
        assert_eq!(
            overlap_of("/var/lib/weglarka/ingress-logs"),
            [OverlapRelation::Inside]
        );
        assert_eq!(overlap_of("/var/lib"), [OverlapRelation::Ancestor]);
        assert_eq!(
            overlap_of("/run/user/1001/weglarka"),
            [OverlapRelation::Equal]
        );
    }

    #[test]
    fn overlap_rule_allows_siblings_with_a_shared_prefix() {
        assert!(overlap_of("/var/lib/weglarka2").is_empty());
        assert!(overlap_of("/var/log/journal").is_empty());
    }

    #[test]
    fn writable_mounts_come_from_the_service_spec() {
        let settings = settings_with(
            "[runtime]\nhost_mounts = [\"/var/log/journal\"]\nsocket = \"/run/user/1001/podman/podman.sock\"\n",
        );
        let writable = daemon_writable_mounts(&settings);
        for p in [
            "/run/user/1001/podman/podman.sock",
            "/var/lib/weglarka",
            "/run/user/1001/weglarka",
        ] {
            assert!(writable.contains(&PathBuf::from(p)), "{writable:?}");
        }
        assert!(!writable.contains(&PathBuf::from("/var/log/journal")));
        assert!(!writable.contains(&PathBuf::from("/etc/weglarka/weglarka.toml")));
    }

    #[test]
    fn settings_validation_names_the_entry_and_the_mount() {
        let settings =
            settings_with("[runtime]\nhost_mounts = [\"/var/lib/weglarka/ingress-logs\"]\n");
        let message = settings.validate().unwrap_err().to_string();
        assert!(
            message.contains("/var/lib/weglarka/ingress-logs"),
            "{message}"
        );
        assert!(message.contains("is inside /var/lib/weglarka"), "{message}");
        assert!(settings_with("").validate().is_ok());
    }

    #[test]
    fn nginx_dir_and_traefik_file_outside_the_state_dir_are_writable() {
        let mut settings = settings_with("");
        settings.paths.nginx_conf_dir = PathBuf::from("/srv/nginx");
        settings.host.ingress.traefik_dynamic_file = Some(PathBuf::from("/etc/traefik/w.yml"));
        let writable = daemon_writable_mounts(&settings);
        assert!(
            writable.contains(&PathBuf::from("/srv/nginx")),
            "{writable:?}"
        );
        assert!(writable.contains(&PathBuf::from("/etc/traefik/w.yml")));
    }
}
