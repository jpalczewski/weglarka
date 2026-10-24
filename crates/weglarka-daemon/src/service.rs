//! The description of Węglarka's own service, shared by `platform install` and the host-side
//! self-update switcher (`weglarka-daemon self-update`): both must render exactly the same unit, only
//! with a different image.
//!
//! The switcher runs on the host — the container has no `systemctl`, no `/etc/passwd` and no write
//! access to its own unit — so it also resolves the Podman socket here (`docs/decisions/0027`).

use std::path::PathBuf;

use weglarka_core::platform::{Hardening, Platform, Result, ServiceSpec};

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
    use weglarka_core::config::HostConfig;

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
}
