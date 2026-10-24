//! Ingress management: generating `nginx.conf` and the Traefik file, the nginx container, networks.
//!
//! `apply` is idempotent: with no change to the config or the container it does nothing (notably it
//! does not touch the Traefik file, which has a ~2 s reload throttle). The nginx container carries
//! a `weglarka.ingress-hash` label (image + publishing + hardening — what cannot change on a live
//! container).
//! App networks are *not* part of it: they are connected/disconnected on the running container, and
//! a config change is validated with `nginx -t` (rolled back on failure) and applied with `SIGHUP`.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::StreamExt;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use tokio::sync::{Notify, watch};
use weglarka_core::app::{AppSpec, InstanceName, Security};
use weglarka_core::config::{HostConfig, IngressMode};
use weglarka_core::labels;
use weglarka_core::podman::{
    BindMount, ContainerFilter, ContainerSpec, ContainerState, NetworkSpec, PodmanClient,
    PodmanError, PortMapping, RestartPolicy,
};
use weglarka_core::reconcile::Reconciler;
use weglarka_core::state::{self, write_atomic};
use weglarka_core::uid_range::UidRange;
use weglarka_core::volumes;
use weglarka_ingress::{nginx, traefik};

/// Network joined by both the Węglarka and nginx containers (webhooks: `proxy_pass http://weglarka:<port>`).
pub const WEBHOOK_NETWORK: &str = labels::INGRESS_NETWORK;
pub const NGINX_CONTAINER: &str = "weglarka-nginx";
pub const HASH_LABEL: &str = "weglarka.ingress-hash";
const NGINX_CONF_FILE: &str = "nginx.conf";
const NGINX_CONF_MOUNT: &str = "/etc/nginx";
const NGINX_STOP_TIMEOUT: u32 = 10;
/// Delay before re-running `apply` after a best-effort network operation failed.
const RETRY_DELAY: Duration = Duration::from_secs(3);

#[derive(Debug, thiserror::Error)]
pub enum IngressApplyError {
    #[error("cannot read apps: {0}")]
    State(#[from] state::StateError),
    #[error("cannot generate config: {0}")]
    Generate(#[from] weglarka_ingress::IngressError),
    #[error("podman: {0}")]
    Podman(#[from] PodmanError),
    #[error("uid range for nginx: {0}")]
    Engine(#[from] weglarka_core::reconcile::EngineError),
    #[error("i/o on {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("network {0} has no gateway address (no DNS resolver for nginx)")]
    NoResolver(String),
    #[error(
        "nginx rejected the new config (nginx -t exit {0}); previous config restored — \
         inspect with `podman exec weglarka-nginx nginx -t`"
    )]
    ConfigRejected(i32),
}

fn io_err(path: &Path) -> impl FnOnce(std::io::Error) -> IngressApplyError + '_ {
    move |source| IngressApplyError::Io {
        path: path.to_owned(),
        source,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyReport {
    /// Nothing needed changing.
    Unchanged,
    Changed {
        conf_written: bool,
        traefik_written: bool,
        nginx: NginxAction,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NginxAction {
    None,
    Created,
    Recreated,
    Started,
    Reloaded,
    /// Only the set of attached networks changed (no config change).
    NetworksSynced,
}

pub struct IngressManager<P: PodmanClient> {
    engine: Arc<Reconciler<P>>,
    host: HostConfig,
    conf_dir: PathBuf,
    apps_path: PathBuf,
    apply_lock: tokio::sync::Mutex<()>,
    notify: Notify,
    last_error: Mutex<Option<String>>,
    /// Set when a best-effort step (detaching a stale network) failed: `run` retries soon.
    retry_soon: AtomicBool,
}

impl<P: PodmanClient> IngressManager<P> {
    pub fn new(engine: Arc<Reconciler<P>>, host: HostConfig, conf_dir: PathBuf) -> Self {
        let apps_path = engine.paths().apps.clone();
        Self {
            engine,
            host,
            conf_dir,
            apps_path,
            apply_lock: tokio::sync::Mutex::new(()),
            notify: Notify::new(),
            last_error: Mutex::new(None),
            retry_soon: AtomicBool::new(false),
        }
    }

    /// The set of apps/domains changed — recompute ingress (coalesces many calls into one).
    pub fn request_apply(&self) {
        self.notify.notify_one();
    }

    /// Error from the last `apply` (for `doctor`); `None` means the last run succeeded.
    pub fn last_error(&self) -> Option<String> {
        self.last_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn conf_path(&self) -> PathBuf {
        self.conf_dir.join(NGINX_CONF_FILE)
    }

    /// Loop: apply at startup, after `request_apply` and every `period` (self-heals the nginx container).
    pub async fn run(&self, period: Duration, mut shutdown: watch::Receiver<bool>) {
        loop {
            match self.apply().await {
                Ok(ApplyReport::Unchanged) => {}
                Ok(report) => tracing::info!(?report, "ingress applied"),
                Err(e) => tracing::error!(error = %e, "ingress apply failed"),
            }
            tokio::select! {
                _ = self.notify.notified() => {}
                _ = tokio::time::sleep(if self.retry_soon.load(Ordering::Relaxed) { period.min(RETRY_DELAY) } else { period }) => {}
                _ = shutdown.changed() => return,
            }
        }
    }

    pub async fn apply(&self) -> Result<ApplyReport, IngressApplyError> {
        let _g = self.apply_lock.lock().await;
        self.retry_soon.store(false, Ordering::Relaxed);
        let result = self.apply_locked().await;
        *self.last_error.lock().unwrap_or_else(|e| e.into_inner()) =
            result.as_ref().err().map(ToString::to_string);
        result
    }

    async fn apply_locked(&self) -> Result<ApplyReport, IngressApplyError> {
        let apps: BTreeMap<InstanceName, AppSpec> = state::load_apps(&self.apps_path)?.apps;
        let routed: Vec<&InstanceName> = apps
            .iter()
            .filter(|(_, s)| !s.domains.is_empty())
            .map(|(n, _)| n)
            .collect();

        // Networks: ours (webhooks) plus one per app with a domain (idempotent, independent of deploys).
        let podman = self.engine.podman();
        let mut networks = vec![WEBHOOK_NETWORK.to_owned()];
        networks.extend(routed.iter().map(|n| labels::network_name(n)));
        for net in &networks {
            podman
                .network_create(&NetworkSpec {
                    name: net.clone(),
                    internal: false,
                    labels: BTreeMap::from([("weglarka.managed".to_owned(), "ingress".to_owned())]),
                })
                .await?;
        }
        let mut resolvers = Vec::new();
        let mut forwarder_subnets = Vec::new();
        for net in &networks {
            let info = podman.network_inspect(net).await?;
            if info.gateways.is_empty() {
                return Err(IngressApplyError::NoResolver(net.clone()));
            }
            resolvers.extend(info.gateways);
            if net == WEBHOOK_NETWORK {
                forwarder_subnets = info.subnets;
            }
        }

        // Default trust: only `net-weglarka`, the primary network of the nginx container, where the port
        // forwarder connects from. App networks are never trusted (docs/decisions/0007).
        let trusted = if self.host.ingress.trusted_proxies.is_empty() {
            forwarder_subnets
        } else {
            self.host.ingress.trusted_proxies.clone()
        };
        let options = nginx::NginxOptions::new(resolvers).with_trusted_proxies(&trusted)?;
        let conf = nginx::generate(&self.host, &apps, &options)?;
        let traefik_yaml = match (
            &self.host.ingress.traefik_dynamic_file,
            self.host.ingress.mode,
        ) {
            (Some(_), IngressMode::Behind) => Some(traefik::generate(
                &self.host,
                &apps,
                &traefik::TraefikOptions::default(),
            )?),
            _ => None,
        };

        let previous = fs::read(self.conf_path()).ok();
        let conf_written = self.write_conf(&conf)?;
        // Traefik is updated only once nginx accepted the config (no route to a server that is not there).
        let nginx = match self
            .ensure_nginx(&networks, options.listen_port, conf_written)
            .await
        {
            Ok(action) => action,
            Err(e) => {
                // Roll back so the next `apply` sees the difference again and retries.
                if let (true, Some(old)) = (conf_written, &previous) {
                    let path = self.conf_path();
                    if let Err(re) = write_atomic(&path, old, 0o644) {
                        tracing::error!(error = %re, "cannot restore previous nginx.conf");
                    }
                }
                return Err(e);
            }
        };
        let traefik_written = match (&self.host.ingress.traefik_dynamic_file, &traefik_yaml) {
            (Some(path), Some(yaml)) => write_in_place(path, yaml.as_bytes())?,
            _ => false,
        };

        if !conf_written && !traefik_written && nginx == NginxAction::None {
            Ok(ApplyReport::Unchanged)
        } else {
            Ok(ApplyReport::Changed {
                conf_written,
                traefik_written,
                nginx,
            })
        }
    }

    /// `nginx.conf` atomically (the directory is mounted, so the `rename` is visible in the container).
    fn write_conf(&self, conf: &str) -> Result<bool, IngressApplyError> {
        let path = self.conf_path();
        if fs::read(&path).is_ok_and(|old| old == conf.as_bytes()) {
            return Ok(false);
        }
        fs::create_dir_all(&self.conf_dir).map_err(io_err(&self.conf_dir))?;
        // The nginx container runs under a different uid (userns=auto) — the directory and file must be readable.
        fs::set_permissions(&self.conf_dir, fs::Permissions::from_mode(0o755))
            .map_err(io_err(&self.conf_dir))?;
        write_atomic(&path, conf.as_bytes(), 0o644).map_err(io_err(&path))?;
        Ok(true)
    }

    async fn ensure_nginx(
        &self,
        networks: &[String],
        listen_port: u16,
        conf_changed: bool,
    ) -> Result<NginxAction, IngressApplyError> {
        let podman = self.engine.podman();
        let image = &self.host.ingress.nginx_image;
        let bind = self.host.ingress.bind;
        // The range is part of the container's identity: nginx created before ranges existed is
        // recreated once, now on its own map instead of libpod's shared default (docs/decisions/0009).
        let range = self.engine.ensure_ingress_range().await?;
        let hash = ingress_hash(
            image,
            &bind.to_string(),
            listen_port,
            range,
            &nginx_security(),
        );

        let existing = podman
            .container_list(&ContainerFilter::default())
            .await?
            .into_iter()
            .find(|c| c.name == NGINX_CONTAINER);

        let existed = existing.is_some();
        let Some(existing) = existing.filter(|c| c.labels.get(HASH_LABEL) == Some(&hash)) else {
            self.create_nginx(networks, listen_port, hash, range, existed)
                .await?;
            return Ok(if existed {
                NginxAction::Recreated
            } else {
                NginxAction::Created
            });
        };

        // Networks are attached to the live container; removal waits until the new config is live.
        let missing: Vec<&String> = networks
            .iter()
            .filter(|n| !existing.networks.contains(n))
            .collect();
        let stale: Vec<&String> = existing
            .networks
            .iter()
            .filter(|n| !networks.contains(n))
            .collect();
        for net in &missing {
            podman.network_connect(net, NGINX_CONTAINER).await?;
        }

        let mut action = NginxAction::None;
        if existing.state != ContainerState::Running {
            podman.container_start(NGINX_CONTAINER).await?;
            action = NginxAction::Started;
        } else if conf_changed {
            let test = ["nginx", "-t", "-c", "/etc/nginx/nginx.conf"].map(str::to_owned);
            let code = podman.container_exec(NGINX_CONTAINER, &test).await?;
            if code != 0 {
                return Err(IngressApplyError::ConfigRejected(code));
            }
            podman.container_kill(NGINX_CONTAINER, "HUP").await?;
            action = NginxAction::Reloaded;
        } else if !missing.is_empty() {
            action = NginxAction::NetworksSynced;
        }
        // Detaching a stale network is best effort: a container removed concurrently (`apps remove`)
        // can make libpod fail the call. That must not block the new config and the Traefik file
        // (the removed app's router would stay) — log it and retry shortly (`retry_soon`).
        for net in &stale {
            match podman.network_disconnect(net, NGINX_CONTAINER).await {
                Ok(()) | Err(PodmanError::NotFound(_)) => {
                    if action == NginxAction::None {
                        action = NginxAction::NetworksSynced;
                    }
                }
                Err(e) => {
                    tracing::warn!(network = %net, error = %e, "cannot detach stale network from nginx, will retry");
                    self.retry_soon.store(true, Ordering::Relaxed);
                }
            }
        }
        Ok(action)
    }

    /// (Re)creates the nginx container with the current set of networks.
    async fn create_nginx(
        &self,
        networks: &[String],
        listen_port: u16,
        hash: String,
        range: UidRange,
        replace: bool,
    ) -> Result<(), IngressApplyError> {
        let podman = self.engine.podman();
        let image = &self.host.ingress.nginx_image;
        let bind = self.host.ingress.bind;
        self.ensure_image(image).await?;
        if replace {
            match podman
                .container_stop(NGINX_CONTAINER, NGINX_STOP_TIMEOUT)
                .await
            {
                Ok(()) | Err(PodmanError::NotFound(_)) => {}
                Err(e) => return Err(e.into()),
            }
            podman.container_remove(NGINX_CONTAINER, true).await?;
        }
        podman
            .container_create(&ContainerSpec {
                name: NGINX_CONTAINER.to_owned(),
                image: image.clone(),
                // The image's own CMD starts nginx; nothing to add.
                command: vec![],
                // No `weglarka.instance` — reconcile would treat the container as an orphan.
                labels: BTreeMap::from([(HASH_LABEL.to_owned(), hash)]),
                env: BTreeMap::new(),
                networks: networks.to_vec(),
                secrets: vec![],
                publish: vec![PortMapping {
                    host_ip: Some(bind.ip().to_string()),
                    host_port: bind.port(),
                    container_port: listen_port,
                }],
                restart: RestartPolicy::Always,
                userns_auto: false,
                mounts: vec![BindMount {
                    source: self.conf_dir.display().to_string(),
                    target: NGINX_CONF_MOUNT.to_owned(),
                    read_only: true,
                }],
                volumes: vec![],
                resources: Default::default(),
                healthcheck: None,
                id_mapping: Some(volumes::id_mapping(range)),
                security: nginx_security(),
            })
            .await?;
        podman.container_start(NGINX_CONTAINER).await?;
        Ok(())
    }

    async fn ensure_image(&self, image: &str) -> Result<(), IngressApplyError> {
        let podman = self.engine.podman();
        match podman.image_inspect(image).await {
            Ok(_) => Ok(()),
            Err(PodmanError::NotFound(_)) => {
                let mut stream = std::pin::pin!(podman.image_pull(image));
                while let Some(ev) = stream.next().await {
                    ev?;
                }
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }
}

/// Version of the ingress hash input; bump when its shape changes (recreates every nginx container).
const INGRESS_HASH_FORMAT: &str = "weglarka.ingress-hash/v2";

/// Hardened profile of the nginx container — ours to choose, unlike an app's `security`, so it is always
/// on (docs/decisions/0014): read-only root with libpod's writable `/tmp`, `/var/tmp` and `/run` tmpfs
/// (`read_write_tmpfs`, the `podman run --read-only` default), every capability dropped, and only the
/// three nginx genuinely needs added back, plus `no-new-privileges`.
///
/// The three are not a safety margin, they are what the official image does even though our generated
/// config has no `user` directive: nginx falls back to the worker user compiled into the image
/// (`nginx`, uid 101), chowns its temp directories to it (`CHOWN`) and the master drops to it
/// (`SETGID`, `SETUID`). Measured on `nginx:1-alpine` with exactly this profile: without `CHOWN` the
/// container dies with `chown("/tmp/client_body", 101) failed`, with `CHOWN` only the worker dies with
/// `setgid(101) failed`. `NET_BIND_SERVICE` is not needed (8080), and `pid` plus every `*_temp_path`
/// already live under `/tmp` (`weglarka-ingress/src/nginx.rs`), the one writable place this profile
/// leaves — the generator test keeps that invariant.
fn nginx_security() -> Security {
    Security {
        read_only: true,
        tmpfs: vec![],
        cap_drop: vec!["ALL".to_owned()],
        cap_add: ["CHOWN", "SETGID", "SETUID"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        no_new_privileges: true,
    }
}

/// Spec hash of the nginx container: only what cannot change on a live container. The set of app
/// networks is deliberately absent (it is synced with connect/disconnect), as is the config (reload).
/// Hardening is in: changing the profile must recreate the container, not leave an old, writable one.
fn ingress_hash(
    image: &str,
    bind: &str,
    listen_port: u16,
    range: UidRange,
    security: &Security,
) -> String {
    let input = IngressHashInput {
        format: INGRESS_HASH_FORMAT,
        image,
        bind,
        listen_port,
        range_start: range.start,
        range_size: range.size,
        security,
    };
    let json = serde_json::to_vec(&input).expect("ingress hash input is always serializable");
    hex::encode(&Sha256::digest(json)[..8])
}

/// Field order is part of the hash format (mirrors `weglarka_core::hash::HashInput`).
#[derive(Serialize)]
struct IngressHashInput<'a> {
    format: &'static str,
    image: &'a str,
    bind: &'a str,
    listen_port: u16,
    range_start: u32,
    range_size: u32,
    security: &'a Security,
}

/// Overwrites a file in place (truncate + write + fsync), without `rename`: the ACL on the Traefik
/// directory grants traversal only, and the file is created up front. Returns `false` if the
/// content is already up to date.
pub fn write_in_place(path: &Path, bytes: &[u8]) -> Result<bool, IngressApplyError> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o644)
        .open(path)
        .map_err(io_err(path))?;
    let mut current = Vec::new();
    file.read_to_end(&mut current).map_err(io_err(path))?;
    if current == bytes {
        return Ok(false);
    }
    file.set_len(0).map_err(io_err(path))?;
    // After `read_to_end` the position is at the end — after `set_len(0)` we must seek back to the start.
    std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(0)).map_err(io_err(path))?;
    file.write_all(bytes).map_err(io_err(path))?;
    file.sync_all().map_err(io_err(path))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_in_place_keeps_inode_and_skips_identical() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.yml");
        fs::write(&path, "old content that is long").unwrap();
        let inode = fs::metadata(&path).unwrap().ino();
        assert!(write_in_place(&path, b"new").unwrap());
        assert_eq!(fs::read(&path).unwrap(), b"new");
        assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
        assert!(!write_in_place(&path, b"new").unwrap());
    }

    #[test]
    fn hardened_profile_is_read_only_yet_workable() {
        let s = nginx_security();
        assert!(s.read_only, "read-only root");
        assert!(s.no_new_privileges, "no-new-privileges");
        assert_eq!(s.cap_drop, ["ALL"]);
        assert_eq!(
            s.cap_add,
            ["CHOWN", "SETGID", "SETUID"],
            "worker-uid drop and temp-dir chown, nothing more"
        );
        assert!(s.tmpfs.is_empty(), "libpod's writable /tmp is enough");
    }

    #[test]
    fn hash_covers_image_bind_port_and_uid_range() {
        let r = UidRange {
            start: 1,
            size: 4096,
        };
        let sec = nginx_security();
        let a = ingress_hash("i", "x", 80, r, &sec);
        assert_eq!(a, ingress_hash("i", "x", 80, r, &sec));
        assert_ne!(a, ingress_hash("j", "x", 80, r, &sec));
        assert_ne!(a, ingress_hash("i", "y", 80, r, &sec));
        assert_ne!(a, ingress_hash("i", "x", 81, r, &sec));
        assert_ne!(
            a,
            ingress_hash(
                "i",
                "x",
                80,
                UidRange {
                    start: 4097,
                    size: 4096
                },
                &sec
            )
        );
    }

    /// Upgrading from a build without hardening must recreate nginx: the profile is in the hash.
    #[test]
    fn hash_covers_hardening() {
        let r = UidRange {
            start: 1,
            size: 4096,
        };
        let hardened = nginx_security();
        let unhardened = Security::default();
        assert_ne!(
            ingress_hash("i", "x", 80, r, &hardened),
            ingress_hash("i", "x", 80, r, &unhardened),
            "a profile change must not leave the old container in place"
        );
        let mut no_nnp = hardened.clone();
        no_nnp.no_new_privileges = false;
        assert_ne!(
            ingress_hash("i", "x", 80, r, &hardened),
            ingress_hash("i", "x", 80, r, &no_nnp)
        );
    }
}
