//! Ingress management: generating `nginx.conf` and the Traefik file, the nginx container, networks.
//!
//! `apply` is idempotent: with no change to the config or the container it does nothing (notably it
//! does not touch the Traefik file, which has a ~2 s reload throttle). The nginx container carries
//! a `weglarka.ingress-hash` label (image + networks + publishing); a change in the set of app
//! networks means recreating the container (there is no `network_disconnect`), a config-only
//! change means `SIGHUP`.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::StreamExt;
use sha2::{Digest as _, Sha256};
use tokio::sync::{Notify, watch};
use weglarka_core::app::{AppSpec, InstanceName};
use weglarka_core::config::{HostConfig, IngressMode};
use weglarka_core::labels;
use weglarka_core::podman::{
    BindMount, ContainerFilter, ContainerSpec, ContainerState, NetworkSpec, PodmanClient,
    PodmanError, PortMapping, RestartPolicy,
};
use weglarka_core::reconcile::Reconciler;
use weglarka_core::state::{self, write_atomic};
use weglarka_ingress::{nginx, traefik};

/// Network joined by both the Węglarka and nginx containers (webhooks: `proxy_pass http://weglarka:<port>`).
pub const WEBHOOK_NETWORK: &str = "net-weglarka";
pub const NGINX_CONTAINER: &str = "weglarka-nginx";
pub const HASH_LABEL: &str = "weglarka.ingress-hash";
const NGINX_CONF_FILE: &str = "nginx.conf";
const NGINX_CONF_MOUNT: &str = "/etc/nginx";
const NGINX_STOP_TIMEOUT: u32 = 10;

#[derive(Debug, thiserror::Error)]
pub enum IngressApplyError {
    #[error("cannot read apps: {0}")]
    State(#[from] state::StateError),
    #[error("cannot generate config: {0}")]
    Generate(#[from] weglarka_ingress::IngressError),
    #[error("podman: {0}")]
    Podman(#[from] PodmanError),
    #[error("i/o on {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("network {0} has no gateway address (no DNS resolver for nginx)")]
    NoResolver(String),
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
}

pub struct IngressManager<P: PodmanClient> {
    engine: Arc<Reconciler<P>>,
    host: HostConfig,
    conf_dir: PathBuf,
    apps_path: PathBuf,
    apply_lock: tokio::sync::Mutex<()>,
    notify: Notify,
    last_error: Mutex<Option<String>>,
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
                _ = tokio::time::sleep(period) => {}
                _ = shutdown.changed() => return,
            }
        }
    }

    pub async fn apply(&self) -> Result<ApplyReport, IngressApplyError> {
        let _g = self.apply_lock.lock().await;
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
        for net in &networks {
            let info = podman.network_inspect(net).await?;
            if info.gateways.is_empty() {
                return Err(IngressApplyError::NoResolver(net.clone()));
            }
            resolvers.extend(info.gateways);
        }

        let options = nginx::NginxOptions::new(resolvers);
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

        let conf_written = self.write_conf(&conf)?;
        let traefik_written = match (&self.host.ingress.traefik_dynamic_file, &traefik_yaml) {
            (Some(path), Some(yaml)) => write_in_place(path, yaml.as_bytes())?,
            _ => false,
        };
        let nginx = self
            .ensure_nginx(&networks, options.listen_port, conf_written)
            .await?;

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
        let hash = ingress_hash(image, networks, &bind.to_string(), listen_port);

        let existing = podman
            .container_list(&ContainerFilter::default())
            .await?
            .into_iter()
            .find(|c| c.name == NGINX_CONTAINER);

        let action = match &existing {
            None => NginxAction::Created,
            Some(c) if c.labels.get(HASH_LABEL) != Some(&hash) => NginxAction::Recreated,
            Some(c) if c.state != ContainerState::Running => NginxAction::Started,
            Some(_) if conf_changed => NginxAction::Reloaded,
            Some(_) => NginxAction::None,
        };

        match action {
            NginxAction::None => {}
            NginxAction::Reloaded => {
                podman.container_kill(NGINX_CONTAINER, "HUP").await?;
            }
            NginxAction::Started => {
                podman.container_start(NGINX_CONTAINER).await?;
            }
            NginxAction::Created | NginxAction::Recreated => {
                self.ensure_image(image).await?;
                if existing.is_some() {
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
                        userns_auto: true,
                        mounts: vec![BindMount {
                            source: self.conf_dir.display().to_string(),
                            target: NGINX_CONF_MOUNT.to_owned(),
                            read_only: true,
                        }],
                    })
                    .await?;
                podman.container_start(NGINX_CONTAINER).await?;
            }
        }
        Ok(action)
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

fn ingress_hash(image: &str, networks: &[String], bind: &str, listen_port: u16) -> String {
    let mut nets: Vec<&String> = networks.iter().collect();
    nets.sort();
    let mut h = Sha256::new();
    for part in [image, bind] {
        h.update(part.as_bytes());
        h.update([0]);
    }
    h.update(listen_port.to_be_bytes());
    for n in nets {
        h.update([0]);
        h.update(n.as_bytes());
    }
    hex::encode(&h.finalize()[..8])
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
    fn hash_ignores_network_order_but_not_membership() {
        let a = ingress_hash("i", &["a".into(), "b".into()], "x", 80);
        let b = ingress_hash("i", &["b".into(), "a".into()], "x", 80);
        let c = ingress_hash("i", &["a".into()], "x", 80);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
