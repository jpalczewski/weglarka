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
use std::net::{IpAddr, SocketAddr};
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
use weglarka_ingress::{Domain, nginx, traefik};

/// Network joined by both the Węglarka and nginx containers (webhooks: `proxy_pass http://weglarka:<port>`).
pub const WEBHOOK_NETWORK: &str = labels::INGRESS_NETWORK;
pub const NGINX_CONTAINER: &str = "weglarka-nginx";
pub const HASH_LABEL: &str = "weglarka.ingress-hash";
const NGINX_CONF_FILE: &str = "nginx.conf";
const NGINX_CONF_MOUNT: &str = "/etc/nginx";
const NGINX_STOP_TIMEOUT: u32 = 10;
/// `<nginx_conf_dir>` subdirectories (issue #95): TLS material and the ACME HTTP-01 webroot. Both sit
/// inside the directory mounted at `/etc/nginx`, so `edge` needs no extra mount and no hash entry
/// for mounts: the nginx container already sees them.
const TLS_SUBDIR: &str = "tls";
const ACME_SUBDIR: &str = "acme";
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

        // `edge` (issue #95): certificates come from the state dir on every pass, so a renewal is
        // picked up (the fingerprint makes the config differ) and a missing one simply leaves the
        // domain without a TLS server. `behind` has no TLS material of its own (Traefik owns it).
        let (certificates, tls_fingerprint) = if self.host.ingress.mode == IngressMode::Edge {
            self.ensure_tls_material()?
        } else {
            (Vec::new(), None)
        };

        // Default trust: nginx's own addresses (docs/decisions/0032), unless the operator pinned a list.
        // Only `behind` trusts anybody: in `edge` nginx terminates TLS and direct clients are untrusted.
        let behind = self.host.ingress.mode == IngressMode::Behind;
        let pinned = !self.host.ingress.trusted_proxies.is_empty();
        let render = Render {
            apps: &apps,
            resolvers: &resolvers,
            forwarder_subnets: &forwarder_subnets,
            networks: &networks,
            certificates: &certificates,
            tls_fingerprint: tls_fingerprint.as_deref(),
        };
        let mut own_addresses = if behind {
            self.nginx_addresses().await?
        } else {
            Vec::new()
        };
        let (mut conf_written, mut nginx) = self.apply_nginx(&render, &own_addresses).await?;
        // The addresses the config trusts were read before nginx was (re)created or joined a new network, so
        // they may be stale (or the bootstrap fallback): never leave that config in place. Re-read and, if
        // they moved, regenerate and reload within this pass. If the re-read fails, retry shortly.
        if behind && !pinned {
            let current = self.nginx_addresses().await.inspect_err(|_| {
                self.retry_soon.store(true, Ordering::Relaxed);
            })?;
            if current != own_addresses {
                tracing::info!("nginx addresses changed, regenerating the trusted peers");
                own_addresses = current;
                let (written, action) = self.apply_nginx(&render, &own_addresses).await?;
                conf_written |= written;
                if matches!(nginx, NginxAction::None | NginxAction::NetworksSynced) {
                    nginx = action;
                }
            }
        }
        // Traefik is updated only once nginx accepted the config (no route to a server that is not there).
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

    /// Generates `nginx.conf` for the given own addresses, writes it and brings the container in line
    /// (create/reload); a rejected config is rolled back on disk. Returns `(conf_written, action)`.
    async fn apply_nginx(
        &self,
        r: &Render<'_>,
        own_addresses: &[IpAddr],
    ) -> Result<(bool, NginxAction), IngressApplyError> {
        let mut options = nginx::NginxOptions::new(r.resolvers.to_vec());
        if self.host.ingress.mode == IngressMode::Behind {
            let trusted = if self.host.ingress.trusted_proxies.is_empty() {
                default_trusted(own_addresses, r.forwarder_subnets)
            } else {
                self.host.ingress.trusted_proxies.clone()
            };
            options = options.with_trusted_proxies(&trusted)?;
        } else {
            options.certificates = r.certificates.to_vec();
            options.tls_fingerprint = r.tls_fingerprint.map(str::to_owned);
        }
        let conf = nginx::generate(&self.host, r.apps, &options)?;

        let previous = fs::read(self.conf_path()).ok();
        let conf_written = self.write_conf(&conf)?;
        match self
            .ensure_nginx(
                r.networks,
                options.listen_port,
                options.https_listen_port,
                conf_written,
            )
            .await
        {
            Ok(action) => Ok((conf_written, action)),
            Err(e) => {
                // Roll back so the next `apply` sees the difference again and retries.
                if let (true, Some(old)) = (conf_written, &previous) {
                    let path = self.conf_path();
                    if let Err(re) = write_atomic(&path, old, 0o644) {
                        tracing::error!(error = %re, "cannot restore previous nginx.conf");
                    }
                }
                Err(e)
            }
        }
    }

    /// The running nginx container's own addresses on all its networks (sorted); empty when it does not
    /// exist yet or is not running.
    async fn nginx_addresses(&self) -> Result<Vec<IpAddr>, IngressApplyError> {
        let containers = self
            .engine
            .podman()
            .container_list(&ContainerFilter::default())
            .await?;
        Ok(containers
            .into_iter()
            .find(|c| c.name == NGINX_CONTAINER && c.state == ContainerState::Running)
            .map(|c| c.addresses)
            .unwrap_or_default())
    }

    /// `nginx.conf` atomically (the directory is mounted, so the `rename` is visible in the container).
    fn write_conf(&self, conf: &str) -> Result<bool, IngressApplyError> {
        let path = self.conf_path();
        if fs::read(&path).is_ok_and(|old| old == conf.as_bytes()) {
            return Ok(false);
        }
        fs::create_dir_all(&self.conf_dir).map_err(io_err(&self.conf_dir))?;
        // The nginx container runs in its own uid namespace: the directory and `nginx.conf` must be
        // readable by the container's worker uid (the ACME webroot files are served by it).
        fs::set_permissions(&self.conf_dir, fs::Permissions::from_mode(0o755))
            .map_err(io_err(&self.conf_dir))?;
        write_atomic(&path, conf.as_bytes(), 0o644).map_err(io_err(&path))?;
        Ok(true)
    }

    /// `edge` TLS material from the state dir (issue #95): creates the ACME webroot (`0755`, the worker
    /// serves the tokens) and the TLS directory (`0700`, only the master — running as the daemon's user
    /// under the ingress uid map — needs it), then returns the domains with a `<domain>.crt` +
    /// `<domain>.key` pair and a fingerprint of the material.
    ///
    /// The fingerprint is rendered into `nginx.conf`, so renewing a certificate changes the config and
    /// rides the normal `nginx -t` + SIGHUP path; it is metadata only (name, size, mtime), the daemon
    /// never reads the private keys. Anything that is not a regular `<domain>.crt` file, or has no
    /// matching key, is ignored: the domain simply keeps its redirect and has no TLS server.
    fn ensure_tls_material(&self) -> Result<(Vec<Domain>, Option<String>), IngressApplyError> {
        let acme = self.conf_dir.join(ACME_SUBDIR);
        let tls = self.conf_dir.join(TLS_SUBDIR);
        fs::create_dir_all(&acme).map_err(io_err(&acme))?;
        fs::set_permissions(&acme, fs::Permissions::from_mode(0o755)).map_err(io_err(&acme))?;
        if !tls.is_dir() {
            fs::create_dir_all(&tls).map_err(io_err(&tls))?;
            fs::set_permissions(&tls, fs::Permissions::from_mode(0o700)).map_err(io_err(&tls))?;
        }

        let mut candidates: Vec<Domain> = Vec::new();
        let entries = match fs::read_dir(&tls) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok((candidates, Some(empty_fingerprint())));
            }
            Err(e) => return Err(io_err(&tls)(e)),
        };
        for entry in entries {
            let entry = entry.map_err(io_err(&tls))?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Some(stem) = name.strip_suffix(".crt") else {
                continue;
            };
            match Domain::new(stem) {
                Ok(domain) => candidates.push(domain),
                Err(_) => {
                    tracing::warn!(file = %name, "ignoring a TLS file whose name is not a domain")
                }
            }
        }
        candidates.sort();
        candidates.dedup();

        let mut material = Vec::new();
        let mut certificates = Vec::new();
        for domain in candidates {
            let cert = tls.join(format!("{domain}.crt"));
            let key = tls.join(format!("{domain}.key"));
            let (Ok(cert_meta), Ok(key_meta)) =
                (fs::symlink_metadata(&cert), fs::symlink_metadata(&key))
            else {
                tracing::debug!(%domain, "no certificate pair in the TLS directory");
                continue;
            };
            if !cert_meta.is_file() || !key_meta.is_file() {
                tracing::warn!(%domain, "certificate or key is not a regular file, ignoring");
                continue;
            }
            material.push(format!(
                "{domain}:{}:{}:{}:{}",
                cert_meta.len(),
                mtime_nanos(&cert_meta),
                key_meta.len(),
                mtime_nanos(&key_meta)
            ));
            certificates.push(domain);
        }
        let fingerprint = if material.is_empty() {
            empty_fingerprint()
        } else {
            let digest = Sha256::digest(material.join("\n").as_bytes());
            hex::encode(&digest[..4])
        };
        Ok((certificates, Some(fingerprint)))
    }

    /// `edge`: the TLS material directory (`<nginx_conf_dir>/tls`).
    pub fn tls_dir(&self) -> PathBuf {
        self.conf_dir.join(TLS_SUBDIR)
    }

    /// `edge`: the ACME HTTP-01 webroot (`<nginx_conf_dir>/acme`).
    pub fn acme_dir(&self) -> PathBuf {
        self.conf_dir.join(ACME_SUBDIR)
    }

    async fn ensure_nginx(
        &self,
        networks: &[String],
        listen_port: u16,
        https_listen_port: u16,
        conf_changed: bool,
    ) -> Result<NginxAction, IngressApplyError> {
        let podman = self.engine.podman();
        let image = &self.host.ingress.nginx_image;
        let bind = self.host.ingress.bind;
        let https_bind = self.host.ingress.https_bind;
        // The range is part of the container's identity: nginx created before ranges existed is
        // recreated once, now on its own map instead of libpod's shared default (docs/decisions/0009).
        let range = self.engine.ensure_ingress_range().await?;
        let hash = ingress_hash(
            image,
            bind,
            https_bind,
            listen_port,
            https_listen_port,
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
            self.create_nginx(
                networks,
                listen_port,
                https_listen_port,
                hash,
                range,
                existed,
            )
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
        https_listen_port: u16,
        hash: String,
        range: UidRange,
        replace: bool,
    ) -> Result<(), IngressApplyError> {
        let podman = self.engine.podman();
        let image = &self.host.ingress.nginx_image;
        let bind = self.host.ingress.bind;
        // nginx listens on unprivileged ports inside the container; only the *host* side is 80/443 in
        // `edge`, so the hardened profile needs no `NET_BIND_SERVICE` (ADR 0014).
        let mut publish = vec![PortMapping {
            host_ip: Some(bind.ip().to_string()),
            host_port: bind.port(),
            container_port: listen_port,
        }];
        if let Some(https) = self.host.ingress.https_bind {
            publish.push(PortMapping {
                host_ip: Some(https.ip().to_string()),
                host_port: https.port(),
                container_port: https_listen_port,
            });
        }
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
                network_aliases: Default::default(),
                secrets: vec![],
                publish,
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
                // `edge`/`behind`: container uid 0 is the daemon's host user, so the TLS master reads
                // the 0600 keys; the worker stays in the reserved ingress range (docs/decisions/0035).
                id_mapping: Some(volumes::ingress_id_mapping(range)),
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
/// v3 (issue #95): the mode and the second publish are part of the identity.
const INGRESS_HASH_FORMAT: &str = "weglarka.ingress-hash/v3";

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
/// Inputs of one `nginx.conf` rendering that do not depend on nginx's addresses.
struct Render<'a> {
    apps: &'a BTreeMap<InstanceName, AppSpec>,
    resolvers: &'a [IpAddr],
    forwarder_subnets: &'a [String],
    networks: &'a [String],
    /// `edge`: domains with a certificate pair in [`TLS_SUBDIR`]; empty in `behind`.
    certificates: &'a [Domain],
    /// `edge`: fingerprint of the TLS material. It is rendered into `nginx.conf`, so a renewed
    /// certificate re-renders the config and goes through the usual `nginx -t` + SIGHUP path
    /// (never a recreate). `None` in `behind`.
    tls_fingerprint: Option<&'a str>,
}

/// Peers whose `X-Forwarded-*` nginx trusts by default (docs/decisions/0032): nginx's **own**
/// addresses. With rootless Podman the published port is served by a forwarder that dials from inside
/// nginx's network namespace, so its source address is one of nginx's own interface addresses — on
/// whichever attached network it picked, not necessarily `net-weglarka`. An app container reaching
/// nginx over its network has a different address and stays untrusted.
///
/// Before the container runs (first `apply`) there are no addresses yet; the `net-weglarka` subnet
/// bootstraps the config until the next pass replaces it.
fn default_trusted(own_addresses: &[IpAddr], bootstrap_subnets: &[String]) -> Vec<String> {
    if own_addresses.is_empty() {
        bootstrap_subnets.to_vec()
    } else {
        own_addresses.iter().map(ToString::to_string).collect()
    }
}

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
#[allow(clippy::too_many_arguments)]
fn ingress_hash(
    image: &str,
    bind: SocketAddr,
    https_bind: Option<SocketAddr>,
    listen_port: u16,
    https_listen_port: u16,
    range: UidRange,
    security: &Security,
) -> String {
    let input = IngressHashInput {
        format: INGRESS_HASH_FORMAT,
        image,
        bind: bind.to_string(),
        https_bind: https_bind.map(|b| b.to_string()),
        listen_port,
        https_listen_port,
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
    bind: String,
    https_bind: Option<String>,
    listen_port: u16,
    https_listen_port: u16,
    range_start: u32,
    range_size: u32,
    security: &'a Security,
}

/// The fingerprint of an empty TLS directory. It still renders into the config (so switching to
/// `edge` re-renders) and a later first certificate changes it.
fn empty_fingerprint() -> String {
    hex::encode(&Sha256::digest(b"no tls material")[..4])
}

/// Seconds/nanoseconds of a file's mtime; `0` when the platform does not report it.
fn mtime_nanos(meta: &fs::Metadata) -> u128 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_nanos())
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
    fn default_trust_is_nginx_own_addresses_with_a_bootstrap_fallback() {
        let own: Vec<IpAddr> = ["10.89.0.2", "10.89.2.6"]
            .map(|a| a.parse().unwrap())
            .into();
        let subnets = ["10.89.0.0/24".to_owned()];
        // Single hosts, never the networks they sit in.
        assert_eq!(default_trusted(&own, &subnets), ["10.89.0.2", "10.89.2.6"]);
        // No running container yet: the webhook network keeps the first config valid.
        assert_eq!(default_trusted(&[], &subnets), ["10.89.0.0/24"]);
    }

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
        let bind = "127.0.0.1:18080".parse().unwrap();
        let a = ingress_hash("i", bind, None, 8080, 8443, r, &sec);
        assert_eq!(a, ingress_hash("i", bind, None, 8080, 8443, r, &sec));
        assert_ne!(a, ingress_hash("j", bind, None, 8080, 8443, r, &sec));
        assert_ne!(
            a,
            ingress_hash(
                "i",
                "127.0.0.1:18081".parse().unwrap(),
                None,
                8080,
                8443,
                r,
                &sec
            )
        );
        assert_ne!(a, ingress_hash("i", bind, None, 8081, 8443, r, &sec));
        assert_ne!(
            a,
            ingress_hash(
                "i",
                bind,
                None,
                8080,
                8443,
                UidRange {
                    start: 4097,
                    size: 4096
                },
                &sec
            )
        );
    }

    /// `edge` (issue #95): the second publish is part of the container's identity, so changing
    /// `https_bind` must recreate it instead of leaving the old port mapping in place.
    #[test]
    fn hash_covers_the_edge_tls_publish() {
        let r = UidRange {
            start: 1,
            size: 4096,
        };
        let sec = nginx_security();
        let bind = "0.0.0.0:80".parse().unwrap();
        let https = "0.0.0.0:443".parse().unwrap();
        let a = ingress_hash("i", bind, Some(https), 8080, 8443, r, &sec);
        assert_eq!(a, ingress_hash("i", bind, Some(https), 8080, 8443, r, &sec));
        assert_ne!(
            a,
            ingress_hash(
                "i",
                bind,
                Some("0.0.0.0:444".parse().unwrap()),
                8080,
                8443,
                r,
                &sec
            )
        );
        assert_ne!(a, ingress_hash("i", bind, None, 8080, 8443, r, &sec));
        assert_ne!(a, ingress_hash("i", bind, Some(https), 8080, 8444, r, &sec));
    }

    /// Upgrading from a build without hardening must recreate nginx: the profile is in the hash.
    #[test]
    fn hash_covers_hardening() {
        let r = UidRange {
            start: 1,
            size: 4096,
        };
        let bind = "127.0.0.1:18080".parse().unwrap();
        let hardened = nginx_security();
        let unhardened = Security::default();
        assert_ne!(
            ingress_hash("i", bind, None, 8080, 8443, r, &hardened),
            ingress_hash("i", bind, None, 8080, 8443, r, &unhardened),
            "a profile change must not leave the old container in place"
        );
        let mut no_nnp = hardened.clone();
        no_nnp.no_new_privileges = false;
        assert_ne!(
            ingress_hash("i", bind, None, 8080, 8443, r, &hardened),
            ingress_hash("i", bind, None, 8080, 8443, r, &no_nnp)
        );
    }
}
