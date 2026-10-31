//! Ingress management: generating `nginx.conf` and the Traefik file, the nginx container, networks.
//!
//! `apply` is idempotent: with no change to the config or the container it does nothing (notably it
//! does not touch the Traefik file, which has a ~2 s reload throttle). The nginx container carries
//! a `weglarka.ingress-hash` label (image + publishing + hardening — what cannot change on a live
//! container).
//! App networks are *not* part of it: they are connected/disconnected on the running container, and
//! a config change is validated with `nginx -t` (rolled back on failure) and applied with `SIGHUP`.

use std::collections::{BTreeMap, BTreeSet};
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
use weglarka_engine::reconcile::Reconciler;
use weglarka_engine::volumes;
use weglarka_ingress::{Domain, nginx, traefik};
use weglarka_model::app::{AppKind, AppSpec, InstanceName, Security};
use weglarka_model::config::{HostConfig, IngressMode, WILDCARD_CERT_PREFIX};
use weglarka_model::fsutil::write_atomic;
use weglarka_model::labels;
use weglarka_model::podman::{
    BindMount, ContainerFilter, ContainerSpec, ContainerState, NetworkSpec, PodmanClient,
    PodmanError, PodmanResultExt, PortMapping, RestartPolicy,
};
use weglarka_model::state;
use weglarka_model::uid_range::UidRange;

use crate::service::SERVICE_NAME;

/// Network joined by both the Węglarka and nginx containers (webhooks: `proxy_pass http://weglarka:<port>`).
pub const WEBHOOK_NETWORK: &str = labels::INGRESS_NETWORK;
pub const NGINX_CONTAINER: &str = "weglarka-nginx";
/// `edge` port forwarder (issue #162, docs/decisions/0043): publishes the public sockets on the default
/// (pasta) network, which keeps the client address, and relays to nginx's unix sockets with PROXY protocol.
pub const FORWARDER_CONTAINER: &str = "weglarka-forwarder";
pub const HASH_LABEL: &str = "weglarka.ingress-hash";
/// The canonical JSON the hash was computed from, so a later mismatch can name the field that changed
/// (the `reason` logged when a container has to be recreated, issue #183). Informational: only the hash decides.
pub const SPEC_LABEL: &str = "weglarka.ingress-spec";
const NGINX_CONF_FILE: &str = "nginx.conf";
const NGINX_CONF_MOUNT: &str = "/etc/nginx";
const NGINX_STOP_TIMEOUT: u32 = 10;
/// The forwarder is a stateless relay that exits on SIGTERM: a stop that takes longer is a bug worth failing fast on.
const FORWARDER_STOP_TIMEOUT: u32 = 3;
/// `<nginx_conf_dir>/run` (`0700`): the two unix sockets nginx listens on for the forwarder. A subdirectory
/// of the one directory nginx already mounts, so the trust boundary of docs/decisions/0036 is unchanged; it is
/// mounted a second time, writable, at [`SOCKET_CONTAINER_DIR`].
const SOCKET_SUBDIR: &str = "run";
const SOCKET_CONTAINER_DIR: &str = "/run/weglarka-ingress";
/// Ports the forwarder listens on inside its container (the host side is `bind` / `https_bind`).
const FORWARDER_HTTP_PORT: u16 = 8080;
const FORWARDER_HTTPS_PORT: u16 = 8443;

/// `<nginx_conf_dir>/probe` (`0700`): the daemon's health-probe socket (docs/decisions/0054). Mounted writable into
/// nginx **only** — not into [`SOCKET_SUBDIR`], which the internet-facing forwarder mounts: the probe socket
/// skips TLS and forward auth, so the mounts are what isolate it. The daemon reaches it by the host path.
const PROBE_SUBDIR: &str = "probe";
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
    Engine(#[from] weglarka_engine::reconcile::EngineError),
    #[error("i/o on {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot find the daemon's own container to run the port forwarder from its image: {0}")]
    ForwarderImage(PodmanError),
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
    /// The refreshed CDN range list (`[ingress.cdn]` without a pin); `None` = bundled or pinned.
    cdn_ranges: std::sync::OnceLock<Arc<crate::cdn::CdnRanges>>,
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
            cdn_ranges: std::sync::OnceLock::new(),
        }
    }

    /// Hands the manager the refreshed CDN list; set once at startup.
    pub fn set_cdn_ranges(&self, ranges: Arc<crate::cdn::CdnRanges>) {
        let _ = self.cdn_ranges.set(ranges);
    }

    /// The CDN trust the next `nginx.conf` renders (`None` without `[ingress.cdn]`).
    pub fn cdn_trust(
        &self,
    ) -> Result<Option<weglarka_ingress::CdnTrust>, weglarka_ingress::IngressError> {
        cdn_trust(&self.host, self.cdn_ranges.get().map(|r| &**r))
    }

    /// The refresh state for `doctor`; `None` unless the ranges come from the provider.
    pub fn cdn_status(&self) -> Option<crate::cdn::CdnStatus> {
        self.cdn_ranges.get().map(|r| r.status())
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
        // A static site (ADR 0049) has no container, hence no network for nginx to join.
        let routed: Vec<&InstanceName> = apps
            .iter()
            .filter(|(_, s)| !s.domains.is_empty() && s.kind == AppKind::Container)
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
        let TlsMaterial {
            certificates,
            wildcards,
            fingerprint: tls_fingerprint,
        } = if self.host.ingress.mode == IngressMode::Edge {
            self.ensure_tls_material()?
        } else {
            TlsMaterial::default()
        };

        if self.host.ingress.mode == IngressMode::Edge {
            self.ensure_socket_dir()?;
        }
        self.ensure_probe_dir()?;

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
            wildcards: &wildcards,
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

    /// Static sites that have no release yet; their routes answer 503 (issue #205). A state file
    /// that cannot be read leaves the set empty: the previous behaviour, never a broken config.
    fn unreleased_sites(&self, apps: &BTreeMap<InstanceName, AppSpec>) -> BTreeSet<InstanceName> {
        let state = state::load_state(&self.engine.paths().state).unwrap_or_default();
        apps.iter()
            .filter(|(name, spec)| {
                spec.kind == AppKind::Static
                    && state.apps.get(*name).is_none_or(|s| s.current.is_none())
            })
            .map(|(name, _)| name.clone())
            .collect()
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
            options.wildcard_certificates = r.wildcards.to_vec();
            options.tls_fingerprint = r.tls_fingerprint.map(str::to_owned);
            options.proxy_socket_dir = Some(SOCKET_CONTAINER_DIR.to_owned());
            options.cdn = cdn_trust(&self.host, self.cdn_ranges.get().map(|r| &**r))?;
        }
        options.unreleased = self.unreleased_sites(r.apps);
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
            Ok(action) => {
                if self.host.ingress.mode == IngressMode::Edge {
                    self.ensure_forwarder().await?;
                } else {
                    self.remove_forwarder().await?;
                }
                Ok((conf_written, action))
            }
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

    fn socket_dir(&self) -> PathBuf {
        self.conf_dir.join(SOCKET_SUBDIR)
    }

    fn probe_dir(&self) -> PathBuf {
        probe_dir(&self.conf_dir)
    }

    /// The `0700` directory of nginx's probe socket, in both modes; the mode is re-applied on every
    /// pass like the forwarder's, because it is what keeps other local users off the socket.
    fn ensure_probe_dir(&self) -> Result<(), IngressApplyError> {
        let dir = self.probe_dir();
        fs::create_dir_all(&dir).map_err(io_err(&dir))?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).map_err(io_err(&dir))
    }

    /// The `0700` directory of nginx's forwarder sockets. The mode is the whole protection against a
    /// local user forging a PROXY header, so it is re-applied on every pass.
    fn ensure_socket_dir(&self) -> Result<(), IngressApplyError> {
        let dir = self.socket_dir();
        fs::create_dir_all(&dir).map_err(io_err(&dir))?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).map_err(io_err(&dir))
    }

    /// nginx does not unlink a socket file a killed predecessor left behind (`bind() … Address already
    /// in use`), so the files go before every start of the container.
    fn remove_stale_sockets(&self) -> Result<(), IngressApplyError> {
        let sockets = [
            (self.socket_dir(), nginx::PLAIN_SOCKET),
            (self.socket_dir(), nginx::TLS_SOCKET),
            (self.probe_dir(), nginx::PROBE_SOCKET),
        ];
        for (dir, name) in sockets {
            let path = dir.join(name);
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(io_err(&path)(e)),
            }
        }
        Ok(())
    }

    /// `edge`: the forwarder container, created from the daemon's own image (the binary is already
    /// there, so no second image to pin or pull). Identity = [`FORWARDER_REVISION`] + publishes + hardening
    /// — deliberately *not* the image id, so a daemon self-update leaves it running (issue #183): its
    /// ports are the one thing that cannot be swapped without a gap.
    async fn ensure_forwarder(&self) -> Result<(), IngressApplyError> {
        let podman = self.engine.podman();
        let own = Self::own_container(podman).await?;
        let bind = self.host.ingress.bind;
        // Validated at startup (`HostConfig::validate`); the plain publish is the fallback.
        let https_bind = self.host.ingress.https_bind.unwrap_or(bind);
        let security = forwarder_security();
        let (hash, spec) = forwarder_identity(bind, https_bind, &security);

        let existing = podman
            .container_list(&ContainerFilter::default())
            .await?
            .into_iter()
            .find(|c| c.name == FORWARDER_CONTAINER);
        if let Some(existing) = &existing {
            if existing.labels.get(HASH_LABEL) == Some(&hash) {
                if existing.state != ContainerState::Running {
                    podman.container_start(FORWARDER_CONTAINER).await?;
                }
                return Ok(());
            }
            let reason = recreate_reason(existing.labels.get(SPEC_LABEL), &spec);
            let gap = std::time::Instant::now();
            self.remove_forwarder().await?;
            let result = self
                .create_forwarder(own.image_id, hash, spec, bind, https_bind, security)
                .await;
            // Unlike nginx the forwarder cannot be swapped while serving: its published ports are
            // closed from the stop until the new container starts.
            tracing::warn!(
                container = FORWARDER_CONTAINER,
                reason = %reason,
                gap_ms = u64::try_from(gap.elapsed().as_millis()).unwrap_or(u64::MAX),
                "forwarder recreated: the public ports were closed meanwhile"
            );
            return result;
        }
        self.create_forwarder(own.image_id, hash, spec, bind, https_bind, security)
            .await
    }

    async fn create_forwarder(
        &self,
        image_id: String,
        hash: String,
        spec: String,
        bind: SocketAddr,
        https_bind: SocketAddr,
        security: Security,
    ) -> Result<(), IngressApplyError> {
        let podman = self.engine.podman();
        let listen = |bind: SocketAddr, port: u16, socket: &str| {
            let any = if bind.is_ipv6() { "[::]" } else { "0.0.0.0" };
            format!("{any}:{port}={SOCKET_CONTAINER_DIR}/{socket}")
        };
        let mut command = vec!["forward".to_owned()];
        for route in [
            listen(bind, FORWARDER_HTTP_PORT, nginx::PLAIN_SOCKET),
            listen(https_bind, FORWARDER_HTTPS_PORT, nginx::TLS_SOCKET),
        ] {
            command.push("--route".to_owned());
            command.push(route);
        }
        let publish = vec![
            PortMapping {
                host_ip: Some(bind.ip().to_string()),
                host_port: bind.port(),
                container_port: FORWARDER_HTTP_PORT,
            },
            PortMapping {
                host_ip: Some(https_bind.ip().to_string()),
                host_port: https_bind.port(),
                container_port: FORWARDER_HTTPS_PORT,
            },
        ];
        podman
            .container_create(&ContainerSpec {
                name: FORWARDER_CONTAINER.to_owned(),
                image: image_id,
                command,
                entrypoint: None,
                // No `weglarka.instance` — reconcile would treat the container as an orphan.
                labels: BTreeMap::from([
                    (HASH_LABEL.to_owned(), hash),
                    (SPEC_LABEL.to_owned(), spec),
                ]),
                env: BTreeMap::new(),
                // No network: libpod's rootless default (pasta), the one that keeps the client address.
                networks: vec![],
                network_aliases: Default::default(),
                secrets: vec![],
                publish,
                restart: RestartPolicy::Always,
                userns_auto: false,
                // Container root is the runtime user on libpod's default map, so it can open the
                // `0700` socket directory; nothing else is mounted.
                mounts: vec![BindMount {
                    source: self.socket_dir().display().to_string(),
                    target: SOCKET_CONTAINER_DIR.to_owned(),
                    read_only: false,
                }],
                volumes: vec![],
                resources: Default::default(),
                healthcheck: None,
                id_mapping: None,
                keep_groups: false,
                security,
            })
            .await?;
        podman.container_start(FORWARDER_CONTAINER).await?;
        Ok(())
    }

    /// The daemon's own container. Podman sets a container's hostname to its id prefix, which also
    /// works when the quadlet's name is not `weglarka` (the smoke tests name it differently); the
    /// well-known name is the fallback.
    async fn own_container(
        podman: &P,
    ) -> Result<weglarka_model::podman::ContainerInfo, IngressApplyError> {
        let hostname = fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
        let hostname = hostname.trim();
        if !hostname.is_empty()
            && let Ok(info) = podman.container_inspect(hostname).await
        {
            return Ok(info);
        }
        podman
            .container_inspect(SERVICE_NAME)
            .await
            .map_err(IngressApplyError::ForwarderImage)
    }

    /// Removes the forwarder if there is one (a switch to `behind`, or a replaced identity).
    async fn remove_forwarder(&self) -> Result<(), IngressApplyError> {
        let podman = self.engine.podman();
        podman
            .container_stop(FORWARDER_CONTAINER, FORWARDER_STOP_TIMEOUT)
            .await
            .ignore_not_found()?;
        podman
            .container_remove(FORWARDER_CONTAINER, true)
            .await
            .ignore_not_found()?;
        Ok(())
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
    /// `<domain>.key` pair, the apexes with a wildcard pair (`_wildcard.<apex>.crt|key`, issue #97)
    /// and a fingerprint of the material.
    ///
    /// The fingerprint is rendered into `nginx.conf`, so renewing a certificate changes the config and
    /// rides the normal `nginx -t` + SIGHUP path; it is metadata only (name, size, mtime), the daemon
    /// never reads the private keys. Anything that is not a regular `<domain>.crt` file, or has no
    /// matching key, is ignored: the domain simply keeps its redirect and has no TLS server.
    fn ensure_tls_material(&self) -> Result<TlsMaterial, IngressApplyError> {
        let acme = self.conf_dir.join(ACME_SUBDIR);
        let tls = self.conf_dir.join(TLS_SUBDIR);
        fs::create_dir_all(&acme).map_err(io_err(&acme))?;
        fs::set_permissions(&acme, fs::Permissions::from_mode(0o755)).map_err(io_err(&acme))?;
        if !tls.is_dir() {
            fs::create_dir_all(&tls).map_err(io_err(&tls))?;
            fs::set_permissions(&tls, fs::Permissions::from_mode(0o700)).map_err(io_err(&tls))?;
        }

        let mut candidates: Vec<Domain> = Vec::new();
        let mut wildcard_candidates: Vec<Domain> = Vec::new();
        let entries = match fs::read_dir(&tls) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(TlsMaterial {
                    fingerprint: Some(empty_fingerprint()),
                    ..TlsMaterial::default()
                });
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
            // `_wildcard.<apex>`: the pair of a wildcard certificate (`*.<apex>` + `<apex>`).
            if let Some(apex) = stem.strip_prefix(WILDCARD_CERT_PREFIX) {
                match Domain::new(apex) {
                    Ok(apex) => wildcard_candidates.push(apex),
                    Err(_) => tracing::warn!(
                        file = %name,
                        "ignoring a wildcard TLS file whose name is not `_wildcard.<domain>`"
                    ),
                }
                continue;
            }
            match Domain::new(stem) {
                Ok(domain) => candidates.push(domain),
                Err(_) => {
                    tracing::warn!(file = %name, "ignoring a TLS file whose name is not a domain")
                }
            }
        }
        candidates.sort();
        candidates.dedup();
        wildcard_candidates.sort();
        wildcard_candidates.dedup();

        let mut material = Vec::new();
        let pair = |stem: &str| -> Option<String> {
            let cert = tls.join(format!("{stem}.crt"));
            let key = tls.join(format!("{stem}.key"));
            let (Ok(cert_meta), Ok(key_meta)) =
                (fs::symlink_metadata(&cert), fs::symlink_metadata(&key))
            else {
                tracing::debug!(%stem, "no certificate pair in the TLS directory");
                return None;
            };
            if !cert_meta.is_file() || !key_meta.is_file() {
                tracing::warn!(%stem, "certificate or key is not a regular file, ignoring");
                return None;
            }
            Some(format!(
                "{stem}:{}:{}:{}:{}",
                cert_meta.len(),
                mtime_nanos(&cert_meta),
                key_meta.len(),
                mtime_nanos(&key_meta)
            ))
        };
        let mut certificates = Vec::new();
        for domain in candidates {
            if let Some(entry) = pair(domain.as_str()) {
                material.push(entry);
                certificates.push(domain);
            }
        }
        let mut wildcards = Vec::new();
        for apex in wildcard_candidates {
            if let Some(entry) = pair(&format!("{WILDCARD_CERT_PREFIX}{apex}")) {
                material.push(entry);
                wildcards.push(apex);
            }
        }
        let fingerprint = if material.is_empty() {
            empty_fingerprint()
        } else {
            let digest = Sha256::digest(material.join("\n").as_bytes());
            hex::encode(&digest[..4])
        };
        Ok(TlsMaterial {
            certificates,
            wildcards,
            fingerprint: Some(fingerprint),
        })
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
        let (hash, spec) = ingress_identity(
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
        let reason = existing
            .as_ref()
            .filter(|c| c.labels.get(HASH_LABEL) != Some(&hash))
            .map(|c| recreate_reason(c.labels.get(SPEC_LABEL), &spec));
        let Some(existing) = existing.filter(|c| c.labels.get(HASH_LABEL) == Some(&hash)) else {
            self.create_nginx(
                networks,
                listen_port,
                https_listen_port,
                (hash, spec),
                range,
                reason,
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
            self.remove_stale_sockets()?;
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
        identity: (String, String),
        range: UidRange,
        replace: Option<String>,
    ) -> Result<(), IngressApplyError> {
        let (hash, spec) = identity;
        let podman = self.engine.podman();
        let image = &self.host.ingress.nginx_image;
        let bind = self.host.ingress.bind;
        // nginx listens on unprivileged ports inside the container; only the *host* side is 80/443 in
        // `edge`, so the hardened profile needs no `NET_BIND_SERVICE` (ADR 0014).
        let edge = self.host.ingress.mode == IngressMode::Edge;
        // `edge`: the forwarder owns the public sockets (rootlessport would hide the client address,
        // issue #162); nginx publishes nothing and is reached over its unix sockets.
        let mut publish = Vec::new();
        let mut mounts = vec![BindMount {
            source: self.conf_dir.display().to_string(),
            target: NGINX_CONF_MOUNT.to_owned(),
            read_only: true,
        }];
        if edge {
            mounts.push(BindMount {
                source: self.socket_dir().display().to_string(),
                target: SOCKET_CONTAINER_DIR.to_owned(),
                read_only: false,
            });
        } else {
            publish.push(PortMapping {
                host_ip: Some(bind.ip().to_string()),
                host_port: bind.port(),
                container_port: listen_port,
            });
        }
        // Both modes: the probe socket's directory, isolated from the forwarder's (docs/decisions/0054).
        mounts.push(BindMount {
            source: self.probe_dir().display().to_string(),
            target: nginx::PROBE_CONTAINER_DIR.to_owned(),
            read_only: false,
        });
        let _ = https_listen_port;
        self.ensure_image(image).await?;
        // Everything slow (the image pull) is done: from here to the start below nothing serves.
        let gap = std::time::Instant::now();
        if replace.is_some() {
            podman
                .container_stop(NGINX_CONTAINER, NGINX_STOP_TIMEOUT)
                .await
                .ignore_not_found()?;
            podman.container_remove(NGINX_CONTAINER, true).await?;
        }
        // nginx does not unlink the socket a killed predecessor left behind.
        self.remove_stale_sockets()?;
        podman
            .container_create(&ContainerSpec {
                name: NGINX_CONTAINER.to_owned(),
                image: image.clone(),
                // The image's own CMD starts nginx; nothing to add.
                command: vec![],
                entrypoint: None,
                // No `weglarka.instance` — reconcile would treat the container as an orphan.
                labels: BTreeMap::from([
                    (HASH_LABEL.to_owned(), hash),
                    (SPEC_LABEL.to_owned(), spec),
                ]),
                env: BTreeMap::new(),
                networks: networks.to_vec(),
                network_aliases: Default::default(),
                secrets: vec![],
                publish,
                restart: RestartPolicy::Always,
                userns_auto: false,
                mounts,
                volumes: vec![],
                resources: Default::default(),
                healthcheck: None,
                // `edge`/`behind`: container uid 0 is the daemon's host user, so the TLS master reads
                // the 0600 keys; the worker stays in the reserved ingress range (docs/decisions/0036).
                id_mapping: Some(volumes::ingress_id_mapping(range)),
                keep_groups: false,
                security: nginx_security(),
            })
            .await?;
        podman.container_start(NGINX_CONTAINER).await?;
        if let Some(reason) = replace {
            // In `edge` the forwarder keeps the public sockets and holds new connections until nginx
            // listens again (it retries the unix socket); in `behind` Traefik sees a refused upstream.
            tracing::warn!(
                container = NGINX_CONTAINER,
                reason = %reason,
                gap_ms = u64::try_from(gap.elapsed().as_millis()).unwrap_or(u64::MAX),
                "nginx recreated (not reloaded)"
            );
        }
        Ok(())
    }

    async fn ensure_image(&self, image: &str) -> Result<(), IngressApplyError> {
        let podman = self.engine.podman();
        if !podman.image_inspect(image).await.exists()? {
            let mut stream = std::pin::pin!(podman.image_pull(image));
            while let Some(ev) = stream.next().await {
                ev?;
            }
        }
        Ok(())
    }
}

/// Version of the ingress hash input; bump when its shape changes (recreates every nginx container).
/// v3 (issue #95): the mode and the second publish are part of the identity. v4 (issue #162): `edge`
/// nginx publishes nothing and listens on the forwarder's unix sockets. v5 (issue #221,
/// docs/decisions/0054): both modes mount the probe directory, so an nginx created without it must be
/// recreated once — `nginx -t` on a config that listens on the probe socket would fail forever otherwise.
const INGRESS_HASH_FORMAT: &str = "weglarka.ingress-hash/v5";

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
/// What the `edge` scan of the TLS directory found (empty in `behind`).
#[derive(Default)]
struct TlsMaterial {
    /// Domains with a `<domain>.crt|key` pair.
    certificates: Vec<Domain>,
    /// Apexes with a `_wildcard.<apex>.crt|key` pair (issue #97).
    wildcards: Vec<Domain>,
    /// Fingerprint of the material (`None` in `behind`).
    fingerprint: Option<String>,
}

/// Inputs of one `nginx.conf` rendering that do not depend on nginx's addresses.
struct Render<'a> {
    apps: &'a BTreeMap<InstanceName, AppSpec>,
    resolvers: &'a [IpAddr],
    forwarder_subnets: &'a [String],
    networks: &'a [String],
    /// `edge`: domains with a certificate pair in [`TLS_SUBDIR`]; empty in `behind`.
    certificates: &'a [Domain],
    /// `edge`: apex domains with a wildcard pair (`_wildcard.<apex>.crt|key`); empty in `behind`.
    wildcards: &'a [Domain],
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

/// Host path of the probe socket under `conf_dir` (`<nginx_conf_dir>/probe/probe.sock`): what the
/// daemon's health prober dials.
pub fn probe_socket_path(conf_dir: &Path) -> PathBuf {
    probe_dir(conf_dir).join(nginx::PROBE_SOCKET)
}

fn probe_dir(conf_dir: &Path) -> PathBuf {
    conf_dir.join(PROBE_SUBDIR)
}

pub(crate) fn nginx_security() -> Security {
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

/// Canonical spec JSON of the nginx container and the hash of it.
#[allow(clippy::too_many_arguments)]
fn ingress_identity(
    image: &str,
    bind: SocketAddr,
    https_bind: Option<SocketAddr>,
    listen_port: u16,
    https_listen_port: u16,
    range: UidRange,
    security: &Security,
) -> (String, String) {
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
    let json = serde_json::to_string(&input).expect("ingress hash input is always serializable");
    (hex::encode(&Sha256::digest(json.as_bytes())[..8]), json)
}

/// Names what differs between the spec a container was created from (its [`SPEC_LABEL`]) and the
/// wanted one: the `reason` logged when a recreate is unavoidable.
fn recreate_reason(old: Option<&String>, new: &str) -> String {
    let Some(old) = old else {
        return "container predates the recorded spec (identity inputs or hash format changed)"
            .to_owned();
    };
    let (Ok(serde_json::Value::Object(old)), Ok(serde_json::Value::Object(new))) = (
        serde_json::from_str::<serde_json::Value>(old),
        serde_json::from_str::<serde_json::Value>(new),
    ) else {
        return "recorded spec is unreadable".to_owned();
    };
    let changed: Vec<&str> = new
        .iter()
        .filter(|(k, v)| old.get(*k) != Some(v))
        .map(|(k, _)| k.as_str())
        .chain(
            old.keys()
                .filter(|k| !new.contains_key(*k))
                .map(String::as_str),
        )
        .collect();
    format!("changed: {}", changed.join(", "))
}

/// Spec hash of the nginx container: only what cannot change on a live container. The set of app
/// networks is deliberately absent (it is synced with connect/disconnect), as is the config (reload).
/// Hardening is in: changing the profile must recreate the container, not leave an old, writable one.
#[cfg(test)]
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
    ingress_identity(
        image,
        bind,
        https_bind,
        listen_port,
        https_listen_port,
        range,
        security,
    )
    .0
}

/// Bump when the forwarder's behaviour changes in a way that needs the new binary running: a plain
/// daemon self-update does not recreate it (its published ports would be closed meanwhile, issue #183).
/// 2: exits on SIGTERM and holds connections while nginx is replaced.
const FORWARDER_REVISION: u32 = 2;

/// Identity of the forwarder container: its revision, what it publishes and its hardening (canonical
/// spec JSON and its hash).
fn forwarder_identity(
    bind: SocketAddr,
    https_bind: SocketAddr,
    security: &Security,
) -> (String, String) {
    #[derive(Serialize)]
    struct Input<'a> {
        format: &'static str,
        revision: u32,
        bind: String,
        https_bind: String,
        security: &'a Security,
    }
    let json = serde_json::to_string(&Input {
        format: "weglarka.forwarder-hash/v2",
        revision: FORWARDER_REVISION,
        bind: bind.to_string(),
        https_bind: https_bind.to_string(),
        security,
    })
    .expect("forwarder hash input is always serializable");
    (hex::encode(&Sha256::digest(json.as_bytes())[..8]), json)
}

/// The forwarder needs nothing: no capability, a read-only root, no privilege escalation. (Binding
/// host ports below 1024 is the host sysctl's business, not a container capability.)
fn forwarder_security() -> Security {
    Security {
        read_only: true,
        tmpfs: vec![],
        cap_drop: vec!["ALL".to_owned()],
        cap_add: vec![],
        no_new_privileges: true,
    }
}

/// Field order is part of the hash format (mirrors `weglarka_model::hash::HashInput`).
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

/// `[ingress.cdn]` as the generator's trust: the pinned ranges, else the provider's bundled list.
pub(crate) fn cdn_trust(
    host: &weglarka_model::config::HostConfig,
    refreshed: Option<&crate::cdn::CdnRanges>,
) -> Result<Option<weglarka_ingress::CdnTrust>, weglarka_ingress::IngressError> {
    let Some(cdn) = host.ingress.cdn.as_ref() else {
        return Ok(None);
    };
    match refreshed {
        Some(ranges) if cdn.ranges.is_empty() => ranges.trust().map(Some),
        _ => weglarka_ingress::CdnTrust::from_config(cdn.provider, &cdn.ranges).map(Some),
    }
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
    fn recreate_reason_names_the_changed_inputs() {
        let sec = nginx_security();
        let range = UidRange {
            start: 100_000,
            size: 65_536,
        };
        let spec = |image: &str, bind: &str| {
            ingress_identity(image, bind.parse().unwrap(), None, 8080, 8443, range, &sec).1
        };
        let old = spec("nginx:1", "127.0.0.1:80");
        assert_eq!(
            recreate_reason(Some(&old), &spec("nginx:2", "127.0.0.1:80")),
            "changed: image"
        );
        assert_eq!(
            recreate_reason(Some(&old), &spec("nginx:2", "127.0.0.1:81")),
            "changed: bind, image"
        );
        assert!(recreate_reason(None, &old).contains("predates"));
        assert!(recreate_reason(Some(&"{".to_owned()), &old).contains("unreadable"));
    }

    #[test]
    fn forwarder_identity_ignores_the_daemon_image() {
        let sec = forwarder_security();
        let a = forwarder_identity(
            "0.0.0.0:80".parse().unwrap(),
            "0.0.0.0:443".parse().unwrap(),
            &sec,
        );
        let b = forwarder_identity(
            "0.0.0.0:80".parse().unwrap(),
            "0.0.0.0:444".parse().unwrap(),
            &sec,
        );
        assert_ne!(a.0, b.0);
        assert!(!a.1.contains("image"));
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
                &sec,
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
                &sec,
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
                &sec,
            )
        );
        assert_ne!(a, ingress_hash("i", bind, None, 8080, 8443, r, &sec));
        assert_ne!(a, ingress_hash("i", bind, Some(https), 8080, 8444, r, &sec));
    }

    /// docs/decisions/0054: both modes mount the probe directory from v5 on, so a container created
    /// by an older daemon (v3 `behind`, v4 `edge`) has a different identity and is recreated once.
    #[test]
    fn hash_format_v5_recreates_nginx_created_without_the_probe_mount() {
        let r = UidRange {
            start: 1,
            size: 4096,
        };
        let (_, spec) = ingress_identity(
            "i",
            "127.0.0.1:18080".parse().unwrap(),
            None,
            8080,
            8443,
            r,
            &nginx_security(),
        );
        assert!(spec.contains("weglarka.ingress-hash/v5"), "{spec}");
        for old in ["v3", "v4"] {
            let old_spec = spec.replace("v5", old);
            assert_ne!(
                recreate_reason(Some(&old_spec), &spec),
                "changed: ",
                "{old} must differ"
            );
            assert!(recreate_reason(Some(&old_spec), &spec).contains("format"));
        }
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
