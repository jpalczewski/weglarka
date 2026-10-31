//! The Węglarka daemon — wires everything together: admin API (unix socket), webhook listener (TCP),
//! the `weglarka-engine` reconcile loop, ingress (nginx + Traefik) and the systemd `Platform`.
//!
//! The daemon is generic over `PodmanClient` (the trait is not dyn-compatible), so tests
//! run it on `FakePodman` and the binary on `LibpodClient`.

pub mod access;
pub mod acme;
pub mod admin;
pub mod admin_token;
pub mod app;
mod app_view;
pub mod cdn;
pub mod certificates;
pub mod config_view;
pub mod doctor;
pub mod events;
pub mod forgejo;
pub mod forward;
pub mod forwarder;
pub mod generated;
pub mod github;
pub mod health_probe;
pub mod identity;
pub mod images;
pub mod ingress;
pub mod logs;
pub mod metrics;
pub mod platform;
/// `PUT /v1/apps/{name}/image`: deploy an image archive built elsewhere (issue #109).
pub mod push;
/// Host-side switcher of Węglarka's own image (issue #99, `docs/decisions/0027`).
pub mod self_update;
/// The service description shared by `platform install` and the switcher.
pub mod service;
pub mod settings;
pub mod shared_networks;
pub mod shared_volumes;
pub mod sites;
mod stream;
/// Host-side watchdog of a switch in flight: the automatic fallback of issue #100
/// (`docs/decisions/0034`).
pub mod supervise;
pub mod update;
pub mod volumes;
pub mod webhook;

use std::net::SocketAddr;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use weglarka_model::webhook::WebhookSource;

use tokio::net::{TcpListener, UnixListener};
use tokio::sync::{mpsc, watch};
use tokio::task::{JoinHandle, JoinSet};
use weglarka_engine::config_mounts::ConfigError;
use weglarka_engine::reconcile::{Reconciler, ReconcilerOptions};
use weglarka_model::podman::PodmanClient;
use weglarka_model::secret_ops::SecretOps;
use weglarka_model::secret_store::SecretStore;
use weglarka_model::secrets::FileSecretStore;
use weglarka_model::state;

pub use app::Daemon;
pub use settings::{Paths, Settings, SettingsError};

use ingress::IngressManager;

#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error(transparent)]
    State(#[from] state::StateError),
    #[error(transparent)]
    Secret(#[from] weglarka_model::secret_store::SecretError),
    /// `host_ports` that cannot work on this host (privileged ports, conflicts, the ingress bind).
    #[error(transparent)]
    HostPorts(#[from] weglarka_model::host_ports::HostPortError),
    /// `apps.toml` mounts a shared volume that is not declared in `[shared_volumes.<name>]`
    /// (issue #33).
    #[error("invalid shared volumes in apps.toml: {0}")]
    SharedVolumes(String),
    /// The startup preconditions of host config mounts are not met: `config_root` is configured but
    /// unusable, or an app declares `configs` while it is unset (issue #118,
    /// `docs/decisions/0028-config-root-mounts.md`). A single missing/escaping source is *not* a
    /// startup error — the engine refuses to mount it and `doctor` reports it.
    #[error("config mounts: {0}")]
    Configs(#[from] ConfigError),
    /// The `[notify]` section is invalid (bad URL/topic, unreadable token file…). Notifications are
    /// opt-in, but once configured they must work — a silent no-op would hide a broken deployment.
    #[error("notifications: {0}")]
    Notify(#[from] weglarka_notify::NotifySettingsError),
    /// `[webhook.forgejo]` is present but unusable.
    #[error("{0}")]
    Webhook(String),
    /// `[self_update]` cannot work (a digest instead of a tag, an interval that is too short…).
    #[error("[self_update] {0}")]
    SelfUpdateConfig(String),
    /// `[acme.dns]` is unusable (an unreadable or world-readable token file, an invalid apex).
    #[error("{0}")]
    Acme(String),
    /// `[admin.http]` cannot be served (docs/decisions/0056).
    #[error("[admin.http] {0}")]
    AdminHttp(String),
    /// `[ingress]` cannot work in the selected mode (an `edge` host without `https_bind`, a
    /// `behind`-only key in `edge`, a privileged publish port without the opt-in — issue #95).
    #[error("{0}")]
    Ingress(String),
    #[error("{what}: {source}")]
    Io {
        what: String,
        source: std::io::Error,
    },
}

fn io(what: impl Into<String>) -> impl FnOnce(std::io::Error) -> StartError {
    let what = what.into();
    move |source| StartError::Io { what, source }
}

/// Startup preconditions of host config mounts (issue #118), deliberately tolerant about the single
/// sources: an operator may add an app with `configs` before creating the files, and a symlink target
/// may move. The daemon refuses to start only when:
///
/// * `config_root` is configured but is not a usable directory (a typo would otherwise hide every
///   config and only surface as blocked instances), or
/// * an app declares `configs` while `config_root` is unset (the feature is off).
///
/// Per-source resolution stays strict where a bind mount is actually created and where a failure can
/// still be recovered from: the engine's `launch`/reconcile/`reload` refuse a missing or escaping
/// source, and `doctor` reports each mount's status. `config_root` here is the path already resolved
/// against the config directory by [`Paths::resolve`].
const SERVER_STOP_TIMEOUT: Duration = Duration::from_secs(10);
const TASK_DRAIN_TIMEOUT: Duration = Duration::from_secs(60);

/// A running daemon; `stop` shuts it down gracefully.
pub struct Running<P: PodmanClient + 'static> {
    pub daemon: Arc<Daemon<P>>,
    pub admin_socket: PathBuf,
    /// Socket of the token listener (`[admin.http]`); `None` without it.
    pub admin_token_socket: Option<PathBuf>,
    pub webhook_addr: SocketAddr,
    /// Where `/metrics` listens; `None` without `[metrics]` or after a failed start.
    pub metrics_addr: Option<SocketAddr>,
    shutdown: watch::Sender<bool>,
    admin: JoinHandle<()>,
    /// The token listener (`[admin.http]`); `None` without it.
    admin_token: Option<JoinHandle<()>>,
    webhook: JoinHandle<()>,
    /// The metrics listener (`[metrics]`); `None` when absent or when it could not bind.
    metrics: Option<JoinHandle<()>>,
    /// Joins the metrics network in the background; ends when joined or on shutdown.
    metrics_join: Option<JoinHandle<()>>,
    ingress: JoinHandle<()>,
    reconcile: JoinHandle<()>,
    /// Notification worker; `None` when notifications are not configured.
    notify: Option<JoinHandle<()>>,
    /// ACME worker; `None` when `[acme]` is absent or paused.
    acme: Option<JoinHandle<()>>,
    /// CDN range refresh (`[ingress.cdn]` without a pin).
    cdn: Option<JoinHandle<()>>,
    /// Generated config worker (#212); `None` when no generator is registered.
    generated: Option<JoinHandle<()>>,
}

fn ensure_dir(dir: &Path, mode: u32) -> Result<(), StartError> {
    if dir.as_os_str().is_empty() || dir.exists() {
        return Ok(());
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(mode)
        .create(dir)
        .map_err(io(format!("create {}", dir.display())))
}

/// Binds a unix socket for an API listener: creates its directory with `dir_mode`, removes only a stale
/// *socket*, and sets `socket_mode` right after the bind. The full-trust admin socket is `0700`/`0600`;
/// the token listener's is more open because its callers are containers with other uids and every
/// request there carries a verified token (docs/decisions/0056).
fn bind_unix(path: &Path, dir_mode: u32, socket_mode: u32) -> Result<UnixListener, StartError> {
    if let Some(parent) = path.parent() {
        ensure_dir(parent, dir_mode)?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => {
            std::fs::remove_file(path).map_err(io(format!("remove stale {}", path.display())))?;
        }
        Ok(_) => {
            return Err(StartError::Io {
                what: format!("socket {}", path.display()),
                source: std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "path exists and is not a socket",
                ),
            });
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io(format!("stat {}", path.display()))(e)),
    }
    let listener = UnixListener::bind(path).map_err(io(format!("bind {}", path.display())))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(socket_mode))
        .map_err(io(format!("chmod {}", path.display())))?;
    Ok(listener)
}

/// Sets `dir`'s mode whatever it was created with (`ensure_dir` leaves an existing directory alone).
fn enforce_dir_mode(dir: &Path, mode: u32) -> Result<(), StartError> {
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode))
        .map_err(io(format!("chmod {}", dir.display())))
}

/// Serves `app` on `listener` until `shutdown` flips; a server that stops by itself is logged.
fn spawn_server<L>(
    name: &'static str,
    listener: L,
    app: axum::Router,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<()>
where
    L: axum::serve::Listener,
    L::Addr: std::fmt::Debug,
{
    tokio::spawn(async move {
        let stop = async move {
            let _ = shutdown.wait_for(|stop| *stop).await;
        };
        if let Err(e) = axum::serve(listener, app)
            .with_graceful_shutdown(stop)
            .await
        {
            tracing::error!(server = name, error = %e, "server stopped");
        }
    })
}

/// Binds the metrics listener. It needs no Podman, so it is up before the network join finishes.
async fn bind_metrics(
    config: &weglarka_model::config::MetricsConfig,
) -> Result<(TcpListener, SocketAddr), String> {
    let listener = TcpListener::bind(config.listen)
        .await
        .map_err(|e| format!("bind {}: {e}", config.listen))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?;
    Ok((listener, addr))
}

pub async fn start<P: PodmanClient + 'static>(
    settings: Settings,
    podman: P,
) -> Result<Running<P>, StartError> {
    start_with(settings, podman, Vec::new()).await
}

/// [`start`] with extra config generators (#212) next to the built-in ones — how the integration
/// tests run the pipeline without the identity provider.
pub async fn start_with<P: PodmanClient + 'static>(
    settings: Settings,
    podman: P,
    extra_generators: Vec<Arc<dyn weglarka_model::generated::ConfigGenerator>>,
) -> Result<Running<P>, StartError> {
    let Settings { host, paths, .. } = settings;
    ensure_dir(&paths.state_dir, 0o755)?;

    // Secrets: an empty 0600 file if missing; loose permissions = refuse to start.
    let secrets = Arc::new(FileSecretStore::new(&paths.secrets));
    secrets.init()?;
    secrets.check_permissions()?;
    // Corrupt TOMLs surface immediately rather than at the first reconcile.
    let apps = state::load_apps(&paths.state.apps)?;
    state::load_state(&paths.state.state)?;
    // Self-update (issue #99): `[self_update]` must be valid even inside the container, so a typo
    // stops the daemon instead of silently never updating it.
    if let Some(self_update) = &host.self_update {
        self_update
            .validate()
            .map_err(StartError::SelfUpdateConfig)?;
    }
    // The `[ingress]` shape for the selected mode (issue #95): a mode/key mismatch or a privileged
    // publish port without the opt-in stops the daemon instead of failing at the first `apply`.
    host.validate().map_err(StartError::Ingress)?;
    // Host-wide `host_ports` rules (privileged ports, two apps on one socket, the ingress bind)
    // stop the daemon instead of failing at container start (`docs/decisions/0013-host-ports.md`).
    weglarka_model::host_ports::validate(&host, &apps)?;
    // Shared-volume mounts must resolve to a declaration (issue #33). `load_apps` already enforces
    // it; kept here next to the host rules so a broken `apps.toml` is rejected at startup loudly.
    weglarka_model::shared_volumes::validate(&apps).map_err(StartError::SharedVolumes)?;
    // Host config mounts (issue #118): only the root's own preconditions stop the daemon — a single
    // missing/escaping source is refused by the engine at launch and reported by `doctor`, so that an
    // app added before its files exist does not keep the daemon from starting.
    weglarka_engine::config_mounts::validate_host(&host, &apps)?;
    // Forward auth needs `[identity]`; the ingress generator refuses such an app without it anyway,
    // but the daemon should say why at startup instead of at the first `apply`.
    weglarka_model::identity::validate_host(&host, &apps).map_err(StartError::Ingress)?;

    // Notifications (issue #38): validated before anything is bound, so a broken `[notify]` section
    // stops the daemon instead of failing silently at the first deploy.
    let notifier = weglarka_notify::Notifier::build(
        host.notify.as_ref(),
        paths.state.apps.clone(),
        paths.notifications.clone(),
    )?;
    let notify = notifier.as_ref().map(weglarka_notify::Notifier::handle);
    // Self-update (issue #99): confirm which image this process really runs and resolve a switch the
    // host-side switcher requested, before anything reconciles against the old world.
    // Every producer (engine, ACME, self-update) emits into one fan-out: the delivery sink the daemon
    // had before (the notifier or the log) plus the bounded history behind `GET /v1/events`.
    let history = Arc::new(weglarka_model::history::EventHistory::default());
    let delivery: Arc<dyn weglarka_model::events::EventSink> = match &notifier {
        Some(notifier) => notifier.sink(),
        None => Arc::new(weglarka_model::events::TracingSink),
    };
    // `[metrics]` adds the counters behind `weglarka_deploys_total` and friends (#352); without it
    // nothing is counted.
    let counters = host
        .metrics
        .as_ref()
        .map(|_| Arc::new(metrics::daemon::EventCounters::default()));
    let mut sinks: Vec<Arc<dyn weglarka_model::events::EventSink>> =
        vec![delivery, history.clone()];
    if let Some(counters) = &counters {
        sinks.push(counters.clone());
    }
    let events: Arc<dyn weglarka_model::events::EventSink> =
        Arc::new(weglarka_model::history::FanOut::new(sinks));
    self_update::confirm_startup(&podman, &paths.state_dir, events.as_ref()).await;
    // The engine resolves and mounts an app's `configs` against the same root the API and doctor
    // read (issue #118); `None` keeps the feature off.
    let defaults = ReconcilerOptions::default();
    let options = ReconcilerOptions {
        config_root: paths.config_root.clone(),
        host_mounts: host.runtime.host_mounts.clone(),
        group_add: host.runtime.group_add.clone(),
        // Static sites live in the one directory nginx mounts (ADR 0049, ADR 0036).
        sites_root: Some(paths.nginx_conf_dir.join("sites")),
        // The token admin API socket, mounted into the `[admin.http] clients` only (ADR 0056).
        admin_token: host.admin.http.as_ref().map(|http| {
            weglarka_engine::admin_token::AdminTokenMount {
                dir: paths.admin_token_dir.clone(),
                clients: http.clients.iter().cloned().collect(),
            }
        }),
        // The scraper app kept on the metrics networks (issue #365); host policy, like the above.
        metrics_scraper: host.metrics.as_ref().and_then(|m| {
            m.scraper
                .clone()
                .map(|instance| weglarka_engine::scraper::MetricsScraper {
                    instance,
                    network: m.network.clone(),
                })
        }),
        dependency_wait_secs: host
            .runtime
            .dependency_wait_secs
            .unwrap_or(defaults.dependency_wait_secs),
        ..defaults
    };
    let mut reconciler = Reconciler::new(
        podman,
        secrets.clone() as Arc<dyn SecretStore>,
        paths.state.clone(),
        options,
    )
    .with_http_prober(Arc::new(health_probe::NginxProber::new(
        ingress::probe_socket_path(&paths.nginx_conf_dir),
    )))
    // Crash-loop / unhealthy thresholds (`[monitor]`): the reconcile pass observes them and emits
    // events, so the notifications above deliver them and the log gets them even without a channel.
    .with_monitor(weglarka_engine::crash::Policy::from_config(&host.monitor))
    // What an `oidc` app gets injected (#91); inert without `[identity]`.
    .with_identity(host.identity.clone())
    // The engine emits into the durable pipeline (when configured), the log and the history.
    .with_events(events.clone());
    // Generated config (#212): the engine bootstraps a consumer's files before its first start; the
    // worker below keeps them current. With no generator registered the feature is off entirely.
    let mut generators = generated::registered(&host);
    generators.extend(extra_generators);
    let digests = generated::credential_digests(secrets.clone() as Arc<dyn SecretOps>);
    if !generators.is_empty() {
        reconciler = reconciler.with_generated(weglarka_engine::generated::GeneratedWiring {
            generators: generators.clone(),
            digests: digests.clone(),
        });
    }
    let engine = Arc::new(reconciler);
    let generated_worker = (!generators.is_empty()).then(|| {
        Arc::new(generated::GeneratedWorker::new(
            engine.clone(),
            generators,
            digests,
            generated::DEBOUNCE,
        ))
    });
    // A daemon that died in the middle of `weglarka run` left its one-off container behind; this
    // process has no run yet, so every one found is stale (issue #106). Podman being down is not a
    // reason to refuse to start: the reconcile loop reports it.
    match engine.remove_stale_runs().await {
        Ok(0) => {}
        Ok(removed) => tracing::info!(removed, "removed stale one-off containers"),
        Err(error) => tracing::warn!(%error, "cannot look for stale one-off containers"),
    }
    // The same for a forward relay (issue #108).
    match engine.remove_stale_forwards().await {
        Ok(0) => {}
        Ok(removed) => tracing::info!(removed, "removed stale forward relays"),
        Err(error) => tracing::warn!(%error, "cannot look for stale forward relays"),
    }
    let ingress = Arc::new(IngressManager::new(
        engine.clone(),
        host.clone(),
        paths.nginx_conf_dir.clone(),
    ));
    // ACME (issue #96): the worker shares the engine's event sink and asks the ingress to apply
    // whenever it wrote a certificate.
    // `[ingress.cdn]` without a pin (issue #159): the saved or bundled provider list, refreshed daily.
    let cdn_ranges = host
        .ingress
        .cdn
        .as_ref()
        .filter(|cdn| cdn.ranges.is_empty())
        .map(|cdn| Arc::new(cdn::CdnRanges::load(cdn.provider, paths.cdn_ranges.clone())));
    if let Some(ranges) = &cdn_ranges {
        ingress.set_cdn_ranges(ranges.clone());
    }
    let acme_worker = acme::build(
        host.acme.as_ref(),
        &paths,
        &host.webhook.domain,
        events,
        ingress.clone(),
    )?;
    let mut webhook_sources: Vec<Box<dyn WebhookSource>> = vec![Box::new(github::GitHub)];
    if let Some(forgejo) = &host.webhook.forgejo {
        webhook_sources.push(Box::new(
            forgejo::Forgejo::new(forgejo).map_err(StartError::Webhook)?,
        ));
    }
    let (trigger_tx, trigger_rx) = mpsc::channel(8);
    let daemon = Arc::new(Daemon {
        host: host.clone(),
        paths: paths.clone(),
        engine: engine.clone(),
        secrets,
        ingress: ingress.clone(),
        webhook_sources,
        notify: notify.clone(),
        events: history,
        acme: acme_worker.as_ref().map(acme::AcmeWorker::status),
        generated: generated_worker.clone(),
        desired_lock: tokio::sync::Mutex::new(()),
        started: std::time::Instant::now(),
        triggers: trigger_tx,
        webhook_addr: OnceLock::new(),
        metrics: metrics::StatusCell::default(),
        tasks: Mutex::new(JoinSet::new()),
    });

    let admin_listener = bind_unix(&host.admin.socket, 0o700, 0o600)?;
    let webhook_listener = TcpListener::bind(host.webhook.listen)
        .await
        .map_err(io(format!("bind {}", host.webhook.listen)))?;
    let webhook_addr = webhook_listener
        .local_addr()
        .map_err(io("webhook local_addr"))?;
    let _ = daemon.webhook_addr.set(webhook_addr);

    let (shutdown, shutdown_rx) = watch::channel(false);
    let admin = spawn_server(
        "admin API",
        admin_listener,
        admin::router(daemon.clone()),
        shutdown_rx.clone(),
    );
    // The token listener (docs/decisions/0056): only with `[admin.http]` (which needs `[identity]`,
    // checked by `host.validate()` above). It shares the routes of the socket above, behind a bearer.
    let admin_token = match (&host.admin.http, &host.identity) {
        (Some(http), Some(identity)) => {
            let listener = bind_unix(&paths.admin_token_socket(), 0o711, 0o666)?;
            // Re-applied on every start, like the probe directory: a directory that already existed
            // (or was created under a restrictive umask) must still be traversable by the clients'
            // uids, and must not have drifted wider than intended.
            enforce_dir_mode(&paths.admin_token_dir, 0o711)?;
            let issuer_host = weglarka_model::identity::issuer_host(&identity.issuer)
                .map_err(|reason| {
                    StartError::AdminHttp(format!("issuer {:?}: {reason}", identity.issuer))
                })?
                .to_owned();
            let verifier = Arc::new(admin_token::JwksVerifier::new(
                admin_token::ProbeJwks {
                    socket: ingress::probe_socket_path(&paths.nginx_conf_dir),
                    issuer_host,
                },
                http.validation(&identity.issuer),
            ));
            Some(spawn_server(
                "admin token API",
                listener,
                admin_token::token_router(daemon.clone(), verifier),
                shutdown_rx.clone(),
            ))
        }
        _ => None,
    };
    let webhook = spawn_server(
        "webhook",
        webhook_listener,
        webhook::router(daemon.clone()),
        shutdown_rx.clone(),
    );
    // Metrics (ADR 0061): opt-in. A bind failure is logged and shown by `doctor`; the network join runs
    // in the background and never delays or stops the daemon.
    // `counters` exists exactly when `[metrics]` does; pairing them keeps the listener from ever
    // serving a set the event fan-out does not feed.
    let (metrics, metrics_join, metrics_addr) = match host.metrics.as_ref().zip(counters) {
        Some((config, counters)) => match bind_metrics(config).await {
            Ok((listener, addr)) => {
                daemon.metrics.set(metrics::ListenerStatus::Joining {
                    addr,
                    network: config.network.clone(),
                    last_error: None,
                });
                let server = spawn_server(
                    "metrics",
                    listener,
                    metrics::router(Arc::new(metrics::DaemonMetrics::new(
                        daemon.clone(),
                        counters,
                        metrics::host::ProcSource::new(paths.proc_root.clone()),
                    ))),
                    shutdown_rx.clone(),
                );
                let join = tokio::spawn({
                    let daemon = daemon.clone();
                    let config = config.clone();
                    let rx = shutdown_rx.clone();
                    async move {
                        metrics::keep_joined(
                            daemon.engine.podman(),
                            &config,
                            addr,
                            &daemon.metrics,
                            rx,
                        )
                        .await;
                    }
                });
                (Some(server), Some(join), Some(addr))
            }
            Err(error) => {
                tracing::error!(%error, "metrics listener not started");
                daemon.metrics.set(metrics::ListenerStatus::Failed(error));
                (None, None, None)
            }
        },
        None => (None, None, None),
    };

    let period = Duration::from_secs(host.runtime.reconcile_interval_secs.max(1));
    let ingress_task = tokio::spawn({
        let ingress = ingress.clone();
        let rx = shutdown_rx.clone();
        async move { ingress.run(period, rx).await }
    });
    let reconcile = tokio::spawn({
        let engine = engine.clone();
        async move { engine.run(trigger_rx, period).await }
    });
    let acme_task = acme_worker.map(|worker| {
        let rx = shutdown_rx.clone();
        tokio::spawn(async move { worker.run(rx).await })
    });
    let generated_task = generated_worker.map(|worker| {
        let rx = shutdown_rx.clone();
        tokio::spawn(async move { worker.run(rx).await })
    });
    let cdn_task = cdn_ranges.map(|ranges| {
        let rx = shutdown_rx.clone();
        let ingress = ingress.clone();
        tokio::spawn(async move {
            ranges
                .run(&cdn::CloudflareApi, move || ingress.request_apply(), rx)
                .await;
        })
    });
    let notify_task = notifier.map(|notifier| {
        let rx = shutdown_rx.clone();
        tokio::spawn(async move { notifier.run(rx).await })
    });

    tracing::info!(
        admin = %host.admin.socket.display(),
        webhook = %webhook_addr,
        "weglarka-daemon started"
    );
    Ok(Running {
        daemon,
        admin_socket: host.admin.socket.clone(),
        admin_token_socket: admin_token.is_some().then(|| paths.admin_token_socket()),
        webhook_addr,
        metrics_addr,
        shutdown,
        admin,
        admin_token,
        webhook,
        metrics,
        metrics_join,
        ingress: ingress_task,
        reconcile,
        notify: notify_task,
        acme: acme_task,
        cdn: cdn_task,
        generated: generated_task,
    })
}

impl<P: PodmanClient + 'static> Running<P> {
    /// Graceful stop: servers stop accepting requests, in-flight webhook deploys finish (up to a
    /// limit), and the reconcile loop exits once the trigger channel closes.
    pub async fn stop(self) {
        let Running {
            daemon,
            shutdown,
            admin,
            admin_token,
            webhook,
            metrics,
            metrics_join,
            ingress,
            reconcile,
            notify,
            acme,
            cdn,
            generated,
            admin_socket,
            admin_token_socket,
            ..
        } = self;
        let _ = shutdown.send(true);
        for (name, handle) in [("admin", admin), ("webhook", webhook), ("ingress", ingress)] {
            if tokio::time::timeout(SERVER_STOP_TIMEOUT, handle)
                .await
                .is_err()
            {
                tracing::warn!(task = name, "did not stop in time");
            }
        }
        if let Some(handle) = admin_token
            && tokio::time::timeout(SERVER_STOP_TIMEOUT, handle)
                .await
                .is_err()
        {
            tracing::warn!("admin token API did not stop in time");
        }
        if let Some(handle) = metrics
            && tokio::time::timeout(SERVER_STOP_TIMEOUT, handle)
                .await
                .is_err()
        {
            tracing::warn!("metrics listener did not stop in time");
        }
        if let Some(handle) = metrics_join
            && tokio::time::timeout(SERVER_STOP_TIMEOUT, handle)
                .await
                .is_err()
        {
            tracing::warn!("metrics network join did not stop in time");
        }
        if let Some(handle) = notify
            && tokio::time::timeout(SERVER_STOP_TIMEOUT, handle)
                .await
                .is_err()
        {
            tracing::warn!("notification worker did not stop in time");
        }
        if let Some(handle) = cdn
            && tokio::time::timeout(SERVER_STOP_TIMEOUT, handle)
                .await
                .is_err()
        {
            tracing::warn!("CDN ranges refresh did not stop in time");
        }
        if let Some(handle) = generated
            && tokio::time::timeout(SERVER_STOP_TIMEOUT, handle)
                .await
                .is_err()
        {
            tracing::warn!("generated config worker did not stop in time");
        }
        if let Some(handle) = acme
            && tokio::time::timeout(SERVER_STOP_TIMEOUT, handle)
                .await
                .is_err()
        {
            tracing::warn!("ACME worker did not stop in time");
        }

        let mut tasks =
            std::mem::take(&mut *daemon.tasks.lock().unwrap_or_else(|e| e.into_inner()));
        let drain = async { while tasks.join_next().await.is_some() {} };
        if tokio::time::timeout(TASK_DRAIN_TIMEOUT, drain)
            .await
            .is_err()
        {
            tracing::warn!("aborting webhook tasks still running");
            tasks.abort_all();
        }

        // The last reference to `Daemon` holds the trigger sender — dropping it ends the loop.
        drop(daemon);
        let abort = reconcile.abort_handle();
        if tokio::time::timeout(TASK_DRAIN_TIMEOUT, reconcile)
            .await
            .is_err()
        {
            tracing::warn!("aborting reconcile loop");
            abort.abort();
        }
        let _ = std::fs::remove_file(admin_socket);
        if let Some(socket) = admin_token_socket {
            let _ = std::fs::remove_file(socket);
        }
        tracing::info!("weglarka-daemon stopped");
    }
}
