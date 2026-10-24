//! The Węglarka daemon — wires everything together: admin API (unix socket), webhook listener (TCP),
//! the `weglarka-core` reconcile loop, ingress (nginx + Traefik) and the systemd `Platform`.
//!
//! The daemon is generic over `PodmanClient` (the trait is not dyn-compatible), so tests
//! run it on `FakePodman` and the binary on `LibpodClient`.

pub mod admin;
pub mod app;
pub mod doctor;
pub mod forgejo;
pub mod github;
pub mod health_probe;
pub mod images;
pub mod ingress;
pub mod platform;
/// Host-side switcher of Węglarka's own image (issue #99, `docs/decisions/0027`).
pub mod self_update;
/// The service description shared by `platform install` and the switcher.
pub mod service;
pub mod settings;
pub mod shared_networks;
pub mod shared_volumes;
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
use weglarka_core::webhook::WebhookSource;

use tokio::net::{TcpListener, UnixListener};
use tokio::sync::{mpsc, watch};
use tokio::task::{JoinHandle, JoinSet};
use weglarka_core::config_mounts::ConfigError;
use weglarka_core::podman::PodmanClient;
use weglarka_core::reconcile::{Reconciler, ReconcilerOptions};
use weglarka_core::secret_store::SecretStore;
use weglarka_core::secrets::FileSecretStore;
use weglarka_core::state;

pub use app::Daemon;
pub use settings::{Paths, Settings, SettingsError};

use ingress::IngressManager;

#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error(transparent)]
    State(#[from] state::StateError),
    #[error(transparent)]
    Secret(#[from] weglarka_core::secret_store::SecretError),
    /// `host_ports` that cannot work on this host (privileged ports, conflicts, the ingress bind).
    #[error(transparent)]
    HostPorts(#[from] weglarka_core::host_ports::HostPortError),
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
    pub webhook_addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    admin: JoinHandle<()>,
    webhook: JoinHandle<()>,
    ingress: JoinHandle<()>,
    reconcile: JoinHandle<()>,
    /// Notification worker; `None` when notifications are not configured.
    notify: Option<JoinHandle<()>>,
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

/// Binds the admin API socket: removes only a stale *socket*, sets mode 0600 right after the bind.
fn bind_admin(path: &Path) -> Result<UnixListener, StartError> {
    if let Some(parent) = path.parent() {
        ensure_dir(parent, 0o700)?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => {
            std::fs::remove_file(path).map_err(io(format!("remove stale {}", path.display())))?;
        }
        Ok(_) => {
            return Err(StartError::Io {
                what: format!("admin socket {}", path.display()),
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
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(io(format!("chmod {}", path.display())))?;
    Ok(listener)
}

pub async fn start<P: PodmanClient + 'static>(
    settings: Settings,
    podman: P,
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
    // Host-wide `host_ports` rules (privileged ports, two apps on one socket, the ingress bind)
    // stop the daemon instead of failing at container start (`docs/decisions/0013-host-ports.md`).
    weglarka_core::host_ports::validate(&host, &apps)?;
    // Shared-volume mounts must resolve to a declaration (issue #33). `load_apps` already enforces
    // it; kept here next to the host rules so a broken `apps.toml` is rejected at startup loudly.
    weglarka_core::shared_volumes::validate(&apps).map_err(StartError::SharedVolumes)?;
    // Host config mounts (issue #118): only the root's own preconditions stop the daemon — a single
    // missing/escaping source is refused by the engine at launch and reported by `doctor`, so that an
    // app added before its files exist does not keep the daemon from starting.
    weglarka_core::config_mounts::validate_host(&host, &apps)?;

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
    {
        let events: Arc<dyn weglarka_core::events::EventSink> = match &notifier {
            Some(notifier) => notifier.sink(),
            None => Arc::new(weglarka_core::events::TracingSink),
        };
        self_update::confirm_startup(&podman, &paths.state_dir, events.as_ref()).await;
    }
    // The engine resolves and mounts an app's `configs` against the same root the API and doctor
    // read (issue #118); `None` keeps the feature off.
    let options = ReconcilerOptions {
        config_root: paths.config_root.clone(),
        ..ReconcilerOptions::default()
    };
    let mut reconciler = Reconciler::new(
        podman,
        secrets.clone() as Arc<dyn SecretStore>,
        paths.state.clone(),
        options,
    )
    .with_http_prober(Arc::new(health_probe::NginxProber::default_target()))
    // Crash-loop / unhealthy thresholds (`[monitor]`): the reconcile pass observes them and emits
    // events, so the notifications above deliver them and the log gets them even without a channel.
    .with_monitor(weglarka_core::crash::Policy::from_config(&host.monitor));
    if let Some(notifier) = &notifier {
        // The engine emits into the durable pipeline instead of only into the log.
        reconciler = reconciler.with_events(notifier.sink());
    }
    let engine = Arc::new(reconciler);
    let ingress = Arc::new(IngressManager::new(
        engine.clone(),
        host.clone(),
        paths.nginx_conf_dir.clone(),
    ));
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
        desired_lock: tokio::sync::Mutex::new(()),
        started: std::time::Instant::now(),
        triggers: trigger_tx,
        webhook_addr: OnceLock::new(),
        tasks: Mutex::new(JoinSet::new()),
    });

    let admin_listener = bind_admin(&host.admin.socket)?;
    let webhook_listener = TcpListener::bind(host.webhook.listen)
        .await
        .map_err(io(format!("bind {}", host.webhook.listen)))?;
    let webhook_addr = webhook_listener
        .local_addr()
        .map_err(io("webhook local_addr"))?;
    let _ = daemon.webhook_addr.set(webhook_addr);

    let (shutdown, shutdown_rx) = watch::channel(false);
    let wait = |mut rx: watch::Receiver<bool>| async move {
        let _ = rx.wait_for(|stop| *stop).await;
    };
    let admin = tokio::spawn({
        let app = admin::router(daemon.clone());
        let rx = shutdown_rx.clone();
        async move {
            if let Err(e) = axum::serve(admin_listener, app)
                .with_graceful_shutdown(wait(rx))
                .await
            {
                tracing::error!(error = %e, "admin API server stopped");
            }
        }
    });
    let webhook = tokio::spawn({
        let app = webhook::router(daemon.clone());
        let rx = shutdown_rx.clone();
        async move {
            if let Err(e) = axum::serve(webhook_listener, app)
                .with_graceful_shutdown(wait(rx))
                .await
            {
                tracing::error!(error = %e, "webhook server stopped");
            }
        }
    });

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
        webhook_addr,
        shutdown,
        admin,
        webhook,
        ingress: ingress_task,
        reconcile,
        notify: notify_task,
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
            webhook,
            ingress,
            reconcile,
            notify,
            admin_socket,
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
        if let Some(handle) = notify
            && tokio::time::timeout(SERVER_STOP_TIMEOUT, handle)
                .await
                .is_err()
        {
            tracing::warn!("notification worker did not stop in time");
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
        tracing::info!("weglarka-daemon stopped");
    }
}
