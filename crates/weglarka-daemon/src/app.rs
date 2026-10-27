//! Daemon state shared by the admin API, the webhook listener and doctor.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinSet;
use weglarka_engine::reconcile::{Reconciler, Trigger};
use weglarka_model::config::HostConfig;
use weglarka_model::podman::PodmanClient;
use weglarka_model::secrets::FileSecretStore;
use weglarka_model::webhook::WebhookSource;
use weglarka_notify::NotifyHandle;

use crate::ingress::IngressManager;
use crate::settings::Paths;

/// Name of the app secret holding the webhook HMAC key (stored as `<instance>.webhook-hmac`).
pub const WEBHOOK_SECRET: &str = "webhook-hmac";

/// How long a mutating operation waits for the engine mutex (a deploy holds it through the health gate).
pub const MUTATION_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Daemon<P: PodmanClient> {
    pub host: HostConfig,
    pub paths: Paths,
    pub engine: Arc<Reconciler<P>>,
    pub secrets: Arc<FileSecretStore>,
    pub ingress: Arc<IngressManager<P>>,
    /// Enabled webhook adapters; `/webhook/{source}/{instance}` picks one by `WebhookSource::name`.
    pub webhook_sources: Vec<Box<dyn WebhookSource>>,
    /// `None` when `weglarka.toml` configures no notification channel.
    pub notify: Option<Arc<NotifyHandle>>,
    /// What the ACME worker found on its last pass; `None` when `[acme]` is absent or paused.
    pub acme: Option<Arc<crate::acme::AcmeStatus>>,
    /// Serializes "check and save" in `apps add` (the engine locks only the save itself).
    pub desired_lock: tokio::sync::Mutex<()>,
    /// When the process started: reported by `GET /v1/health`, the readiness probe the host-side
    /// self-update watchdog uses (issue #100).
    pub started: std::time::Instant,
    pub(crate) triggers: mpsc::Sender<Trigger>,
    pub(crate) webhook_addr: OnceLock<SocketAddr>,
    pub(crate) tasks: Mutex<JoinSet<()>>,
}

impl<P: PodmanClient + 'static> Daemon<P> {
    /// Desired state changed: reconcile and ingress kick in immediately (coalesced with other requests).
    pub fn changed(&self) {
        // A full channel means a reconcile is already scheduled.
        let _ = self.triggers.try_send(Trigger::Changed);
        self.ingress.request_apply();
    }

    /// Spawns a background task tracked for the duration of graceful shutdown.
    pub fn spawn_tracked(&self, fut: impl Future<Output = ()> + Send + 'static) {
        let mut tasks = self.tasks.lock().unwrap_or_else(|e| e.into_inner());
        while tasks.try_join_next().is_some() {}
        tasks.spawn(fut);
    }
}

impl<P: PodmanClient> Daemon<P> {
    pub fn webhook_source(&self, name: &str) -> Option<&dyn WebhookSource> {
        self.webhook_sources
            .iter()
            .map(|s| s.as_ref())
            .find(|s| s.name() == name)
    }

    pub fn webhook_addr(&self) -> Option<SocketAddr> {
        self.webhook_addr.get().copied()
    }
}
