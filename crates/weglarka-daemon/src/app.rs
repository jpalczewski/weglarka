//! Wspólny stan demona współdzielony przez admin API, listener webhooków i doctora.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinSet;
use weglarka_core::config::HostConfig;
use weglarka_core::podman::PodmanClient;
use weglarka_core::reconcile::{Reconciler, Trigger};
use weglarka_core::secrets::FileSecretStore;
use weglarka_core::webhook::WebhookSource;

use crate::ingress::IngressManager;
use crate::settings::Paths;

/// Nazwa sekretu apki z kluczem HMAC webhooka (w magazynie jako `<instancja>.webhook-hmac`).
pub const WEBHOOK_SECRET: &str = "webhook-hmac";

/// Jak długo operacja mutująca czeka na muteks silnika (deploy trzyma go przez bramkę zdrowia).
pub const MUTATION_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Daemon<P: PodmanClient> {
    pub host: HostConfig,
    pub paths: Paths,
    pub engine: Arc<Reconciler<P>>,
    pub secrets: Arc<FileSecretStore>,
    pub ingress: Arc<IngressManager<P>>,
    pub github: Box<dyn WebhookSource>,
    /// Serializuje „sprawdź i zapisz” w `apps add` (silnik blokuje dopiero sam zapis).
    pub desired_lock: tokio::sync::Mutex<()>,
    pub(crate) triggers: mpsc::Sender<Trigger>,
    pub(crate) webhook_addr: OnceLock<SocketAddr>,
    pub(crate) tasks: Mutex<JoinSet<()>>,
}

impl<P: PodmanClient + 'static> Daemon<P> {
    /// Stan pożądany się zmienił: reconcile i ingress ruszają od razu (zlane z innymi żądaniami).
    pub fn changed(&self) {
        // Pełny kanał = reconcile i tak jest już zaplanowany.
        let _ = self.triggers.try_send(Trigger::Changed);
        self.ingress.request_apply();
    }

    /// Uruchamia zadanie w tle śledzone na czas graceful shutdownu.
    pub fn spawn_tracked(&self, fut: impl Future<Output = ()> + Send + 'static) {
        let mut tasks = self.tasks.lock().unwrap_or_else(|e| e.into_inner());
        while tasks.try_join_next().is_some() {}
        tasks.spawn(fut);
    }
}

impl<P: PodmanClient> Daemon<P> {
    pub fn webhook_addr(&self) -> Option<SocketAddr> {
        self.webhook_addr.get().copied()
    }
}
