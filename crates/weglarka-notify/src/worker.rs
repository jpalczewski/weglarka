//! The delivery worker: engine events -> messages -> dedup -> outbox -> channels, with retries.
//!
//! The engine calls [`Sink::emit`] while it holds its mutex, so the sink only forwards the event to
//! this worker through a bounded queue — no I/O ever happens on the engine's path. The worker renders
//! each event, suppresses flapping, appends the notifications to the durable [`Outbox`] and only then
//! delivers, retrying with a backoff until a channel accepts them (`ChannelError::Retryable`) or the
//! outbox limits give up.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use tokio::sync::{mpsc, watch};
use weglarka_model::app::AppsFile;
use weglarka_model::config::NotifyConfig;
use weglarka_model::events::{Event, EventSink, Severity};
use weglarka_model::state;

use crate::dedup::Windows;
use crate::message::{self, Message};
use crate::outbox::Outbox;
use crate::settings::{NotifySettings, NotifySettingsError};

/// Bound on the engine -> worker queue. Events arrive at human rates (a deploy at a time); a full
/// queue means the worker is stuck, and the event is still in the daemon log.
const EVENT_QUEUE: usize = 256;
/// How often the worker wakes up to close dedup windows and retry pending notifications.
const TICK: Duration = Duration::from_secs(30);

/// The engine's sink: forwards an event to the worker, never blocks or does I/O.
pub struct Sink {
    tx: mpsc::Sender<Event>,
}

impl EventSink for Sink {
    fn emit(&self, event: Event) {
        match self.tx.try_send(event) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(event)) => {
                tracing::warn!(?event, "notification queue is full; event not delivered")
            }
            Err(mpsc::error::TrySendError::Closed(event)) => {
                tracing::debug!(?event, "notification worker is gone")
            }
        }
    }
}

/// Per-channel view of the queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelStatus {
    pub name: String,
    pub min_severity: Severity,
    pub pending: usize,
}

/// What `GET /v1/notifications` reports.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StatusSnapshot {
    pub enabled: bool,
    pub channels: Vec<ChannelStatus>,
    pub pending: usize,
    pub dropped: u64,
    pub last_error: Option<String>,
    /// RFC 3339 of the last successful delivery.
    pub last_delivered_at: Option<String>,
}

/// State shared between the worker and the daemon (`notify status`).
#[derive(Debug, Default)]
struct Shared {
    pending: usize,
    pending_by_channel: std::collections::BTreeMap<String, usize>,
    dropped: u64,
    last_error: Option<String>,
    last_delivered_at: Option<SystemTime>,
}

/// The daemon's handle on the notifier: status and the `notify test` delivery.
pub struct NotifyHandle {
    settings: Arc<NotifySettings>,
    shared: Arc<Mutex<Shared>>,
}

impl std::fmt::Debug for NotifyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotifyHandle")
            .field("channels", &self.settings.channels)
            .finish_non_exhaustive()
    }
}

impl NotifyHandle {
    pub fn snapshot(&self) -> StatusSnapshot {
        let shared = self.shared.lock().unwrap_or_else(|e| e.into_inner());
        StatusSnapshot {
            enabled: true,
            channels: self
                .settings
                .channels
                .iter()
                .map(|channel| ChannelStatus {
                    name: channel.name.to_owned(),
                    min_severity: channel.min_severity,
                    pending: shared
                        .pending_by_channel
                        .get(channel.name)
                        .copied()
                        .unwrap_or(0),
                })
                .collect(),
            pending: shared.pending,
            dropped: shared.dropped,
            last_error: shared.last_error.clone(),
            last_delivered_at: shared
                .last_delivered_at
                .map(weglarka_model::secrets::rfc3339_utc),
        }
    }

    /// `notify test`: delivers now, bypassing the outbox and dedup, and reports the channel's verdict.
    pub async fn test(&self, label: &str) -> Result<(), String> {
        let Some(channel) = self.settings.channels.first() else {
            return Err("no notification channel is configured".to_owned());
        };
        let message = message::test_message(label);
        match tokio::time::timeout(crate::ntfy::SEND_TIMEOUT, channel.channel.send(&message)).await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(error.to_string()),
            Err(_) => Err("the notification test timed out".to_owned()),
        }
    }
}

/// The notification worker. One per daemon; `None` when `[notify]` configures no channel.
pub struct Notifier {
    settings: Arc<NotifySettings>,
    rx: mpsc::Receiver<Event>,
    sink: mpsc::Sender<Event>,
    outbox: Outbox,
    windows: Windows,
    apps_path: PathBuf,
    shared: Arc<Mutex<Shared>>,
    clock: Box<dyn Fn() -> SystemTime + Send + Sync>,
}

impl Notifier {
    /// Validates the optional `[notify]` section and builds the worker (`None` = no channel).
    /// Ours is the only sink of the engine, so an invalid configuration is a startup error, not a
    /// silent no-op.
    pub fn build(
        config: Option<&NotifyConfig>,
        apps_path: impl Into<PathBuf>,
        outbox_path: impl Into<PathBuf>,
    ) -> Result<Option<Self>, NotifySettingsError> {
        let Some(config) = config else {
            return Ok(None);
        };
        let Some(settings) = NotifySettings::load(config)? else {
            return Ok(None);
        };
        Ok(Some(Self::with_settings(
            Arc::new(settings),
            apps_path,
            outbox_path,
        )))
    }

    fn with_settings(
        settings: Arc<NotifySettings>,
        apps_path: impl Into<PathBuf>,
        outbox_path: impl Into<PathBuf>,
    ) -> Self {
        let (sink, rx) = mpsc::channel(EVENT_QUEUE);
        let outbox = Outbox::load(outbox_path);
        let shared = Arc::new(Mutex::new(Shared::default()));
        let mut notifier = Self {
            windows: Windows::new(settings.dedup_window),
            settings,
            rx,
            sink,
            outbox,
            apps_path: apps_path.into(),
            shared,
            clock: Box::new(SystemTime::now),
        };
        notifier.refresh();
        notifier
    }

    /// Injectable clock (tests).
    pub fn with_clock(mut self, clock: impl Fn() -> SystemTime + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    /// The sink to install as the engine's event sink.
    pub fn sink(&self) -> Arc<dyn EventSink> {
        Arc::new(Sink {
            tx: self.sink.clone(),
        })
    }

    pub fn handle(&self) -> Arc<NotifyHandle> {
        Arc::new(NotifyHandle {
            settings: self.settings.clone(),
            shared: self.shared.clone(),
        })
    }

    pub fn outbox_path(&self) -> &std::path::Path {
        self.outbox.path()
    }

    /// The worker loop: deliver what a previous run left, then handle events and ticks until shutdown.
    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) {
        self.flush_and_deliver().await;
        let mut ticker = tokio::time::interval(TICK);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = ticker.tick() => self.flush_and_deliver().await,
                event = self.rx.recv() => match event {
                    Some(event) => self.on_event(event).await,
                    None => break,
                },
                _ = shutdown.changed() => break,
            }
        }
        // Everything is persisted on each mutation; the last state is already on disk.
        self.refresh();
    }

    /// Renders an event, applies dedup and queues it for every channel that wants its severity.
    async fn on_event(&mut self, event: Event) {
        let now = (self.clock)();
        let message = message::render(&event, &self.apps());
        if self.settings.accepting(message.severity).next().is_none() {
            tracing::debug!(severity = %message.severity, title = %message.title, "notification below the channel's min_severity");
            return;
        }
        let admission = self.windows.admit(message, now);
        if let Some(summary) = admission.summary {
            self.enqueue(&summary, now);
        }
        if let Some(message) = admission.message {
            self.enqueue(&message, now);
        }
        self.deliver_due(now).await;
    }

    /// Closes expired windows and retries the pending queue.
    async fn flush_and_deliver(&mut self) {
        let now = (self.clock)();
        for summary in self.windows.flush(now) {
            self.enqueue(&summary, now);
        }
        if let Err(error) = self.outbox.prune(now) {
            tracing::error!(error = %error, "cannot prune the notification outbox");
        }
        self.deliver_due(now).await;
    }

    /// `apps.toml` only supplies the click-through link; a read error must not drop a notification.
    fn apps(&self) -> AppsFile {
        state::load_apps(&self.apps_path).unwrap_or_else(|error| {
            tracing::debug!(error = %error, "cannot read apps.toml; notifications without links");
            AppsFile::default()
        })
    }

    fn enqueue(&mut self, message: &Message, now: SystemTime) {
        let channels: Vec<&'static str> = self
            .settings
            .accepting(message.severity)
            .map(|channel| channel.name)
            .collect();
        for name in channels {
            if let Err(error) = self.outbox.push(name, message, now) {
                tracing::error!(error = %error, channel = name, "cannot queue the notification");
                self.set_error(error.to_string());
            }
        }
        self.refresh();
    }

    async fn deliver_due(&mut self, now: SystemTime) {
        while let Some(item) = self.outbox.due(now) {
            let Some(spec) = self.settings.channel(&item.channel) else {
                tracing::warn!(id = item.id, channel = %item.channel, "no channel of that name is configured; dropping the notification");
                if let Err(error) = self.outbox.forget(item.id) {
                    tracing::error!(error = %error, "cannot update the notification outbox");
                    // The item stays due and would be picked again: stop instead of spinning.
                    break;
                }
                continue;
            };
            let result = spec.channel.send(&item.message()).await;
            match result {
                Ok(()) => match self.outbox.delivered(item.id) {
                    Ok(Some(delivered)) => {
                        tracing::debug!(id = delivered.id, channel = %delivered.channel, "notification delivered");
                        self.shared
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .last_delivered_at = Some(now);
                    }
                    Ok(None) => {}
                    Err(error) => {
                        tracing::error!(error = %error, "cannot update the notification outbox");
                        // Delivered but not persisted: retrying now would loop on the same item.
                        break;
                    }
                },
                Err(error) => {
                    let permanent = error.is_permanent();
                    tracing::warn!(id = item.id, channel = spec.name, permanent, error = %error, "notification delivery failed");
                    self.set_error(error.to_string());
                    match self.outbox.fail(item.id, now, permanent) {
                        Ok(Some(dropped)) => {
                            tracing::error!(id = dropped.id, channel = %dropped.channel, "giving up on a notification")
                        }
                        Ok(None) => {}
                        Err(e) => {
                            tracing::error!(error = %e, "cannot update the notification outbox");
                            break;
                        }
                    }
                    if !permanent {
                        // The channel is down (or rate-limiting): do not hammer the rest of the queue.
                        break;
                    }
                }
            }
        }
        self.refresh();
    }

    fn set_error(&mut self, error: String) {
        self.shared
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .last_error = Some(error);
    }

    fn refresh(&mut self) {
        let (pending, per_channel, dropped) = (
            self.outbox.len(),
            self.outbox.per_channel(),
            self.outbox.dropped(),
        );
        let mut shared = self.shared.lock().unwrap_or_else(|e| e.into_inner());
        shared.pending = pending;
        shared.pending_by_channel = per_channel;
        shared.dropped = dropped;
    }
}

/// Channel refused on purpose: kept for the tests below to build a [`ChannelSpec`] without ntfy.
#[cfg(test)]
struct FakeChannel {
    sent: Mutex<Vec<Message>>,
    error: Mutex<Option<crate::channel::ChannelError>>,
}

#[cfg(test)]
impl FakeChannel {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            sent: Mutex::new(Vec::new()),
            error: Mutex::new(None),
        })
    }

    fn sent(&self) -> Vec<Message> {
        self.sent.lock().unwrap().clone()
    }
}

#[cfg(test)]
impl crate::channel::Channel for FakeChannel {
    fn name(&self) -> &'static str {
        "ntfy"
    }

    fn send<'a>(&'a self, message: &'a Message) -> crate::channel::SendFuture<'a> {
        Box::pin(async move {
            if let Some(error) = self.error.lock().unwrap().clone() {
                return Err(error);
            }
            self.sent.lock().unwrap().push(message.clone());
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::{Channel, ChannelError};
    use crate::settings::ChannelSpec;
    use weglarka_model::app::{Digest, InstanceName};

    fn instance() -> InstanceName {
        InstanceName::new("ntfy").unwrap()
    }

    fn digest() -> Digest {
        Digest::new(format!("sha256:{}", "a".repeat(64))).unwrap()
    }

    fn failed_deploy() -> Event {
        Event::DeployFailed {
            instance: instance(),
            digest: Some(digest()),
            reason: "health gate failed".into(),
        }
    }

    struct Harness {
        _dir: tempfile::TempDir,
        notifier: Notifier,
        channel: Arc<FakeChannel>,
        now: Arc<Mutex<SystemTime>>,
    }

    fn harness(window_secs: u64, min_severity: Severity) -> Harness {
        let dir = tempfile::Builder::new()
            .prefix("wgn")
            .tempdir_in("/tmp")
            .unwrap();
        let apps = dir.path().join("apps.toml");
        std::fs::write(
            &apps,
            "[apps.ntfy]\nimage = \"ghcr.io/x/ntfy:1\"\ndomains = [\"nz.example.com\"]\n",
        )
        .unwrap();
        let channel = FakeChannel::new();
        let settings = Arc::new(NotifySettings {
            dedup_window: Duration::from_secs(window_secs),
            channels: vec![ChannelSpec {
                name: "ntfy",
                min_severity,
                channel: channel.clone(),
            }],
        });
        let now = Arc::new(Mutex::new(SystemTime::UNIX_EPOCH));
        let clock = now.clone();
        let notifier =
            Notifier::with_settings(settings, apps, dir.path().join("notifications.toml"))
                .with_clock(move || *clock.lock().unwrap());
        Harness {
            _dir: dir,
            notifier,
            channel,
            now,
        }
    }

    fn advance(harness: &Harness, secs: u64) {
        let mut now = harness.now.lock().unwrap();
        *now += Duration::from_secs(secs);
    }

    #[tokio::test]
    async fn an_event_is_rendered_queued_and_delivered_once() {
        let mut harness = harness(0, Severity::Info);
        harness.notifier.on_event(failed_deploy()).await;
        let sent = harness.channel.sent();
        assert_eq!(sent.len(), 1, "{sent:?}");
        assert_eq!(sent[0].severity, Severity::Warning);
        assert_eq!(sent[0].title, "deploy failed: ntfy");
        assert_eq!(sent[0].click.as_deref(), Some("https://nz.example.com"));
        // The outbox is empty after a successful delivery.
        assert_eq!(harness.notifier.outbox.len(), 0);
        let status = harness.notifier.handle().snapshot();
        assert_eq!(status.pending, 0);
        assert_eq!(status.dropped, 0);
        assert!(status.last_delivered_at.is_some());
    }

    #[tokio::test]
    async fn flapping_is_summarised_inside_the_window() {
        let mut harness = harness(300, Severity::Info);
        harness.notifier.on_event(failed_deploy()).await;
        for _ in 0..3 {
            harness.notifier.on_event(failed_deploy()).await;
        }
        assert_eq!(
            harness.channel.sent().len(),
            1,
            "only the first one is sent"
        );
        advance(&harness, 300);
        harness.notifier.flush_and_deliver().await;
        let sent = harness.channel.sent();
        assert_eq!(sent.len(), 2, "{sent:?}");
        assert_eq!(sent[1].title, "3 more: deploy failed: ntfy");
    }

    #[tokio::test]
    async fn a_delivery_failure_keeps_the_notification_and_retries_later() {
        let mut harness = harness(0, Severity::Info);
        *harness.channel.error.lock().unwrap() =
            Some(ChannelError::Retryable("ntfy is down".into()));
        harness.notifier.on_event(failed_deploy()).await;
        assert!(harness.channel.sent().is_empty());
        assert_eq!(harness.notifier.outbox.len(), 1, "queued, not lost");
        assert_eq!(
            harness.notifier.handle().snapshot().last_error.as_deref(),
            Some("ntfy is down")
        );

        // Not due yet: the retry waits for the backoff.
        harness.notifier.flush_and_deliver().await;
        assert!(harness.channel.sent().is_empty());
        assert_eq!(harness.notifier.outbox.len(), 1);

        *harness.channel.error.lock().unwrap() = None;
        advance(&harness, 31);
        harness.notifier.flush_and_deliver().await;
        assert_eq!(
            harness.channel.sent().len(),
            1,
            "delivered exactly once after the outage"
        );
        assert_eq!(harness.notifier.outbox.len(), 0);
    }

    #[tokio::test]
    async fn a_permanent_failure_drops_only_that_notification() {
        let mut harness = harness(0, Severity::Info);
        // First attempt fails permanently, the next notification goes through.
        *harness.channel.error.lock().unwrap() = Some(ChannelError::Permanent(
            "ntfy refused the access token".into(),
        ));
        harness.notifier.on_event(failed_deploy()).await;
        assert_eq!(harness.notifier.outbox.len(), 0, "dropped");
        assert_eq!(harness.notifier.handle().snapshot().dropped, 1);

        *harness.channel.error.lock().unwrap() = None;
        harness.notifier.on_event(failed_deploy()).await;
        assert_eq!(harness.channel.sent().len(), 1);
    }

    #[tokio::test]
    async fn events_below_min_severity_are_dropped_before_dedup() {
        let mut harness = harness(0, Severity::Critical);
        harness.notifier.on_event(failed_deploy()).await;
        assert!(harness.channel.sent().is_empty());
        assert_eq!(harness.notifier.outbox.len(), 0);
        harness
            .notifier
            .on_event(Event::RollbackFailed {
                instance: instance(),
                reason: "boom".into(),
            })
            .await;
        assert_eq!(harness.channel.sent().len(), 1);
        assert_eq!(harness.channel.sent()[0].severity, Severity::Critical);
    }

    #[tokio::test]
    async fn a_restart_delivers_what_the_previous_run_left_pending() {
        let mut harness = harness(0, Severity::Info);
        *harness.channel.error.lock().unwrap() =
            Some(ChannelError::Retryable("ntfy is down".into()));
        harness.notifier.on_event(failed_deploy()).await;
        let outbox = harness.notifier.outbox_path().to_owned();
        // Simulate a daemon restart: a fresh notifier over the same outbox path and channel.
        let settings = Arc::new(NotifySettings {
            dedup_window: Duration::ZERO,
            channels: vec![ChannelSpec {
                name: "ntfy",
                min_severity: Severity::Info,
                channel: harness.channel.clone(),
            }],
        });
        *harness.channel.error.lock().unwrap() = None;
        let clock = harness.now.clone();
        let mut restarted = Notifier::with_settings(settings, "/nonexistent/apps.toml", outbox)
            .with_clock(move || *clock.lock().unwrap());
        advance(&harness, 31);
        restarted.flush_and_deliver().await;
        assert_eq!(harness.channel.sent().len(), 1);
        assert_eq!(restarted.outbox.len(), 0);
    }

    #[tokio::test]
    async fn notify_test_reports_the_channel_verdict() {
        let harness = harness(0, Severity::Info);
        let handle = harness.notifier.handle();
        handle.test("węglarka.example.com").await.unwrap();
        assert_eq!(harness.channel.sent().len(), 1);
        assert!(
            harness.channel.sent()[0]
                .body
                .contains("węglarka.example.com")
        );

        *harness.channel.error.lock().unwrap() = Some(ChannelError::Permanent(
            "ntfy refused the access token".into(),
        ));
        let error = handle.test("x").await.unwrap_err();
        assert!(error.contains("access token"), "{error}");
    }

    #[test]
    fn the_sink_drops_events_instead_of_blocking_the_engine() {
        // A channel of capacity 1 with no receiver task: the second emit must not block.
        let (tx, rx) = mpsc::channel(1);
        let sink = Sink { tx };
        sink.emit(failed_deploy());
        sink.emit(failed_deploy());
        drop(rx);
        // The sink also tolerates a closed channel.
        sink.emit(failed_deploy());
    }

    #[test]
    fn snapshot_lists_the_channels() {
        let harness = harness(0, Severity::Warning);
        let snapshot = harness.notifier.handle().snapshot();
        assert!(snapshot.enabled);
        assert_eq!(snapshot.channels.len(), 1);
        assert_eq!(snapshot.channels[0].name, "ntfy");
        assert_eq!(snapshot.channels[0].min_severity, Severity::Warning);
        assert_eq!(snapshot.pending, 0);
    }

    #[test]
    fn the_channel_trait_object_is_usable() {
        let channel: Arc<dyn Channel> = FakeChannel::new();
        assert_eq!(channel.name(), "ntfy");
    }
}
