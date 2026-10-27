//! Notifications: engine events -> message -> dedup -> durable outbox -> channels (ntfy).
//!
//! The daemon installs [`worker::Sink`] as the engine's [`EventSink`](weglarka_model::events::EventSink).
//! `emit` runs while the engine mutex is held, so the sink only forwards the event to the worker
//! (a bounded channel; it never does I/O). The worker renders each event into a [`Message`],
//! suppresses flapping ([`dedup`]), appends the accepted messages to a durable outbox for every
//! channel that wants that severity, and only then delivers them — so a notification survives a
//! crashed daemon, a restarted ntfy or Węglarka updating ntfy itself.
//!
//! Decisions and rejected alternatives: `docs/decisions/0021-notifications.md`.

pub mod channel;
pub mod dedup;
pub mod endpoint;
pub mod message;
pub mod ntfy;
pub mod outbox;
pub mod settings;
pub mod worker;

pub use channel::{Channel, ChannelError, SendFuture};
pub use message::Message;
pub use settings::{ChannelSpec, NotifySettings, NotifySettingsError};
pub use worker::{ChannelStatus, Notifier, NotifyHandle, Sink, StatusSnapshot};
