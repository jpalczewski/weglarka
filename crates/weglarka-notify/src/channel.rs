//! Delivery channels: one trait behind which ntfy (now) and mail (later) live.
//!
//! `Channel` must be dyn-compatible (`Arc<dyn Channel>`), so the future is boxed — the same shape as
//! `weglarka_core::limits::HttpProber`; native `async fn` in traits is not dyn-compatible
//! (`docs/decisions/0001-async-traits.md`).

use std::future::Future;
use std::pin::Pin;

use crate::message::Message;

/// Future returned by [`Channel::send`].
pub type SendFuture<'a> = Pin<Box<dyn Future<Output = Result<(), ChannelError>> + Send + 'a>>;

/// Why a delivery failed. The distinction decides whether the outbox retries.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChannelError {
    /// Worth retrying: network, TLS handshake, timeouts, 408/429/5xx.
    #[error("{0}")]
    Retryable(String),
    /// Permanent: bad credentials, a rejected request (4xx), a redirect. Retrying cannot help.
    #[error("{0}")]
    Permanent(String),
}

impl ChannelError {
    pub fn is_permanent(&self) -> bool {
        matches!(self, Self::Permanent(_))
    }
}

/// A delivery target. Implementations must not log the message body at `debug` or above — it can
/// name apps and reasons that the operator wants in the notification only.
pub trait Channel: Send + Sync {
    /// Stable name: it is stored in the outbox, so a queued notification survives a restart, and it
    /// appears in `notify status` (`ntfy`).
    fn name(&self) -> &'static str;

    fn send<'a>(&'a self, message: &'a Message) -> SendFuture<'a>;
}
