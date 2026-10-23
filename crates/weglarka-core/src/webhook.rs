//! `WebhookSource` trait — adapter for new-image event sources (MVP: GitHub; Forgejo later).
//! Deliberately synchronous and dyn-compatible: it operates on an already-read request, so the
//! daemon can hold a `Vec<Box<dyn WebhookSource>>` without async-trait overhead.

#[derive(Debug, thiserror::Error)]
pub enum WebhookError {
    #[error("missing or malformed signature")]
    BadSignature,
    #[error("malformed webhook payload: {0}")]
    BadPayload(String),
}

/// Raw HTTP-side request (headers + body), framework-independent.
#[derive(Debug, Clone, Default)]
pub struct WebhookRequest {
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl WebhookRequest {
    /// Header lookup, case-insensitive.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Normalized event: a new image appeared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookEvent {
    /// Delivery identifier for deduplication (e.g. `X-GitHub-Delivery`).
    pub delivery_id: Option<String>,
    pub image_ref: String,
}

pub trait WebhookSource: Send + Sync {
    fn name(&self) -> &'static str;

    /// Verifies the signature (HMAC) with the app's secret; constant time.
    fn verify(&self, request: &WebhookRequest, secret: &[u8]) -> Result<(), WebhookError>;

    /// `Ok(None)` — a valid but irrelevant event (e.g. ping, other type).
    fn normalize(&self, request: &WebhookRequest) -> Result<Option<WebhookEvent>, WebhookError>;
}
