//! Trait `WebhookSource` — adapter źródła zdarzeń o nowym obrazie (MVP: GitHub; później Forgejo).
//! Celowo synchroniczny i dyn-compatible: operuje na już wczytanym żądaniu, więc daemon może
//! trzymać `Vec<Box<dyn WebhookSource>>` bez kosztów async-trait.

#[derive(Debug, thiserror::Error)]
pub enum WebhookError {
    #[error("missing or malformed signature")]
    BadSignature,
    #[error("malformed webhook payload: {0}")]
    BadPayload(String),
}

/// Surowe żądanie po stronie HTTP (nagłówki + ciało), niezależne od frameworka.
#[derive(Debug, Clone, Default)]
pub struct WebhookRequest {
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl WebhookRequest {
    /// Nagłówek bez rozróżniania wielkości liter.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Znormalizowane zdarzenie: pojawił się nowy obraz.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookEvent {
    /// Identyfikator dostawy do deduplikacji (np. `X-GitHub-Delivery`).
    pub delivery_id: Option<String>,
    pub image_ref: String,
}

pub trait WebhookSource: Send + Sync {
    fn name(&self) -> &'static str;

    /// Weryfikuje podpis (HMAC) sekretem apki; czas stały.
    fn verify(&self, request: &WebhookRequest, secret: &[u8]) -> Result<(), WebhookError>;

    /// `Ok(None)` — poprawne, ale nieistotne zdarzenie (np. ping, inny typ).
    fn normalize(&self, request: &WebhookRequest) -> Result<Option<WebhookEvent>, WebhookError>;
}
