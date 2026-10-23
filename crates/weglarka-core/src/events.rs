//! Zdarzenia domenowe silnika (deploy ok/fail/rollback…) — typy pod przyszły dziennik zdarzeń.
//! W MVP bez trwałego logu: domyślny odbiornik tylko loguje przez `tracing`.

use std::sync::Mutex;

use crate::app::{Digest, InstanceName};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    DeployOk {
        instance: InstanceName,
        digest: Digest,
        generation: u64,
    },
    DeployFailed {
        instance: InstanceName,
        digest: Option<Digest>,
        reason: String,
    },
    /// Nowa wersja odrzucona przez bramkę zdrowia, przywrócono poprzedni digest.
    RolledBack {
        instance: InstanceName,
        failed: Digest,
        restored: Digest,
        reason: String,
    },
    /// Rollback też się nie powiódł — instancja wymaga interwencji.
    RollbackFailed {
        instance: InstanceName,
        reason: String,
    },
    /// Kontener odtworzony z przypiętego digestu (brak kontenera lub drift `spec-hash`).
    Recreated {
        instance: InstanceName,
        reason: String,
    },
    /// Kontener usunięty, bo instancji nie ma w `apps.toml`.
    Pruned { container: String },
    /// Webhook odrzucony jako duplikat (`delivery_id` już widziany).
    WebhookDuplicate { delivery_id: String },
}

/// Odbiornik zdarzeń; synchroniczny i dyn-compatible (przyszły dziennik dopisuje do pliku).
pub trait EventSink: Send + Sync {
    fn emit(&self, event: Event);
}

/// Domyślny odbiornik: `tracing` (poziom info, błędy jako warn).
pub struct TracingSink;

impl EventSink for TracingSink {
    fn emit(&self, event: Event) {
        match &event {
            Event::DeployFailed { .. } | Event::RollbackFailed { .. } => {
                tracing::warn!(?event, "weglarka event")
            }
            _ => tracing::info!(?event, "weglarka event"),
        }
    }
}

/// Zbiera zdarzenia w pamięci (testy).
#[derive(Default)]
pub struct VecSink(Mutex<Vec<Event>>);

impl VecSink {
    pub fn events(&self) -> Vec<Event> {
        self.0.lock().expect("sink mutex poisoned").clone()
    }
}

impl EventSink for VecSink {
    fn emit(&self, event: Event) {
        self.0.lock().expect("sink mutex poisoned").push(event);
    }
}
