//! In-memory [`DnsProvider`] for tests (feature `testing`): keeps the live TXT records and a log of
//! calls, and can be told to fail.

use std::sync::Mutex;

use crate::name::{valid_record_name, valid_txt_value};
use crate::provider::{DnsError, DnsProvider, RecordHandle};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    Set { name: String, value: String },
    Remove { handle: RecordHandle },
}

#[derive(Default)]
struct Inner {
    next: u64,
    /// `(handle, name, value)` of the records that currently exist.
    records: Vec<(RecordHandle, String, String)>,
    calls: Vec<Call>,
    fail_set: Option<String>,
    fail_remove: Option<String>,
}

#[derive(Default)]
pub struct FakeDns {
    inner: Mutex<Inner>,
}

impl FakeDns {
    pub fn new() -> Self {
        Self::default()
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Every call so far, in order.
    pub fn calls(&self) -> Vec<Call> {
        self.inner().calls.clone()
    }

    /// `(name, value)` of the records that currently exist — empty means the cleanup ran.
    pub fn records(&self) -> Vec<(String, String)> {
        self.inner()
            .records
            .iter()
            .map(|(_, name, value)| (name.clone(), value.clone()))
            .collect()
    }

    /// The next `set_txt` fails with an API error carrying `message`.
    pub fn fail_next_set(&self, message: &str) {
        self.inner().fail_set = Some(message.to_owned());
    }

    /// The next `remove_txt` fails with an API error carrying `message`.
    pub fn fail_next_remove(&self, message: &str) {
        self.inner().fail_remove = Some(message.to_owned());
    }
}

impl DnsProvider for FakeDns {
    async fn set_txt(&self, name: &str, value: &str) -> Result<RecordHandle, DnsError> {
        if !valid_record_name(name) {
            return Err(DnsError::InvalidName(name.to_owned()));
        }
        if !valid_txt_value(value) {
            return Err(DnsError::InvalidValue);
        }
        let mut inner = self.inner();
        inner.calls.push(Call::Set {
            name: name.to_owned(),
            value: value.to_owned(),
        });
        if let Some(message) = inner.fail_set.take() {
            return Err(DnsError::Api {
                status: 500,
                message,
            });
        }
        inner.next += 1;
        let handle = RecordHandle::new(format!("fake-{}", inner.next));
        inner
            .records
            .push((handle.clone(), name.to_owned(), value.to_owned()));
        Ok(handle)
    }

    async fn remove_txt(&self, handle: &RecordHandle) -> Result<(), DnsError> {
        let mut inner = self.inner();
        inner.calls.push(Call::Remove {
            handle: handle.clone(),
        });
        if let Some(message) = inner.fail_remove.take() {
            return Err(DnsError::Api {
                status: 500,
                message,
            });
        }
        // Idempotent like the real adapters: a missing record is fine.
        inner.records.retain(|(h, _, _)| h != handle);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tracks_records_calls_and_failures() {
        let dns = FakeDns::new();
        let a = dns
            .set_txt("_acme-challenge.example.eu", "aaa")
            .await
            .unwrap();
        let b = dns
            .set_txt("_acme-challenge.example.eu", "bbb")
            .await
            .unwrap();
        assert_eq!(dns.records().len(), 2);
        dns.remove_txt(&a).await.unwrap();
        dns.remove_txt(&a).await.unwrap();
        assert_eq!(
            dns.records(),
            [("_acme-challenge.example.eu".to_owned(), "bbb".to_owned())]
        );
        dns.fail_next_remove("boom");
        assert!(dns.remove_txt(&b).await.is_err());
        dns.remove_txt(&b).await.unwrap();
        assert!(dns.records().is_empty());
        dns.fail_next_set("quota");
        assert!(matches!(
            dns.set_txt("example.eu", "ccc").await,
            Err(DnsError::Api { status: 500, .. })
        ));
        assert_eq!(dns.calls().len(), 7);
    }
}
