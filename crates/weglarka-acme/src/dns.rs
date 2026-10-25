use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use weglarka_dns::{DnsProvider, RecordHandle};

use crate::error::AcmeError;
use crate::solver::{Challenge, ChallengeKind, ChallengeSolver};

/// DNS-01: publishes `_acme-challenge.<name>` TXT = `base64url(sha256(key authorization))` through a
/// [`DnsProvider`] (RFC 8555 §8.4) and removes exactly that record afterwards.
///
/// A wildcard order (`*.example.eu` plus `example.eu`) has two challenges for the same name, so the
/// provider is asked to add a record per challenge and the solver remembers one [`RecordHandle`] per
/// `(record name, value)`. `present` is idempotent for a challenge it already published; `cleanup`
/// is idempotent for one it no longer holds, and keeps the handle when the provider refuses the
/// delete, so a later cleanup can retry it.
pub struct DnsSolver<P> {
    provider: P,
    records: Mutex<HashMap<(String, String), RecordHandle>>,
}

impl<P: DnsProvider> DnsSolver<P> {
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            records: Mutex::default(),
        }
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    fn key(challenge: &Challenge) -> (String, String) {
        (
            format!("_acme-challenge.{}", challenge.name()),
            challenge.dns01_txt_value(),
        )
    }

    fn records(&self) -> std::sync::MutexGuard<'_, HashMap<(String, String), RecordHandle>> {
        self.records.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The provider's text only: a `DnsError` never carries the token or the TXT value.
fn failed(challenge: &Challenge, e: weglarka_dns::DnsError) -> AcmeError {
    AcmeError::Challenge {
        name: challenge.name().to_owned(),
        reason: e.to_string(),
    }
}

impl<P: DnsProvider> ChallengeSolver for DnsSolver<P> {
    fn kind(&self) -> ChallengeKind {
        ChallengeKind::Dns01
    }

    async fn present(&self, challenge: &Challenge) -> Result<(), AcmeError> {
        let (name, value) = Self::key(challenge);
        if self.records().contains_key(&(name.clone(), value.clone())) {
            return Ok(());
        }
        let handle = self
            .provider
            .set_txt(&name, &value)
            .await
            .map_err(|e| failed(challenge, e))?;
        self.records().insert((name, value), handle);
        Ok(())
    }

    async fn cleanup(&self, challenge: &Challenge) -> Result<(), AcmeError> {
        let key = Self::key(challenge);
        // Not held across the await; put back on failure so the delete can be retried.
        let Some(handle) = self.records().remove(&key) else {
            return Ok(());
        };
        if let Err(e) = self.provider.remove_txt(&handle).await {
            self.records().insert(key, handle);
            return Err(failed(challenge, e));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, UNIX_EPOCH};

    use weglarka_dns::testing::{Call, FakeDns};
    use weglarka_dns::{DnsError, RecordHandle};

    use super::*;
    use crate::cert::{CertId, CertSpec};
    use crate::client::AcmeClient;
    use crate::manager::{Manager, Outcome};
    use crate::store::CertStore;
    use crate::testing::FakeAcme;

    const DAY: Duration = Duration::from_secs(24 * 3600);

    fn challenge(name: &str, token: &str) -> Challenge {
        Challenge::new(name, token.into(), format!("{token}.thumbprint"))
    }

    /// `Manager` owns its solver, so the tests keep a second reference to the fake provider.
    struct Shared(Arc<FakeDns>);

    impl DnsProvider for Shared {
        fn set_txt(
            &self,
            name: &str,
            value: &str,
        ) -> impl std::future::Future<Output = Result<RecordHandle, DnsError>> + Send {
            self.0.set_txt(name, value)
        }

        fn remove_txt(
            &self,
            handle: &RecordHandle,
        ) -> impl std::future::Future<Output = Result<(), DnsError>> + Send {
            self.0.remove_txt(handle)
        }
    }

    #[tokio::test]
    async fn publishes_the_dns01_value_at_the_acme_challenge_name() {
        let solver = DnsSolver::new(FakeDns::new());
        let c = challenge("example.eu", "tok");
        solver.present(&c).await.unwrap();
        assert_eq!(
            solver.provider().records(),
            [("_acme-challenge.example.eu".to_owned(), c.dns01_txt_value())]
        );
        assert_eq!(solver.kind(), ChallengeKind::Dns01);
    }

    #[tokio::test]
    async fn present_and_cleanup_are_idempotent() {
        let solver = DnsSolver::new(FakeDns::new());
        let c = challenge("example.eu", "tok");
        solver.present(&c).await.unwrap();
        solver.present(&c).await.unwrap();
        assert_eq!(solver.provider().records().len(), 1, "no duplicate record");
        solver.cleanup(&c).await.unwrap();
        solver.cleanup(&c).await.unwrap();
        assert!(solver.provider().records().is_empty());
        let removes = solver
            .provider()
            .calls()
            .into_iter()
            .filter(|c| matches!(c, Call::Remove { .. }))
            .count();
        assert_eq!(removes, 1, "the second cleanup does not call the provider");
    }

    #[tokio::test]
    async fn two_challenges_on_one_name_are_two_records_removed_independently() {
        let solver = DnsSolver::new(FakeDns::new());
        let (a, b) = (
            challenge("example.eu", "one"),
            challenge("example.eu", "two"),
        );
        solver.present(&a).await.unwrap();
        solver.present(&b).await.unwrap();
        assert_eq!(solver.provider().records().len(), 2);
        solver.cleanup(&a).await.unwrap();
        assert_eq!(
            solver.provider().records(),
            [("_acme-challenge.example.eu".to_owned(), b.dns01_txt_value())]
        );
        solver.cleanup(&b).await.unwrap();
        assert!(solver.provider().records().is_empty());
    }

    #[tokio::test]
    async fn a_failed_delete_is_reported_and_can_be_retried() {
        let solver = DnsSolver::new(FakeDns::new());
        let c = challenge("example.eu", "tok");
        solver.present(&c).await.unwrap();
        solver.provider().fail_next_remove("API down");
        let err = solver.cleanup(&c).await.unwrap_err();
        assert!(
            matches!(&err, AcmeError::Challenge { name, reason }
            if name == "example.eu" && reason.contains("API down")),
            "{err}"
        );
        assert_eq!(solver.provider().records().len(), 1);
        solver.cleanup(&c).await.unwrap();
        assert!(solver.provider().records().is_empty());
    }

    #[tokio::test]
    async fn a_failed_publish_is_a_challenge_error_and_leaves_nothing_behind() {
        let solver = DnsSolver::new(FakeDns::new());
        let c = challenge("example.eu", "tok");
        solver.provider().fail_next_set("quota");
        let err = solver.present(&c).await.unwrap_err();
        assert!(matches!(&err, AcmeError::Challenge { reason, .. } if reason.contains("quota")));
        solver.cleanup(&c).await.unwrap();
        assert!(solver.provider().records().is_empty());
    }

    #[tokio::test]
    async fn a_name_the_provider_rejects_is_a_challenge_error() {
        let solver = DnsSolver::new(FakeDns::new());
        let err = solver
            .present(&challenge("Bad Name", "tok"))
            .await
            .unwrap_err();
        assert!(matches!(err, AcmeError::Challenge { .. }));
    }

    #[tokio::test]
    async fn a_failed_order_still_cleans_the_dns_records() {
        let solver = DnsSolver::new(FakeDns::new());
        let fake = FakeAcme::new(UNIX_EPOCH + 90 * DAY);
        fake.fail_next("CA said no");
        let spec = CertSpec::single("example.eu").unwrap();
        assert!(fake.issue(&spec, &solver).await.is_err());
        assert!(solver.provider().records().is_empty());
        assert_eq!(solver.provider().calls().len(), 2, "one set, one remove");
    }

    #[tokio::test]
    async fn the_manager_issues_a_wildcard_with_dns01_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let store = CertStore::new(dir.path().join("tls"));
        let now = UNIX_EPOCH + 2000 * DAY;
        let dns = Arc::new(FakeDns::new());
        let manager = Manager::new(
            FakeAcme::new(now + 90 * DAY),
            DnsSolver::new(Shared(dns.clone())),
            store.clone(),
            30 * DAY,
        );
        let wildcard = CertSpec::new(
            CertId::new("_wildcard.example.eu").unwrap(),
            vec!["*.example.eu".into(), "example.eu".into()],
        )
        .unwrap();
        let report = manager.pass(now, std::slice::from_ref(&wildcard)).await;
        assert!(
            matches!(report.outcomes[0].1, Outcome::Issued { .. }),
            "{:?}",
            report.outcomes
        );
        assert!(
            store
                .key_path(wildcard.id())
                .ends_with("_wildcard.example.eu.key")
        );
        assert!(store.key_path(wildcard.id()).exists());
        let sets: Vec<_> = dns
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                Call::Set { name, .. } => Some(name),
                Call::Remove { .. } => None,
            })
            .collect();
        assert_eq!(sets, ["_acme-challenge.example.eu"; 2], "wildcard + apex");
        assert!(dns.records().is_empty(), "both records were removed");
    }

    #[test]
    fn wildcard_identifier_maps_to_the_base_record_name() {
        let c = Challenge::new("*.example.eu", "t".into(), "k".into());
        assert_eq!(
            DnsSolver::<FakeDns>::key(&c).0,
            "_acme-challenge.example.eu"
        );
    }
}
