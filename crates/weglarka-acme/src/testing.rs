//! Test doubles: an in-memory [`AcmeClient`] + [`CertInspector`] that needs no CA and no network.
//!
//! [`FakeAcme`] still drives the [`ChallengeSolver`] it is given — present, then cleanup, also when
//! the scripted order fails — so solver and manager tests exercise the real seam. Its certificates
//! are not PEM: the chain is `FAKE-CERT not_after=<unix seconds>` and the key a fixed marker.

use std::collections::VecDeque;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::cert::{CertId, CertSpec, Issued, PrivateKeyPem};
use crate::client::{AcmeClient, CertInspector};
use crate::error::AcmeError;
use crate::solver::{Challenge, ChallengeSolver};

/// A scripted CA: every order succeeds with `not_after`, unless a failure was queued.
#[derive(Debug)]
pub struct FakeAcme {
    not_after: SystemTime,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    /// One entry per order, in order: `None` succeeds, `Some(reason)` fails.
    failures: VecDeque<Option<String>>,
    orders: Vec<CertId>,
}

impl FakeAcme {
    pub fn new(not_after: SystemTime) -> Self {
        Self {
            not_after,
            state: Mutex::default(),
        }
    }

    /// The next order fails with this reason (after presenting and cleaning up its challenges).
    pub fn fail_next(&self, reason: &str) {
        self.fail_next_after(0, reason);
    }

    /// The order after the next `skip` orders fails (those succeed), e.g. to fail the second
    /// certificate of a pass.
    pub fn fail_next_after(&self, skip: usize, reason: &str) {
        let mut state = self.lock();
        state.failures.extend(std::iter::repeat_n(None, skip));
        state.failures.push_back(Some(reason.to_owned()));
    }

    /// Ids of the certificates ordered so far, in order.
    pub fn orders(&self) -> Vec<CertId> {
        self.lock().orders.clone()
    }

    /// The chain this fake would issue with the given expiry (to pre-seed a store in tests).
    pub fn chain_expiring_at(not_after: SystemTime) -> Vec<u8> {
        let secs = not_after
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        format!("FAKE-CERT not_after={secs}").into_bytes()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl AcmeClient for FakeAcme {
    async fn issue<S: ChallengeSolver>(
        &self,
        spec: &CertSpec,
        solver: &S,
    ) -> Result<Issued, AcmeError> {
        let failure = {
            let mut state = self.lock();
            state.orders.push(spec.id().clone());
            state.failures.pop_front().flatten()
        };
        let challenges: Vec<_> = spec
            .names()
            .iter()
            .enumerate()
            .map(|(i, name)| Challenge {
                name: name.trim_start_matches("*.").to_owned(),
                token: format!("fake-token-{i}"),
                key_authorization: format!("fake-token-{i}.fake-thumbprint"),
            })
            .collect();
        let mut result = Ok(());
        for challenge in &challenges {
            if let Err(e) = solver.present(challenge).await {
                result = Err(e);
                break;
            }
        }
        for challenge in &challenges {
            if let Err(e) = solver.cleanup(challenge).await {
                tracing::warn!(error = %e, "challenge cleanup failed");
            }
        }
        result?;
        if let Some(reason) = failure {
            return Err(AcmeError::Order(reason));
        }
        Ok(Issued {
            chain_pem: Self::chain_expiring_at(self.not_after),
            key: PrivateKeyPem::new(b"FAKE-KEY".to_vec()),
            not_after: self.not_after,
        })
    }
}

impl CertInspector for FakeAcme {
    fn not_after(&self, chain_pem: &[u8]) -> Result<SystemTime, AcmeError> {
        let text = std::str::from_utf8(chain_pem).map_err(|e| AcmeError::Expiry(e.to_string()))?;
        let secs = text
            .strip_prefix("FAKE-CERT not_after=")
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or_else(|| AcmeError::Expiry("not a fake certificate".into()))?;
        Ok(UNIX_EPOCH + Duration::from_secs(secs))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::Arc;

    use super::*;
    use crate::manager::{Manager, Outcome};
    use crate::solver::{ChallengeKind, Http01Solver};
    use crate::store::CertStore;

    const DAY: Duration = Duration::from_secs(24 * 3600);
    const WINDOW: Duration = Duration::from_secs(30 * 24 * 3600);

    struct Rig {
        _dir: tempfile::TempDir,
        webroot: std::path::PathBuf,
        store: CertStore,
        fake: Arc<FakeAcme>,
        manager: Manager<Arc<FakeAcme>, Http01Solver>,
        now: SystemTime,
    }

    impl AcmeClient for Arc<FakeAcme> {
        fn issue<S: ChallengeSolver>(
            &self,
            spec: &CertSpec,
            solver: &S,
        ) -> impl std::future::Future<Output = Result<Issued, AcmeError>> + Send {
            self.as_ref().issue(spec, solver)
        }
    }

    impl CertInspector for Arc<FakeAcme> {
        fn not_after(&self, chain_pem: &[u8]) -> Result<SystemTime, AcmeError> {
            self.as_ref().not_after(chain_pem)
        }
    }

    fn rig() -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let webroot = dir.path().join("acme");
        fs::create_dir(&webroot).unwrap();
        let store = CertStore::new(dir.path().join("tls"));
        let now = UNIX_EPOCH + 2000 * DAY;
        let fake = Arc::new(FakeAcme::new(now + 90 * DAY));
        let manager = Manager::new(
            fake.clone(),
            Http01Solver::new(&webroot),
            store.clone(),
            WINDOW,
        );
        Rig {
            _dir: dir,
            webroot,
            store,
            fake,
            manager,
            now,
        }
    }

    fn spec(domain: &str) -> CertSpec {
        CertSpec::single(domain).unwrap()
    }

    fn seed(rig: &Rig, spec: &CertSpec, not_after: SystemTime) {
        let issued = Issued {
            chain_pem: FakeAcme::chain_expiring_at(not_after),
            key: PrivateKeyPem::new(b"old-key".to_vec()),
            not_after,
        };
        rig.store.write(spec.id(), &issued).unwrap();
    }

    #[tokio::test]
    async fn issues_when_nothing_is_on_disk_and_cleans_the_webroot() {
        let rig = rig();
        let s = spec("app.example.eu");
        let report = rig.manager.pass(rig.now, std::slice::from_ref(&s)).await;
        assert!(matches!(report.outcomes[0].1, Outcome::Issued { .. }));
        assert!(report.changed());
        assert_eq!(fs::read(rig.store.key_path(s.id())).unwrap(), b"FAKE-KEY");
        assert_eq!(fs::read_dir(&rig.webroot).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn renews_only_inside_the_window() {
        let rig = rig();
        let (fresh, due, expired) = (
            spec("fresh.example.eu"),
            spec("due.example.eu"),
            spec("old.example.eu"),
        );
        seed(&rig, &fresh, rig.now + 60 * DAY);
        seed(&rig, &due, rig.now + 10 * DAY);
        seed(&rig, &expired, rig.now - DAY);
        let report = rig
            .manager
            .pass(rig.now, &[fresh.clone(), due.clone(), expired.clone()])
            .await;
        assert!(matches!(report.outcomes[0].1, Outcome::Valid { .. }));
        assert!(matches!(
            report.outcomes[1].1,
            Outcome::Renewed {
                was_expired: false,
                ..
            }
        ));
        assert!(matches!(
            report.outcomes[2].1,
            Outcome::Renewed {
                was_expired: true,
                ..
            }
        ));
        assert_eq!(rig.fake.orders(), [due.id().clone(), expired.id().clone()]);
        // A second pass finds everything valid: no new orders.
        let again = rig.manager.pass(rig.now, &[fresh, due, expired]).await;
        assert!(!again.changed());
        assert_eq!(rig.fake.orders().len(), 2);
    }

    #[tokio::test]
    async fn failure_keeps_the_old_certificate_cleans_up_and_does_not_stop_the_pass() {
        let rig = rig();
        let (bad, good) = (spec("bad.example.eu"), spec("good.example.eu"));
        seed(&rig, &bad, rig.now + 5 * DAY);
        rig.fake.fail_next("rate limited");
        let report = rig.manager.pass(rig.now, &[bad.clone(), good]).await;
        assert!(
            matches!(&report.outcomes[0].1, Outcome::Failed(AcmeError::Order(r)) if r == "rate limited")
        );
        assert!(matches!(report.outcomes[1].1, Outcome::Issued { .. }));
        assert_eq!(fs::read(rig.store.key_path(bad.id())).unwrap(), b"old-key");
        assert_eq!(fs::read_dir(&rig.webroot).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn wildcard_needs_dns01_and_never_reaches_the_client_with_http01() {
        let rig = rig();
        let wildcard = CertSpec::new(
            CertId::new("_wildcard.example.eu").unwrap(),
            vec!["*.example.eu".into()],
        )
        .unwrap();
        let report = rig.manager.pass(rig.now, &[wildcard]).await;
        assert!(matches!(
            report.outcomes[0].1,
            Outcome::Failed(AcmeError::UnsupportedChallenge { kind: "dns-01" })
        ));
        assert!(rig.fake.orders().is_empty());
        assert_eq!(rig.manager_kind(), ChallengeKind::Http01);
    }

    impl Rig {
        fn manager_kind(&self) -> ChallengeKind {
            Http01Solver::new(&self.webroot).kind()
        }
    }

    #[tokio::test]
    async fn corrupt_certificate_on_disk_is_a_failure_not_a_reissue() {
        let rig = rig();
        let s = spec("app.example.eu");
        std::fs::create_dir_all(rig.store.cert_path(s.id()).parent().unwrap()).unwrap();
        fs::write(rig.store.cert_path(s.id()), b"garbage").unwrap();
        let report = rig.manager.pass(rig.now, &[s]).await;
        assert!(matches!(
            report.outcomes[0].1,
            Outcome::Failed(AcmeError::Expiry(_))
        ));
        assert!(rig.fake.orders().is_empty());
    }
}
