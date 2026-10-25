//! The ACME worker: keeps one certificate per routed domain valid (issue #96,
//! `docs/decisions/0038-acme-engine-seams.md`).
//!
//! Each pass takes the domains the ingress routes (the webhook domain plus every app domain), asks
//! [`weglarka_acme::Manager`] to issue or renew what is missing or inside the renewal window, emits
//! the resulting events and, when a file changed, asks the ingress to apply — it rescans `tls/` and
//! reloads nginx (`nginx -t` + SIGHUP), it never recreates the container (ADR 0036).

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use tokio::sync::watch;
use weglarka_acme::{
    AcmeClient, CertInspector, CertSpec, Http01Solver, InstantAcme, InstantAcmeSettings, Manager,
    Outcome,
};
use weglarka_core::config::AcmeConfig;
use weglarka_core::events::{Event, EventSink};
use weglarka_core::state;

use crate::settings::Paths;

/// First pass waits for the ingress to come up: HTTP-01 is answered by nginx, so ordering before
/// it listens only burns one of the CA's failed-validation allowances.
const STARTUP_DELAY: Duration = Duration::from_secs(30);
/// After a pass with failures the next one comes sooner than `check_interval_secs`, but not so
/// soon that retries run into the CA's failed-validation limit (5 per hostname per hour).
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(30 * 60);
const DAY: Duration = Duration::from_secs(24 * 3600);

/// What the last pass found, for `doctor`.
#[derive(Debug, Default)]
pub struct AcmeStatus {
    inner: Mutex<StatusInner>,
}

#[derive(Debug, Default)]
struct StatusInner {
    last_pass: Option<SystemTime>,
    failures: Vec<(String, String)>,
}

/// A copy of [`AcmeStatus`] taken at one moment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StatusSnapshot {
    /// When the last pass finished; `None` before the first one.
    pub last_pass: Option<SystemTime>,
    /// `(certificate id, reason)` for every certificate the last pass failed on.
    pub failures: Vec<(String, String)>,
}

impl AcmeStatus {
    pub fn snapshot(&self) -> StatusSnapshot {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        StatusSnapshot {
            last_pass: inner.last_pass,
            failures: inner.failures.clone(),
        }
    }

    fn record(&self, at: SystemTime, failures: Vec<(String, String)>) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.last_pass = Some(at);
        inner.failures = failures;
    }
}

/// Host directories the worker reads and writes.
#[derive(Debug, Clone)]
pub struct Dirs {
    /// HTTP-01 webroot served by nginx (`<nginx_conf_dir>/acme`).
    pub webroot: PathBuf,
    /// Certificate directory scanned by the ingress (`<nginx_conf_dir>/tls`).
    pub tls: PathBuf,
    /// `apps.toml`, the source of the routed domains.
    pub apps: PathBuf,
}

pub struct AcmeWorker<C> {
    manager: Manager<C, Http01Solver>,
    apps_path: PathBuf,
    webhook_domain: String,
    events: Arc<dyn EventSink>,
    /// Asks the ingress to apply (rescan `tls/`, reload nginx).
    on_change: Box<dyn Fn() + Send + Sync>,
    status: Arc<AcmeStatus>,
    period: Duration,
}

impl<C: AcmeClient + CertInspector> AcmeWorker<C> {
    pub fn new(
        client: C,
        config: &AcmeConfig,
        dirs: Dirs,
        webhook_domain: String,
        events: Arc<dyn EventSink>,
        on_change: Box<dyn Fn() + Send + Sync>,
    ) -> Self {
        let manager = Manager::new(
            client,
            Http01Solver::new(dirs.webroot),
            weglarka_acme::CertStore::new(dirs.tls),
            Duration::from_secs(config.renew_before_days * DAY.as_secs()),
        );
        Self {
            manager,
            apps_path: dirs.apps,
            webhook_domain,
            events,
            on_change,
            status: Arc::new(AcmeStatus::default()),
            period: Duration::from_secs(config.check_interval_secs),
        }
    }

    pub fn status(&self) -> Arc<AcmeStatus> {
        self.status.clone()
    }

    /// Loop: a first pass after the startup delay, then every `check_interval_secs` (sooner after a
    /// pass that failed). A pass in flight is dropped on shutdown; a leftover challenge token in the
    /// webroot is harmless.
    pub async fn run(&self, mut shutdown: watch::Receiver<bool>) {
        let mut wait = STARTUP_DELAY;
        loop {
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                _ = shutdown.changed() => return,
            }
            let all_ok = tokio::select! {
                ok = self.pass() => ok,
                _ = shutdown.changed() => return,
            };
            wait = if all_ok {
                self.period
            } else {
                self.period.min(RETRY_AFTER_FAILURE)
            };
        }
    }

    /// One pass over the routed domains. Returns `false` when any certificate failed.
    pub async fn pass(&self) -> bool {
        let specs = match self.specs() {
            Ok(specs) => specs,
            Err(e) => {
                tracing::error!(error = %e, "ACME pass skipped: cannot read apps.toml");
                self.status
                    .record(SystemTime::now(), vec![("apps.toml".into(), e)]);
                return false;
            }
        };
        let now = SystemTime::now();
        let report = self.manager.pass(now, &specs).await;
        let mut failures = Vec::new();
        for (id, outcome) in &report.outcomes {
            let cert = id.to_string();
            match outcome {
                Outcome::Valid { .. } => {}
                Outcome::Issued { not_after } => self.events.emit(Event::CertificateIssued {
                    cert,
                    renewed: false,
                    expires_in_days: days_left(now, *not_after),
                }),
                Outcome::Renewed { not_after, .. } => self.events.emit(Event::CertificateIssued {
                    cert,
                    renewed: true,
                    expires_in_days: days_left(now, *not_after),
                }),
                Outcome::Failed(e) => {
                    let reason = e.to_string();
                    self.events.emit(Event::CertificateRenewalFailed {
                        cert: cert.clone(),
                        reason: reason.clone(),
                        expires_in_days: self
                            .manager
                            .current_not_after(id)
                            .map(|not_after| days_left(now, not_after)),
                    });
                    failures.push((cert, reason));
                }
            }
        }
        if report.changed() {
            (self.on_change)();
        }
        let all_ok = failures.is_empty();
        self.status.record(SystemTime::now(), failures);
        all_ok
    }

    /// One single-name certificate per routed domain; a name that cannot be a public DNS name
    /// (nothing an ACME CA would sign) is skipped with a warning.
    fn specs(&self) -> Result<Vec<CertSpec>, String> {
        let apps = state::load_apps(&self.apps_path).map_err(|e| e.to_string())?;
        let mut domains = vec![self.webhook_domain.clone()];
        for spec in apps.apps.values() {
            domains.extend(spec.domains.iter().cloned());
        }
        domains.sort();
        domains.dedup();
        Ok(domains
            .iter()
            .filter_map(|domain| match CertSpec::single(domain) {
                Ok(spec) => Some(spec),
                Err(e) => {
                    tracing::warn!(domain = %domain, error = %e, "no ACME certificate for this domain");
                    None
                }
            })
            .collect())
    }
}

/// Whole days left, rounded down; `0` once expired.
fn days_left(now: SystemTime, not_after: SystemTime) -> u64 {
    not_after
        .duration_since(now)
        .map_or(0, |left| left.as_secs() / DAY.as_secs())
}

/// The worker for the configured `[acme]` section, or `None` when it is absent or paused.
pub fn build<P: weglarka_core::podman::PodmanClient + 'static>(
    config: Option<&AcmeConfig>,
    paths: &Paths,
    webhook_domain: &str,
    events: Arc<dyn EventSink>,
    ingress: Arc<crate::ingress::IngressManager<P>>,
) -> Option<AcmeWorker<InstantAcme>> {
    let config = config.filter(|c| c.enabled)?;
    let client = InstantAcme::new(InstantAcmeSettings {
        directory_url: config.directory_url.clone(),
        contact_email: config.email.clone(),
        account_key: paths.acme_account_key.clone(),
        terms_agreed: config.accept_terms,
    });
    Some(AcmeWorker::new(
        client,
        config,
        Dirs {
            webroot: ingress.acme_dir(),
            tls: ingress.tls_dir(),
            apps: paths.state.apps.clone(),
        },
        webhook_domain.to_owned(),
        events,
        Box::new(move || ingress.request_apply()),
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use weglarka_acme::testing::FakeAcme;
    use weglarka_core::events::VecSink;

    use super::*;

    const DAYS: fn(u64) -> Duration = |d| Duration::from_secs(d * 24 * 3600);

    struct Rig {
        dir: tempfile::TempDir,
        worker: AcmeWorker<SharedFake>,
        sink: Arc<VecSink>,
        applies: Arc<AtomicUsize>,
        fake: SharedFake,
    }

    /// `FakeAcme` behind an `Arc` so the test keeps a handle to script and inspect it.
    #[derive(Clone)]
    struct SharedFake(Arc<FakeAcme>);

    impl AcmeClient for SharedFake {
        fn issue<S: weglarka_acme::ChallengeSolver>(
            &self,
            spec: &CertSpec,
            solver: &S,
        ) -> impl std::future::Future<
            Output = Result<weglarka_acme::Issued, weglarka_acme::AcmeError>,
        > + Send {
            self.0.issue(spec, solver)
        }
    }

    impl CertInspector for SharedFake {
        fn not_after(&self, chain: &[u8]) -> Result<SystemTime, weglarka_acme::AcmeError> {
            self.0.not_after(chain)
        }
    }

    fn rig(apps_toml: &str) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("acme")).unwrap();
        let apps_path = dir.path().join("apps.toml");
        std::fs::write(&apps_path, apps_toml).unwrap();
        let config = AcmeConfig {
            accept_terms: true,
            email: None,
            directory_url: AcmeConfig::LETS_ENCRYPT_STAGING.to_owned(),
            enabled: true,
            renew_before_days: 30,
            check_interval_secs: 3600,
        };
        let fake = SharedFake(Arc::new(FakeAcme::new(SystemTime::now() + DAYS(90))));
        let sink = Arc::new(VecSink::default());
        let applies = Arc::new(AtomicUsize::new(0));
        let worker = AcmeWorker::new(
            fake.clone(),
            &config,
            Dirs {
                webroot: dir.path().join("acme"),
                tls: dir.path().join("tls"),
                apps: apps_path,
            },
            "hook.example.eu".to_owned(),
            sink.clone(),
            Box::new({
                let applies = applies.clone();
                move || {
                    applies.fetch_add(1, Ordering::SeqCst);
                }
            }),
        );
        Rig {
            dir,
            worker,
            sink,
            applies,
            fake,
        }
    }

    #[tokio::test]
    async fn issues_for_every_routed_domain_once_and_asks_for_one_apply_per_change() {
        let rig = rig("");
        assert!(rig.worker.pass().await);
        let tls = rig.dir.path().join("tls");
        assert!(tls.join("hook.example.eu.crt").is_file());
        assert!(tls.join("hook.example.eu.key").is_file());
        assert_eq!(rig.applies.load(Ordering::SeqCst), 1);
        let events = rig.sink.events();
        assert!(matches!(
            events.as_slice(),
            [Event::CertificateIssued { cert, renewed: false, expires_in_days: 89 | 90 }]
                if cert == "hook.example.eu"
        ));

        // Nothing is due, so the second pass neither orders, emits nor applies.
        assert!(rig.worker.pass().await);
        assert_eq!(rig.fake.0.orders().len(), 1);
        assert_eq!(rig.applies.load(Ordering::SeqCst), 1);
        assert_eq!(rig.sink.events().len(), 1);
        let status = rig.worker.status().snapshot();
        assert!(status.last_pass.is_some() && status.failures.is_empty());
    }

    #[tokio::test]
    async fn a_failure_is_reported_critical_without_a_certificate_and_recorded_for_doctor() {
        let rig = rig("");
        rig.fake.0.fail_next("rate limited");
        assert!(!rig.worker.pass().await);
        let events = rig.sink.events();
        assert!(matches!(
            events.as_slice(),
            [Event::CertificateRenewalFailed { reason, expires_in_days: None, .. }]
                if reason.contains("rate limited")
        ));
        assert_eq!(
            events[0].severity(),
            weglarka_core::events::Severity::Critical
        );
        assert_eq!(rig.applies.load(Ordering::SeqCst), 0);
        let status = rig.worker.status().snapshot();
        assert_eq!(status.failures.len(), 1);
        assert_eq!(status.failures[0].0, "hook.example.eu");

        // The retry succeeds and clears the recorded failure.
        assert!(rig.worker.pass().await);
        assert!(rig.worker.status().snapshot().failures.is_empty());
    }

    #[tokio::test]
    async fn an_unreadable_apps_file_fails_the_pass_instead_of_guessing_the_domains() {
        let rig = rig("this is not toml = =");
        assert!(!rig.worker.pass().await);
        assert!(rig.fake.0.orders().is_empty());
        assert_eq!(rig.worker.status().snapshot().failures[0].0, "apps.toml");
    }
}
