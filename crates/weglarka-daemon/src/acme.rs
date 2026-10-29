//! The ACME worker: keeps one certificate per routed domain valid (issue #96,
//! `docs/decisions/0038-acme-engine-seams.md`) and, with `[acme.dns]`, one wildcard certificate per
//! configured apex over DNS-01 (issue #97, `docs/decisions/0039-acme-dns01.md`).
//!
//! Each pass takes the domains the ingress routes (the webhook domain plus every app domain), asks
//! [`weglarka_acme::Manager`] to issue or renew what is missing or inside the renewal window, emits
//! the resulting events and, when a file changed, asks the ingress to apply — it rescans `tls/` and
//! reloads nginx (`nginx -t` + SIGHUP), it never recreates the container (ADR 0036). The wildcard
//! certificates go through a second manager (same store, a DNS-01 solver); the ingress does not
//! serve them yet, so every routed domain keeps its own HTTP-01 certificate.

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use tokio::sync::watch;
use weglarka_acme::{
    AcmeClient, AcmeError, CertId, CertInspector, CertSpec, DnsSolver, Http01Solver, InstantAcme,
    InstantAcmeSettings, Manager, Outcome, PassReport,
};
use weglarka_dns::{Cloudflare, DnsError, DnsProvider, RecordHandle};
use weglarka_model::config::{
    AcmeConfig, AcmeDnsConfig, DnsProviderKind, WILDCARD_CERT_PREFIX, wildcard_covers,
};
use weglarka_model::events::{Event, EventSink};
use weglarka_model::secret_store::SecretValue;
use weglarka_model::state;

use crate::StartError;
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

/// The configured DNS host (`[acme.dns] provider`). A new provider is a variant here and in
/// [`DnsProviderKind`]; the worker only sees [`DnsProvider`].
pub enum DnsBackend {
    Cloudflare(Cloudflare),
}

impl DnsProvider for DnsBackend {
    async fn set_txt(&self, name: &str, value: &str) -> Result<RecordHandle, DnsError> {
        match self {
            Self::Cloudflare(cloudflare) => cloudflare.set_txt(name, value).await,
        }
    }

    async fn remove_txt(&self, handle: &RecordHandle) -> Result<(), DnsError> {
        match self {
            Self::Cloudflare(cloudflare) => cloudflare.remove_txt(handle).await,
        }
    }
}

/// The wildcard side of the worker: its own manager (a DNS-01 solver on the same store) and the
/// certificates it keeps.
struct DnsIssuer<C, P> {
    manager: Manager<C, DnsSolver<P>>,
    specs: Vec<CertSpec>,
    /// The apexes behind `specs`, to decide which domains a wildcard already covers.
    apexes: Vec<String>,
}

pub struct AcmeWorker<C, P = DnsBackend> {
    manager: Manager<C, Http01Solver>,
    dns: Option<DnsIssuer<C, P>>,
    tls: PathBuf,
    renew_before: Duration,
    apps_path: PathBuf,
    webhook_domain: String,
    events: Arc<dyn EventSink>,
    /// Asks the ingress to apply (rescan `tls/`, reload nginx).
    on_change: Box<dyn Fn() + Send + Sync>,
    status: Arc<AcmeStatus>,
    period: Duration,
}

impl<C: AcmeClient + CertInspector, P: DnsProvider> AcmeWorker<C, P> {
    pub fn new(
        client: C,
        config: &AcmeConfig,
        dirs: Dirs,
        webhook_domain: String,
        events: Arc<dyn EventSink>,
        on_change: Box<dyn Fn() + Send + Sync>,
    ) -> Self {
        let renew_before = Duration::from_secs(config.renew_before_days * DAY.as_secs());
        let manager = Manager::new(
            client,
            Http01Solver::new(dirs.webroot),
            weglarka_acme::CertStore::new(dirs.tls.clone()),
            renew_before,
        );
        Self {
            manager,
            dns: None,
            tls: dirs.tls,
            renew_before,
            apps_path: dirs.apps,
            webhook_domain,
            events,
            on_change,
            status: Arc::new(AcmeStatus::default()),
            period: Duration::from_secs(config.check_interval_secs),
        }
    }

    /// Adds a wildcard certificate (`*.<apex>` and `<apex>`, stored as `_wildcard.<apex>`) per
    /// apex, ordered over DNS-01 through `provider`. `client` is a second ACME client for the same
    /// account: a manager owns its client.
    pub fn with_dns(
        mut self,
        client: C,
        provider: P,
        wildcards: &[String],
        propagation: Duration,
    ) -> Result<Self, AcmeError> {
        let specs = wildcards
            .iter()
            .map(|apex| wildcard_spec(apex))
            .collect::<Result<Vec<_>, _>>()?;
        let manager = Manager::new(
            client,
            DnsSolver::new(provider, propagation),
            weglarka_acme::CertStore::new(self.tls.clone()),
            self.renew_before,
        );
        self.dns = Some(DnsIssuer {
            manager,
            specs,
            apexes: wildcards.to_vec(),
        });
        Ok(self)
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
        let now = SystemTime::now();
        let mut failures = Vec::new();
        let mut changed = false;
        // Wildcards first: a domain they cover needs no certificate of its own, and the domain
        // certificates below are decided by what is on disk after this step.
        if let Some(dns) = &self.dns {
            let report = dns.manager.pass(now, &dns.specs).await;
            changed |= report.changed();
            self.record(
                &report,
                now,
                |id| dns.manager.current_not_after(id),
                &mut failures,
            );
        }
        let specs = match self.specs(now) {
            Ok(specs) => specs,
            Err(e) => {
                tracing::error!(error = %e, "ACME pass skipped: cannot read apps.toml");
                failures.push(("apps.toml".into(), e));
                self.status.record(SystemTime::now(), failures);
                if changed {
                    (self.on_change)();
                }
                return false;
            }
        };
        let report = self.manager.pass(now, &specs).await;
        changed |= report.changed();
        self.record(
            &report,
            now,
            |id| self.manager.current_not_after(id),
            &mut failures,
        );
        if changed {
            (self.on_change)();
        }
        let all_ok = failures.is_empty();
        self.status.record(SystemTime::now(), failures);
        all_ok
    }

    /// Emits the event of every outcome of one manager's pass and collects its failures.
    fn record(
        &self,
        report: &PassReport,
        now: SystemTime,
        current_not_after: impl Fn(&CertId) -> Option<SystemTime>,
        failures: &mut Vec<(String, String)>,
    ) {
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
                        expires_in_days: current_not_after(id)
                            .map(|not_after| days_left(now, not_after)),
                    });
                    failures.push((cert, reason));
                }
            }
        }
    }

    /// One single-name certificate per routed domain, except a domain that has no certificate of its
    /// own and is covered by a valid wildcard on disk (it is served with the wildcard, issue #97). A
    /// domain that already has its own certificate keeps being renewed — nginx prefers it, so letting
    /// it expire would serve an expired certificate — and a failed or missing wildcard falls back to
    /// per-domain issuance. A name that cannot be a public DNS name (nothing an ACME CA would sign)
    /// is skipped with a warning.
    fn specs(&self, now: SystemTime) -> Result<Vec<CertSpec>, String> {
        let apps = state::load_apps(&self.apps_path).map_err(|e| e.to_string())?;
        let mut domains = vec![self.webhook_domain.clone()];
        for spec in apps.apps.values() {
            domains.extend(spec.domains.iter().cloned());
        }
        domains.sort();
        domains.dedup();
        // Apexes whose wildcard certificate is on disk and unexpired, judged by the same inspector
        // that decides renewals.
        let covering: Vec<&str> = self
            .dns
            .iter()
            .flat_map(|dns| {
                dns.apexes
                    .iter()
                    .zip(&dns.specs)
                    .filter(|(_, spec)| {
                        dns.manager
                            .current_not_after(spec.id())
                            .is_some_and(|not_after| not_after > now)
                    })
                    .map(|(apex, _)| apex.as_str())
            })
            .collect();
        Ok(domains
            .iter()
            .filter(|domain| {
                let own = self.tls.join(format!("{domain}.crt")).exists();
                let covered = !own && covering.iter().any(|apex| wildcard_covers(apex, domain));
                if covered {
                    tracing::debug!(%domain, "served by a wildcard certificate, no certificate of its own");
                }
                !covered
            })
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

/// `notAfter` of a PEM chain; the production reader for [`covering_wildcard`] and `certificates::collect`.
pub(crate) fn real_not_after(chain: &[u8]) -> Option<SystemTime> {
    weglarka_acme::chain_not_after(chain).ok()
}

/// The apex of the first wildcard certificate that covers `domain`, is on disk and is unexpired
/// (`tls/_wildcard.<apex>.crt`): the domain then needs no certificate of its own. `not_after` reads
/// the expiry of a chain (a parameter so tests need no real x509).
pub(crate) fn covering_wildcard(
    tls: &Path,
    apexes: &[String],
    domain: &str,
    now: SystemTime,
    not_after: &dyn Fn(&[u8]) -> Option<SystemTime>,
) -> Option<String> {
    apexes
        .iter()
        .filter(|apex| wildcard_covers(apex, domain))
        .find(|apex| {
            std::fs::read(tls.join(format!("{WILDCARD_CERT_PREFIX}{apex}.crt")))
                .ok()
                .and_then(|chain| not_after(&chain))
                .is_some_and(|not_after| not_after > now)
        })
        .cloned()
}

/// `*.<apex>` plus `<apex>` in one certificate, stored under the id `_wildcard.<apex>` (a literal
/// `*` never reaches a file name, ADR 0038).
fn wildcard_spec(apex: &str) -> Result<CertSpec, AcmeError> {
    CertSpec::new(
        CertId::new(weglarka_model::config::wildcard_cert_stem(apex))?,
        vec![format!("*.{apex}"), apex.to_owned()],
    )
}

/// Reads the DNS API token: a 0600 file whose trailing newline is dropped, printable ASCII only (it
/// becomes an `Authorization` header). The value never appears in an error.
fn read_token(path: &Path) -> Result<SecretValue, String> {
    let fail = |what: &str| format!("[acme.dns] token_file {}: {what}", path.display());
    let metadata = std::fs::metadata(path).map_err(|e| fail(&e.to_string()))?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(fail(
            "must not be accessible by group or others (chmod 600)",
        ));
    }
    let raw = std::fs::read_to_string(path).map_err(|e| fail(&e.to_string()))?;
    let token = raw.trim_end_matches(['\r', '\n']);
    if token.is_empty() {
        return Err(fail("is empty"));
    }
    if !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(fail("has characters that cannot go into an HTTP header"));
    }
    Ok(SecretValue::new(token))
}

/// The provider named by `[acme.dns]`, with its token read from the file.
fn dns_backend(config: &AcmeDnsConfig) -> Result<DnsBackend, String> {
    let token = read_token(&config.token_file)?;
    match config.provider {
        DnsProviderKind::Cloudflare => Cloudflare::new(&token)
            .map(DnsBackend::Cloudflare)
            .map_err(|e| format!("[acme.dns] {e}")),
    }
}

/// Whole days left, rounded down; `0` once expired.
fn days_left(now: SystemTime, not_after: SystemTime) -> u64 {
    not_after
        .duration_since(now)
        .map_or(0, |left| left.as_secs() / DAY.as_secs())
}

/// The worker for the configured `[acme]` section, or `None` when it is absent or paused. An
/// unusable `[acme.dns]` (unreadable or world-readable token file) is a startup error: wildcard
/// certificates are opt-in, but once configured a silent skip would hide a broken deployment.
pub fn build<P: weglarka_model::podman::PodmanClient + 'static>(
    config: Option<&AcmeConfig>,
    paths: &Paths,
    webhook_domain: &str,
    events: Arc<dyn EventSink>,
    ingress: Arc<crate::ingress::IngressManager<P>>,
) -> Result<Option<AcmeWorker<InstantAcme>>, StartError> {
    let Some(config) = config.filter(|c| c.enabled) else {
        return Ok(None);
    };
    let client = || {
        InstantAcme::new(InstantAcmeSettings {
            directory_url: config.directory_url.clone(),
            contact_email: config.email.clone(),
            account_key: paths.acme_account_key.clone(),
            terms_agreed: config.accept_terms,
        })
    };
    let mut worker = AcmeWorker::new(
        client(),
        config,
        Dirs {
            webroot: ingress.acme_dir(),
            tls: ingress.tls_dir(),
            apps: paths.state.apps.clone(),
        },
        webhook_domain.to_owned(),
        events,
        Box::new(move || ingress.request_apply()),
    );
    if let Some(dns) = &config.dns {
        let backend = dns_backend(dns).map_err(StartError::Acme)?;
        worker = worker
            .with_dns(
                client(),
                backend,
                &dns.wildcards,
                Duration::from_secs(dns.propagation_secs),
            )
            .map_err(|e| StartError::Acme(format!("[acme.dns] {e}")))?;
    }
    Ok(Some(worker))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use weglarka_acme::testing::FakeAcme;
    use weglarka_dns::testing::FakeDns;
    use weglarka_model::events::VecSink;

    use super::*;

    const DAYS: fn(u64) -> Duration = |d| Duration::from_secs(d * 24 * 3600);

    struct Rig {
        dir: tempfile::TempDir,
        worker: AcmeWorker<SharedFake, SharedDns>,
        sink: Arc<VecSink>,
        applies: Arc<AtomicUsize>,
        fake: SharedFake,
        dns: Arc<FakeDns>,
    }

    /// `FakeDns` behind an `Arc`, for the same reason as [`SharedFake`].
    struct SharedDns(Arc<FakeDns>);

    impl DnsProvider for SharedDns {
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
        rig_with_wildcards(apps_toml, &[])
    }

    fn rig_with_wildcards(apps_toml: &str, wildcards: &[&str]) -> Rig {
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
            dns: None,
        };
        let fake = SharedFake(Arc::new(FakeAcme::new(SystemTime::now() + DAYS(90))));
        let sink = Arc::new(VecSink::default());
        let applies = Arc::new(AtomicUsize::new(0));
        let dns = Arc::new(FakeDns::new());
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
        let worker = if wildcards.is_empty() {
            worker
        } else {
            let apexes: Vec<String> = wildcards.iter().map(|w| (*w).to_owned()).collect();
            worker
                .with_dns(
                    fake.clone(),
                    SharedDns(dns.clone()),
                    &apexes,
                    Duration::ZERO,
                )
                .unwrap()
        };
        Rig {
            dir,
            worker,
            sink,
            applies,
            fake,
            dns,
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
            weglarka_model::events::Severity::Critical
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

    const APPS: &str = "[apps.blog]\nimage = \"ghcr.io/example/blog:latest\"\n\
        domains = [\"blog.example.eu\", \"www.blog.example.eu\", \"site.example.org\"]\n";

    fn certs_on_disk(rig: &Rig) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(rig.dir.path().join("tls"))
            .map(|dir| {
                dir.map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                    .filter(|n| n.ends_with(".crt"))
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    #[tokio::test]
    async fn a_wildcard_replaces_the_certificates_of_the_domains_it_covers() {
        let rig = rig_with_wildcards(APPS, &["example.eu"]);
        assert!(rig.worker.pass().await);
        // The webhook domain and `blog.example.eu` are covered (one label below the apex) and get no
        // certificate of their own; `www.blog.example.eu` (two labels) and the other apex still do.
        assert_eq!(
            certs_on_disk(&rig),
            [
                "_wildcard.example.eu.crt",
                "site.example.org.crt",
                "www.blog.example.eu.crt"
            ]
        );
        assert!(
            rig.dir
                .path()
                .join("tls/_wildcard.example.eu.key")
                .is_file()
        );
        let orders = rig.fake.0.orders();
        assert_eq!(orders.len(), 3, "{orders:?}");
        assert_eq!(
            orders[0].as_str(),
            "_wildcard.example.eu",
            "wildcards go first"
        );
        // The TXT records of both names (apex and wildcard) were published and removed again.
        let sets = rig
            .dns
            .calls()
            .into_iter()
            .filter(|c| matches!(c, weglarka_dns::testing::Call::Set { .. }))
            .count();
        assert_eq!(sets, 2);
        assert!(rig.dns.records().is_empty());
        // One apply for the whole pass, one event per certificate.
        assert_eq!(rig.applies.load(Ordering::SeqCst), 1);
        assert_eq!(rig.sink.events().len(), 3);

        // Nothing is due on the second pass.
        assert!(rig.worker.pass().await);
        assert_eq!(rig.fake.0.orders().len(), 3);
        assert_eq!(rig.applies.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_domain_with_its_own_certificate_keeps_being_renewed_next_to_a_wildcard() {
        let rig = rig_with_wildcards(APPS, &["example.eu"]);
        // `blog.example.eu` already has a (soon expiring) certificate of its own: nginx prefers it
        // over the wildcard, so it must not be left to expire.
        let tls = rig.dir.path().join("tls");
        std::fs::create_dir_all(&tls).unwrap();
        let soon = FakeAcme::chain_expiring_at(SystemTime::now() + DAYS(5));
        std::fs::write(tls.join("blog.example.eu.crt"), soon).unwrap();
        std::fs::write(tls.join("blog.example.eu.key"), "old").unwrap();
        assert!(rig.worker.pass().await);
        let orders: Vec<String> = rig
            .fake
            .0
            .orders()
            .iter()
            .map(|id| id.to_string())
            .collect();
        assert!(orders.contains(&"blog.example.eu".to_owned()), "{orders:?}");
    }

    #[tokio::test]
    async fn a_failed_wildcard_falls_back_to_a_certificate_per_domain() {
        let rig = rig_with_wildcards(APPS, &["example.eu"]);
        // The wildcard order goes first and fails: nothing covers the domains yet.
        rig.fake.0.fail_next("DNS propagation timed out");
        assert!(!rig.worker.pass().await);
        assert_eq!(
            certs_on_disk(&rig),
            [
                "blog.example.eu.crt",
                "hook.example.eu.crt",
                "site.example.org.crt",
                "www.blog.example.eu.crt"
            ]
        );
        let status = rig.worker.status().snapshot();
        assert_eq!(status.failures.len(), 1);
        assert_eq!(status.failures[0].0, "_wildcard.example.eu");
        assert!(
            rig.dns.records().is_empty(),
            "cleanup also ran after the failure"
        );
        assert_eq!(
            rig.applies.load(Ordering::SeqCst),
            1,
            "the issued certificates are applied"
        );
    }

    #[test]
    fn the_token_file_must_be_private_and_clean() {
        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, content: &[u8], mode: u32| {
            let path = dir.path().join(name);
            std::fs::write(&path, content).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            path
        };
        let ok = read_token(&write("ok", b"cf-token\n", 0o600)).unwrap();
        assert_eq!(ok.expose(), b"cf-token");
        for (name, content, mode, expect) in [
            ("open", &b"cf-token"[..], 0o644, "chmod 600"),
            ("empty", b"\n", 0o600, "is empty"),
            ("spaced", b"two words", 0o600, "HTTP header"),
            ("multiline", b"a\nb", 0o600, "HTTP header"),
        ] {
            let err = read_token(&write(name, content, mode)).unwrap_err();
            assert!(err.contains(expect), "{name}: {err}");
            assert!(
                !err.contains("cf-token") && !err.contains("two words"),
                "{err}"
            );
        }
        assert!(read_token(&dir.path().join("missing")).is_err());
    }

    #[test]
    fn a_bad_wildcard_apex_is_refused_before_the_worker_starts() {
        let rig = rig("");
        let err = rig.worker.with_dns(
            rig.fake.clone(),
            SharedDns(rig.dns.clone()),
            &["Not A Domain".into()],
            Duration::ZERO,
        );
        assert!(err.is_err());
    }
}
