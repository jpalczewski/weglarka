//! `GET /v1/certificates` (`read` scope): expiry of every certificate the ACME worker looks after.
//!
//! [`collect`] is the single reader of `tls/`: the endpoint renders its rows and `doctor`'s `acme.*`
//! checks judge the same rows, so the two cannot disagree. Only `notAfter` is read from a chain —
//! key files, the account key and the DNS token file are never opened here.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use weglarka_api::{CertStatus, CertificateRecord, CertificatesResponse, endpoints};
use weglarka_model::config::{AcmeConfig, wildcard_cert_stem};
use weglarka_model::podman::PodmanClient;

use crate::admin::Fail;
use crate::app::Daemon;
use crate::events::rfc3339;

type Shared<P> = State<Arc<Daemon<P>>>;

const DAY_SECS: i64 = 24 * 3600;

pub fn routes<P: PodmanClient + 'static>() -> Router<Arc<Daemon<P>>> {
    Router::new().route(endpoints::CERTIFICATES.path, get(list::<P>))
}

/// One certificate on disk, or one routed domain that a wildcard serves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Cert {
    pub id: String,
    pub names: Vec<String>,
    pub wildcard: bool,
    /// `notAfter` of the chain; `None` = no readable certificate of its own.
    pub not_after: Option<SystemTime>,
    /// For a domain without a certificate of its own: the wildcard apex that serves it.
    pub covered_by: Option<String>,
}

impl Cert {
    /// The name `doctor` prints: the domain, or `*.<apex>`.
    pub fn label(&self) -> &str {
        &self.names[0]
    }

    /// Own `notAfter` first: an expired certificate of its own is reported even next to a wildcard.
    pub fn status(&self, now: SystemTime, window: Duration) -> CertStatus {
        match self.not_after {
            Some(at) => match at.duration_since(now) {
                Err(_) => CertStatus::Expired,
                Ok(left) if left <= window => CertStatus::RenewalDue,
                Ok(_) => CertStatus::Valid,
            },
            None if self.covered_by.is_some() => CertStatus::Covered,
            None => CertStatus::Missing,
        }
    }

    /// Whole days left (negative once expired), rounded down.
    pub fn days_left(&self, now: SystemTime) -> Option<i64> {
        let at = self.not_after?;
        let secs = |t: SystemTime| {
            t.duration_since(UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        };
        Some((secs(at) - secs(now)).div_euclid(DAY_SECS))
    }
}

/// The renewal window as a duration.
pub(crate) fn window(config: &AcmeConfig) -> Duration {
    Duration::from_secs(config.renew_before_days.saturating_mul(24 * 3600))
}

/// Domains the ingress routes: the webhook domain and every app domain. `None` when `apps.toml`
/// cannot be read (`doctor`'s `state.apps` reports that).
pub(crate) fn routed_domains<P: PodmanClient>(d: &Daemon<P>) -> Option<Vec<String>> {
    let apps = weglarka_model::state::load_apps(&d.paths.state.apps).ok()?;
    let mut domains: Vec<String> = vec![d.host.webhook.domain.clone()];
    for spec in apps.apps.values() {
        domains.extend(spec.domains.iter().cloned());
    }
    domains.sort();
    domains.dedup();
    Some(domains)
}

/// One row per routed domain, then one per `[acme.dns]` wildcard.
pub(crate) fn collect(
    tls: &Path,
    config: &AcmeConfig,
    domains: &[String],
    now: SystemTime,
) -> Vec<Cert> {
    collect_with(tls, config, domains, now, &crate::acme::real_not_after)
}

/// [`collect`] with the reader of a chain's `notAfter` injected.
fn collect_with(
    tls: &Path,
    config: &AcmeConfig,
    domains: &[String],
    now: SystemTime,
    not_after: &dyn Fn(&[u8]) -> Option<SystemTime>,
) -> Vec<Cert> {
    let read = |stem: &str| std::fs::read(tls.join(format!("{stem}.crt"))).ok();
    let apexes: &[String] = config.dns.as_ref().map_or(&[], |dns| &dns.wildcards);
    let mut certs = Vec::new();
    for domain in domains {
        // Without a readable file of its own a valid wildcard may serve it (issue #97); an
        // unparseable file of its own is just missing.
        let chain = read(domain);
        let covered_by = if chain.is_none() {
            crate::acme::covering_wildcard(tls, apexes, domain, now, not_after)
        } else {
            None
        };
        certs.push(Cert {
            id: domain.clone(),
            names: vec![domain.clone()],
            wildcard: false,
            not_after: chain.and_then(|chain| not_after(&chain)),
            covered_by,
        });
    }
    for apex in apexes {
        let stem = wildcard_cert_stem(apex);
        certs.push(Cert {
            names: vec![format!("*.{apex}"), apex.clone()],
            not_after: read(&stem).and_then(|chain| not_after(&chain)),
            id: stem,
            wildcard: true,
            covered_by: None,
        });
    }
    certs
}

async fn list<P: PodmanClient + 'static>(State(d): Shared<P>) -> Result<Response, Fail> {
    let status = d.acme.as_ref().map(|s| s.snapshot()).unwrap_or_default();
    let Some(config) = d.host.acme.as_ref().filter(|c| c.enabled) else {
        return Ok(axum::Json(CertificatesResponse::default()).into_response());
    };
    let domains = routed_domains(&d).ok_or_else(|| Fail::internal("apps.toml cannot be read"))?;
    let now = SystemTime::now();
    let window = window(config);
    let certificates: Vec<CertificateRecord> = collect(&d.ingress.tls_dir(), config, &domains, now)
        .into_iter()
        .map(|cert| CertificateRecord {
            status: cert.status(now, window),
            not_after: cert.not_after.map(rfc3339),
            days_left: cert.days_left(now),
            covered_by: cert.covered_by.as_ref().map(|apex| format!("*.{apex}")),
            failed: status.failures.iter().any(|(id, _)| *id == cert.id),
            id: cert.id,
            names: cert.names,
            wildcard: cert.wildcard,
        })
        .collect();
    Ok(axum::Json(CertificatesResponse {
        acme_enabled: true,
        renew_before_days: Some(config.renew_before_days),
        last_pass: status.last_pass.map(rfc3339),
        failures: u32::try_from(certificates.iter().filter(|c| c.failed).count())
            .unwrap_or(u32::MAX),
        certificates,
    })
    .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use weglarka_acme::testing::FakeAcme;
    use weglarka_model::config::HostConfig;

    const DAY: Duration = Duration::from_secs(24 * 3600);

    fn config(dns: &str) -> AcmeConfig {
        let toml = format!(
            "[ingress]\nmode = \"edge\"\nbind = \"0.0.0.0:80\"\nhttps_bind = \"0.0.0.0:443\"\n\
             [admin]\nsocket = \"/run/a.sock\"\n[webhook]\nlisten = \"127.0.0.1:0\"\n\
             domain = \"hooks.example.com\"\n[acme]\naccept_terms = true\nrenew_before_days = 30\n{dns}"
        );
        HostConfig::from_toml_str(&toml).unwrap().acme.unwrap()
    }

    fn write(tls: &Path, stem: &str, not_after: SystemTime) {
        std::fs::write(
            tls.join(format!("{stem}.crt")),
            FakeAcme::chain_expiring_at(not_after),
        )
        .unwrap();
    }

    /// Reads the expiry of the chains `FakeAcme` writes (`FAKE-CERT not_after=<secs>`).
    fn fake_not_after(chain: &[u8]) -> Option<SystemTime> {
        let text = std::str::from_utf8(chain).ok()?;
        let secs = text.strip_prefix("FAKE-CERT not_after=")?.parse().ok()?;
        Some(UNIX_EPOCH + Duration::from_secs(secs))
    }

    fn by_id<'a>(certs: &'a [Cert], id: &str) -> &'a Cert {
        certs.iter().find(|c| c.id == id).unwrap()
    }

    #[test]
    fn expiring_expired_valid_and_missing_certificates_are_told_apart() {
        let dir = tempfile::tempdir().unwrap();
        let now = SystemTime::now();
        write(dir.path(), "soon.example.com", now + 10 * DAY);
        write(dir.path(), "old.example.com", now - 3 * DAY);
        write(dir.path(), "fine.example.com", now + 80 * DAY);
        std::fs::write(dir.path().join("junk.example.com.crt"), "not a pem").unwrap();
        let config = config("");
        let domains = ["soon", "old", "fine", "junk", "none"]
            .map(|n| format!("{n}.example.com"))
            .to_vec();
        let certs = collect_with(dir.path(), &config, &domains, now, &fake_not_after);
        let w = window(&config);
        let status = |id: &str| by_id(&certs, id).status(now, w);
        assert_eq!(status("soon.example.com"), CertStatus::RenewalDue);
        assert_eq!(status("old.example.com"), CertStatus::Expired);
        assert_eq!(status("fine.example.com"), CertStatus::Valid);
        assert_eq!(status("junk.example.com"), CertStatus::Missing);
        assert_eq!(status("none.example.com"), CertStatus::Missing);
        assert_eq!(by_id(&certs, "soon.example.com").days_left(now), Some(10));
        assert_eq!(by_id(&certs, "old.example.com").days_left(now), Some(-3));
        assert_eq!(by_id(&certs, "none.example.com").days_left(now), None);
    }

    #[test]
    fn a_valid_wildcard_serves_a_domain_without_a_certificate_of_its_own() {
        let dir = tempfile::tempdir().unwrap();
        let now = SystemTime::now();
        write(dir.path(), "_wildcard.example.com", now + 60 * DAY);
        write(dir.path(), "own.example.com", now - DAY);
        let config = config(
            "[acme.dns]\nprovider = \"cloudflare\"\ntoken_file = \"/t\"\nwildcards = [\"example.com\"]\n",
        );
        let domains = vec!["app.example.com".to_owned(), "own.example.com".to_owned()];
        let certs = collect_with(dir.path(), &config, &domains, now, &fake_not_after);
        let w = window(&config);
        let app = by_id(&certs, "app.example.com");
        assert_eq!(app.status(now, w), CertStatus::Covered);
        assert_eq!(app.covered_by.as_deref(), Some("example.com"));
        // An expired certificate of its own is reported even though the wildcard would serve it.
        assert_eq!(
            by_id(&certs, "own.example.com").status(now, w),
            CertStatus::Expired
        );
        let wildcard = by_id(&certs, "_wildcard.example.com");
        assert!(wildcard.wildcard);
        assert_eq!(wildcard.names, ["*.example.com", "example.com"]);
        assert_eq!(wildcard.status(now, w), CertStatus::Valid);
    }

    #[test]
    fn an_expired_wildcard_covers_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let now = SystemTime::now();
        write(dir.path(), "_wildcard.example.com", now - DAY);
        let config = config(
            "[acme.dns]\nprovider = \"cloudflare\"\ntoken_file = \"/t\"\nwildcards = [\"example.com\"]\n",
        );
        let certs = collect_with(
            dir.path(),
            &config,
            &["app.example.com".to_owned()],
            now,
            &fake_not_after,
        );
        let w = window(&config);
        assert_eq!(
            by_id(&certs, "app.example.com").status(now, w),
            CertStatus::Missing
        );
        assert_eq!(
            by_id(&certs, "_wildcard.example.com").status(now, w),
            CertStatus::Expired
        );
    }

    #[test]
    fn nothing_routed_and_no_wildcards_is_an_empty_list() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            collect_with(
                dir.path(),
                &config(""),
                &[],
                SystemTime::now(),
                &fake_not_after
            )
            .is_empty()
        );
    }
}
