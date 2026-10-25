//! Opt-in end-to-end test against Let's Encrypt **staging** (issue #96).
//!
//! HTTP-01 needs a public port 80 that serves `WEGLARKA_ACME_STAGING_WEBROOT` at
//! `/.well-known/acme-challenge/` for `WEGLARKA_ACME_STAGING_DOMAIN`, so this cannot run on a plain CI
//! runner. Without both variables the test prints a note and returns (same convention as
//! `WEGLARKA_PODMAN_SOCKET` in `weglarka-podman`).

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use weglarka_acme::renewal::DEFAULT_RENEW_BEFORE;
use weglarka_acme::{
    CertSpec, CertStore, Http01Solver, InstantAcme, InstantAcmeSettings, Manager, Outcome,
};

const STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

#[tokio::test]
async fn issues_a_certificate_from_lets_encrypt_staging() {
    let (Some(domain), Some(webroot)) = (
        env("WEGLARKA_ACME_STAGING_DOMAIN"),
        env("WEGLARKA_ACME_STAGING_WEBROOT"),
    ) else {
        eprintln!("WEGLARKA_ACME_STAGING_DOMAIN/_WEBROOT not set — skipping staging test");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let client = InstantAcme::new(InstantAcmeSettings {
        directory_url: env("WEGLARKA_ACME_STAGING_DIRECTORY").unwrap_or_else(|| STAGING.into()),
        contact_email: env("WEGLARKA_ACME_STAGING_EMAIL"),
        account_key: dir.path().join("acme/account.key"),
        terms_agreed: true,
    });
    let store = CertStore::new(dir.path().join("tls"));
    let manager = Manager::new(
        client,
        Http01Solver::new(PathBuf::from(webroot)),
        store.clone(),
        DEFAULT_RENEW_BEFORE,
    );
    let spec = CertSpec::single(&domain).unwrap();

    let report = manager
        .pass(SystemTime::now(), std::slice::from_ref(&spec))
        .await;
    let Outcome::Issued { not_after } = &report.outcomes[0].1 else {
        panic!(
            "expected an issued certificate, got {:?}",
            report.outcomes[0].1
        );
    };
    assert!(*not_after > SystemTime::now() + Duration::from_secs(24 * 3600));
    assert!(store.read_chain(spec.id()).unwrap().is_some());

    // A second pass finds the fresh certificate valid and orders nothing.
    let again = manager.pass(SystemTime::now(), &[spec]).await;
    assert!(matches!(again.outcomes[0].1, Outcome::Valid { .. }));
}
