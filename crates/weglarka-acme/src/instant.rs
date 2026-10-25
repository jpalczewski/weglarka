//! The real [`AcmeClient`]: orders certificates from an ACME CA through `instant-acme`.
//!
//! TLS is `ring` with the bundled Mozilla roots (`webpki-roots`) because the daemon image is
//! `scratch` and has no CA store (docs/decisions/0021); the crate's default platform verifier is
//! deliberately not used. The account is created on first use and its credentials (which contain
//! the account private key) are kept in a `0600` file outside the webroot and `tls/`.

use std::fmt::Write as _;
use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, HttpClient, Identifier,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use rustls::{ClientConfig, RootCertStore};
use tokio::sync::OnceCell;
use weglarka_core::state::write_atomic;

use crate::cert::{CertSpec, Issued, PrivateKeyPem};
use crate::client::{AcmeClient, CertInspector};
use crate::error::AcmeError;
use crate::solver::{Challenge, ChallengeKind, ChallengeSolver};

const ACCOUNT_KEY_MODE: u32 = 0o600;
const ACCOUNT_DIR_MODE: u32 = 0o700;
/// Upper bound for the CA to validate challenges and to issue the certificate.
const ORDER_TIMEOUT: Duration = Duration::from_secs(120);

/// Where and how to talk to the CA.
#[derive(Debug, Clone)]
pub struct InstantAcmeSettings {
    /// ACME directory URL (Let's Encrypt production or staging).
    pub directory_url: String,
    /// Contact address for expiry notices, without the `mailto:` scheme.
    pub contact_email: Option<String>,
    /// File holding the account credentials (`0600`); created on first use.
    pub account_key: PathBuf,
    /// The operator accepted the CA's terms of service; account creation is refused otherwise.
    pub terms_agreed: bool,
}

/// [`AcmeClient`] over `instant-acme`; also the production [`CertInspector`].
pub struct InstantAcme {
    settings: InstantAcmeSettings,
    account: OnceCell<Account>,
}

impl std::fmt::Debug for InstantAcme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstantAcme")
            .field("directory_url", &self.settings.directory_url)
            .finish_non_exhaustive()
    }
}

impl InstantAcme {
    pub fn new(settings: InstantAcmeSettings) -> Self {
        Self {
            settings,
            account: OnceCell::new(),
        }
    }

    async fn account(&self) -> Result<&Account, AcmeError> {
        self.account.get_or_try_init(|| self.load_or_create()).await
    }

    async fn load_or_create(&self) -> Result<Account, AcmeError> {
        let path = &self.settings.account_key;
        let io_err = |source| AcmeError::Io {
            path: path.clone(),
            source,
        };
        match fs::read(path) {
            Ok(bytes) => {
                let mode = fs::metadata(path).map_err(io_err)?.permissions().mode();
                if mode & 0o077 != 0 {
                    return Err(AcmeError::AccountKey(format!(
                        "{} must not be accessible by group or others (mode {:o})",
                        path.display(),
                        mode & 0o777
                    )));
                }
                let credentials: AccountCredentials = serde_json::from_slice(&bytes)
                    .map_err(|_| AcmeError::AccountKey("not a valid credentials file".into()))?;
                Account::builder_with_http(http_client()?)
                    .from_credentials(credentials)
                    .await
                    .map_err(order_err)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => self.create_account().await,
            Err(e) => Err(io_err(e)),
        }
    }

    async fn create_account(&self) -> Result<Account, AcmeError> {
        if !self.settings.terms_agreed {
            return Err(AcmeError::AccountKey(
                "the CA's terms of service have not been accepted".into(),
            ));
        }
        let path = &self.settings.account_key;
        let contact = self
            .settings
            .contact_email
            .as_ref()
            .map(|email| format!("mailto:{email}"));
        let contacts: Vec<&str> = contact.iter().map(String::as_str).collect();
        let (account, credentials) = Account::builder_with_http(http_client()?)
            .create(
                &NewAccount {
                    contact: &contacts,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                self.settings.directory_url.clone(),
                None,
            )
            .await
            .map_err(order_err)?;
        let bytes = serde_json::to_vec(&credentials)
            .map_err(|_| AcmeError::AccountKey("cannot serialize the credentials".into()))?;
        let io_err = |source| AcmeError::Io {
            path: path.clone(),
            source,
        };
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(ACCOUNT_DIR_MODE)
                .create(dir)
                .map_err(io_err)?;
        }
        write_atomic(path, &bytes, ACCOUNT_KEY_MODE).map_err(io_err)?;
        tracing::info!(directory = %self.settings.directory_url, "ACME account created");
        Ok(account)
    }
}

impl AcmeClient for InstantAcme {
    async fn issue<S: ChallengeSolver>(
        &self,
        spec: &CertSpec,
        solver: &S,
    ) -> Result<Issued, AcmeError> {
        let account = self.account().await?;
        let identifiers: Vec<Identifier> = spec
            .names()
            .iter()
            .map(|n| Identifier::Dns(n.clone()))
            .collect();
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .map_err(order_err)?;

        let mut presented = Vec::new();
        let result = drive(&mut order, solver, &mut presented).await;
        // Cleanup runs on every path; its own failure never masks the order result.
        for challenge in &presented {
            if let Err(e) = solver.cleanup(challenge).await {
                tracing::warn!(name = %challenge.name(), error = %e, "challenge cleanup failed");
            }
        }
        let (chain_pem, key_pem) = result?;
        let not_after = chain_not_after(chain_pem.as_bytes())?;
        Ok(Issued {
            chain_pem: chain_pem.into_bytes(),
            key: PrivateKeyPem::new(key_pem.into_bytes()),
            not_after,
        })
    }
}

impl CertInspector for InstantAcme {
    fn not_after(&self, chain_pem: &[u8]) -> Result<SystemTime, AcmeError> {
        chain_not_after(chain_pem)
    }
}

/// Presents every pending challenge, waits for validation, finalizes and downloads the chain.
/// Challenges are recorded in `presented` as soon as they are presented, for the caller's cleanup.
async fn drive<S: ChallengeSolver>(
    order: &mut instant_acme::Order,
    solver: &S,
    presented: &mut Vec<Challenge>,
) -> Result<(String, String), AcmeError> {
    let wanted = match solver.kind() {
        ChallengeKind::Http01 => ChallengeType::Http01,
        ChallengeKind::Dns01 => ChallengeType::Dns01,
    };
    // Present every challenge first, let the answers settle, and only then ask the CA to validate:
    // it checks once, so a record that is not visible yet fails the whole order.
    let mut authorizations = order.authorizations();
    while let Some(next) = authorizations.next().await {
        let mut authz = next.map_err(order_err)?;
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            other => return Err(AcmeError::Order(format!("authorization is {other:?}"))),
        }
        let handle = authz.challenge(wanted.clone()).ok_or_else(|| {
            AcmeError::Order(format!(
                "the CA offers no {} challenge for this name",
                solver.kind().as_str()
            ))
        })?;
        let challenge = Challenge::new(
            &handle.identifier().to_string(),
            handle.token.clone(),
            handle.key_authorization().as_str().to_owned(),
        );
        solver.present(&challenge).await?;
        presented.push(challenge);
    }
    solver.settle().await;
    let mut authorizations = order.authorizations();
    while let Some(next) = authorizations.next().await {
        let mut authz = next.map_err(order_err)?;
        if authz.status != AuthorizationStatus::Pending {
            continue;
        }
        if let Some(mut handle) = authz.challenge(wanted.clone()) {
            handle.set_ready().await.map_err(order_err)?;
        }
    }
    let policy = RetryPolicy::new().timeout(ORDER_TIMEOUT);
    let status = order.poll_ready(&policy).await.map_err(order_err)?;
    if status != OrderStatus::Ready {
        let why = challenge_failures(order, &wanted).await;
        return Err(AcmeError::Order(format!("order ended as {status:?}{why}")));
    }
    let key_pem = order.finalize().await.map_err(order_err)?;
    let chain_pem = order.poll_certificate(&policy).await.map_err(order_err)?;
    Ok((chain_pem, key_pem))
}

/// Why the CA rejected the challenges of a failed order, as `"; <name>: <detail>"` pieces (empty when
/// the CA gave no reason or the authorizations cannot be fetched again).
async fn challenge_failures(order: &mut instant_acme::Order, wanted: &ChallengeType) -> String {
    let mut out = String::new();
    let mut authorizations = order.authorizations();
    while let Some(Ok(authz)) = authorizations.next().await {
        for problem in authz
            .challenges
            .iter()
            .filter(|c| c.r#type == *wanted)
            .filter_map(|c| c.error.as_ref())
        {
            let _ = write!(
                out,
                "; {}: {}",
                authz.identifier(),
                problem.detail.as_deref().unwrap_or("no detail")
            );
        }
    }
    out
}

/// `notAfter` of the first (leaf) certificate of a PEM chain.
pub fn chain_not_after(chain_pem: &[u8]) -> Result<SystemTime, AcmeError> {
    let expiry = |e: &dyn std::fmt::Display| AcmeError::Expiry(e.to_string());
    let (_, pem) = x509_parser::pem::parse_x509_pem(chain_pem).map_err(|e| expiry(&e))?;
    let cert = pem.parse_x509().map_err(|e| expiry(&e))?;
    let secs = cert.validity().not_after.timestamp();
    Ok(match u64::try_from(secs) {
        Ok(secs) => UNIX_EPOCH + Duration::from_secs(secs),
        Err(_) => UNIX_EPOCH,
    })
}

fn order_err(e: instant_acme::Error) -> AcmeError {
    AcmeError::Order(e.to_string())
}

/// HTTPS client trusting the bundled roots over the `ring` provider (HTTP/1.1 only).
fn http_client() -> Result<Box<dyn HttpClient>, AcmeError> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // Explicit provider: never touch the process-wide default (another component may install one).
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .map_err(|e| AcmeError::Order(format!("TLS setup: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = HttpsConnectorBuilder::new()
        .with_tls_config(config)
        .https_only()
        .enable_http1()
        .build();
    Ok(Box::new(
        HyperClient::builder(TokioExecutor::new()).build(connector),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEAF: &[u8] = include_bytes!("../tests/fixtures/leaf.crt");

    #[test]
    fn reads_not_after_of_the_leaf() {
        // `openssl x509 -enddate` of the fixture: Oct  1 07:51:01 2126 GMT.
        let want = UNIX_EPOCH + Duration::from_secs(4_946_514_661);
        assert_eq!(chain_not_after(LEAF).unwrap(), want);
    }

    #[test]
    fn garbage_is_an_expiry_error() {
        assert!(matches!(
            chain_not_after(b"not a pem"),
            Err(AcmeError::Expiry(_))
        ));
    }

    #[tokio::test]
    async fn account_creation_requires_accepted_terms_and_files_must_be_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("account.key");
        let client = InstantAcme::new(InstantAcmeSettings {
            directory_url: "https://acme.invalid/directory".into(),
            contact_email: None,
            account_key: path.clone(),
            terms_agreed: false,
        });
        assert!(matches!(
            client.account().await,
            Err(AcmeError::AccountKey(m)) if m.contains("terms")
        ));
        assert!(!path.exists());

        fs::write(&path, b"{}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let client = InstantAcme::new(InstantAcmeSettings {
            directory_url: "https://acme.invalid/directory".into(),
            contact_email: None,
            account_key: path,
            terms_agreed: true,
        });
        assert!(matches!(
            client.account().await,
            Err(AcmeError::AccountKey(m)) if m.contains("must not be accessible")
        ));
    }
}
