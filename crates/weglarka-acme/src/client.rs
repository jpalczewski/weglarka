use std::future::Future;
use std::time::SystemTime;

use crate::cert::{CertSpec, Issued};
use crate::error::AcmeError;
use crate::solver::ChallengeSolver;

/// Talks to the CA and obtains one certificate for `spec`, answering every challenge through
/// `solver` (and cleaning up after it, also on failure). The real implementation over
/// `instant-acme` lands next to this trait; [`crate::testing::FakeAcme`] is the in-memory one.
pub trait AcmeClient: Send + Sync {
    fn issue<S: ChallengeSolver>(
        &self,
        spec: &CertSpec,
        solver: &S,
    ) -> impl Future<Output = Result<Issued, AcmeError>> + Send;
}

/// Reads the expiry (`notAfter`) of an issued PEM chain, so a restarted daemon can decide about
/// renewal from the files on disk alone.
pub trait CertInspector: Send + Sync {
    fn not_after(&self, chain_pem: &[u8]) -> Result<SystemTime, AcmeError>;
}
