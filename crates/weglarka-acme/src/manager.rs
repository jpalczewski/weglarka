use std::time::{Duration, SystemTime};

use crate::cert::{CertId, CertSpec};
use crate::client::{AcmeClient, CertInspector};
use crate::error::AcmeError;
use crate::renewal::{self, Decision};
use crate::solver::{ChallengeKind, ChallengeSolver};
use crate::store::CertStore;

/// What one pass did for one certificate.
#[derive(Debug)]
pub enum Outcome {
    /// Nothing on disk yet; a certificate was ordered and stored.
    Issued { not_after: SystemTime },
    /// Inside the renewal window (or expired); a new certificate replaced the old one.
    Renewed {
        not_after: SystemTime,
        was_expired: bool,
    },
    /// Still valid outside the renewal window.
    Valid { not_after: SystemTime },
    /// Issuance or inspection failed; the previous certificate (if any) is untouched.
    Failed(AcmeError),
}

/// Result of [`Manager::pass`]: one outcome per certificate, in input order.
#[derive(Debug, Default)]
pub struct PassReport {
    pub outcomes: Vec<(CertId, Outcome)>,
}

impl PassReport {
    /// Whether any certificate on disk changed — the caller then asks the ingress to apply, which
    /// rescans `tls/` and reloads nginx (never recreates the container).
    pub fn changed(&self) -> bool {
        self.outcomes
            .iter()
            .any(|(_, o)| matches!(o, Outcome::Issued { .. } | Outcome::Renewed { .. }))
    }
}

/// One reconcile pass over the configured certificates. Scheduling (loop, backoff, shutdown),
/// events and the `request_apply` call belong to the caller; this type has no clock of its own.
#[derive(Debug)]
pub struct Manager<C, S> {
    client: C,
    solver: S,
    store: CertStore,
    renew_before: Duration,
}

impl<C, S> Manager<C, S>
where
    C: AcmeClient + CertInspector,
    S: ChallengeSolver,
{
    pub fn new(client: C, solver: S, store: CertStore, renew_before: Duration) -> Self {
        Self {
            client,
            solver,
            store,
            renew_before,
        }
    }

    pub async fn pass(&self, now: SystemTime, specs: &[CertSpec]) -> PassReport {
        let mut report = PassReport::default();
        for spec in specs {
            let outcome = match self.one(now, spec).await {
                Ok(outcome) => outcome,
                Err(e) => {
                    tracing::warn!(cert = %spec.id(), error = %e, "certificate pass failed");
                    Outcome::Failed(e)
                }
            };
            report.outcomes.push((spec.id().clone(), outcome));
        }
        report
    }

    async fn one(&self, now: SystemTime, spec: &CertSpec) -> Result<Outcome, AcmeError> {
        let existing = match self.store.read_chain(spec.id())? {
            Some(chain) => {
                let not_after = self.client.not_after(&chain)?;
                match renewal::decide(now, not_after, self.renew_before) {
                    Decision::Wait => return Ok(Outcome::Valid { not_after }),
                    decision => Some(decision),
                }
            }
            None => None,
        };
        if spec.has_wildcard() && self.solver.kind() != ChallengeKind::Dns01 {
            return Err(AcmeError::UnsupportedChallenge {
                kind: ChallengeKind::Dns01.as_str(),
            });
        }
        let issued = self.client.issue(spec, &self.solver).await?;
        self.store.write(spec.id(), &issued)?;
        let not_after = issued.not_after;
        tracing::info!(cert = %spec.id(), "certificate stored");
        Ok(match existing {
            None => Outcome::Issued { not_after },
            Some(decision) => Outcome::Renewed {
                not_after,
                was_expired: decision == Decision::Expired,
            },
        })
    }
}
