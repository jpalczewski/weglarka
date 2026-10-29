//! `GET /v1/certificates`: the state of every TLS certificate the ACME worker looks after.

use serde::{Deserialize, Serialize};

/// Where a certificate stands against the renewal threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertStatus {
    /// Valid, with more than `renew_before_days` left.
    Valid,
    /// Valid, but inside the renewal window: the worker renews it on its next pass.
    RenewalDue,
    /// `not_after` is in the past.
    Expired,
    /// No readable certificate yet (not issued, or the file is unparseable).
    Missing,
    /// No certificate of its own, served by a valid wildcard (`covered_by`).
    Covered,
}

/// One certificate, or one routed domain served by a wildcard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateRecord {
    /// File stem under `tls/`: the domain, or `_wildcard.<apex>`.
    pub id: String,
    /// Names the certificate is ordered for (`*.example.com` and `example.com` for a wildcard).
    pub names: Vec<String>,
    /// The certificate is a wildcard one.
    pub wildcard: bool,
    pub status: CertStatus,
    /// `YYYY-MM-DDTHH:MM:SSZ` (UTC); absent for `missing` and `covered`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    /// Whole days until `not_after`, negative once expired; absent with `not_after`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub days_left: Option<i64>,
    /// For `covered`: the wildcard that serves the domain (`*.<apex>`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covered_by: Option<String>,
    /// The last worker pass failed on this certificate. The reason stays in the daemon log and
    /// `doctor`: it is free-form text from the CA.
    pub failed: bool,
}

/// `GET /v1/certificates`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificatesResponse {
    /// An enabled `[acme]` section exists. `false` (no section, or `enabled = false`) leaves
    /// `certificates` empty: certificates the operator places by hand are not listed.
    pub acme_enabled: bool,
    /// Renew when this many days or fewer are left.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renew_before_days: Option<u64>,
    /// When the worker's last pass finished; absent before the first one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_pass: Option<String>,
    /// Certificates the last pass failed on (rows with `failed`); a pass-level failure such as an
    /// unreadable `apps.toml` is not counted.
    pub failures: u32,
    pub certificates: Vec<CertificateRecord>,
}
