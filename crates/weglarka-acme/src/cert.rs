use std::fmt;
use std::time::SystemTime;

use crate::error::AcmeError;

const MAX_ID_LEN: usize = 200;
const MAX_NAME_LEN: usize = 253;

/// Why a [`CertId`] was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid certificate id {id:?}: {reason}")]
pub struct CertIdError {
    id: String,
    reason: &'static str,
}

/// Stable identifier of a certificate; becomes the file stem `tls/<id>.crt|key`.
///
/// Restricted to lowercase `[a-z0-9._-]` without a leading dot, so it can never contain a path
/// separator, `..` or `*`. A single-name certificate uses the domain itself (the layout the ingress
/// already scans); a wildcard certificate is expected to use `_wildcard.<apex>` (issue #97).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CertId(String);

impl CertId {
    pub fn new(id: impl Into<String>) -> Result<Self, CertIdError> {
        let id = id.into();
        let reason = if id.is_empty() {
            Some("empty")
        } else if id.len() > MAX_ID_LEN {
            Some("too long")
        } else if id.starts_with('.') {
            Some("leading dot")
        } else if !id.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')
        }) {
            Some("only lowercase letters, digits, '.', '-' and '_' are allowed")
        } else {
            None
        };
        match reason {
            Some(reason) => Err(CertIdError { id, reason }),
            None => Ok(Self(id)),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CertId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One certificate to keep valid: an id plus the names (SANs) it covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertSpec {
    id: CertId,
    names: Vec<String>,
}

impl CertSpec {
    /// A certificate for a single domain, stored under the domain's own name (what #96 uses).
    pub fn single(domain: &str) -> Result<Self, AcmeError> {
        Self::new(CertId::new(domain)?, vec![domain.to_owned()])
    }

    /// A certificate for `names`. A wildcard is accepted only as a whole leading label
    /// (`*.example.eu`); which solver can satisfy it is decided at issuance time.
    pub fn new(id: CertId, names: Vec<String>) -> Result<Self, AcmeError> {
        if names.is_empty() {
            return Err(AcmeError::InvalidName {
                name: String::new(),
                reason: "a certificate needs at least one name",
            });
        }
        for name in &names {
            validate_name(name)?;
        }
        Ok(Self { id, names })
    }

    pub fn id(&self) -> &CertId {
        &self.id
    }

    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// Whether any name is a wildcard (such certificates require DNS-01).
    pub fn has_wildcard(&self) -> bool {
        self.names.iter().any(|n| n.starts_with("*."))
    }
}

/// The name a certificate name is validated and challenged under: a wildcard `*.example.eu` is
/// proven at `example.eu` (RFC 8555 §7.1.3), so the `*.` prefix goes.
pub(crate) fn base_name(name: &str) -> &str {
    name.strip_prefix("*.").unwrap_or(name)
}

fn validate_name(name: &str) -> Result<(), AcmeError> {
    let bad = |reason| {
        Err(AcmeError::InvalidName {
            name: name.to_owned(),
            reason,
        })
    };
    let host = base_name(name);
    if host.is_empty() || name.len() > MAX_NAME_LEN {
        return bad("empty or too long");
    }
    if host.starts_with('.') || host.ends_with('.') || host.contains("..") {
        return bad("empty label");
    }
    if !host.contains('.') {
        return bad("a public DNS name needs at least two labels");
    }
    let label_ok = |l: &str| {
        l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    if !host.split('.').all(label_ok) {
        return bad("labels must be lowercase letters, digits and '-'");
    }
    Ok(())
}

/// PEM-encoded private key. `Debug` is redacted and there is no `Display`/`Clone`: the bytes are
/// reachable only through [`PrivateKeyPem::expose`], which the store calls to write the `0600` file.
pub struct PrivateKeyPem(Vec<u8>);

impl PrivateKeyPem {
    pub fn new(pem: Vec<u8>) -> Self {
        Self(pem)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for PrivateKeyPem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKeyPem(<redacted>)")
    }
}

/// The result of one successful order: the chain (leaf first), its key and its expiry.
#[derive(Debug)]
pub struct Issued {
    pub chain_pem: Vec<u8>,
    pub key: PrivateKeyPem,
    pub not_after: SystemTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_rejects_path_tricks_and_wildcards() {
        for bad in [
            "",
            ".hidden",
            "a/b",
            "..",
            "*.example.eu",
            "Example.EU",
            "a b",
            "a\0b",
        ] {
            assert!(CertId::new(bad).is_err(), "{bad:?}");
        }
        for ok in ["example.eu", "_wildcard.example.eu", "a-b.c_d"] {
            assert!(CertId::new(ok).is_ok(), "{ok:?}");
        }
        assert!(CertId::new("a".repeat(MAX_ID_LEN + 1)).is_err());
    }

    #[test]
    fn spec_validates_names() {
        assert!(CertSpec::single("app.example.eu").is_ok());
        let wildcard = CertSpec::new(
            CertId::new("_wildcard.example.eu").unwrap(),
            vec!["*.example.eu".into(), "example.eu".into()],
        )
        .unwrap();
        assert!(wildcard.has_wildcard());
        for bad in [
            "localhost",
            "a..b.eu",
            "-a.eu",
            "a.eu.",
            "x*.eu",
            "a.*.eu",
            "*",
            "*.",
            "UP.eu",
        ] {
            assert!(
                CertSpec::new(CertId::new("x").unwrap(), vec![bad.into()]).is_err(),
                "{bad:?}"
            );
        }
        assert!(CertSpec::new(CertId::new("x").unwrap(), vec![]).is_err());
    }

    #[test]
    fn private_key_debug_is_redacted() {
        let key = PrivateKeyPem::new(b"-----BEGIN PRIVATE KEY-----secret".to_vec());
        let shown = format!("{key:?}");
        assert!(shown.contains("redacted") && !shown.contains("secret"));
        let issued = Issued {
            chain_pem: b"chain".to_vec(),
            key,
            not_after: SystemTime::UNIX_EPOCH,
        };
        assert!(!format!("{issued:?}").contains("secret"));
    }
}
