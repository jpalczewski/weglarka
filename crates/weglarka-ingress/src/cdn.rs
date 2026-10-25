//! CDN trust for `edge` (issue #159, `docs/decisions/0044-edge-cdn-client-address.md`).
//!
//! A request whose peer address lies inside the CDN's ranges carries the visitor's address in a
//! provider header; every other peer is its own client and the header is ignored. The ranges are
//! data: this module owns the bundled snapshot per provider and the validated [`CdnTrust`] the
//! nginx generator renders.

use weglarka_core::config::CdnProvider;

use crate::plan::{Cidr, IngressError};

/// Cloudflare's published prefixes (`GET https://api.cloudflare.com/client/v4/ips`) and the `etag`
/// of that snapshot (taken 2026-10-25).
pub const CLOUDFLARE_ETAG: &str = "38f79d050aa027e3be3865e495dcc9bc";
pub const CLOUDFLARE_RANGES: &[&str] = &[
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
];

/// Where the rendered ranges came from. It is rendered as a comment, so a changed list (a new
/// `etag`) changes `nginx.conf` and takes the `nginx -t` + reload path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RangeSource {
    /// The snapshot compiled into the binary.
    Bundled { etag: String },
    /// `[ingress.cdn] ranges`, pinned by the operator.
    Pinned,
}

impl RangeSource {
    /// The comment value; its alphabet is checked by [`CdnTrust::new`].
    fn label(&self) -> String {
        match self {
            Self::Bundled { etag } => format!("bundled etag {etag}"),
            Self::Pinned => "pinned".to_owned(),
        }
    }
}

/// What the generator needs: the visitor header, the peers allowed to set it, where they came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdnTrust {
    /// nginx variable of the request header (`$http_cf_connecting_ip`), derived from the provider.
    pub header_variable: String,
    pub ranges: Vec<Cidr>,
    pub source: RangeSource,
}

impl CdnTrust {
    pub fn new(
        provider: CdnProvider,
        ranges: Vec<Cidr>,
        source: RangeSource,
    ) -> Result<Self, IngressError> {
        if ranges.is_empty() {
            return Err(IngressError::InvalidOption {
                name: "cdn",
                reason: "at least one range required".to_owned(),
            });
        }
        if let RangeSource::Bundled { etag } = &source
            && !(!etag.is_empty() && etag.bytes().all(|b| b.is_ascii_alphanumeric()))
        {
            return Err(IngressError::InvalidOption {
                name: "cdn",
                reason: format!("{etag:?}: etag must be alphanumeric"),
            });
        }
        Ok(Self {
            header_variable: header_variable(provider.client_ip_header()),
            ranges,
            source,
        })
    }

    /// Trust for `provider`: the operator's pinned `ranges` when given, else the bundled snapshot.
    pub fn from_config(provider: CdnProvider, pinned: &[String]) -> Result<Self, IngressError> {
        if pinned.is_empty() {
            let ranges = match provider {
                CdnProvider::Cloudflare => CLOUDFLARE_RANGES,
            };
            let ranges = ranges
                .iter()
                .map(|r| r.parse())
                .collect::<Result<Vec<Cidr>, _>>()?;
            let etag = match provider {
                CdnProvider::Cloudflare => CLOUDFLARE_ETAG,
            };
            Self::new(
                provider,
                ranges,
                RangeSource::Bundled {
                    etag: etag.to_owned(),
                },
            )
        } else {
            let ranges = pinned
                .iter()
                .map(|r| r.parse())
                .collect::<Result<Vec<Cidr>, _>>()?;
            Self::new(provider, ranges, RangeSource::Pinned)
        }
    }

    pub(crate) fn source_label(&self) -> String {
        self.source.label()
    }
}

/// `CF-Connecting-IP` → `$http_cf_connecting_ip`.
fn header_variable(header: &str) -> String {
    let mut v = String::from("$http_");
    v.extend(header.chars().map(|c| match c {
        '-' => '_',
        c => c.to_ascii_lowercase(),
    }));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bundled_snapshot_parses_and_names_the_header_variable() {
        let t = CdnTrust::from_config(CdnProvider::Cloudflare, &[]).unwrap();
        assert_eq!(t.ranges.len(), 22);
        assert_eq!(t.header_variable, "$http_cf_connecting_ip");
        assert_eq!(t.source_label(), format!("bundled etag {CLOUDFLARE_ETAG}"));
    }

    #[test]
    fn a_pin_replaces_the_bundled_list() {
        let t =
            CdnTrust::from_config(CdnProvider::Cloudflare, &["203.0.113.0/24".to_owned()]).unwrap();
        assert_eq!(t.ranges.len(), 1);
        assert_eq!(t.source, RangeSource::Pinned);
    }
}
