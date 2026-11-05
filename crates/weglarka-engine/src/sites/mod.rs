//! Static-site release handling (ADR 0049, #101/#102): the untrusted-image extractor and the
//! on-disk release layout (`releases/<id>`, `current`).

mod extract;
mod releases;

pub use extract::{ExtractLimits, ExtractReport, SiteError, extract_release};
pub use releases::{
    ReleaseError, ReleaseGate, ServedRelease, SiteReleases, release_id, served_release,
};
