//! The CDN range list of `[ingress.cdn]` (issue #159, `docs/decisions/0044-edge-cdn-client-address.md`).
//!
//! Without a pin the ranges nginx trusts for the visitor header are the provider's published
//! prefixes. The binary bundles a snapshot; [`CdnRanges`] keeps a newer list the daemon refreshed
//! from the provider's API in `<state dir>/cdn-ranges.toml` (public data, `0644`, tolerant serde)
//! and hands the best list to the ingress. A refresh that fails or is implausible
//! ([`CdnTrust::from_refreshed`]) keeps the last good list; a stale list fails closed (an unlisted
//! edge address is simply untrusted).

use std::future::Future;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use weglarka_ingress::{CdnTrust, IngressError};
use weglarka_model::config::CdnProvider;
use weglarka_model::fsutil::write_atomic;

/// Refresh cadence; Cloudflare says the ranges "do not change frequently".
const REFRESH_EVERY: Duration = Duration::from_secs(24 * 3600);
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(3600);
const MAX_JITTER_SECS: u64 = 3600;
/// `doctor` warns when the last successful refresh is older than this.
pub const STALE_AFTER: Duration = Duration::from_secs(7 * 24 * 3600);

/// The state file. Tolerant on purpose (no `deny_unknown_fields`): public data, a newer daemon may
/// add fields and an older one must keep reading it.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Stored {
    etag: String,
    /// Unix seconds of the successful fetch.
    fetched_at: u64,
    ranges: Vec<String>,
}

/// What `doctor` reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CdnStatus {
    /// Etag and age of the refreshed list in use; `None` = the bundled snapshot.
    pub refreshed: Option<(String, Duration)>,
    /// The reason the last refresh was not applied; cleared by the next success.
    pub last_error: Option<String>,
}

/// `(etag, CIDRs)` as the provider published them.
pub type Fetched = (String, Vec<String>);

/// A source of the provider's published prefixes (`FakeFetcher` in the tests).
pub trait RangeFetcher: Send + Sync {
    fn fetch(&self) -> impl Future<Output = Result<Fetched, String>> + Send;
}

/// Cloudflare's `GET /client/v4/ips`.
pub struct CloudflareApi;

impl RangeFetcher for CloudflareApi {
    async fn fetch(&self) -> Result<Fetched, String> {
        weglarka_dns::public_ips()
            .await
            .map(|ips| (ips.etag, ips.cidrs))
            .map_err(|e| e.to_string())
    }
}

struct Inner {
    stored: Option<Stored>,
    last_error: Option<String>,
}

pub struct CdnRanges {
    provider: CdnProvider,
    path: PathBuf,
    inner: Mutex<Inner>,
}

impl CdnRanges {
    /// Loads the persisted list. A missing file is normal; an unreadable, corrupted or implausible one
    /// falls back to the bundled list with a warning.
    pub fn load(provider: CdnProvider, path: PathBuf) -> Self {
        let stored = match std::fs::read_to_string(&path) {
            Ok(text) => match toml::from_str::<Stored>(&text) {
                Ok(stored) => {
                    match CdnTrust::from_refreshed(provider, &stored.etag, &stored.ranges) {
                        Ok(_) => Some(stored),
                        Err(error) => {
                            tracing::warn!(path = %path.display(), %error, "ignoring the saved CDN ranges, using the bundled list");
                            None
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(path = %path.display(), %error, "ignoring the corrupted CDN ranges file, using the bundled list");
                    None
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "cannot read the CDN ranges file, using the bundled list");
                None
            }
        };
        Self {
            provider,
            path,
            inner: Mutex::new(Inner {
                stored,
                last_error: None,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The trust the next `nginx.conf` renders: the refreshed list when there is one, else the bundled.
    pub fn trust(&self) -> Result<CdnTrust, IngressError> {
        match &self.lock().stored {
            Some(s) => CdnTrust::from_refreshed(self.provider, &s.etag, &s.ranges),
            None => CdnTrust::from_config(self.provider, &[]),
        }
    }

    pub fn status(&self) -> CdnStatus {
        let inner = self.lock();
        CdnStatus {
            refreshed: inner.stored.as_ref().map(|s| {
                let at = UNIX_EPOCH + Duration::from_secs(s.fetched_at);
                (
                    s.etag.clone(),
                    SystemTime::now().duration_since(at).unwrap_or_default(),
                )
            }),
            last_error: inner.last_error.clone(),
        }
    }

    /// Time until the next refresh is due, given when the last one succeeded.
    fn due_in(&self) -> Duration {
        match self.status().refreshed {
            Some((_, age)) => REFRESH_EVERY.saturating_sub(age),
            None => Duration::ZERO,
        }
    }

    /// One refresh. `Ok(true)` = the rendered list changed (the caller re-applies the ingress),
    /// `Ok(false)` = same etag. On an error the last good list stays in place and the reason is kept
    /// for `doctor`.
    pub async fn refresh<F: RangeFetcher>(&self, fetcher: &F) -> Result<bool, String> {
        let result = self.try_refresh(fetcher).await;
        self.lock().last_error = result.as_ref().err().cloned();
        result
    }

    async fn try_refresh<F: RangeFetcher>(&self, fetcher: &F) -> Result<bool, String> {
        let (etag, ranges) = fetcher.fetch().await?;
        // Plausibility first: nothing is persisted or applied from a list that fails it.
        CdnTrust::from_refreshed(self.provider, &etag, &ranges).map_err(|e| e.to_string())?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let same = self
            .lock()
            .stored
            .as_ref()
            .is_some_and(|s| s.etag == etag && s.ranges == ranges);
        let stored = Stored {
            etag,
            fetched_at: now,
            ranges,
        };
        let text = toml::to_string(&stored).map_err(|e| e.to_string())?;
        write_atomic(&self.path, text.as_bytes(), 0o644)
            .map_err(|e| format!("cannot save {}: {e}", self.path.display()))?;
        self.lock().stored = Some(stored);
        Ok(!same)
    }

    /// Refreshes daily (with jitter; the first run is due when the saved list is a day old) until
    /// `shutdown`. `on_change` runs after a refresh that changed the list.
    pub async fn run<F: RangeFetcher>(
        &self,
        fetcher: &F,
        on_change: impl Fn() + Send,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let mut wait = self.due_in() + startup_jitter();
        loop {
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                _ = shutdown.changed() => return,
            }
            let result = tokio::select! {
                r = self.refresh(fetcher) => r,
                _ = shutdown.changed() => return,
            };
            wait = match result {
                Ok(changed) => {
                    if changed {
                        tracing::info!("CDN ranges refreshed");
                        on_change();
                    }
                    REFRESH_EVERY + startup_jitter()
                }
                Err(error) => {
                    tracing::warn!(%error, "CDN ranges refresh failed, keeping the last good list");
                    RETRY_AFTER_FAILURE
                }
            };
        }
    }
}

/// Up to an hour, from the clock: spreads hosts without a random-number dependency.
fn startup_jitter() -> Duration {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::from(d.subsec_nanos()));
    Duration::from_secs(nanos % MAX_JITTER_SECS)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use weglarka_ingress::{CLOUDFLARE_RANGES, RangeSource};

    use super::*;

    struct FakeFetcher(Mutex<Vec<Result<Fetched, String>>>);

    impl FakeFetcher {
        fn new(answers: Vec<Result<Fetched, String>>) -> Arc<Self> {
            Arc::new(Self(Mutex::new(answers)))
        }
    }

    impl RangeFetcher for Arc<FakeFetcher> {
        async fn fetch(&self) -> Result<Fetched, String> {
            self.0.lock().unwrap().remove(0)
        }
    }

    fn list(extra: &[&str]) -> Vec<String> {
        CLOUDFLARE_RANGES
            .iter()
            .copied()
            .chain(extra.iter().copied())
            .map(str::to_owned)
            .collect()
    }

    fn ranges(dir: &tempfile::TempDir) -> CdnRanges {
        CdnRanges::load(CdnProvider::Cloudflare, dir.path().join("cdn-ranges.toml"))
    }

    #[tokio::test]
    async fn a_new_etag_is_persisted_and_changes_the_rendered_list() {
        let dir = tempfile::tempdir().unwrap();
        let r = ranges(&dir);
        assert!(matches!(
            r.trust().unwrap().source,
            RangeSource::Bundled { .. }
        ));

        let f = FakeFetcher::new(vec![
            Ok(("e2".into(), list(&["198.51.100.0/24"]))),
            Ok(("e2".into(), list(&["198.51.100.0/24"]))),
        ]);
        assert_eq!(r.refresh(&f).await, Ok(true));
        let trust = r.trust().unwrap();
        assert_eq!(trust.ranges.len(), 23);
        assert_eq!(trust.source, RangeSource::Refreshed { etag: "e2".into() });
        // The same list again is not a change (no re-apply).
        assert_eq!(r.refresh(&f).await, Ok(false));

        // It survives a restart, and the file is public data (0644).
        let again = ranges(&dir);
        assert_eq!(again.trust().unwrap(), trust);
        let mode = std::fs::metadata(dir.path().join("cdn-ranges.toml"))
            .unwrap()
            .permissions();
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(mode.mode() & 0o777, 0o644);
    }

    #[tokio::test]
    async fn a_failed_or_implausible_fetch_keeps_the_last_good_list() {
        let dir = tempfile::tempdir().unwrap();
        let r = ranges(&dir);
        let f = FakeFetcher::new(vec![
            Ok(("good".into(), list(&["198.51.100.0/24"]))),
            Err("connection refused".into()),
            Ok(("empty".into(), Vec::new())),
            Ok(("dropped".into(), vec!["198.51.100.0/24".into()])),
        ]);
        r.refresh(&f).await.unwrap();
        let good = r.trust().unwrap();

        assert!(r.refresh(&f).await.is_err());
        assert_eq!(r.status().last_error.as_deref(), Some("connection refused"));
        assert!(r.refresh(&f).await.is_err());
        let err = r.refresh(&f).await.unwrap_err();
        assert!(err.contains("bundled prefix"), "{err}");
        assert_eq!(r.trust().unwrap(), good, "the last good list stays");
        // Nothing implausible reached the disk.
        assert_eq!(ranges(&dir).trust().unwrap(), good);
    }

    #[tokio::test]
    async fn a_success_clears_the_reported_error() {
        let dir = tempfile::tempdir().unwrap();
        let r = ranges(&dir);
        let f = FakeFetcher::new(vec![Err("boom".into()), Ok(("ok1".into(), list(&[])))]);
        assert!(r.refresh(&f).await.is_err());
        assert!(r.status().last_error.is_some());
        r.refresh(&f).await.unwrap();
        assert_eq!(r.status().last_error, None);
        assert_eq!(r.status().refreshed.unwrap().0, "ok1");
    }

    #[test]
    fn a_corrupted_state_file_falls_back_to_the_bundled_list() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cdn-ranges.toml");
        std::fs::write(
            &path,
            "etag = \"x\"\nranges = [\"not a cidr\"]\nfetched_at = 1\n",
        )
        .unwrap();
        let r = CdnRanges::load(CdnProvider::Cloudflare, path.clone());
        assert!(matches!(
            r.trust().unwrap().source,
            RangeSource::Bundled { .. }
        ));
        std::fs::write(&path, "}{ garbage").unwrap();
        let r = CdnRanges::load(CdnProvider::Cloudflare, path);
        assert!(matches!(
            r.trust().unwrap().source,
            RangeSource::Bundled { .. }
        ));
        assert_eq!(r.status().refreshed, None);
    }
}
