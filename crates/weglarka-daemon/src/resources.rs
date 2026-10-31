//! One resource snapshot per cache window, shared by everything that reads container resource use
//! (the Prometheus families, the stats API, `doctor`), independent of whether `[metrics]` is on.
//!
//! The snapshot is built from one `container_list` and one unfiltered `container_stats`; the result is
//! served for [`TTL`], and a caller that arrives while a refresh runs waits for it instead of starting
//! its own. Nothing is sampled in the background, and a failed refresh is cached for the window too, so
//! a broken libpod is not asked on every call.
//!
//! Who gets an entry:
//! - a container with a valid `weglarka.instance` label: the app, with a role from its name
//!   (`<instance>` is active, `<instance>.next` the challenger, `<instance>.prev` the retiring one; a
//!   stray copy under any other name gets nothing);
//! - the ingress, the forwarder and the daemon itself, by their fixed names, with the active role;
//! - nothing else. One-off `run`, `forward` and import containers are skipped first: their names hold
//!   tokens, so every run would start new series.
//!
//! Missing data is `None`, never zero: no stats entry (a container that is not running), a `0` that a
//! running container cannot honestly report (memory, CPU, pids), block I/O that is `0` in both
//! directions (libpod reports that without the `io` controller), no network interface, and no memory
//! limit (the stats `MemLimit` is the host's RAM then, so it is never used).
//!
//! The CPU rate is computed here from the previous successful snapshot, so clients stay stateless.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime};

use tokio::sync::Mutex;
use tokio::time::Instant;
use weglarka_model::app::InstanceName;
use weglarka_model::labels;
use weglarka_model::podman::{
    ContainerFilter, ContainerInfo, ContainerState, ContainerStats, PodmanClient,
};

use crate::ingress::{FORWARDER_CONTAINER, NGINX_CONTAINER};
use crate::service::SERVICE_NAME;

/// How long one snapshot is served.
pub const TTL: Duration = Duration::from_secs(10);

/// Longest wait for libpod in one refresh; below Prometheus' default 10 s scrape timeout, so a hung
/// libpod reads as `weglarka_resource_metrics_up 0` rather than a failed scrape.
pub const REFRESH_TIMEOUT: Duration = Duration::from_secs(8);

/// The CPU rate needs a previous snapshot no older than this; an older one says nothing about "now".
pub const MAX_CPU_WINDOW: Duration = Duration::from_secs(300);

/// A value cached for a time to live.
///
/// The lock is held through a refresh, so concurrent callers wait for it instead of starting their
/// own. A failed refresh is cached like any other result when `T` carries the failure.
#[derive(Debug)]
pub struct TtlCell<T>(Mutex<Option<(Instant, T)>>);

impl<T> Default for TtlCell<T> {
    fn default() -> Self {
        Self(Mutex::new(None))
    }
}

impl<T: Clone> TtlCell<T> {
    /// The cached value while it is younger than `ttl`, otherwise the result of `refresh`.
    pub async fn get_or_refresh(&self, ttl: Duration, refresh: impl Future<Output = T>) -> T {
        let mut slot = self.0.lock().await;
        if let Some(value) = Self::fresh(&slot, ttl) {
            return value;
        }
        let value = refresh.await;
        *slot = Some((Instant::now(), value.clone()));
        value
    }

    /// Like [`Self::get_or_refresh`], but a refresh that yields `None` is not cached: the next call
    /// tries again.
    pub async fn get_or_try_refresh(
        &self,
        ttl: Duration,
        refresh: impl Future<Output = Option<T>>,
    ) -> Option<T> {
        let mut slot = self.0.lock().await;
        if let Some(value) = Self::fresh(&slot, ttl) {
            return Some(value);
        }
        let value = refresh.await?;
        *slot = Some((Instant::now(), value.clone()));
        Some(value)
    }

    fn fresh(slot: &Option<(Instant, T)>, ttl: Duration) -> Option<T> {
        slot.as_ref()
            .filter(|(at, _)| at.elapsed() < ttl)
            .map(|(_, value)| value.clone())
    }
}

/// A system container the daemon reports by its fixed name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SystemContainer {
    Ingress,
    Forwarder,
    Daemon,
}

impl SystemContainer {
    /// The container's well-known name, which is also its metrics `app` label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ingress => NGINX_CONTAINER,
            Self::Forwarder => FORWARDER_CONTAINER,
            Self::Daemon => SERVICE_NAME,
        }
    }
}

/// Whose container it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Owner {
    App(InstanceName),
    System(SystemContainer),
}

impl Owner {
    /// The text form: the instance name, or the system container's name.
    pub fn label(&self) -> String {
        match self {
            Self::App(instance) => instance.to_string(),
            Self::System(system) => system.as_str().to_owned(),
        }
    }
}

/// Which of an app's containers it is during a blue/green deploy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    Active,
    Challenger,
    Retiring,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Challenger => "challenger",
            Self::Retiring => "retiring",
        }
    }
}

/// CPU use over the window between two snapshots.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CpuRate {
    /// Cores used on average: CPU seconds per wall-clock second.
    pub cores: f64,
    /// The wall-clock time between the two snapshots the rate is computed from.
    pub window: Duration,
}

/// One container's resource use.
#[derive(Debug, Clone, PartialEq)]
pub struct ContainerResources {
    pub owner: Owner,
    pub role: Role,
    pub container_id: String,
    pub restarts: u32,
    pub oom_killed: bool,
    /// From the container, never from stats (`MemLimit` is the host's RAM when unlimited).
    pub memory_limit: Option<u64>,
    pub memory_bytes: Option<u64>,
    pub cpu_nanos: Option<u64>,
    pub cpu_rate: Option<CpuRate>,
    pub pids: Option<u64>,
    pub block_read_bytes: Option<u64>,
    pub block_write_bytes: Option<u64>,
    pub network_rx_bytes: Option<u64>,
    pub network_tx_bytes: Option<u64>,
}

/// Every reported container at one moment.
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceSnapshot {
    pub taken_at: SystemTime,
    pub containers: Vec<ContainerResources>,
}

/// Why there is no snapshot; the text goes to logs, never to a `read` caller.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unavailable {
    #[error("libpod did not answer in {} s", REFRESH_TIMEOUT.as_secs())]
    Timeout,
    #[error("{0}")]
    Podman(String),
}

type Cached = Result<Arc<ResourceSnapshot>, Unavailable>;

/// The daemon's one snapshot source.
#[derive(Debug, Default)]
pub struct SnapshotCache {
    cell: TtlCell<Cached>,
    /// The last successful snapshot, the base of the next CPU rate.
    previous: StdMutex<Option<Arc<ResourceSnapshot>>>,
}

impl SnapshotCache {
    /// The snapshot, from the cache while it is fresh (a failure is served for the window too).
    pub async fn snapshot<P: PodmanClient>(&self, podman: &P) -> Cached {
        self.cell
            .get_or_refresh(TTL, async {
                let result = refresh(podman, self.previous()).await.map(Arc::new);
                match &result {
                    Ok(snapshot) => {
                        *self.previous.lock().unwrap_or_else(|e| e.into_inner()) =
                            Some(snapshot.clone());
                    }
                    Err(error) => tracing::warn!(%error, "resource snapshot unavailable"),
                }
                result
            })
            .await
    }

    fn previous(&self) -> Option<Arc<ResourceSnapshot>> {
        self.previous
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

async fn refresh<P: PodmanClient>(
    podman: &P,
    previous: Option<Arc<ResourceSnapshot>>,
) -> Result<ResourceSnapshot, Unavailable> {
    let all = ContainerFilter::default();
    // The cache lock is held through the refresh, so a libpod that never answers must not hold every
    // later caller with it.
    let (containers, stats) = tokio::time::timeout(REFRESH_TIMEOUT, async {
        tokio::join!(podman.container_list(&all), podman.container_stats())
    })
    .await
    .map_err(|_| Unavailable::Timeout)?;
    let containers = containers.map_err(|e| Unavailable::Podman(e.to_string()))?;
    let stats = stats.map_err(|e| Unavailable::Podman(e.to_string()))?;
    Ok(build(
        &containers,
        &stats,
        previous.as_deref(),
        SystemTime::now(),
    ))
}

/// `(owner, role)` of a container, or `None` when it gets no entry.
fn identify(c: &ContainerInfo) -> Option<(Owner, Role)> {
    if [labels::RUN, labels::FORWARD, labels::IMPORT_FOR]
        .iter()
        .any(|marker| c.labels.contains_key(*marker))
    {
        return None;
    }
    if let Some(label) = c.labels.get(labels::INSTANCE) {
        // Only a validated name may become a label value.
        let instance = InstanceName::new(label.as_str()).ok()?;
        // Only the three names a deploy gives: a stray copy under another name (a duplicate that
        // reconcile has not removed yet) must not claim the app's series. The name then determines
        // `(owner, role)`, and container names are unique, so no two containers share a series.
        let role = if c.name == labels::container_name(&instance) {
            Role::Active
        } else if c.name == labels::challenger_name(&instance) {
            Role::Challenger
        } else if c.name == labels::retiring_name(&instance) {
            Role::Retiring
        } else {
            return None;
        };
        return Some((Owner::App(instance), role));
    }
    [
        SystemContainer::Ingress,
        SystemContainer::Forwarder,
        SystemContainer::Daemon,
    ]
    .into_iter()
    .find(|s| s.as_str() == c.name)
    .map(|s| (Owner::System(s), Role::Active))
}

fn nonzero(value: u64) -> Option<u64> {
    (value > 0).then_some(value)
}

/// The snapshot of `containers` and `stats`; `previous` is the base of the CPU rate.
fn build(
    containers: &[ContainerInfo],
    stats: &[ContainerStats],
    previous: Option<&ResourceSnapshot>,
    taken_at: SystemTime,
) -> ResourceSnapshot {
    let stats: HashMap<&str, &ContainerStats> =
        stats.iter().map(|s| (s.name.as_str(), s)).collect();
    let before: HashMap<&str, &ContainerResources> = previous
        .map(|p| {
            p.containers
                .iter()
                .map(|c| (c.container_id.as_str(), c))
                .collect()
        })
        .unwrap_or_default();
    let containers = containers
        .iter()
        .filter_map(|c| identify(c).map(|(owner, role)| (c, owner, role)))
        .map(|(c, owner, role)| {
            let s = stats
                .get(c.name.as_str())
                .filter(|_| c.state == ContainerState::Running);
            let cpu_nanos = s.and_then(|s| nonzero(s.cpu_nanos));
            let cpu_rate = cpu_nanos.and_then(|now| {
                let base = before.get(c.id.as_str())?;
                cpu_rate(base.cpu_nanos?, previous?.taken_at, now, taken_at)
            });
            let block = s.filter(|s| s.block_read_bytes > 0 || s.block_write_bytes > 0);
            ContainerResources {
                owner,
                role,
                container_id: c.id.clone(),
                restarts: c.restarts,
                oom_killed: c.oom_killed,
                memory_limit: c.memory_limit,
                memory_bytes: s.and_then(|s| nonzero(s.memory_usage)),
                cpu_nanos,
                cpu_rate,
                pids: s.and_then(|s| nonzero(s.pids)),
                block_read_bytes: block.map(|s| s.block_read_bytes),
                block_write_bytes: block.map(|s| s.block_write_bytes),
                network_rx_bytes: s.and_then(|s| s.network).map(|n| n.rx_bytes),
                network_tx_bytes: s.and_then(|s| s.network).map(|n| n.tx_bytes),
            }
        })
        .collect();
    ResourceSnapshot {
        taken_at,
        containers,
    }
}

/// Cores used between two readings of the same container's CPU counter. `None` when the counter went
/// back (the container restarted under the same id), the clock did, or the readings are further apart
/// than [`MAX_CPU_WINDOW`].
fn cpu_rate(
    before_nanos: u64,
    before_at: SystemTime,
    now_nanos: u64,
    now_at: SystemTime,
) -> Option<CpuRate> {
    let window = now_at.duration_since(before_at).ok()?;
    if window.is_zero() || window > MAX_CPU_WINDOW || now_nanos < before_nanos {
        return None;
    }
    Some(CpuRate {
        cores: (now_nanos - before_nanos) as f64 / window.as_nanos() as f64,
        window,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use weglarka_model::podman::NetworkIo;

    use super::*;

    fn container(name: &str, labels: &[(&str, &str)]) -> ContainerInfo {
        ContainerInfo {
            id: format!("id-{name}"),
            name: name.to_owned(),
            image: "example.com/app:1".to_owned(),
            image_id: "sha256:0".to_owned(),
            labels: labels
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            state: ContainerState::Running,
            exit_code: None,
            health: None,
            restarts: 0,
            started_at: None,
            networks: Vec::new(),
            addresses: Vec::new(),
            published_ports: Vec::new(),
            memory_limit: None,
            oom_killed: false,
        }
    }

    fn id(c: &ContainerInfo) -> Option<(String, &'static str)> {
        identify(c).map(|(owner, role)| (owner.label(), role.as_str()))
    }

    #[test]
    fn identity_follows_the_label_contract() {
        let web = [(labels::INSTANCE, "web")];
        let named = |app: &str, role| Some((app.to_owned(), role));
        assert_eq!(id(&container("web", &web)), named("web", "active"));
        assert_eq!(id(&container("web.next", &web)), named("web", "challenger"));
        assert_eq!(id(&container("web.prev", &web)), named("web", "retiring"));
        for infra in [NGINX_CONTAINER, FORWARDER_CONTAINER, SERVICE_NAME] {
            assert_eq!(id(&container(infra, &[])), named(infra, "active"));
        }
        assert_eq!(id(&container("stranger", &[])), None);
        // Markers win over the instance label; an invalid instance never becomes a label value.
        for marker in [labels::RUN, labels::FORWARD, labels::IMPORT_FOR] {
            let labels = [(marker, "true"), (labels::INSTANCE, "web")];
            assert_eq!(id(&container("web", &labels)), None, "{marker}");
        }
        let bad = [(labels::INSTANCE, "Not A Name\n")];
        assert_eq!(id(&container("odd", &bad)), None);
    }

    #[test]
    fn a_stray_copy_does_not_claim_the_apps_series() {
        // A duplicate reconcile has not removed yet carries the label under another name; it must not
        // win the app's series even when its name sorts first.
        let real = container("web", &[(labels::INSTANCE, "web")]);
        let mut stray = container("aaa-web", &[(labels::INSTANCE, "web")]);
        stray.restarts = 5;
        assert_eq!(id(&stray), None);
        let snapshot = build(&[stray, real], &[], None, SystemTime::UNIX_EPOCH);
        assert_eq!(snapshot.containers.len(), 1);
        assert_eq!(snapshot.containers[0].restarts, 0);
    }

    #[test]
    fn missing_data_is_none_not_zero() {
        let web = container("web", &[(labels::INSTANCE, "web")]);
        let at = SystemTime::UNIX_EPOCH;
        // No stats entry at all.
        let c = &build(std::slice::from_ref(&web), &[], None, at).containers[0];
        assert_eq!(
            (c.memory_bytes, c.cpu_nanos, c.pids, c.block_read_bytes),
            (None, None, None, None)
        );
        // Zeros a running container cannot honestly report, and no interface.
        let zero = ContainerStats {
            name: "web".to_owned(),
            ..Default::default()
        };
        let c = &build(std::slice::from_ref(&web), &[zero], None, at).containers[0];
        assert_eq!(
            (
                c.memory_bytes,
                c.cpu_nanos,
                c.pids,
                c.block_write_bytes,
                c.network_rx_bytes
            ),
            (None, None, None, None, None)
        );
        // Real values; a stopped container gets none of them even with a stats entry.
        let live = ContainerStats {
            name: "web".to_owned(),
            memory_usage: 5,
            cpu_nanos: 7,
            pids: 2,
            block_read_bytes: 0,
            block_write_bytes: 9,
            network: Some(NetworkIo {
                rx_bytes: 3,
                tx_bytes: 4,
            }),
        };
        let c = &build(
            std::slice::from_ref(&web),
            std::slice::from_ref(&live),
            None,
            at,
        )
        .containers[0];
        assert_eq!(
            (c.memory_bytes, c.cpu_nanos, c.pids),
            (Some(5), Some(7), Some(2))
        );
        assert_eq!(
            (c.block_read_bytes, c.block_write_bytes),
            (Some(0), Some(9))
        );
        assert_eq!((c.network_rx_bytes, c.network_tx_bytes), (Some(3), Some(4)));
        let mut stopped = web;
        stopped.state = ContainerState::Exited;
        let c = &build(&[stopped], &[live], None, at).containers[0];
        assert_eq!(c.memory_bytes, None);
    }

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn stat_with_cpu(name: &str, nanos: u64) -> ContainerStats {
        ContainerStats {
            name: name.to_owned(),
            memory_usage: 1,
            cpu_nanos: nanos,
            pids: 1,
            ..Default::default()
        }
    }

    /// Two builds one after another, as two refreshes would make them.
    fn rate_between(
        first: (&str, u64, u64),
        second: (&str, u64, u64),
    ) -> (Option<CpuRate>, Option<CpuRate>) {
        let labels = [(labels::INSTANCE, "web")];
        let one = |name: &str, nanos, previous: Option<&ResourceSnapshot>, secs| {
            let mut c = container("web", &labels);
            c.id = name.to_owned();
            build(&[c], &[stat_with_cpu("web", nanos)], previous, at(secs))
        };
        let a = one(first.0, first.1, None, first.2);
        let b = one(second.0, second.1, Some(&a), second.2);
        (a.containers[0].cpu_rate, b.containers[0].cpu_rate)
    }

    #[test]
    fn cpu_rate_of_the_same_container_is_cores_over_the_window() {
        // 2 CPU seconds in 10 wall seconds: 0.2 cores.
        let (first, second) = rate_between(("a", 1_000_000_000, 100), ("a", 3_000_000_000, 110));
        assert_eq!(first, None, "the first snapshot has no base");
        let rate = second.expect("rate");
        assert!((rate.cores - 0.2).abs() < 1e-9, "{rate:?}");
        assert_eq!(rate.window, Duration::from_secs(10));
    }

    #[test]
    fn cpu_rate_needs_the_same_container_a_forward_counter_and_a_recent_base() {
        // A new container id: no rate.
        assert_eq!(
            rate_between(("a", 1_000_000_000, 100), ("b", 3_000_000_000, 110)).1,
            None
        );
        // The counter went back.
        assert_eq!(
            rate_between(("a", 3_000_000_000, 100), ("a", 1_000_000_000, 110)).1,
            None
        );
        // The previous snapshot is older than the window.
        assert_eq!(
            rate_between(("a", 1, 100), ("a", 3_000_000_000, 100 + 301)).1,
            None
        );
        // Exactly at the limit still counts.
        assert!(
            rate_between(("a", 1, 100), ("a", 3_000_000_000, 100 + 300))
                .1
                .is_some()
        );
        // The clock did not move, or went back.
        assert_eq!(rate_between(("a", 1, 100), ("a", 5, 100)).1, None);
        assert_eq!(rate_between(("a", 1, 100), ("a", 5, 90)).1, None);
    }

    #[tokio::test(start_paused = true)]
    async fn ttl_cell_serves_within_the_ttl_and_refreshes_after_it() {
        let cell = TtlCell::default();
        let calls = AtomicUsize::new(0);
        let refresh = || async {
            calls.fetch_add(1, Ordering::SeqCst);
            1
        };
        cell.get_or_refresh(TTL, refresh()).await;
        tokio::time::advance(TTL - Duration::from_millis(1)).await;
        cell.get_or_refresh(TTL, refresh()).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_millis(1)).await;
        cell.get_or_refresh(TTL, refresh()).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_callers_share_one_refresh() {
        let cell = TtlCell::default();
        let calls = AtomicUsize::new(0);
        let refresh = async {
            calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_secs(1)).await;
            42
        };
        let (a, b, c) = tokio::join!(
            cell.get_or_refresh(TTL, refresh),
            cell.get_or_refresh(TTL, async {
                calls.fetch_add(1, Ordering::SeqCst);
                0
            }),
            cell.get_or_refresh(TTL, async {
                calls.fetch_add(1, Ordering::SeqCst);
                0
            }),
        );
        assert_eq!((a, b, c), (42, 42, 42));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn ttl_cell_serves_a_failure_until_the_ttl_passes() {
        let cell: TtlCell<Result<u32, String>> = TtlCell::default();
        let calls = AtomicUsize::new(0);
        let refresh = |result: Result<u32, String>| {
            let calls = &calls;
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                result
            }
        };
        assert_eq!(
            cell.get_or_refresh(TTL, refresh(Err("down".into()))).await,
            Err("down".to_owned())
        );
        tokio::time::advance(TTL - Duration::from_millis(1)).await;
        // Libpod is back, but the failure is still served inside the window.
        assert_eq!(
            cell.get_or_refresh(TTL, refresh(Ok(1))).await,
            Err("down".to_owned())
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_millis(1)).await;
        assert_eq!(cell.get_or_refresh(TTL, refresh(Ok(1))).await, Ok(1));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn try_refresh_does_not_cache_a_miss() {
        let cell = TtlCell::default();
        assert_eq!(
            cell.get_or_try_refresh(TTL, async { None::<u32> }).await,
            None
        );
        assert_eq!(
            cell.get_or_try_refresh(TTL, async { Some(1) }).await,
            Some(1)
        );
        assert_eq!(
            cell.get_or_try_refresh(TTL, async { Some(2) }).await,
            Some(1)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn snapshots_inside_the_ttl_cost_one_list_and_one_stats_call() {
        use weglarka_engine::testing::{Call, FakePodman};

        let fake = FakePodman::default();
        let cache = SnapshotCache::default();
        let stats_calls = |fake: &FakePodman| {
            fake.calls()
                .iter()
                .filter(|c| matches!(c, Call::ContainerStats))
                .count()
        };
        let first = cache.snapshot(&fake).await.expect("snapshot");
        tokio::time::advance(TTL - Duration::from_millis(1)).await;
        let second = cache.snapshot(&fake).await.expect("snapshot");
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!((fake.container_list_calls(), stats_calls(&fake)), (1, 1));
        tokio::time::advance(Duration::from_millis(1)).await;
        cache.snapshot(&fake).await.expect("snapshot");
        assert_eq!((fake.container_list_calls(), stats_calls(&fake)), (2, 2));
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_refresh_is_served_for_the_window() {
        use weglarka_engine::testing::FakePodman;

        let fake = FakePodman::default();
        fake.fail_stats(Some("boom"));
        let cache = SnapshotCache::default();
        assert!(cache.snapshot(&fake).await.is_err());
        fake.fail_stats(None);
        assert!(cache.snapshot(&fake).await.is_err(), "cached failure");
        assert_eq!(fake.container_list_calls(), 1);
        tokio::time::advance(TTL).await;
        assert!(cache.snapshot(&fake).await.is_ok());
    }
}
