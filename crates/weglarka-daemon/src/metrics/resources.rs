//! Per-app resource metrics (issue #351): one `container_list` and one unfiltered `container_stats`
//! per refresh, labelled by the ADR 0061 contract.
//!
//! Who gets a series:
//! - a container with a valid `weglarka.instance` label: `app=<instance>`, `role` from its name
//!   (`<instance>` is active, `<instance>.next` the challenger, `<instance>.prev` the retiring one; a
//!   stray copy under any other name gets nothing);
//! - the ingress, the forwarder and the daemon itself, by their fixed names, with `role="active"`;
//! - nothing else. One-off `run`, `forward` and import containers are skipped first: their names hold
//!   tokens, so every run would start new series.
//!
//! Missing data is no sample, never zero: no stats entry (a container that is not running), a `0` that
//! a running container cannot honestly report (memory, CPU, pids), block I/O that is `0` in both
//! directions (libpod reports that without the `io` controller), no network interface, and no memory
//! limit (the stats `MemLimit` is the host's RAM then, so it is never used).
//!
//! The result is cached for [`TTL`]: a scrape inside that window, or one that arrives while a refresh
//! runs, gets the same families without another libpod call. Nothing is sampled in the background.

use std::collections::BTreeMap;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::time::Instant;
use weglarka_model::app::InstanceName;
use weglarka_model::labels;
use weglarka_model::podman::{
    ContainerFilter, ContainerInfo, ContainerState, ContainerStats, PodmanClient,
};

use super::encode::{Family, Kind, Sample};
use crate::app::Daemon;
use crate::ingress::{FORWARDER_CONTAINER, NGINX_CONTAINER};
use crate::service::SERVICE_NAME;

/// How long one refresh is served.
pub const TTL: Duration = Duration::from_secs(10);

/// Longest wait for libpod in one refresh; below Prometheus' default 10 s scrape timeout, so a hung
/// libpod reads as `weglarka_resource_metrics_up 0` rather than a failed scrape.
pub const REFRESH_TIMEOUT: Duration = Duration::from_secs(8);

/// The last refresh and when it was made; the lock is held through a refresh, so concurrent scrapes
/// wait for it instead of starting their own.
#[derive(Debug, Default)]
pub struct Cache(Mutex<Option<(Instant, Vec<Family>)>>);

impl Cache {
    /// The cached families while they are younger than `ttl`, otherwise the result of `refresh`.
    pub async fn get_or_refresh(
        &self,
        ttl: Duration,
        refresh: impl Future<Output = Vec<Family>>,
    ) -> Vec<Family> {
        let mut slot = self.0.lock().await;
        if let Some((at, families)) = slot.as_ref()
            && at.elapsed() < ttl
        {
            return families.clone();
        }
        let families = refresh.await;
        *slot = Some((Instant::now(), families.clone()));
        families
    }
}

/// The resource families, from `cache` when it is fresh.
pub async fn collect<P: PodmanClient>(daemon: &Daemon<P>, cache: &Cache) -> Vec<Family> {
    cache
        .get_or_refresh(TTL, refresh(daemon.engine.podman()))
        .await
}

async fn refresh<P: PodmanClient>(podman: &P) -> Vec<Family> {
    let all = ContainerFilter::default();
    // The cache lock is held through the refresh, so a libpod that never answers must not hold every
    // later scrape with it.
    let Ok((containers, stats)) = tokio::time::timeout(REFRESH_TIMEOUT, async {
        tokio::join!(podman.container_list(&all), podman.container_stats())
    })
    .await
    else {
        tracing::warn!(
            timeout_secs = REFRESH_TIMEOUT.as_secs(),
            "resource metrics unavailable: libpod did not answer in time"
        );
        return vec![up(false)];
    };
    match (containers, stats) {
        (Ok(containers), Ok(stats)) => {
            let mut families = families(&containers, &stats);
            families.push(up(true));
            families
        }
        (containers, stats) => {
            let error = containers.err().or(stats.err());
            if let Some(error) = error {
                tracing::warn!(%error, "resource metrics unavailable");
            }
            vec![up(false)]
        }
    }
}

fn up(ok: bool) -> Family {
    Family {
        name: "weglarka_resource_metrics_up",
        help: "1 if the last container list and stats calls succeeded, 0 if either failed or timed out (the per-container families are then absent).",
        kind: Kind::Gauge,
        samples: vec![Sample::new(Vec::new(), if ok { 1.0 } else { 0.0 })],
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Role {
    Active,
    Challenger,
    Retiring,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Challenger => "challenger",
            Self::Retiring => "retiring",
        }
    }
}

/// `(app, role)` of a container, or `None` when it gets no series.
fn identify(c: &ContainerInfo) -> Option<(String, Role)> {
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
        // `(app, role)`, and container names are unique, so no two containers share a series.
        let role = if c.name == labels::container_name(&instance) {
            Role::Active
        } else if c.name == labels::challenger_name(&instance) {
            Role::Challenger
        } else if c.name == labels::retiring_name(&instance) {
            Role::Retiring
        } else {
            return None;
        };
        return Some((instance.to_string(), role));
    }
    [NGINX_CONTAINER, FORWARDER_CONTAINER, SERVICE_NAME]
        .contains(&c.name.as_str())
        .then(|| (c.name.clone(), Role::Active))
}

/// One family per metric; each sample is optional, see the module comment.
struct Builder(BTreeMap<&'static str, Family>);

impl Builder {
    fn add(
        &mut self,
        (name, help, kind): (&'static str, &'static str, Kind),
        labels: &[(&'static str, String)],
        value: Option<f64>,
    ) {
        let family = self.0.entry(name).or_insert_with(|| Family {
            name,
            help,
            kind,
            samples: Vec::new(),
        });
        if let Some(value) = value {
            family.samples.push(Sample::new(labels.to_vec(), value));
        }
    }
}

const MEMORY_USAGE: (&str, &str, Kind) = (
    "weglarka_container_memory_usage_bytes",
    "Working set of the container in bytes (libpod MemUsage).",
    Kind::Gauge,
);
const MEMORY_LIMIT: (&str, &str, Kind) = (
    "weglarka_container_memory_limit_bytes",
    "Memory limit of the container in bytes; absent when it has none.",
    Kind::Gauge,
);
const CPU: (&str, &str, Kind) = (
    "weglarka_container_cpu_seconds_total",
    "CPU time used by the container since it started, in seconds.",
    Kind::Counter,
);
const PIDS: (&str, &str, Kind) = (
    "weglarka_container_pids",
    "Processes and threads in the container.",
    Kind::Gauge,
);
const NET_RX: (&str, &str, Kind) = (
    "weglarka_container_network_receive_bytes_total",
    "Bytes received on the container's network interfaces (loopback excluded).",
    Kind::Counter,
);
const NET_TX: (&str, &str, Kind) = (
    "weglarka_container_network_transmit_bytes_total",
    "Bytes sent on the container's network interfaces (loopback excluded).",
    Kind::Counter,
);
const BLOCK_READ: (&str, &str, Kind) = (
    "weglarka_container_block_read_bytes_total",
    "Bytes read from block devices by the container; needs the io cgroup controller.",
    Kind::Counter,
);
const BLOCK_WRITE: (&str, &str, Kind) = (
    "weglarka_container_block_write_bytes_total",
    "Bytes written to block devices by the container; needs the io cgroup controller.",
    Kind::Counter,
);
const RESTARTS: (&str, &str, Kind) = (
    "weglarka_container_restarts_total",
    "Restarts of the container by its restart policy (libpod RestartCount); starts at 0 when the container is recreated.",
    Kind::Counter,
);
const OOM_KILLED: (&str, &str, Kind) = (
    "weglarka_container_oom_killed",
    "1 if libpod recorded an out-of-memory kill of this container since it was created, else 0.",
    Kind::Gauge,
);

fn nonzero(value: u64) -> Option<f64> {
    (value > 0).then_some(value as f64)
}

fn families(containers: &[ContainerInfo], stats: &[ContainerStats]) -> Vec<Family> {
    let stats: BTreeMap<&str, &ContainerStats> =
        stats.iter().map(|s| (s.name.as_str(), s)).collect();
    let mut out = Builder(BTreeMap::new());
    // `identify` maps each unique container name to its own `(app, role)`, so no series repeats.
    for (c, (app, role)) in containers
        .iter()
        .filter_map(|c| identify(c).map(|id| (c, id)))
    {
        let labels = [("app", app), ("role", role.as_str().to_owned())];
        out.add(RESTARTS, &labels, Some(f64::from(c.restarts)));
        out.add(
            OOM_KILLED,
            &labels,
            Some(if c.oom_killed { 1.0 } else { 0.0 }),
        );
        out.add(
            MEMORY_LIMIT,
            &labels,
            c.memory_limit.map(|limit| limit as f64),
        );
        let Some(s) = stats
            .get(c.name.as_str())
            .filter(|_| c.state == ContainerState::Running)
        else {
            continue;
        };
        out.add(MEMORY_USAGE, &labels, nonzero(s.memory_usage));
        out.add(
            CPU,
            &labels,
            (s.cpu_nanos > 0).then(|| s.cpu_nanos as f64 / 1e9),
        );
        out.add(PIDS, &labels, nonzero(s.pids));
        let block = s.block_read_bytes > 0 || s.block_write_bytes > 0;
        out.add(
            BLOCK_READ,
            &labels,
            block.then_some(s.block_read_bytes as f64),
        );
        out.add(
            BLOCK_WRITE,
            &labels,
            block.then_some(s.block_write_bytes as f64),
        );
        out.add(NET_RX, &labels, s.network.map(|n| n.rx_bytes as f64));
        out.add(NET_TX, &labels, s.network.map(|n| n.tx_bytes as f64));
    }
    out.0.into_values().collect()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

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
        identify(c).map(|(app, role)| (app, role.as_str()))
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
        let families = families(&[stray, real], &[]);
        let restarts = families
            .iter()
            .find(|f| f.name == RESTARTS.0)
            .expect("restarts family");
        assert_eq!(restarts.samples.len(), 1);
        assert_eq!(restarts.samples[0].value, 0.0);
    }

    #[tokio::test(start_paused = true)]
    async fn cache_serves_within_the_ttl_and_refreshes_after_it() {
        let cache = Cache::default();
        let calls = AtomicUsize::new(0);
        let refresh = || async {
            calls.fetch_add(1, Ordering::SeqCst);
            vec![up(true)]
        };
        cache.get_or_refresh(TTL, refresh()).await;
        tokio::time::advance(TTL - Duration::from_millis(1)).await;
        cache.get_or_refresh(TTL, refresh()).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_millis(1)).await;
        cache.get_or_refresh(TTL, refresh()).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
