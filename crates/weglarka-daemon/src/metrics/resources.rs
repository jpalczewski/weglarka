//! Per-app resource metrics (issue #351): a projection of the shared [`ResourceSnapshot`]
//! (`crate::resources`), labelled by the ADR 0061 contract.
//!
//! Series are `app=<instance or system container>`, `role=active|challenger|retiring`. Missing data is
//! no sample, never zero (the snapshot holds `None` for it), and no memory limit means no limit
//! sample. The snapshot is cached for its own TTL, so a scrape inside that window, or one that
//! arrives while a refresh runs, gets the same families without another libpod call.

use std::collections::BTreeMap;

use super::encode::{Family, Kind, Sample};
use crate::app::Daemon;
use crate::resources::ResourceSnapshot;
use weglarka_model::podman::PodmanClient;

/// The resource families, from the daemon's shared snapshot.
pub async fn collect<P: PodmanClient>(daemon: &Daemon<P>) -> Vec<Family> {
    match daemon.resources.snapshot(daemon.engine.podman()).await {
        Ok(snapshot) => {
            let mut families = families(&snapshot);
            families.push(up(true));
            families
        }
        Err(_) => vec![up(false)],
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

/// One family per metric; each sample is optional.
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

fn families(snapshot: &ResourceSnapshot) -> Vec<Family> {
    let mut out = Builder(BTreeMap::new());
    // The snapshot maps each unique container name to its own `(owner, role)`, so no series repeats.
    for c in &snapshot.containers {
        let labels = [
            ("app", c.owner.label()),
            ("role", c.role.as_str().to_owned()),
        ];
        let bytes = |v: Option<u64>| v.map(|v| v as f64);
        out.add(RESTARTS, &labels, Some(f64::from(c.restarts)));
        out.add(
            OOM_KILLED,
            &labels,
            Some(if c.oom_killed { 1.0 } else { 0.0 }),
        );
        out.add(MEMORY_LIMIT, &labels, bytes(c.memory_limit));
        out.add(MEMORY_USAGE, &labels, bytes(c.memory_bytes));
        out.add(CPU, &labels, c.cpu_nanos.map(|n| n as f64 / 1e9));
        out.add(PIDS, &labels, bytes(c.pids));
        out.add(BLOCK_READ, &labels, bytes(c.block_read_bytes));
        out.add(BLOCK_WRITE, &labels, bytes(c.block_write_bytes));
        out.add(NET_RX, &labels, bytes(c.network_rx_bytes));
        out.add(NET_TX, &labels, bytes(c.network_tx_bytes));
    }
    out.0.into_values().collect()
}
