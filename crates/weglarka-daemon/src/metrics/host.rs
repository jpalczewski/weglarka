//! Host metrics (issue #353), read by the daemon itself without a mount or a second container.
//!
//! An unprivileged container sees host-wide values in its own `/proc/meminfo`, `stat`, `loadavg`
//! and `diskstats` (the kernel does not namespace them) while it sees only its own processes, so
//! [`ProcSource`] reads them where the daemon already is. `/proc/net` is per network namespace and
//! would describe the daemon's container, not the host, so no network counter is exported.
//!
//! Names follow `node_exporter` where the meaning is exactly the same (a dashboard built for it keeps
//! working); the container storage filesystem comes from libpod `GET /info` under `weglarka_` names,
//! because it has no real mount point to put in a `node_filesystem_*` label.
//!
//! Every file is read at scrape time and parsed on its own: a file that is missing (an older kernel
//! without PSI, a fixture without it) or does not parse drops only its own families, logged at debug
//! level. Nothing panics on malformed input, and `/metrics` keeps answering `200`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use weglarka_model::podman::{PodmanClient, StorageInfo};

use super::encode::{Family, Kind, Sample};
use super::resources::{Cache, REFRESH_TIMEOUT};

/// Where host metrics come from. Called once per scrape.
///
/// [`ProcSource`] is the default; a later adapter can read a host `node_exporter` over a unix socket
/// and replace it without touching the listener or the other sources.
pub trait HostSource: Send + Sync + 'static {
    fn collect(&self) -> impl Future<Output = Vec<Family>> + Send;
}

/// The default `/proc` root.
pub const PROC_ROOT: &str = "/proc";

/// Reads the host's `/proc` as the daemon's container sees it; `root` is a fixture directory in tests.
#[derive(Debug, Clone)]
pub struct ProcSource {
    root: PathBuf,
}

impl ProcSource {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
}

impl Default for ProcSource {
    fn default() -> Self {
        Self::new(PROC_ROOT)
    }
}

/// Turns one file into families; `None` means "unparsable".
type Parser = fn(&str) -> Option<Vec<Family>>;

/// Each file and its parser.
const FILES: &[(&str, Parser)] = &[
    ("meminfo", meminfo),
    ("stat", stat),
    ("loadavg", loadavg),
    ("diskstats", diskstats),
    ("pressure/cpu", pressure_cpu),
    ("pressure/memory", pressure_memory),
    ("pressure/io", pressure_io),
    ("vmstat", vmstat),
    ("sys/fs/file-nr", file_nr),
];

impl HostSource for ProcSource {
    // The files are small and live in memory (procfs), so they are read inline: no blocking pool.
    async fn collect(&self) -> Vec<Family> {
        FILES
            .iter()
            .flat_map(|(file, parse)| read(&self.root, file, *parse))
            .collect()
    }
}

fn read(root: &Path, file: &str, parse: Parser) -> Vec<Family> {
    let text = match std::fs::read_to_string(root.join(file)) {
        Ok(text) => text,
        Err(error) => {
            tracing::debug!(file, %error, "host metric file unavailable");
            return Vec::new();
        }
    };
    parse(&text).unwrap_or_else(|| {
        tracing::debug!(file, "host metric file not understood");
        Vec::new()
    })
}

fn family(name: &'static str, help: &'static str, kind: Kind, samples: Vec<Sample>) -> Family {
    Family {
        name,
        help,
        kind,
        samples,
    }
}

fn single(name: &'static str, help: &'static str, kind: Kind, value: f64) -> Family {
    family(name, help, kind, vec![Sample::new(Vec::new(), value)])
}

// ---- meminfo ----

const MEMINFO: &[(&str, &str, &str)] = &[
    (
        "MemTotal",
        "node_memory_MemTotal_bytes",
        "Usable RAM of the host in bytes (/proc/meminfo MemTotal).",
    ),
    (
        "MemAvailable",
        "node_memory_MemAvailable_bytes",
        "Memory the host can give to new work without swapping, in bytes (/proc/meminfo MemAvailable).",
    ),
    (
        "SwapTotal",
        "node_memory_SwapTotal_bytes",
        "Swap space of the host in bytes (/proc/meminfo SwapTotal).",
    ),
    (
        "SwapFree",
        "node_memory_SwapFree_bytes",
        "Unused swap space of the host in bytes (/proc/meminfo SwapFree).",
    ),
];

/// `Key:   123 kB` lines; a key that is absent or does not parse is no family.
fn meminfo(text: &str) -> Option<Vec<Family>> {
    let value = |key: &str| {
        text.lines().find_map(|line| {
            let (k, rest) = line.split_once(':')?;
            if k.trim() != key {
                return None;
            }
            let mut parts = rest.split_whitespace();
            let n: u64 = parts.next()?.parse().ok()?;
            match parts.next() {
                None => Some(n),
                Some("kB") => n.checked_mul(1024),
                Some(_) => None,
            }
        })
    };
    Some(
        MEMINFO
            .iter()
            .filter_map(|(key, name, help)| {
                value(key).map(|n| single(name, help, Kind::Gauge, n as f64))
            })
            .collect(),
    )
}

// ---- stat ----

/// Clock ticks per second of `/proc/stat`. The kernel always reports in `USER_HZ`, which is 100 on
/// every Linux architecture Węglarka runs on; `sysconf(_SC_CLK_TCK)` would need `unsafe`.
const USER_HZ: f64 = 100.0;

/// The first eight columns of a `cpuN` line, in kernel order. `guest` and `guest_nice` are already
/// included in `user` and `nice` (`node_exporter` exports them as a separate family; this does not).
const CPU_MODES: [&str; 8] = [
    "user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal",
];

fn stat(text: &str) -> Option<Vec<Family>> {
    let mut out = Vec::new();
    if let Some(cpu) = cpu_seconds(text) {
        out.push(family(
            "node_cpu_seconds_total",
            "Seconds the host's CPUs spent in each mode (/proc/stat).",
            Kind::Counter,
            cpu,
        ));
    }
    let btime = text.lines().find_map(|line| {
        let rest = line.strip_prefix("btime ")?;
        rest.trim().parse::<u64>().ok()
    });
    if let Some(btime) = btime {
        out.push(single(
            "node_boot_time_seconds",
            "Unix time the host booted (/proc/stat btime).",
            Kind::Gauge,
            btime as f64,
        ));
    }
    Some(out)
}

/// Per-CPU lines only (the summed `cpu` line is left out, as in `node_exporter`). One malformed line
/// drops the whole family: a partial CPU set would read as an idle host.
fn cpu_seconds(text: &str) -> Option<Vec<Sample>> {
    let mut samples = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(cpu) = fields.next().and_then(|f| f.strip_prefix("cpu")) else {
            continue;
        };
        if cpu.is_empty() {
            continue;
        }
        cpu.parse::<u32>().ok()?;
        let values: Vec<u64> = fields
            .take(CPU_MODES.len())
            .map(str::parse)
            .collect::<Result<_, _>>()
            .ok()?;
        // `user nice system idle` exist on every kernel; the later columns may be missing on an old one.
        if values.len() < 4 {
            return None;
        }
        for (mode, ticks) in CPU_MODES.iter().zip(values) {
            samples.push(Sample::new(
                vec![("cpu", cpu.to_owned()), ("mode", (*mode).to_owned())],
                ticks as f64 / USER_HZ,
            ));
        }
    }
    (!samples.is_empty()).then_some(samples)
}

// ---- loadavg ----

fn loadavg(text: &str) -> Option<Vec<Family>> {
    let mut fields = text.split_whitespace();
    let mut next = || fields.next()?.parse::<f64>().ok().filter(|v| v.is_finite());
    let (one, five, fifteen) = (next()?, next()?, next()?);
    Some(vec![
        single(
            "node_load1",
            "1m load average of the host.",
            Kind::Gauge,
            one,
        ),
        single(
            "node_load5",
            "5m load average of the host.",
            Kind::Gauge,
            five,
        ),
        single(
            "node_load15",
            "15m load average of the host.",
            Kind::Gauge,
            fifteen,
        ),
    ])
}

// ---- diskstats ----

/// `/proc/diskstats` counts in 512-byte units whatever the device's block size.
const SECTOR_BYTES: f64 = 512.0;

/// `node_exporter`'s default device filter, `^(z?ram|loop|fd|(h|s|v|xv)d[a-z]|nvme\d+n\d+p)\d+$`,
/// plus `mmcblkNpM` partitions: memory and loop devices and partitions are left out, so a host has a
/// handful of series instead of one per partition and loop mount.
fn ignored_device(name: &str) -> bool {
    let stem = name.trim_end_matches(|c: char| c.is_ascii_digit());
    if stem.len() == name.len() {
        return false;
    }
    let disk_letter = |s: &str| {
        let mut chars = s.chars();
        matches!((chars.next(), chars.next()), (Some('a'..='z'), None))
    };
    let numbered = |s: &str, sep: char| {
        s.split_once(sep).is_some_and(|(a, b)| {
            !a.is_empty() && a.bytes().all(|c| c.is_ascii_digit()) && b.is_empty()
        })
    };
    match stem {
        "ram" | "zram" | "loop" | "fd" => true,
        _ => {
            ["hd", "sd", "vd", "xvd"]
                .iter()
                .any(|p| stem.strip_prefix(p).is_some_and(disk_letter))
                || stem.strip_prefix("nvme").is_some_and(|rest| {
                    rest.split_once('n').is_some_and(|(ctrl, ns)| {
                        !ctrl.is_empty()
                            && ctrl.bytes().all(|c| c.is_ascii_digit())
                            && numbered(ns, 'p')
                    })
                })
                || stem
                    .strip_prefix("mmcblk")
                    .is_some_and(|rest| numbered(rest, 'p'))
        }
    }
}

/// A kernel device name, checked before it becomes a label value.
fn device_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b':'))
}

/// `major minor name reads merged sectors_read ms writes merged sectors_written ...`; a malformed line
/// is skipped, the other devices stay.
fn diskstats(text: &str) -> Option<Vec<Family>> {
    let mut read = Vec::new();
    let mut written = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (Some(name), Some(sectors_read), Some(sectors_written)) =
            (fields.get(2), fields.get(5), fields.get(9))
        else {
            continue;
        };
        if ignored_device(name) || !device_name(name) {
            continue;
        }
        let (Ok(sectors_read), Ok(sectors_written)) =
            (sectors_read.parse::<u64>(), sectors_written.parse::<u64>())
        else {
            tracing::debug!(device = name, "diskstats line not understood");
            continue;
        };
        let labels = vec![("device", (*name).to_owned())];
        read.push(Sample::new(
            labels.clone(),
            sectors_read as f64 * SECTOR_BYTES,
        ));
        written.push(Sample::new(labels, sectors_written as f64 * SECTOR_BYTES));
    }
    Some(vec![
        family(
            "node_disk_read_bytes_total",
            "Bytes read from the host's block device (/proc/diskstats, 512-byte sectors).",
            Kind::Counter,
            read,
        ),
        family(
            "node_disk_written_bytes_total",
            "Bytes written to the host's block device (/proc/diskstats, 512-byte sectors).",
            Kind::Counter,
            written,
        ),
    ])
}

// ---- pressure ----

/// `total=` of the `some` or `full` line of a PSI file, in seconds (the kernel counts microseconds).
fn psi_total(text: &str, kind: &str) -> Option<f64> {
    let line = text
        .lines()
        .find(|l| l.split_whitespace().next() == Some(kind))?;
    let total = line
        .split_whitespace()
        .find_map(|f| f.strip_prefix("total="))?;
    Some(total.parse::<u64>().ok()? as f64 / 1e6)
}

fn pressure(
    text: &str,
    some: (&'static str, &'static str),
    full: Option<(&'static str, &'static str)>,
) -> Option<Vec<Family>> {
    let mut out = Vec::new();
    if let Some(value) = psi_total(text, "some") {
        out.push(single(some.0, some.1, Kind::Counter, value));
    }
    if let Some((name, help)) = full
        && let Some(value) = psi_total(text, "full")
    {
        out.push(single(name, help, Kind::Counter, value));
    }
    (!out.is_empty()).then_some(out)
}

/// The CPU file has a `full` line on newer kernels too; like `node_exporter`, only `some` is used.
fn pressure_cpu(text: &str) -> Option<Vec<Family>> {
    pressure(
        text,
        (
            "node_pressure_cpu_waiting_seconds_total",
            "Total time in seconds that processes on the host have waited for CPU time (PSI some).",
        ),
        None,
    )
}

fn pressure_memory(text: &str) -> Option<Vec<Family>> {
    pressure(
        text,
        (
            "node_pressure_memory_waiting_seconds_total",
            "Total time in seconds that processes on the host have waited for memory (PSI some).",
        ),
        Some((
            "node_pressure_memory_stalled_seconds_total",
            "Total time in seconds no process on the host could make progress for lack of memory (PSI full).",
        )),
    )
}

fn pressure_io(text: &str) -> Option<Vec<Family>> {
    pressure(
        text,
        (
            "node_pressure_io_waiting_seconds_total",
            "Total time in seconds that processes on the host have waited due to IO congestion (PSI some).",
        ),
        Some((
            "node_pressure_io_stalled_seconds_total",
            "Total time in seconds no process on the host could make progress due to IO congestion (PSI full).",
        )),
    )
}

// ---- vmstat ----

/// Only `oom_kill`: the out-of-memory kills on the host since boot.
fn vmstat(text: &str) -> Option<Vec<Family>> {
    let value = text.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        (fields.next()? == "oom_kill").then_some(())?;
        fields.next()?.parse::<u64>().ok()
    })?;
    Some(vec![single(
        "node_vmstat_oom_kill",
        "Out-of-memory kills on the host since boot (/proc/vmstat oom_kill).",
        Kind::Counter,
        value as f64,
    )])
}

// ---- file-nr ----

/// `allocated  unused  maximum`.
fn file_nr(text: &str) -> Option<Vec<Family>> {
    let fields: Vec<u64> = text
        .split_whitespace()
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    let [allocated, _, maximum] = fields[..] else {
        return None;
    };
    Some(vec![
        single(
            "node_filefd_allocated",
            "File handles allocated on the host (/proc/sys/fs/file-nr).",
            Kind::Gauge,
            allocated as f64,
        ),
        single(
            "node_filefd_maximum",
            "Most file handles the host allows (/proc/sys/fs/file-nr).",
            Kind::Gauge,
            maximum as f64,
        ),
    ])
}

// ---- container storage (libpod) ----

/// How long one `/info` answer is served: the call is slower than stats and disk use moves slowly.
pub const STORAGE_TTL: Duration = Duration::from_secs(60);

/// The container storage families, from `cache` when it is fresh. A failed or slow `/info` drops
/// only these families (the failure is cached too, so a broken libpod is not asked on every scrape).
pub async fn storage<P: PodmanClient>(podman: &P, cache: &Cache) -> Vec<Family> {
    cache
        .get_or_refresh(STORAGE_TTL, async {
            match tokio::time::timeout(REFRESH_TIMEOUT, podman.storage_info()).await {
                Ok(Ok(info)) => storage_families(info),
                Ok(Err(error)) => {
                    tracing::warn!(%error, "container storage metrics unavailable");
                    Vec::new()
                }
                Err(_) => {
                    tracing::warn!(
                        timeout_secs = REFRESH_TIMEOUT.as_secs(),
                        "container storage metrics unavailable: libpod did not answer in time"
                    );
                    Vec::new()
                }
            }
        })
        .await
}

fn storage_families(info: StorageInfo) -> Vec<Family> {
    let StorageInfo {
        size_bytes,
        used_bytes,
    } = info;
    let mut out = Vec::new();
    if let Some(size) = size_bytes {
        out.push(single(
            "weglarka_storage_size_bytes",
            "Size of the filesystem holding Podman's container storage (graph root), in bytes.",
            Kind::Gauge,
            size as f64,
        ));
    }
    if let Some(used) = used_bytes {
        out.push(single(
            "weglarka_storage_used_bytes",
            "Bytes used on the filesystem holding Podman's container storage, by anything on it.",
            Kind::Gauge,
            used as f64,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::encode::encode;

    /// The fixture `/proc` shared with the integration tests (invented numbers).
    fn fixture() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc")
    }

    fn names(families: &[Family]) -> Vec<&'static str> {
        let mut names: Vec<_> = families
            .iter()
            .filter(|f| !f.samples.is_empty())
            .map(|f| f.name)
            .collect();
        names.sort_unstable();
        names
    }

    fn value(families: &[Family], name: &str) -> Option<f64> {
        let family = families.iter().find(|f| f.name == name)?;
        Some(family.samples.first()?.value)
    }

    #[tokio::test]
    async fn the_fixture_proc_reads_into_node_exporter_names() {
        let text = encode(ProcSource::new(fixture()).collect().await);
        insta::assert_snapshot!(text);
    }

    #[tokio::test]
    async fn a_missing_root_is_an_empty_page_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let families = ProcSource::new(dir.path().join("absent")).collect().await;
        assert!(families.is_empty());
    }

    #[tokio::test]
    async fn one_missing_or_broken_file_drops_only_its_own_families() {
        let dir = tempfile::tempdir().unwrap();
        for (file, _) in FILES {
            let to = dir.path().join(file);
            std::fs::create_dir_all(to.parent().unwrap()).unwrap();
            std::fs::copy(fixture().join(file), to).unwrap();
        }
        std::fs::remove_file(dir.path().join("pressure/io")).unwrap();
        std::fs::write(dir.path().join("loadavg"), "garbage\n").unwrap();
        let families = ProcSource::new(dir.path()).collect().await;
        let names = names(&families);
        assert!(
            !names.iter().any(|n| n.starts_with("node_load")),
            "{names:?}"
        );
        assert!(
            !names.iter().any(|n| n.contains("pressure_io")),
            "{names:?}"
        );
        for kept in [
            "node_memory_MemAvailable_bytes",
            "node_cpu_seconds_total",
            "node_disk_read_bytes_total",
            "node_pressure_memory_stalled_seconds_total",
            "node_vmstat_oom_kill",
            "node_filefd_maximum",
        ] {
            assert!(names.contains(&kept), "{kept} in {names:?}");
        }
    }

    #[test]
    fn meminfo_converts_kib_and_skips_what_it_cannot_read() {
        let f = meminfo("MemTotal:  2048 kB\nMemFree: 1 kB\nMemAvailable: x kB\nSwapTotal: 0 kB\nSwapFree: 7 MB\n")
            .unwrap();
        assert_eq!(
            names(&f),
            ["node_memory_MemTotal_bytes", "node_memory_SwapTotal_bytes"]
        );
        assert_eq!(
            value(&f, "node_memory_MemTotal_bytes"),
            Some(2048.0 * 1024.0)
        );
        assert_eq!(value(&f, "node_memory_SwapTotal_bytes"), Some(0.0));
        assert!(meminfo("").unwrap().is_empty());
        assert!(
            meminfo(&format!("MemTotal: {} kB\n", u64::MAX))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn stat_reads_ticks_per_cpu_and_drops_cpu_on_a_bad_line() {
        let text = "cpu  10 0 0 0 0 0 0 0 0 0\ncpu0 150 2 30 400 5 1 1 0 9 0\ncpu1 50 0 10 500\nintr 1 2\nbtime 1700000000\n";
        let f = stat(text).unwrap();
        let cpu = f
            .iter()
            .find(|f| f.name == "node_cpu_seconds_total")
            .unwrap();
        // cpu0 has all eight modes (guest columns ignored), cpu1 the four an old kernel reports.
        assert_eq!(cpu.samples.len(), 12);
        assert_eq!(
            cpu.samples[0],
            Sample::new(
                vec![("cpu", "0".to_owned()), ("mode", "user".to_owned())],
                1.5
            )
        );
        assert_eq!(value(&f, "node_boot_time_seconds"), Some(1_700_000_000.0));

        let broken = stat("cpu0 1 2 x 4\nbtime 5\n").unwrap();
        assert_eq!(names(&broken), ["node_boot_time_seconds"]);
        assert!(stat("cpu0 1 2\ncpufreq 1 2 3 4\n").unwrap().is_empty());
        assert!(stat("").unwrap().is_empty());
    }

    #[test]
    fn loadavg_needs_three_numbers() {
        let f = loadavg("0.50 1.25 2.00 1/123 4567\n").unwrap();
        assert_eq!(value(&f, "node_load5"), Some(1.25));
        assert!(loadavg("0.5 1.0\n").is_none());
        assert!(loadavg("0.5 nan 1\n").is_none());
        assert!(loadavg("").is_none());
    }

    #[test]
    fn diskstats_counts_512_byte_sectors_and_skips_partitions_and_virtual_devices() {
        let text = "\
   8       0 sda 100 0 8 0 50 0 4 0 0 0 0
   8       1 sda1 1 0 2 0 3 0 4 0 0 0 0
 259       0 nvme0n1 1 0 10 0 1 0 20 0 0 0 0
 259       1 nvme0n1p1 1 0 1 0 1 0 1 0 0 0 0
 179       0 mmcblk0 1 0 1 0 1 0 1 0 0 0 0
 179       1 mmcblk0p1 1 0 1 0 1 0 1 0 0 0 0
   7       0 loop0 1 0 1 0 1 0 1 0 0 0 0
   1       0 ram0 1 0 1 0 1 0 1 0 0 0 0
 252       0 zram0 1 0 1 0 1 0 1 0 0 0 0
 253       0 dm-0 1 0 3 0 1 0 6 0 0 0 0
   8      16 sdb x 0 y 0 1 0 1 0 0 0 0
   8      32 sdc 1 0
   8      48 sd\"x 1 0 1 0 1 0 1 0 0 0 0
";
        let f = diskstats(text).unwrap();
        let read = f
            .iter()
            .find(|f| f.name == "node_disk_read_bytes_total")
            .unwrap();
        let devices: Vec<&str> = read
            .samples
            .iter()
            .map(|s| s.labels[0].1.as_str())
            .collect();
        assert_eq!(devices, ["sda", "nvme0n1", "mmcblk0", "dm-0"]);
        assert_eq!(read.samples[0].value, 8.0 * 512.0);
        assert_eq!(
            value(&f, "node_disk_written_bytes_total"),
            Some(4.0 * 512.0)
        );
    }

    #[test]
    fn the_device_filter_matches_node_exporter() {
        for skipped in [
            "sda1",
            "hdb12",
            "vdc3",
            "xvda1",
            "nvme10n2p3",
            "loop12",
            "ram0",
            "zram1",
            "fd0",
            "mmcblk1p2",
        ] {
            assert!(ignored_device(skipped), "{skipped}");
        }
        for kept in [
            "sda", "sdaa1", "nvme0n1", "dm-0", "md0", "mmcblk0", "vda", "nbd0", "nvme0n1p",
        ] {
            assert!(!ignored_device(kept), "{kept}");
        }
    }

    #[test]
    fn pressure_reads_microsecond_totals() {
        let text = "some avg10=0.00 avg60=0.00 avg300=0.00 total=2500000\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=1000000\n";
        let f = pressure_io(text).unwrap();
        assert_eq!(
            value(&f, "node_pressure_io_waiting_seconds_total"),
            Some(2.5)
        );
        assert_eq!(
            value(&f, "node_pressure_io_stalled_seconds_total"),
            Some(1.0)
        );
        assert_eq!(
            names(&pressure_cpu(text).unwrap()),
            ["node_pressure_cpu_waiting_seconds_total"]
        );
        assert!(pressure_memory("some total=x\n").is_none());
        assert!(pressure_memory("").is_none());
    }

    #[test]
    fn vmstat_and_file_nr() {
        let f = vmstat("nr_free_pages 12\noom_kill 3\n").unwrap();
        assert_eq!(value(&f, "node_vmstat_oom_kill"), Some(3.0));
        assert!(vmstat("nr_free_pages 12\n").is_none());
        assert!(vmstat("oom_kill -1\n").is_none());

        let f = file_nr("1024\t0\t9223372036854775807\n").unwrap();
        assert_eq!(value(&f, "node_filefd_allocated"), Some(1024.0));
        assert_eq!(value(&f, "node_filefd_maximum"), Some(9.223372036854776e18));
        assert!(file_nr("1 2\n").is_none());
        assert!(file_nr("1 2 3 4\n").is_none());
        assert!(file_nr("a b c\n").is_none());
    }

    #[test]
    fn storage_reports_only_what_libpod_knows() {
        let both = storage_families(StorageInfo {
            size_bytes: Some(10),
            used_bytes: Some(4),
        });
        assert_eq!(
            names(&both),
            ["weglarka_storage_size_bytes", "weglarka_storage_used_bytes"]
        );
        assert!(storage_families(StorageInfo::default()).is_empty());
    }
}
