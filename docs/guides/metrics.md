# Metrics

Węglarka can serve a Prometheus `/metrics` endpoint ([ADR 0061](../decisions/0061-metrics-listener.md)). It is off by
default: without `[metrics]` there is no listener, no network and no cost. When on, the daemon listens on a TCP address
**inside its own container** and joins a dedicated Podman network; a scraper that joins the same network can read it.
Nothing is published on a host address.

## Enabling it

```toml
[metrics]
listen = "0.0.0.0:9464"   # inside the Węglarka container; not published on the host
network = "metrics"       # optional; this is the default
```

Restart the daemon. It binds the listener at once, then creates the network (if missing; it is `internal`, with no
route out) and connects its own container to it in the background, retrying every few seconds up to a minute until
Podman cooperates, so no `platform install` and no second restart is needed. The network name uses lowercase letters, digits and `-`, and must not start with `net-`
(those names belong to app and ingress networks) or `metrics-` (the per-app metrics networks, see
[Opting an app in](#opting-an-app-in)).

The listener serves `GET /metrics` and nothing else: every other path is `404`, and it has no admin route. There is no
authentication in this version; the network is the boundary, and the text carries no secrets. Put on the `metrics`
network only containers you trust to read it.

## Checking it

Run a one-off container on the network and fetch the page (the daemon's container is called `weglarka`):

```bash
podman run --rm --network metrics docker.io/curlimages/curl:latest -s http://weglarka:9464/metrics
```

Expected: exposition text with a `weglarka_build_info{version="…"} 1` line and `weglarka_resource_metrics_up 1`
(families are sorted by name).
`weglarka doctor` shows a `metrics.listener` line when `[metrics]` is set; it is `ok` once the network is joined, `warn`
with the last error while the daemon is still retrying (the page is already served), `fail` when the address could not be
bound (fix `listen` and restart), and absent when `[metrics]` is not set. `GET /v1/config` shows the section.

## What is there

All values are computed when the page is scraped; nothing is sampled in the background, and only the per-app
resources and the container storage size call Podman (see [Per-app resources](#per-app-resources) and
[Host](#host)).
Counters live in memory and start at zero when the daemon starts (Prometheus' `rate()` and `increase()` handle the
reset). A series appears once it has something to say: an app that never failed has no `result="failed"` line.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `weglarka_build_info` | gauge | `version` | Always 1; the running daemon version. |
| `weglarka_deploys_total` | counter | `app`, `result` (`ok`, `failed`) | Deploy attempts since the daemon started; a deploy the reconcile loop retries (a failing pull, for example) counts once per attempt. A deploy rolled back after a failed health gate is counted in `weglarka_rollbacks_total`, not here; a first deploy or a blue-green challenger that fails its gate has nothing to roll back to and counts as `failed`. |
| `weglarka_rollbacks_total` | counter | `app`, `result` (`ok`, `failed`) | Rollbacks to the previous digest after a failed health gate. `failed` means the app needs intervention. |
| `weglarka_app_health_transitions_total` | counter | `app`, `to` (`crash_looping`, `unhealthy`, `recovered`) | Transitions seen by the crash-loop and healthcheck monitor (`[monitor]`). |
| `weglarka_certificate_not_after_seconds` | gauge | `domain` | Expiry of the certificate nginx serves for a routed domain (the webhook domain and every app domain), as a Unix timestamp; a domain served by an `[acme.dns]` wildcard reports the wildcard's expiry. Only with an enabled `[acme]`; a domain without a readable certificate has no line. Re-read at most every 5 minutes. |
| `weglarka_self_update_pending` | gauge | — | 1 while a new daemon image is pinned but the daemon has not confirmed it runs it yet. Only with `[self_update]`. |
| `weglarka_self_update_last_check_timestamp_seconds` | gauge | — | Unix time of the last completed self-update check. |
| `weglarka_self_update_last_error_timestamp_seconds` | gauge | — | Unix time of the last failed or refused self-update attempt; it stays until a later attempt passes the signature check or an update is applied, and is absent when there is none. |

Labels are only ever validated instance names (`app`), routed domains (`domain`) or the fixed values listed above. A
failure reason, an error message, a digest or an image reference never becomes a label: read those with
`weglarka doctor`, `GET /v1/events` or the notifications. Per-app resource use and host metrics are described below;
connecting a Prometheus app is described in [Connecting the scraper](#connecting-the-scraper). An app removed from `apps.toml` keeps its counter lines until the
daemon restarts.

If a file behind a family cannot be read (`apps.toml`, `self-update.toml`), that family is left out of the page and
the page is still served with `200`.

## Per-app resources

Every series carries `app` and `role`:

- an app's container: `app` is the instance name, `role` is `active`, or `challenger`/`retiring` for the `.next`/`.prev`
  containers of a [blue-green deploy](blue-green.md) (a stray copy under another name, which reconcile removes, gets no
  series);
- the ingress (`weglarka-nginx`), the `edge` port forwarder (`weglarka-forwarder`) and the daemon itself (`weglarka`):
  `app` is that name, `role="active"`;
- nothing else. One-off containers (`weglarka run`, `weglarka forward`, volume imports) are skipped: their names carry
  tokens and would start new series on every run. A container without the `weglarka.instance` label that is none of
  the three above is skipped too.

| Metric | Type | Source |
|---|---|---|
| `weglarka_container_memory_usage_bytes` | gauge | working set (libpod `MemUsage`) |
| `weglarka_container_memory_limit_bytes` | gauge | `resources.memory` as Podman stored it; absent when there is no limit |
| `weglarka_container_cpu_seconds_total` | counter | CPU time since the container started |
| `weglarka_container_pids` | gauge | processes and threads |
| `weglarka_container_network_receive_bytes_total` | counter | summed over the container's interfaces, loopback excluded |
| `weglarka_container_network_transmit_bytes_total` | counter | as above |
| `weglarka_container_block_read_bytes_total` | counter | block devices (`io.stat`) |
| `weglarka_container_block_write_bytes_total` | counter | as above |
| `weglarka_container_restarts_total` | counter | restarts by the restart policy (libpod `RestartCount`) |
| `weglarka_container_oom_killed` | gauge | `1` if libpod recorded an out-of-memory kill of this container |
| `weglarka_resource_metrics_up` | gauge | `1` if the last container list and stats calls worked, `0` if either failed or took over 8 s |

Counters restart from zero when a container is recreated (a deploy, a blue-green switch); `rate()` and `increase()`
handle that as a counter reset. The usage numbers exist only for a running container; restarts, the OOM flag and the
limit are also reported for a stopped one.

Each scrape is answered from one container list and one libpod stats call for all containers, cached for 10 seconds:
scrapes within that window, or arriving while a refresh runs, share it. Nothing is sampled between scrapes, so with no
scraper the daemon does no work. If the list or the stats call fails, or libpod does not answer within 8 seconds, the
per-container families are absent, `weglarka_resource_metrics_up` is `0` and `/metrics` still answers `200`; the error
is in the daemon log. Alert on `weglarka_resource_metrics_up == 0`.

### Missing data is no sample, never zero

A value libpod cannot supply is left out rather than reported as `0`, so a dashboard shows a gap instead of a false
"idle":

- memory, CPU and pids of `0` on a running container: libpod writes `0` for a cgroup controller that is not delegated
  to the runtime user; `weglarka doctor`'s `runtime.memory` line reports the same condition;
- block I/O when both directions are `0`: without the `io` controller libpod reads an empty `io.stat` and sends `0`, and
  it cannot be told apart from a container that has not touched a disk yet, so such a container has no block series
  until its first read or write;
- network counters when libpod reports no interface (`--network none`);
- the memory limit when there is none: libpod's stats `MemLimit` then shows the host's RAM, so it is never used.

### Known limits

- **No cumulative OOM counter.** libpod keeps only a flag, set when the container exits after an out-of-memory kill.
  Podman does not clear it when the restart policy starts the container again, so `weglarka_container_oom_killed` reads
  "killed for memory at least once since this container was created", and returns to `0` only when the container is
  recreated. An OOM kill of a child process that does not end the container is not recorded at all.
- **Block I/O needs the `io` controller delegated** to the runtime user's systemd manager. On `myhost`, with the
  runtime user `myuser`:

  ```bash
  cat /sys/fs/cgroup/user.slice/user-$(id -u myuser).slice/user@$(id -u myuser).service/cgroup.controllers
  ```

  Without `io` in the list the block series are absent (systemd's default delegation for user managers is
  `cpu memory pids`; add `io` with a `Delegate=` drop-in for `user@.service`). `weglarka doctor --preflight` mentions a
  missing `io` in its `runtime.cgroups` line; the check stays `ok`, since `io` is optional.

## Host

The daemon reports the host's memory, CPU, load, disks and pressure itself, with no extra container and no host
mount. An unprivileged container sees host-wide values in its own `/proc/meminfo`, `/proc/stat`, `/proc/loadavg` and
`/proc/diskstats` (the kernel does not namespace them), while it still sees only its own processes. The files are
read when the page is scraped. Names and units match [`node_exporter`](https://github.com/prometheus/node_exporter)
where the meaning is exactly the same, so its dashboards and alerts work for these series.

| Metric | Type | Labels | Source |
|---|---|---|---|
| `node_memory_MemTotal_bytes` | gauge | — | `/proc/meminfo` `MemTotal` |
| `node_memory_MemAvailable_bytes` | gauge | — | `/proc/meminfo` `MemAvailable` (what new work can get without swapping) |
| `node_memory_SwapTotal_bytes` | gauge | — | `/proc/meminfo` `SwapTotal` |
| `node_memory_SwapFree_bytes` | gauge | — | `/proc/meminfo` `SwapFree` |
| `node_cpu_seconds_total` | counter | `cpu` (`0`, `1`, …), `mode` (`user`, `nice`, `system`, `idle`, `iowait`, `irq`, `softirq`, `steal`) | `/proc/stat`, per CPU |
| `node_boot_time_seconds` | gauge | — | `/proc/stat` `btime`, a Unix timestamp |
| `node_load1`, `node_load5`, `node_load15` | gauge | — | `/proc/loadavg` |
| `node_disk_read_bytes_total` | counter | `device` | `/proc/diskstats`, sectors read × 512 |
| `node_disk_written_bytes_total` | counter | `device` | `/proc/diskstats`, sectors written × 512 |
| `node_pressure_cpu_waiting_seconds_total` | counter | — | `/proc/pressure/cpu`, `some` |
| `node_pressure_memory_waiting_seconds_total` | counter | — | `/proc/pressure/memory`, `some` |
| `node_pressure_memory_stalled_seconds_total` | counter | — | `/proc/pressure/memory`, `full` |
| `node_pressure_io_waiting_seconds_total` | counter | — | `/proc/pressure/io`, `some` |
| `node_pressure_io_stalled_seconds_total` | counter | — | `/proc/pressure/io`, `full` |
| `node_vmstat_oom_kill` | counter | — | `/proc/vmstat` `oom_kill`: out-of-memory kills on the host since boot |
| `node_filefd_allocated` | gauge | — | `/proc/sys/fs/file-nr`, first field |
| `node_filefd_maximum` | gauge | — | `/proc/sys/fs/file-nr`, third field |
| `weglarka_storage_size_bytes` | gauge | — | libpod `GET /info` `store.graphRootAllocated`: the filesystem holding container storage |
| `weglarka_storage_used_bytes` | gauge | — | libpod `GET /info` `store.graphRootUsed`: bytes used on it, by anything |

Details:

- The `cpu` label counts CPUs the host has, not the CPUs the daemon's container may use. `guest` time is already
  included in `user` and `nice`; there is no `node_cpu_guest_seconds_total`.
- Disks: `node_exporter`'s default filter applies (no `loop`, `ram`, `zram` or `fd` devices and no `sdXN`, `vdXN`,
  `xvdXN`, `hdXN` or `nvmeXnYpZ` partitions), plus `mmcblkXpY` partitions, so a host has one series per disk and
  device-mapper volume, not one per partition and loop mount. Host disk counters come from the kernel and do not need
  the `io` controller; the per-app block I/O series do.
- Pressure (PSI) needs a kernel with `CONFIG_PSI` and PSI enabled; without `/proc/pressure` those families are absent.
- Container storage is one `/info` call, cached for 60 seconds: the call is slower than stats and disk use moves
  slowly. It uses `weglarka_` names rather than `node_filesystem_*` because there is no real mount point to put in a
  `mountpoint` label. The host's free memory from the same call is not used: it is free memory, not available memory.
- A file that is missing or cannot be parsed drops only its own families (logged at debug level), and a failed or slow
  `/info` call drops only the storage families; `/metrics` still answers `200`.

### Deliberately missing

- **Host network traffic.** `/proc/net` belongs to a network namespace: in the daemon's container it would describe the
  daemon's own interfaces, so no `node_network_*` family is exported. Per-app traffic is in
  `weglarka_container_network_*`.
- **Other mount points.** Only the container storage filesystem is known (from libpod); the daemon cannot see the
  host's other filesystems without a mount.
- **Hardware** (`hwmon`, temperatures, SMART), **`systemd`** unit state and **`textfile`** collectors: they need host
  `/sys`, the host's D-Bus or a host directory.

If you need those, run a full `node_exporter` as an ordinary option next to Węglarka, for example as a host service or a
container started by your own unit with the mounts its documentation asks for, and scrape it as a second target. Its
`node_*` series then come with an `instance` label of their own, so drop the duplicate families from one of the two
targets (`metric_relabel_configs`) if both are scraped.

## Opting an app in

An app that serves its own Prometheus endpoint declares the port (and, when it is not `/metrics`, the path):

```toml
[apps.forge]
image = "ghcr.io/example/forge:1"
metrics_port = 9100
metrics_path = "/internal/metrics"   # optional; the default is /metrics
```

or with the CLI:

```bash
weglarka apps update forge --metrics-port 9100 --metrics-path /internal/metrics
```

On the next deploy the daemon creates an `internal` Podman network `metrics-forge` (no route out, labelled
`weglarka.metrics-for=forge`) and attaches the app's container to it. Each opted-in app gets its own network, shared
only with the scraper: on one network for every app, opted-in apps could reach each other, and putting the scraper on
`net-forge` would expose every port of the app. One-off containers (`weglarka run`, `weglarka forward`) never join it.

- **Setting or changing `metrics_port` recreates the container once** (it changes the container's networks), like
  joining a shared network. `metrics_path` alone recreates nothing; only the scraper reads it. Apps that do not set
  either are untouched by the upgrade.
- `metrics_port` is a non-zero port; `metrics_path` starts with `/`, uses only `[A-Za-z0-9_.-]` segments (no query,
  fragment, `..` or trailing `/`) and needs `metrics_port`. A `kind = "static"` app has no container and rejects both.
- **Opting out** (`--metrics-port none`, which also drops the path) recreates the container without the network, and
  the same reconcile pass removes `metrics-forge`. A removed app takes its network with it. Removal is best effort: a
  network something is still attached to stays until a later pass.
- **Blue-green apps** ([blue-green deploys](blue-green.md)): the challenger joins `metrics-<app>` only after its health
  gate, together with the app network and with the instance name as its alias, so a target `forge:9100` resolves
  through the whole switch and never reaches a challenger that failed its gate.
- Nothing checks that the app really listens on the port: a wrong port is a failed scrape later, not a failed deploy.
- `weglarka apps show forge` lists both fields; a `read` token sees them as well.

The scraper reaches these networks once it is named in `[metrics] scraper` (see
[Connecting the scraper](#connecting-the-scraper)). **Not there yet:** no scrape targets are generated, so the scraper's
configuration still has to list `forge:9100` itself; generated targets come with #366.

## Connecting the scraper

Prometheus (or any other scraper) runs as an ordinary managed app: a host service cannot join a Podman network. Name it
in `weglarka.toml`:

```toml
[metrics]
listen = "0.0.0.0:9464"
scraper = "prometheus"    # an app in apps.toml
```

and restart the daemon. From then on reconcile keeps that app's container on the daemon's network (`[metrics] network`,
so it can scrape `weglarka:9464`) and on the `metrics-<app>` network of every opted-in app, never on `net-<app>`:

- The membership is live (`podman network connect`/`disconnect`): **opting an app in or out never restarts the
  scraper**. A late opt-in is joined during the deploy that creates the app's network; every reconcile pass checks the
  rest.
- A recreated scraper (a new image, a spec change) is created on its networks, and a recreated app keeps its network,
  so the scraper stays on it. A [blue-green](blue-green.md) scraper's challenger is created on the metrics networks
  before its health gate: it only reads, so scraping early is harmless, and the serving scraper is on them through the
  whole switch.
- Opting an app out detaches the scraper from `metrics-<app>` in the same pass that removes the network.
- The role is host config, like `[admin.http] clients`: no app can grant it to itself. One-off containers of the
  scraper (`weglarka run`, `weglarka forward`) never join.
- **Removing or moving the role** (deleting `scraper`, or naming another app) detaches the former scraper on the next
  pass after the restart. The engine owns the membership of managed app containers on the metrics networks: an app's
  own containers stay on its own `metrics-<app>`, the scraper stays where it should be, and any other managed app
  container is detached. A container Węglarka does not manage (no `weglarka.instance` label, such as the one-off
  `podman run --network metrics` in [Checking it](#checking-it)) is never touched.
- Without `scraper` nothing joins automatically.

`weglarka doctor` shows a `metrics.scraper` line when `scraper` is set: `ok` with the networks the scraper is on, `warn`
when the app is not in `apps.toml`, has no running container, or is missing from a network it should be on (the next
pass connects it; the daemon log says why it could not). It is never `fail`, and absent without `scraper`.
`GET /v1/config` shows the field.

## Suggested alerts

```yaml
groups:
  - name: weglarka
    rules:
      - alert: WeglarkaCertificateExpiresSoon
        # The ACME worker renews well before this; 14 days left means renewals are failing.
        expr: weglarka_certificate_not_after_seconds - time() < 14 * 24 * 3600
        for: 1h
        annotations:
          summary: "Certificate for {{ $labels.domain }} expires in under 14 days"
      - alert: WeglarkaRollback
        expr: increase(weglarka_rollbacks_total{result="ok"}[1h]) > 0
        annotations:
          summary: "{{ $labels.app }} was rolled back after a failed health gate"
      - alert: WeglarkaRollbackFailed
        expr: increase(weglarka_rollbacks_total{result="failed"}[1h]) > 0
        labels:
          severity: critical
        annotations:
          summary: "{{ $labels.app }} failed its health gate and the rollback failed too"
      - alert: WeglarkaResourceMetricsDown
        # The container list or stats call failed or timed out; the per-container families are missing.
        expr: weglarka_resource_metrics_up == 0
        for: 5m
        annotations:
          summary: "Per-app resource metrics on {{ $labels.instance }} are unavailable"
      - alert: HostMemoryLow
        expr: node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes < 0.1
        for: 10m
        annotations:
          summary: "Under 10% memory available on {{ $labels.instance }}"
      - alert: ContainerStorageFull
        expr: weglarka_storage_used_bytes / weglarka_storage_size_bytes > 0.9
        for: 30m
        annotations:
          summary: "Container storage on {{ $labels.instance }} is over 90% full"
      - alert: WeglarkaSelfUpdatePending
        # A pinned image the daemon still does not run after 30 minutes: the switch did not take effect.
        expr: weglarka_self_update_pending == 1
        for: 30m
        annotations:
          summary: "Self-update on {{ $labels.instance }} is pending for over 30 minutes"
```

`weglarka doctor` on `myhost` explains each of these in detail (`acme.certs`, the app state, `self_update`).

## Rollback

`[metrics]` is a new section of `weglarka.toml`, and the file uses `deny_unknown_fields`: an older Węglarka refuses to
start while it is present. Remove `[metrics]` before downgrading. The listener itself adds no `apps.toml` or
`state.toml` field.

`[metrics] scraper` is a newer field of that section: a Węglarka from before it refuses the file while the field is
there, even if it knows `[metrics]`. Remove the line before downgrading (the section can stay for a version that has
it). The scraper's network membership is not undone by the downgrade: detach it by hand if you no longer want it
(`podman network disconnect metrics-<app> <scraper>`, and the same for the daemon's network); it ends anyway when the
scraper's container is recreated. The field adds nothing to `apps.toml` or `state.toml`.

`metrics_port` and `metrics_path` are new `apps.toml` fields, and they bump [`schema_version`](state-schema.md) to 16.
A daemon from before them refuses an `apps.toml` stamped 16 (and would refuse the fields themselves). Before
downgrading, opt every app out (`weglarka apps update <app> --metrics-port none`) and restore `apps.toml` and
`state.toml` from a backup taken before the upgrade, or set `schema_version` back by hand once neither field is
left; remove the leftover `metrics-<app>` networks with `podman network rm` if the opt-out pass did not. The network and the membership are not removed by the downgrade;
delete the empty network with `podman network rm metrics` if you no longer need it.
