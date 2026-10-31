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
resources call Podman (see [Per-app resources](#per-app-resources)).
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
`weglarka doctor`, `GET /v1/events` or the notifications. Per-app resource use is described below; host metrics come
with #353 and discovery by a Prometheus app with #36. An app removed from `apps.toml` keeps its counter lines until the
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
  `cpu memory pids`; add `io` with a `Delegate=` drop-in for `user@.service`).

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

**Not there yet:** nothing joins the scraper to these networks and no scrape targets are generated, so opting in alone
does not get the app scraped. Connecting a Prometheus app comes with #365, and generated targets with #366.

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

`metrics_port` and `metrics_path` are new `apps.toml` fields, and they bump [`schema_version`](state-schema.md) to 16.
A daemon from before them refuses an `apps.toml` stamped 16 (and would refuse the fields themselves). Before
downgrading, opt every app out (`weglarka apps update <app> --metrics-port none`) and restore `apps.toml` and
`state.toml` from a backup taken before the upgrade, or set `schema_version` back by hand once neither field is
left; remove the leftover `metrics-<app>` networks with `podman network rm` if the opt-out pass did not. The network and the membership are not removed by the downgrade;
delete the empty network with `podman network rm metrics` if you no longer need it.
