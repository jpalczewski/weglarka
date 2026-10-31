# A managed Prometheus

A worked example that puts the [metrics](metrics.md) pieces together: Prometheus as an ordinary Węglarka app on `myhost`,
scraping the daemon and every app that opts in. Targets are generated, so adding an app never means editing
`prometheus.yml` or restarting Prometheus. [Metrics](metrics.md) is the reference for each setting; this guide is the
order to do things in and what to expect.

Prometheus has to be a managed app for this. A host service cannot join a Podman network, so it cannot reach the daemon's
listener or any `metrics-<app>` network.

## Before you start

You need a Węglarka with `[metrics] scraper` and `metrics_port`, and a `config_root`
([host config files](host-configs.md)). Choose the app name now; this guide uses `prometheus`.

## The config file

Put a small `prometheus.yml` under `config_root`, in its own directory:

```yaml
# <config_root>/prometheus/prometheus.yml
global:
  scrape_interval: 15s

rule_files:
  - /config/rules/*.yml

scrape_configs:
  - job_name: weglarka
    file_sd_configs:
      - files:
          - /weglarka/generated/current/targets.yml
        refresh_interval: 30s
```

Keep these as they are:

- **List `targets.yml` by name**, not a `*.yml` glob: the directory also holds `promtool-check.yml`, which is not a target
  list.
- **Keep `refresh_interval` short.** The file is switched by renaming a symlink, which Prometheus' file watch does not
  see, so a new target waits for this interval (5 minutes by default).
- **Leave `honor_labels` off.** With it on, an opted-in app could publish series under another app's labels.

Files must be readable by `nobody` inside the container (`0644`, directories `0755`). A directory created with `mktemp` is
`0700` and will not do.

## Name the scraper

In `weglarka.toml`:

```toml
[metrics]
listen = "0.0.0.0:9464"   # inside the daemon's container; not published on the host
scraper = "prometheus"
```

Restart the daemon. Do this **before** adding the app, so the first container already has its mounts and networks. In the
other order the app is recreated once. `listen` must not be a loopback address: the scraper could never reach it, and
`weglarka doctor` warns about that.

Until the app exists, `metrics.scraper` in `weglarka doctor` is a `warn`. That is expected at this step.

## The app

```toml
# prometheus.toml
image = "docker.io/prom/prometheus:v3.5.0"
auto_update = false
volumes = [{ name = "data", target = "/prometheus" }]
configs = [{ source = "prometheus", target = "/config" }]
resources = { memory = "256m" }
reload_signal = "SIGHUP"
command = [
  "--config.file=/config/prometheus.yml",
  "--storage.tsdb.path=/prometheus",
  "--storage.tsdb.retention.time=15d",
  "--web.listen-address=:9090",
]
```

```bash
weglarka apps add prometheus --spec prometheus.toml
```

- **No domain and no published port.** Prometheus has no login of its own. See [Reaching the UI](#reaching-the-ui).
- **`auto_update = false`.** Update it deliberately, and read the release notes first: an update can change how it stores
  data.
- **A digest-pinned or exact tag.** The validator runs `promtool` from this image, so a scraper image without `promtool`
  has every new target file rejected. The official image has it.
- **`command` replaces the image's default arguments**, so `--storage.tsdb.path` must be set here.
- **The volume** needs no ownership settings: the image runs as `nobody`, and the app's UID range handles it.
- **The memory limit** depends on your number of series and on retention. The value above is a starting point. Watch
  `weglarka_container_memory_usage_bytes{app="prometheus"}` and raise it before it is reached.
- **Mount the directory, not the single file.** An editor that saves by renaming would leave a single-file mount on the
  old content ([host config files](host-configs.md)).

To apply a later change to `prometheus.yml` or the rules:

```bash
weglarka apps reload prometheus
```

That is only for your own files. The generated targets never need it.

## Opting an app in

```bash
weglarka apps update forge --metrics-port 9100
weglarka apps update forge --metrics-path /internal/metrics   # only if it is not /metrics
```

Setting `metrics_port` recreates `forge` once. Prometheus keeps running and joins `metrics-forge` live. Allow for the
recreate plus `refresh_interval` before the target appears. Changing only the path recreates nothing and shows up within
`refresh_interval`.

Prometheus can opt in too, to scrape itself: `weglarka apps update prometheus --metrics-port 9090`.

## Checking it

```bash
weglarka doctor
weglarka forward prometheus 9090
```

In `doctor`, `metrics.listener` and `metrics.scraper` are `ok` and `generated.metrics-targets` is applied. The first
render is `info` and says `unvalidated`, since nothing could run `promtool` before the first deploy; the next one is
checked.

Then open `http://localhost:9090/targets`: the daemon is `weglarka:9464` and each app is `<app>:<metrics_port>`, labelled
`app`. The daemon's target has no `app` label on purpose. Its own per-app series already carry one.

| What you see | Why | What to do |
|---|---|---|
| App is `down`, "blank Content-Type" | Prometheus 3 refuses a page without a `Content-Type`, and some small HTTP servers send none for a file with no extension | Make the app send `text/plain`, or set [`fallback_scrape_protocol`](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#scrape_config) on the job |
| App is `down`, connection refused | Nothing listens on `metrics_port`; Węglarka does not check it | Fix the port, or make the app listen on all addresses and not only `127.0.0.1` |
| A stopped app is `down` | Every opted-in app is listed whether it runs or not | Nothing, or opt it out |
| Daemon is `down` | `[metrics] listen` is a loopback address, or the daemon has not joined its network | Read `metrics.scraper` and `metrics.listener` in `doctor` |
| `generated.metrics-targets` reports a failure | `promtool` rejected the file, is missing from the image, or did not finish in time | Read the output in `doctor`. [Metrics](metrics.md) explains how a check that did not finish is cleared |
| New target does not appear | Still within `refresh_interval`, or the job does not list the file | Wait for the interval, then compare the job with the config above |

## What can reach what

The networks limit who talks to whom, not which ports:

| From | Can reach | Cannot reach |
|---|---|---|
| Prometheus | Every port of every opted-in app, and the daemon's listener | nginx, apps that did not opt in |
| An opted-in app | **Every port of Prometheus**, over the network they share | Other opted-in apps, the daemon's listener, nginx through this network |

So an opted-in app can read everything Prometheus has stored through its query API. Before opting in an app you trust
less than your metrics:

- **Do not add `--web.enable-admin-api` or `--web.enable-lifecycle`.** With them, an opted-in app could delete data or shut
  Prometheus down.
- If the metrics are sensitive, protect the API with Prometheus' own
  [`--web.config.file`](https://prometheus.io/docs/prometheus/latest/configuration/https/) authentication. The job then needs
  credentials if Prometheus scrapes itself.

In the other direction, keep an app's other listeners off this network's reach: bind them to `127.0.0.1` inside the
container or give them their own authentication.

## Alerts

Add rule files to `<config_root>/prometheus/rules/`, for example the rules in the "Suggested alerts" section of
[metrics](metrics.md), then run `weglarka apps reload prometheus`. Without an `alerting` section they only show up on the
`/alerts` page. To be notified, run Alertmanager as another app and point `alerting` at it over a
[shared network](shared-networks.md).

## Reaching the UI

- **For a look:** `weglarka forward prometheus 9090` ([port forward](port-forward.md)). This is the default, and nothing
  stays open.
- **Permanently:** a domain with login in front of it, through [forward auth](forward-auth.md):

  ```toml
  domains = ["prometheus.example.com"]
  port = 9090

  [ingress]
  auth = "forward"
  auth_groups = ["admins"]
  ```

  Never give Prometheus a domain without `auth`: the API is open to anyone who reaches it.
- **Grafana** as another app reaches Prometheus over a [shared network](shared-networks.md), at
  `http://prometheus:9090`.

## Next to an existing Prometheus

If a Prometheus already runs on the host, keep it while the new one fills up. They do not conflict: the managed one
publishes no port and uses its own storage.

1. Set up the managed one as above, and leave the old one alone.
2. Compare the two for a while. The daemon's host metrics use `node_exporter` names and units, so dashboards and alerts
   built for those keep working. There are deliberately no host network counters and only one filesystem; see
   [metrics](metrics.md). If you need those, keep `node_exporter`.
3. Before turning the old one off, find what still depends on it: anything writing with `remote_write`, alert rules,
   dashboards, tunnels and scripts that read its port. Check for what connects over a longer period, not at one moment.
4. Move those over. Reach the managed one through a shared network or forward auth, since it publishes no port.
5. Stop scrapers you no longer need (cAdvisor, for example), then the old Prometheus.

Old data is not migrated. Keep the old data directory for as long as you may want to look at it, by starting the old
Prometheus against it when needed.

## Removing it

1. Remove `scraper` from `[metrics]` and restart the daemon. The app is recreated without its generated mount and leaves
   the metrics networks, so its `file_sd_configs` entry now points at nothing.
2. Remove the app. `--purge-volumes` also deletes the stored metrics; `apps remove` has no undo.

   ```bash
   weglarka apps remove prometheus --purge-volumes
   ```

3. Opt apps out if you no longer want them on a metrics network. Each is recreated once, and its network is removed in that
   reconcile pass, which can take a little while because the recreate comes first.

For downgrading Węglarka past these fields, see the rollback section of [metrics](metrics.md).
