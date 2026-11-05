# Ingress log retention

The ingress access log contains visitor IP addresses, request paths and user agents; `error.log` can contain client
addresses too. This is personal data. Węglarka writes both logs to files it owns, rotates them once a day and deletes
them after a configurable number of days, so a privacy policy can state a period and the host actually keeps to it.
Decision and rejected alternatives: [ADR 0070](../decisions/0070-ingress-log-retention.md).

## Configuration

```toml
# weglarka.toml
[logs]
# Days (1..=3650) or the explicit "unlimited".
retention = 30
```

- **Default:** 30 days when `[logs]` is absent.
- **`retention = "unlimited"`:** rotation continues, but nothing is deleted. Use it only if another mechanism removes
  the files; it defeats the purpose of this feature.
- **`0` is rejected.** It would be too easy to read as "delete immediately"; there is no way to disable deletion except
  `"unlimited"`.
- The setting is host-wide, not per app. nginx writes one access log shared by every app; per-app periods would need
  separate files per app.

`weglarka status` shows the active value (`ingress logs kept: 30 days` or `ingress logs kept: unlimited`). `weglarka
doctor` adds a `logs.retention` check with the directory, the number and size of files, the directory mode and the last
pass.

## Where the files are

```text
<state dir>/ingress-logs/          # mode 0700, only the runtime user
├── access.log                     # current day
├── error.log                      # current day
├── .logdate                       # UTC date the current files belong to
├── access-2026-11-03.log          # completed days
└── error-2026-11-03.log
```

The directory is a writable bind mount at `/var/log/weglarka` in the nginx container. It is deliberately outside
`<nginx_conf_dir>`, so a backup of the configuration does not copy visitor addresses. A backup of the **state
directory** does contain this directory and therefore visitor IPs; handle it as personal data. nginx does not log requests to
its stdout any more; the Podman log of that container keeps only startup/config diagnostics.

The daemon checks once an hour. On the first pass of a UTC day it renames the current files to the completed
`YYYY-MM-DD` names and sends `SIGHUP` to nginx (the master opens the new files; workers inherit the descriptors).
Completed files are deleted when their UTC date is `retention` or more days before today. A file that cannot be
renamed (a collision from an earlier crash) gets a `.1`, `.2`, … suffix instead of overwriting data.

## The guarantee, precisely

- A completed file dated `D` is deleted when today is `D + retention` (UTC), so a line is normally gone within
  `retention` days and at most **`retention + 1` days**: the current file also holds the lines written since the last
  hourly pass.
- If the daemon was down across a day boundary, the first rotation groups that backlog in the file named for the
  day recorded in `.logdate` (the day the current file started), not for its last write. Those lines can live longer
  than `retention + 1`, and a `--since` window after the downtime may not select the whole backlog; the daemon cannot
  split a file it was not running for without reading and rewriting it. This is a deliberate limitation of the first
  version.
- `retention = "unlimited"` means no deletion at all.

A privacy policy for a site behind Węglarka can therefore say, for example: “The server keeps access logs
containing IP addresses for 30 days (at most 31 days) and then deletes them.” Use the value from your own
`weglarka.toml`.

## Container logs (app, nginx, forwarder)

What a container prints to stdout/stderr (`weglarka logs`) is stored by Podman, not by Węglarka, and may contain
secrets or visitor addresses the app logs itself. Without configuration `containers.conf` picks the driver, which
differs between hosts. Pin it ([ADR 0074](../decisions/0074-container-log-driver.md)):

```toml
# weglarka.toml
[logs]
container_driver = "k8s-file"   # or "journald"
container_max_size = "10m"      # k8s-file only: bytes or <n>[k|m|g]
```

| Driver | Where the output lives | How long |
|---|---|---|
| `journald` | the host's systemd journal | until the host's journal retention removes it (`SystemMaxUse=`, `MaxRetentionSec=` in `journald.conf`); shared by every unit and **not managed by Węglarka**. Needs systemd: not available on Alpine/OpenRC hosts |
| `k8s-file` | a file in the container's runtime directory | until the container is removed (every deploy, recreate or `apps remove` deletes it); with `container_max_size` also bounded: when the file reaches the size, conmon truncates it and the oldest output is lost |

- `container_max_size` with `journald` (or without a driver) is rejected when the config is read.
- Unset keeps the create request unchanged, so `containers.conf` decides, as before.
- Applies to app containers and to nginx and the forwarder. It does **not** apply to `weglarka run` and `weglarka
  forward` containers, which keep the host default and live only briefly.
- It is **not** part of an app's spec hash: changing it recreates nothing. A container uses the new setting from its
  next create (a deploy, `deploy --force`, or the next recreate of nginx or the forwarder). `weglarka doctor` check
  `logs.container_driver` lists the containers still on another driver, and warns when `k8s-file` has no size bound.
- No time-based period exists for container output yet (planned with the log collector). For a privacy policy: with
  `k8s-file` you can say the output is kept at most until the app's next deploy and at most the configured size; with
  `journald` the period is whatever the host's journal retention is, which Węglarka neither sets nor checks. A size
  bound is not an age bound: a quiet app can keep old lines for a long time.

## What this does not cover

- **Age-based retention of app container logs.** `weglarka logs` streams what the app's container printed; Podman
  stores it. Węglarka can pin the driver and a size bound (see [Container logs](#container-logs-app-nginx-forwarder))
  but does not prune by age. If an app logs visitor addresses itself, configure its own retention or avoid logging
  them.
- **Traefik's logs in `behind` mode.** Traefik is outside Węglarka and has its own log configuration and retention.
- **The daemon's journal.** The daemon does not log request lines, but the journal is managed by systemd.
- **The old container log.** Before the first start with this feature, nginx logged to Podman's container log. It is
  removed together with the nginx container on the one-time recreate; nothing imports it.
- **The temporary port forwarder's debug log.** A `debug` build of the forwarder can name peers; production runs at
  `info`.

## Reading the log

`weglarka access <app>` reads the same files: completed files whose last write is inside the requested window, then
the current `access.log`. `--since`, `--tail`, the filters and `--follow` are unchanged. History now survives an nginx
recreate and is bounded by the retention period; follow starts at the byte/inode where history stopped, so a line is
not repeated within one connection. A rotation during follow can still lose a line written by an old worker at the
switch, and reconnecting with `--since` can show a line twice; both are best-effort, as before.

## Disk use

Retention bounds age, not the daily volume. At roughly 300 bytes per JSON line, 100 000 requests a day is about
30 MB/day and about 900 MB for 30 days. A noisy health check or polling client can dominate the volume; leave its
successful requests out with [`access_log_skip_paths`](access-log.md).

## Rollback

This is not a state-file schema change: nothing in `apps.toml` or `state.toml` changes and `SCHEMA_VERSION` stays 18.
`[logs]` is host configuration, and an older daemon's `HostConfig` has `deny_unknown_fields`:

1. Remove the `[logs]` section from `weglarka.toml` before starting the older daemon. (A daemon that has
   ingress retention but not container logs refuses only `container_driver` and `container_max_size`: remove those two
   keys. Containers already created keep their driver; nothing else changes.)
2. Remove `<state dir>/ingress-logs` (or restore the directory from a backup). It contains personal data and the older
   daemon does not prune it.
3. Expect the older daemon to recreate nginx once (old hash format) and to write request logs to stdout again. Old
   completed files left in the directory are not read by it.

See [verification and rollback](verify-and-rollback.md).
