# 0070 — Daemon-owned ingress logs with a retention period

Status: accepted (2026-11-04, issue #502)

## Problem

The ingress access log contains visitor IP addresses (`remote_addr`, and behind a CDN the visitor field), paths and
user agents. That is personal data: a site behind Węglarka has to state a retention period in its privacy policy and
then keep to it. Today nginx writes the access log to its stdout, Podman stores it in the container's `k8s-file` log
and nothing deletes it. `error.log` (stderr) also carries client addresses in its messages.

The container runtime cannot express the requirement:

- Podman's `k8s-file` driver offers `max-size`/`max-file` — a size bound, not a number of days. At a low request rate a
  size bound can keep data far longer than a privacy policy allows; at a high rate it can throw away recent data.
- `journald` retention is host-global and needs configuration outside Węglarka and outside the runtime user.
- The daemon cannot truncate or rewrite Podman's log files safely: there is no API for it, the files live outside the
  daemon's mounts, and a concurrent append with a truncation corrupts the runtime's reader.

Constraints, in priority order: security → elegant, extensible code → RAM economy. The change must not put the log
where a configuration backup can pick it up, must not expose it to other local users, and must not make
`weglarka access` (ADR 0063) stop working.

## Decision

**Węglarka owns the ingress access and error files. nginx writes them into a daemon-managed directory, the daemon
rotates them once per UTC day and deletes completed files after `[logs] retention`.**

1. **Location and permissions.** `<state dir>/ingress-logs`, mode `0700`, owned by the runtime user. It is a separate
   writable bind mount at `/var/log/weglarka` in the nginx container, *not* a subdirectory of `<nginx_conf_dir>`: a
   backup of the configuration must never contain visitor addresses.
2. **Config.** `[logs] retention = 30` in `weglarka.toml`; valid values are `1..=3650` days or the explicit string
   `"unlimited"`. The source is `LogRetention` (`Days(u32)` / `Unlimited`); `0` is rejected on purpose. A host setting,
   not an app setting: nginx writes one shared log for every app, so per-app retention would need separate files.
3. **Daily files.** The current files are `access.log` and `error.log`. On the first pass of a UTC day the daemon
   renames them to `access-YYYY-MM-DD.log` / `error-YYYY-MM-DD.log` and records the new date in a sidecar
   (`.logdate`), so a restart just after midnight cannot merge two days. Completed files dated `retention` or more days
   before today are deleted; `unlimited` skips deletion but still rotates.
4. **Reopen with `SIGHUP`, never `SIGUSR1`.** After a rotation the daemon runs `nginx -t` and sends `HUP` through
   `IngressManager::reopen_logs()`, serialized with every other ingress apply. `HUP` makes the master (container uid 0,
   the daemon's host user) open the new files; new workers inherit the descriptors. `SIGUSR1` would ask the **worker**
   (uid 101) to reopen the path itself, and it cannot: the directory is `0700` and the files `0644`, both owned by the
   daemon's user; without `CAP_DAC_OVERRIDE` the reopen fails and nginx keeps writing to the renamed file.
5. **`weglarka access` reads the files.** History selects completed files whose date is inside `since` and then the
   current `access.log`; `since` is applied to the line's `$time_iso8601`. Follow starts at the byte offset and
   `(dev, ino)` where history stopped, so a line is sent exactly once within one stream; a rotation during history is
   handled by draining the old descriptor first and then switching to the new file. The 404 for a missing nginx
   container goes away: the log no longer belongs to it, and history survives its recreation.
6. **One-time recreate.** The nginx container gets a new mount and `INGRESS_HASH_FORMAT` moves to v6, so the first
   daemon with this feature recreates it once. Request logs from before the upgrade (Podman's container log) are lost
   with the old container; that is acceptable and privacy-positive.
7. **Observability.** `weglarka status` shows the period (`ingress logs kept: 30 days` / `unlimited`); `doctor` reports
   the directory, the number and size of files, the mode, and the last pass (`logs.retention`). Neither exposes log
   content or addresses.

### Guarantee in the guide

A completed file is deleted when its UTC date is `retention` days or more before today. The current file contains
today, plus at most the lines written since the last hourly pass, so a line can live up to one day longer than the
configured number. If the daemon was down across days, the first rotation puts the backlog in one file named for its
last write; those lines may live longer. `docs/guides/log-retention.md` states both bounds, so a privacy policy can
quote them. Strictly splitting a backlog by `time` is a follow-up, not part of this change.

## Consequences

- New host config `[logs]`, new state path `<state>/ingress-logs`, new `StatusResponse.log_retention`
  (`Option<LogRetention>`, so a new CLI can talk to an older daemon).
- New background worker (`log_retention`) with a pass at startup and hourly; no state-file schema change.
- nginx no longer logs requests to stdout; Podman's nginx container log keeps only startup/config diagnostics. App
  containers' stdout/stderr logs are unchanged and remain Podman's: Węglarka does not keep them. Traefik's own logs
  (`behind`) and the daemon's journal are outside this feature; the guide says so explicitly.
- `weglarka access` history now survives an nginx recreate and is bounded by the retention period.
- Tests: UTC date arithmetic, rotation with the sidecar and collisions, prune at the boundary and `unlimited`,
  `access` from files (history, follow, rotation, `since`, tail, partial line), `status` and `doctor`, and the ingress
  mount/mode.
- Rollback: remove `[logs]` before downgrading (an older `HostConfig` denies unknown fields), remove
  `<state>/ingress-logs` (it contains personal data and no older daemon prunes it), and expect the older daemon to
  recreate nginx and return to stdout. No `apps.toml`/`state.toml` change and no `SCHEMA_VERSION` bump.

## Rejected alternatives

- **Podman `max-size`/`max-file`.** Bounds bytes, not days; the privacy promise would be false at a low request rate.
- **journald with `MaxRetentionSec`.** Host-global, root-owned, outside the runtime user and outside `weglarka.toml`.
- **Truncating Podman's `ctr.log` through a mount.** Undocumented, storage-driver-specific and racy with the runtime's
  appender; a truncation can lose the recent lines as well as the old ones.
- **A logrotate sidecar container.** Another image and process to supervise, and it still does not give the access
  endpoint a stable source.
- **`SIGUSR1`.** See decision 4: the worker cannot reopen the daemon-owned path; the rotation fails silently and the
  pruner can delete a file nginx still writes to.
- **`copytruncate`.** The window between the copy and the truncation drops lines; the files are already opened by the
  master, so a rename plus `HUP` has no such window.
- **`access_log` with a variable path (`$time_iso8601`).** Gives exact daily files without a rotation, but nginx opens
  files with variables in the **worker**, which would need write access to the personal-data directory; `error_log`
  does not support variables at all. The daemon-owned static file keeps the worker out of the directory.
- **`[logs] retention = 0` as "keep forever".** Too easy to misread as "delete immediately"; `"unlimited"` is
  explicit and greppable.
- **Per-app retention.** The access log is one shared file (ADR 0063); per-app periods would either need one file per
  app (a larger ingress change) or a rewrite of shared files per app.
