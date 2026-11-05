# 0074 — Explicit log driver and size bound for containers

Status: proposed (2026-11-05, issue #554)

## Problem

Węglarka sets no log driver or log options on its containers, so `containers.conf` decides: `journald` with
host-global retention on systemd hosts, `k8s-file` without a size bound (and deleted on every recreate) on hosts without
journald (Alpine with OpenRC). Disk use and the lifetime of container output, which may hold secrets and visitor
addresses, are unpredictable and differ between the supported host families.

Constraints, in priority order: security → elegant, extensible code → RAM economy. Hosts are Ubuntu with systemd or
Alpine with OpenRC, so no design may assume journald, and the daemon must not rewrite Podman's log files (no API, and a
concurrent truncation corrupts the runtime's reader; the same reasoning as ADR 0070).

## Decision

**The operator may pin the log driver and a size bound in `weglarka.toml`; Węglarka sends them in the create request of
the containers it manages.**

1. **Config.** `[logs] container_driver = "journald" | "k8s-file"` and `[logs] container_max_size = "10m"` (bytes or
   `<n>[k|m|g]`, `> 0`; type `ByteSize`). `container_max_size` is valid only with `k8s-file`: with `journald` the
   host's `journald.conf` owns retention and the key would be a promise Węglarka cannot keep; without a driver it is
   rejected too. Unset keeps today's request byte for byte, so `containers.conf` still decides.
2. **Model and wire.** `ContainerSpec.log: Option<ContainerLog { driver: LogDriver, max_size: Option<u64> }>` becomes
   libpod's `log_configuration: { driver, size }` (`size` in bytes, omitted when unset; the equivalent of
   `--log-driver` and `--log-opt max-size=`). `ContainerInfo.log_driver: Option<String>` is read from inspect
   (`HostConfig.LogConfig.Type`). All additive; `FakePodman` records the spec and reports the driver (default
   `journald`, standing for `containers.conf`).
3. **Not in `spec_hash`.** The setting applies from the next container create. Changing it recreates nothing, so a
   host-wide edit cannot cause a fleet restart; an app picks it up on its next deploy or recreate, nginx and the
   forwarder on their next recreate. A container's logs cannot change driver in place anyway.
4. **Scope.** App containers (serving and blue-green challengers) and the system containers (nginx, forwarder). Not
   the short-lived `run` and `forward` containers: they keep the host default and are removed when they finish.
5. **`doctor`.** Check `logs.container_driver`, present only when `container_driver` is set: `warn` lists managed
   long-lived containers whose recorded driver differs from the configured one (the stale ones), `warn` when
   `k8s-file` has no size bound, otherwise `ok`. Containers Węglarka did not create are ignored.
6. **Out of scope.** Time-based retention of container output; it belongs to the collector path (#82). Until then a
   size bound is the only bound for `k8s-file`.

## Consequences

- `[logs]` gains two optional keys. `HostConfig` has `deny_unknown_fields`, so an older daemon refuses a file that
  sets them: remove both keys before a downgrade (listed in `verify-and-rollback.md`). No `apps.toml`/`state.toml`
  change, `SCHEMA_VERSION` stays.
- `k8s-file` with `max-size`: conmon truncates the file when it reaches the bound, so older output is lost; `weglarka
  logs` of a long-running app shows only the tail. `journald` keeps history as long as the host's journal does, shared
  with every unit and not pruned by Węglarka; its retention is not a per-app period and cannot be stated in a privacy
  policy from Węglarka's configuration (see `docs/guides/log-retention.md`).
- The size/`log_configuration` shape is checked on a real Podman by `crates/weglarka-podman/tests/log_driver.rs`.
- `doctor` costs one extra container list, and only when `container_driver` is set; there is no new background work.

## Rejected alternatives

- **Pruning `k8s-file` logs from the daemon:** the files live in Podman's storage outside the daemon's mounts and are
  appended by conmon; rewriting them races the writer.
- **Putting the setting in `spec_hash`** (or recreating every container on change): a one-line host edit would restart
  every app; the gap is reported by `doctor` instead.
- **A per-app `log` field:** nobody needs different drivers per app yet; a host policy is enough and adds nothing to
  `apps.toml` (no schema bump). It can be added later behind the same `ContainerLog`.
- **Always sending a default driver:** would change behaviour for every existing host on upgrade; unset must stay
  unchanged.
