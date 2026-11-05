# 0074 — Explicit log driver and size bound for containers

Status: proposed (2026-11-05, issue #554)

## Problem

Węglarka sets no log driver or log options on its containers, so `containers.conf` decides: `journald` with host-global
retention on systemd hosts, `k8s-file` without a size bound (and deleted on every recreate) on hosts without journald.
Disk use and the lifetime of container output, which may hold secrets and visitor addresses, are unpredictable and
differ between the supported host families.

## Decision

Stub — reserved number. To be written with the implementation of #554. Already decided:

- `[logs] container_driver` and `[logs] container_max_size` (`k8s-file` only); unset keeps today's create request.
- The setting is not part of `spec_hash`: it applies from the next container create, and `doctor` lists containers
  whose driver differs from the configured one.
- It applies to app containers and to the system containers (nginx, forwarder), not to short-lived `run`/`forward`
  containers.
- Time-based per-app retention of container output is out of scope here; it belongs to the collector path (#82).

## Consequences

To be written.

## Rejected alternatives

To be written (pruning `k8s-file` logs from the daemon, a host-wide recreate on every change).
