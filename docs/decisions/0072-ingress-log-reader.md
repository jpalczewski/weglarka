# 0072 — One read-only reader of the ingress log files

Status: proposed (2026-11-05, issue #552)

## Problem

Since ADR 0070 nginx writes its access and error logs to `<state dir>/ingress-logs` (mode `0700`) instead of stdout, so
a log collector (Alloy, ADR 0045) that used to read them from the journal has no supported way to read them. The
workarounds fail: an allowlisted `host_mounts` entry inside the state dir is mounted read-only over the daemon's own
writable state mount, and an ACL granted by hand is reset by the hourly `chmod 0700`. The state dir itself is `0755`,
so the `0700` on `ingress-logs` is what keeps other local users away from visitor addresses.

## Decision

Stub — reserved number. To be written with the implementation of #552. Already decided:

- One reader per host: `[logs] reader = "<instance>"` (a later list is an additive change). An app opts in with
  `ingress_logs = true` (in `spec_hash` only when `true`, `apps.toml` schema 20); any other app asking for it is
  refused (400 on write, blocked in reconcile, `doctor` check `logs.reader`).
- The log root is bind-mounted read-only at `/var/log/weglarka-ingress` in the reader.
- Permission model: to be fixed by a host measurement (group-readable `0750` directory with `keep-groups`, or an
  `idmap` mount). The directory helper only tightens permissions and covers the whole tree (per-app directories,
  ADR 0073).

## Consequences

To be written.

## Rejected alternatives

To be written (allowlisting the path in `host_mounts`, ACLs written by the daemon, `0755`, a FUSE view, the
`weglarka access --follow` stream instead of files).
