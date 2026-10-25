# 0045 — Allowlisted read-only host mounts for apps

Status: proposed (2026-10-25, issue #178). The `host_mounts` half is implemented; the supplementary-group half
(`group_add`) waits for a measurement on a real host (see "Open").

## Problem

A log collector (Alloy, Promtail, Vector) has to read the host journal (`/var/log/journal`, `/run/log/journal`,
`/etc/machine-id`). An app spec can mount only named volumes and, read-only, files under `config_root`
(ADR 0028), so such a collector cannot be a Węglarka app and stays a root container with a Docker socket
elsewhere. Mounting arbitrary host paths from an app spec is not an option: `apps.toml` is written through the
admin API, so whoever can write a spec would pick the host path.

## Decision

**The operator names the paths; an app can only pick from that list, read-only.**

* `[runtime] host_mounts = ["/var/log/journal", ...]` in `weglarka.toml`: absolute, normalized paths (no `.`,
  `..`, empty segments, `:` or `,`; not `/`; no duplicates), validated at startup and by `doctor --preflight`.
* `host_mounts = [{ source, target }]` in an app spec. `source` must **equal** one allowlist entry (no prefix
  match, so a child of an allowed directory is refused). There is no read-write flag.
* The entry must resolve to itself: `canonicalize(source) == source`. A symlink anywhere in the path is refused,
  so what the operator approved is what libpod binds. The canonical path is what mounts.
* The check runs three times: when a spec is written (400 from the admin API), on every reconcile (a failing
  app is blocked, the running container stays, like `configs`) and before a container is created (the deploy
  fails before the old container is touched).
* The daemon container needs to see the path to canonicalize it, so `platform install` mounts every entry
  read-only at the same path (as for `config_root`). Changing the list needs a re-install.
* `host_mounts` of a spec is part of `spec_hash` only when non-empty (sorted, `skip_serializing_if`), so no
  existing app is recreated. `apps.toml` gets `schema_version = 8` (no-op step) because older daemons reject the
  field (`deny_unknown_fields`).
* `apps show` prints a `[host_mounts]` block and `doctor` has `host_mounts.apps` (who reads which path, and
  whether it is still allowlisted and present). The allowlist lives in `weglarka.toml`, which the runtime user
  must not be able to write; the daemon sees it read-only, and the root-owned requirement is documented in the
  guide (an ownership check in `doctor` is tracked with the group half).

## Consequences

* New CLI flag `--host-mount SOURCE:TARGET|none` for `apps add`/`apps update`; new API field
  `ShowAppResponse.host_mounts`.
* Rollback across the schema bump: remove `host_mounts` from apps and `[runtime] host_mounts` from
  `weglarka.toml`, or restore the files from a backup ([guide](../guides/host-mounts.md)).
* Journal access is exposed to every app that mounts it; that is inherent to a collector, hence the explicit
  allowlist and the doctor listing.

## Open

* **Reading the journal needs group `systemd-journal`.** The host gid is not mapped into a rootless
  instance's user namespace (ADR 0009), so `--group-add <gid>` cannot work; the candidate is crun's
  `keep-groups`, which keeps the runtime user's own groups. Whether it works together with an explicit
  `idmappings` is unmeasured. `group_add` (allowlisted names) is implemented only after that measurement.

## Rejected alternatives

* **Free-form host paths in the spec**: lets any spec author read the host.
* **Prefix match on the allowlist**: an allowed `/var/log` would expose every subdirectory and any later mount
  inside it.
* **Following symlinks and checking containment** (as `config_root` does): there is no root to contain the
  path in; exact equality is the only rule that keeps "approved path" meaningful.
* **A read-write flag**: nothing in the issue needs it, and a writable host path is a different threat model.
