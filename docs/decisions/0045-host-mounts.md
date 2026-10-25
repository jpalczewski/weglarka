# 0045 — Allowlisted read-only host mounts and groups for apps

Status: accepted (2026-10-25, issue #178). `host_mounts` and `group_add` are implemented; the group half rests on a
measurement on a real host (see "Measurement").

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

* New CLI flags `--host-mount SOURCE:TARGET|none` and `--group-add NAME|none` for `apps add`/`apps update`; new
  API field `ShowAppResponse.host_mounts`.
* Rollback across the schema bump: remove `host_mounts` from apps and `[runtime] host_mounts` from
  `weglarka.toml`, or restore the files from a backup ([guide](../guides/host-mounts.md)).
* Journal access is exposed to every app that mounts it; that is inherent to a collector, hence the explicit
  allowlist and the doctor listing.

## Groups: `keep-groups`, not a gid

Journal files are `root:systemd-journal 0640`, so a path alone is not enough.

* `[runtime] group_add = ["systemd-journal"]` is the allowlist of group **names**; `group_add = [...]` in an app
  spec may only contain listed names (400 on write, app blocked in reconcile, deploy refused before the old
  container is touched). Names follow `useradd` rules.
* A non-empty `group_add` sets crun's `run.oci.keep_original_groups` annotation on the container
  (`ContainerSpec::keep_groups`, the `--group-add keep-groups` of the CLI). The container then keeps the
  **runtime user's own supplementary groups**; the kernel checks file access against the host gids even though
  the container shows them as `nobody`.
* Consequence to state plainly: it is all-or-nothing. The names are a gate (and documentation), not a selector:
  the app gets every group the runtime user is in. The runtime user should be a member of the groups apps
  need (`systemd-journal`) and of nothing it does not need. `adm` would also read the journal (ACL) but opens
  all of `/var/log`; prefer `systemd-journal`.
* Membership is a host setting (`usermod -aG`), and long-lived user services (`Linger=yes`) keep their old groups
  until restarted. The daemon image has no `/etc/group`, so `doctor` cannot verify membership; the guide has the
  command.
* `group_add` is part of `spec_hash` only when non-empty (sorted); it shares `schema_version = 8` with
  `host_mounts`.

## Measurement

Rootless Podman 6.1.3, crun 1.30.1, Ubuntu 24.04, runtime user in `systemd-journal`, container with
`--uidmap 0:1:65536 --gidmap 0:1:65536`: `--group-add keep-groups` reads the journal file as root and as
`--user 1000:1000`. `--group-add <gid>` (the numeric host gid) does not: it adds an unrelated gid inside the
namespace (`ping` for 999). Without the user being in the group, `keep-groups` reads nothing.

## Rejected alternatives

* **Free-form host paths in the spec**: lets any spec author read the host.
* **Prefix match on the allowlist**: an allowed `/var/log` would expose every subdirectory and any later mount
  inside it.
* **Following symlinks and checking containment** (as `config_root` does): there is no root to contain the
  path in; exact equality is the only rule that keeps "approved path" meaningful.
* **`--group-add <gid>` with a numeric gid**: measured not to work in a mapped user namespace.
* **A read-write flag**: nothing in the issue needs it, and a writable host path is a different threat model.
