# 0072 — One read-only reader of the ingress log files

Status: proposed (2026-11-05, issue #552)

## Problem

Since ADR 0070 nginx writes its access and error logs to `<state dir>/ingress-logs` (mode `0700`) instead of stdout, so
a log collector (Alloy, ADR 0045) that used to read them from the journal has no supported way to read them. The
workarounds fail: an allowlisted `host_mounts` entry inside the state dir is mounted read-only over the daemon's own
writable state mount, and an ACL granted by hand is reset by the hourly `chmod 0700`. The state dir itself is `0755`,
so the `0700` on `ingress-logs` is what keeps other local users away from visitor addresses.

## Decision

**Permission model (implemented with this ADR).** `ingress_logs::ensure_dir` makes every log directory `0750`, owned by
the daemon's user and its primary group (container gid 0 of the daemon is the runtime user's primary group on the host).
The mode is set only when it differs from `0750`: an existing `0700` directory is widened once, `o` bits and `g+w` are
tightened, and a correct directory is left alone (`chmod` resets a POSIX ACL mask). The helper takes a path, so
per-app subdirectories (ADR 0073) use it too. nginx's worker (uid 101) still has no access; it inherits the
descriptors the master opened.

A reader is a container that carries the runtime user's primary group through `keep-groups` (ADR 0045, the crun
annotation `run.oci.keep_original_groups=1`). Group membership is the only access path; the directory is still
unreachable for a container that does not mount it.

**Reader (the plan of the follow-up PR, #552).**

- One reader per host: `[logs] reader = "<instance>"` (a later list is an additive change). An app opts in with
  `ingress_logs = true` (in `spec_hash` only when `true`, `apps.toml` schema 20); any other app asking for it is
  refused (400 on write, blocked in reconcile, `doctor` check `logs.reader`).
- The log root is bind-mounted read-only at `/var/log/weglarka-ingress` in the reader, together with `keep_groups`.

### Measurement

Rootless Podman 6.1.3 with crun on an Ubuntu 24.04 host; the runtime user's primary group has no other members.
Container started with `--uidmap 0:1:65536 --gidmap 0:1:65536` (the shape of an app with an explicit id mapping), a
read-only bind mount of a `0750 <runtime user>:<primary group>` directory holding a `0644` file:

| Variant | Result |
| --- | --- |
| no group option | `Permission denied` |
| `--group-add keep-groups` | reads, as container root and as `--user 1000:1000` |
| annotation `run.oci.keep_original_groups=1` (what `ContainerSpec::keep_groups` sets) | reads; the host groups appear as 65534 inside, but the kernel checks the real gid |
| `idmap` bind mount | `crun: mount_setattr: Operation not permitted` |

## Consequences

- Every app that has `group_add` with `keep-groups` now carries the runtime user's primary group, as before; the
  difference is that the group now means something on one directory. Such an app still cannot reach the files unless
  the directory is mounted into it, and only the configured reader gets that mount.
- The group must stay small. Any other member of the runtime user's primary group can read visitor addresses;
  `docs/guides/log-retention.md` shows how to check with `getent group`. A user with a private primary group (the
  default of `useradd`) has no other members.
- The mode is `0750`, not the `0700` of [ADR 0070](0070-ingress-log-retention.md) (addendum there). `doctor` `logs.retention` now warns on `o` bits or
  `g+w`, not on any group bit.
- Existing installs get the new mode on the first start or hourly pass after the upgrade; an ACL workaround is no
  longer wiped once the mode is `0750`.
- The directory helper only normalises the mode; it never widens beyond `0750`.

## Rejected alternatives

- **An ACL written by the daemon.** The daemon's user namespace does not map the reader's subuid, so the daemon cannot
  name the reader's identity in an ACL, and the reader's process uid inside its own namespace is unknown to the
  daemon (an image may run as any uid).
- **`0755`.** The state dir is `0755`; other local users could then read visitor addresses.
- **An `idmap` bind mount.** Rejected by crun rootless (`mount_setattr: Operation not permitted`, measured above).
- **A FUSE view.** A new process and dependency to supervise for what a mode bit does.
- **Allowlisting the path in `host_mounts`.** It overlaps the daemon's writable state mount; refused since #559.
- **The `weglarka access --follow` stream.** It needs a new long-lived client in every collector and does not give it
  the files, rotation and offsets it already knows how to track.
