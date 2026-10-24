# 0017 — Volumes shared between instances: one uid range per shared volume (issue #33)

Status: proposed (2026-10-24, issue #33). The "at most one shared volume per app" rule is superseded by
[0029](0029-shared-volume-groups.md): the uid range now belongs to a group of volumes.

## Problem

Migration of a multi-process app into Węglarka needs several containers to share **one** SQLite
database in **one** named volume (kajet-turbo: api, mcp, worker, turbo). Today a volume belongs to
exactly one instance: the Podman volume is `<instance>.<volume>`, labelled `weglarka.instance`, and
`ensure_volumes`/`purge`/`list`/`import`/`export` all derive it from that one instance
(`crates/weglarka-core/src/volumes.rs`, `crates/weglarka-core/src/labels.rs`). One app is also
exactly one container (`AppSpec`, ADR 0001 territory), so the four processes are four instances.

Ownership is the blocker: iteration 2 gives every instance its own explicit `userns: private` map
(`docs/decisions/0009-volume-ownership.md`), so the same inode has a **different owner for every
distinct range** and two instances cannot use one volume. The other paths measured for 0009 are
dead ends: `idmap` mounts fail rootless, `U` only chowns at container-create, real `auto` is
non-deterministic. A shared volume therefore needs a **shared uid/gid range**, and with it a
sharing model that answers: who owns the range, who creates the volume, who may delete it, and how
does the data plane (SQLite with several writers) stay correct.

If the sharing model is wrong, the failure modes are data loss (a purge that deletes a volume still
used by another instance, a range change that makes existing files unreadable) and split-brain data
(a typo silently creating a second empty volume).

## Decision

Share a volume through an explicit, top-level declaration; the **shared volume owns the uid range**,
and every instance mounting it runs in that range. The model mirrors how secrets work (bind by
name, declare/store separately).

### Desired state (`apps.toml`)

```toml
[shared_volumes.kajet-data]
# no fields yet: the declaration is the guard against typos and the future home of
# per-volume options (backups / Litestream, range size)

[apps.kajet-api]
image = "ghcr.io/.../kajet-api:latest"
shared_volumes = [{ name = "kajet-data", target = "/data" }]
```

* `AppsFile.shared_volumes: BTreeMap<SharedVolumeName, SharedVolumeSpec>` — declared once, no owner
  instance. `SharedVolumeSpec` is empty and `deny_unknown_fields` for now.
* `AppSpec.shared_volumes: Vec<SharedVolumeRef>` — `{ name, target, read_only }`, skipped in serde
  and in `HashInput` while empty (an app without shared volumes hashes exactly as before; the
  `HASH_FORMAT` stays `v1` and upgrading Węglarka recreates nothing).
* **At most one shared volume per app** (v1): a shared volume is a uid-range boundary, so a second
  one would need a group concept. The validation error says so and points here.
* Private `volumes` and a shared volume may be mixed; the private volumes of a member are created in
  the shared range, which reduces isolation *inside the group* and is documented. V1 does not forbid
  it because it is the natural way to give one member its own cache directory.

### Runtime state (`state.toml`)

`shared_volumes: BTreeMap<SharedVolumeName, SharedVolumeState { uid_range: Option<UidRange> }>`.

* The range is allocated first-fit from the rootless subuid pool exactly like an instance range
  (`DEFAULT_RANGE_SIZE = 65 536`), under the engine lock, before the first member's container is
  created, and is kept while data exists. Members do **not** get their own `AppState.uid_range`:
  the container's effective range is the shared volume's range, otherwise `AppState.uid_range`.
  There is one holder per range, so the global "ranges never overlap" invariant of `validate_state`
  is extended, not relaxed.
* A group of N containers costs **one** range instead of N (the production pool fits ~30 full
  ranges), which is a small bonus next to the correctness win.

### Podman naming and labels

The Podman volume is `wg-shared-<name>` with label `weglarka.shared-volume=<name>` and **no**
`weglarka.instance` label. The name has no `.` while every per-instance volume is
`<instance>.<volume>` (instance and volume names are `[a-z0-9-]`), so the two namespaces cannot
collide; the missing instance label means existing instance purge / orphan settling / volume
filters never touch a shared volume.

### Lifecycle

* **Create:** the first member's deploy/provision (`launch`, `provision_locked`, and the import
  helper) allocates the range, then creates the labelled volume, then the container with the
  group's explicit `IdMapping` and the `weglarka.uid-range` label. Creation is idempotent and
  label-preserving (as for instance volumes).
* **Reconcile:** unchanged in shape — a changed effective range shows up as a `weglarka.uid-range`
  label mismatch and recreates the container once. `settle_shared_volumes` drops the state entry
  (and frees the range) only when the Podman volume is gone **and** no declaration/member remains;
  data for an undeclared volume keeps the range reserved and is reported by `doctor`.
* **`apps remove --purge-volumes` on a member while other members exist:** refused with
  `409 Conflict` (`EngineError::SharedVolumeInUse`, the message lists the members) **before**
  `apps.toml` is written; nothing is deleted. This is the issue's hard requirement.
* **Last member with `--purge-volumes`:** removes the container, its private volumes and the shared
  volume(s), releases the group range. The declaration stays (desired state); the next member gets
  a fresh, empty volume and range.
* **`DELETE /v1/volumes/{name}`:** refuses with 409 while any app mounts it; without `?purge=true`
  it also refuses while the Podman volume (data) exists, so an unmanaged volume is never left
  behind; `?purge=true` deletes the volume and the state entry (range released).
* **Plain `apps remove`** never deletes data: the group volume and its range stay, re-adding the
  member finds the same files with the same owners.

### Import, export and backups

The per-app volume endpoints stay as they are: `{volume}` resolves to the app's private volume or to
a shared volume the app mounts, and the foreign-import helper container runs in the group's range
(this is what maps foreign tar ids correctly, finding 9 of ADR 0009).

* **Import into a shared volume requires every member stopped** (or not started): engines refuse
  with a conflict listing the running members. Writing into a database under live processes — and
  `--replace` removing a volume other containers have mounted — corrupts data. This is stricter
  than for instance volumes because the write path is shared.
* **Export** stays allowed but the docs require stopping the group first for a consistent SQLite
  snapshot (or using `.backup` / `VACUUM INTO` inside a container); the existing WAL caveats apply.
* **Own vs foreign** does not change: `--own` is only correct for a `volumes export` of the **same**
  range; a foreign tar must go through the default import path.

### Container user

A shared range aligns host owners only when every member process uses the same **container** uid:
container uid 1000 maps to `range.start + 1000`, container uid 999 to `range.start + 999`. Węglarka
does not override the image `USER`, so v1 documents the requirement and `doctor` warns when the
running members of a group report different effective users. Forcing a user (or a group/ACL model)
is left out deliberately; see rejected alternatives.

### Guard against range changes with data

An instance whose effective range would change must not be recreated silently when that would make
its existing files unreadable. Before the old container is touched, the shared `launch`/`provision`
prologue (`Reconciler::begin_instance`) compares the old range with the new one and, if they differ
and the instance has existing private volumes, fails with `EngineError::RangeChangeWithData`; the
old container keeps running and the reconcile pass reports the instance as blocked. The old range
comes from the container's `weglarka.uid-range` label, or — when there is no container (an app
provisioned with `start = false`, stopped with `apps stop`, or removed) — from
`AppState::effective_uid_range`, the last range the container and volumes were prepared in, written
by every deploy/recreate/provision (issue #75). The range guard therefore cannot be skipped by a
path that removes the container first, and a hand-edited `apps.toml` is refused as well.
`PUT /v1/apps/{name}` runs the same check early and returns 409 with the migration hint. Joining or
leaving a group **without** private volumes is allowed and is the normal way to migrate: provision
the member (`start = false`), import the data with the foreign mode, then start it.

### Validation

A pure cross-app check (`core/src/shared_volumes.rs`, called by `load_apps`/`save_apps`): every
reference is declared; at most one shared volume per app; mount targets unique across `volumes` and
`shared_volumes` with the existing path rules. Unused declarations are allowed (declared now, used
later). Daemon-side checks on write and at startup add the state/Podman view (membership vs state,
data without a declaration). `doctor` reports `state.shared_volumes`: data without a declaration,
declared but not created, range/label drift, member user mismatch.

## Consequences

* New `apps.toml` section and `state.toml` field. Both files are `deny_unknown_fields`, so **a
  rollback to an older daemon requires removing them** (and deleting `wg-shared-*` volumes by hand
  — the old daemon cannot see them). Documented in `docs/install.md` and in the PR.
* `state.toml` also gains `apps.<name>.effective_uid_range` (issue #75): a derived mirror of the
  effective range, used by the range guard when no container exists. It is not part of the
  disjoint-ranges validation. The same `deny_unknown_fields` rule applies — a downgrade needs the
  line removed — and an older CLI cannot decode `apps show/add/update` and `apps start/stop`
  responses, because `AppState` is part of the API (new CLI with an old daemon is fine). Both are
  documented in `docs/install.md`.
* API: `PUT /v1/volumes/{volume}`, `GET /v1/volumes`, `DELETE /v1/volumes/{volume}?purge=true`,
  an additive `VolumeSummary.shared`, and the 409 on `apps remove --purge-volumes`. The endpoints
  snapshot test changes.
* CLI: `weglarka volumes add|remove`, `volumes list` without an app lists shared volumes,
  `apps add/update --shared-volume NAME=/PATH[:ro]`. Removing a mount from a spec stays on
  `--spec` in v1 (issue #54 extends `--remove-volume`).
* New tests: core model/validation/hash stability, engine scenarios on `FakePodman` (shared range,
  member lifecycle, purge refusal, last-member purge, range-change guard, import while members run,
  provisioning), daemon API tests, CLI request tests, and a real-Podman test proving two containers
  with one explicit map read and write the same volume with stable ownership.
* SQLite with several writers: same container user, WAL mode, local volume only (no NFS), a
  `busy_timeout` for SQLITE_BUSY; Litestream's single-writer assumption is documented and owned by
  issue #37 — this ADR does not implement backups.
* Rejected: implicit share-by-name (a typo creates a second empty database silently and there is no
  place for per-volume options), an owner instance (couples the volume's lifecycle to one app's
  spec and removal), a shared gid + setgid/default-ACL model (needs `setfacl`, a supplementary gid
  map and every image to create files group-writable — fragile for SQLite's `-wal`/`-shm`), and
  multi-container `AppSpec`s (a separate, larger model; issue #35).

## Open questions (Jacek)

1. `wg-shared-<name>` / label `weglarka.shared-volume` as the namespacing scheme — confirm.
2. "At most one shared volume per app" is acceptable for v1?
3. Is the range-change guard (fail + 409) the right UX, or should there be an explicit
   `volumes adopt-range` migration command later?
