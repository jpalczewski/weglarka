# 0029 — Shared volume groups: several shared volumes per app, one uid range per group (issue #129)

Status: proposed (2026-10-24, issue #129). Supersedes the "at most one shared volume per app" rule of
[0017](0017-shared-volumes.md).

## Problem

ADR 0017 makes a shared volume a uid-range boundary: the container runs in the volume's range, so mounting
two shared volumes would need two ranges at once, and the rule "at most one shared volume per app" followed.
A real stack can need two: a SQLite database volume (`/data`) and a volume of git working trees
(`/workspaces`), mounted by the same three processes. The options were to restructure the application so both
live under one mount, or to keep it off Węglarka.

The invariant worth keeping is "one uid range per container", not "one volume per container". The failure
modes of getting this wrong are the ones from 0017: a range released while another volume still holds data
in it (files become unreadable), a volume silently moved to another range (same), and a range change that
recreates a container over data it can no longer read.

## Decision

**The uid range belongs to a group of shared volumes; an app mounts any number of volumes of exactly one
group.**

1. **`apps.toml`:** `[shared_volumes.<name>] group = "<group>"` (optional). Unset means a group named after
   the volume itself — the behaviour before this ADR — so existing files, `spec_hash` and `state.toml` keep
   their meaning. `SharedVolumeSpec.group` is `Option<SharedVolumeName>` with `skip_serializing_if`, and a
   group equal to the volume's own name is not written. `AppSpec` is unchanged, so `spec_hash` is unchanged.
2. **`state.toml` is unchanged in shape.** `shared_volumes.<key>.uid_range` is now keyed by **group** name; for
   an ungrouped volume the key is the volume name, exactly as before. No new state field, no migration of
   data.
3. **Validation** (`shared_volumes::validate`, on every load and save of `apps.toml`): all shared volumes of an
   app belong to the same group (error: "belong to different groups"); the same volume is not mounted twice by
   one app; an explicit group named like another volume must be that volume's own group (otherwise one name
   would denote two ranges).
4. **Podman volume:** `wg-shared-<name>` as before, now also labelled `weglarka.shared-group=<group>`. The
   label is the record of which range the *data* belongs to, because `volume_create` is label-preserving.
   Volumes created before groups only have `weglarka.shared-volume`; their group is their own name.
5. **A volume's group is fixed while the volume exists.** `ensure_shared_volume` compares the declared group
   with the recorded one and fails with `EngineError::SharedGroupChange` (HTTP 409) instead of silently
   running the container in another range; `PUT /v1/volumes/{name}?group=…` on an existing declaration with a
   different group is the same 409; `doctor` warns about a hand-edited `apps.toml` that disagrees. Moving a
   volume is `export` → `remove --purge` → `add --group` → `import`. The range-change guard of 0017 is
   unchanged and still protects private volume data.
6. **Range lifetime:** the range is allocated when the first member of the group is deployed or provisioned.
   It is released (`settle_shared_volumes`, `apps remove --purge-volumes`, `volumes remove --purge`) only when
   **no member of the group remains and no Podman volume of the group exists** (label query, with the
   volume-name label as a fallback for pre-group volumes). Purging one volume therefore never frees the range
   in which a sibling volume still holds files; this is the "purge of the last member frees the range only
   when the last volume of the group is gone" requirement of the issue.
7. **Purge / import guards stay per volume.** `apps remove --purge-volumes` is refused (409, nothing
   touched) when another app mounts any volume this app would delete; import into a shared volume requires the
   members *of that volume* to be stopped and runs the helper container in the group's range.
8. **API/CLI:** `PUT /v1/volumes/{name}` accepts the query parameter `group=<name>` (still no body);
   `SharedVolumeSummary.group` is additive and optional (`#[serde(default)]`), so old CLIs and old daemons
   interoperate. `weglarka volumes add NAME [--group G]`, `volumes list` shows a `GROUP` column.
9. **`doctor`:** `state.shared_volumes` reports group membership (volumes and members of every group with more
   than one volume), keeps the "same container USER" reminder per group, and warns about group drift.
10. **Schema:** `SCHEMA_VERSION` 2 → 3 with a no-op migration step (the field is additive and optional). The
    bump stamps `schema_version = 3` into `apps.toml` and `state.toml` on the first write after the upgrade —
    for every installation, whether or not groups are used — so a rollback to the previous release needs the
    files from before the upgrade (ADR 0023, [the shared volumes guide](../guides/shared-volumes.md)).

## Consequences

* `effective_range*`, `assign_range`, `prepare_container` and `uid_range_matches` resolve the group through the
  declarations in `apps.toml` (`shared_volumes::spec_group`); the free functions take `&AppsFile`.
* New `EngineError::SharedGroupChange` (409). New label `weglarka.shared-group`.
* Rollback to a daemon without groups: remove `group` from the declarations and restore the state files from
  before the upgrade (documented in [the shared volumes guide](../guides/shared-volumes.md)).
* Tests: validation (two groups rejected, collision rule, serialisation), engine scenarios on `FakePodman`
  (one range for two volumes, purge keeps the range until the last volume, group change refused, declaration
  removal), daemon API tests (query parameter, 400/409), doctor, CLI request tests, and a real-Podman test with
  two volumes mounted in one range.

## Rejected alternatives

* **One volume mounted at two targets (sub-paths).** Smaller change, but needs a sub-path option and does not
  fit volumes that are imported, exported and purged separately.
* **Leaving it to the application** (one mount, configurable data directories): pushes a deployment constraint
  into every app.
* **A range per volume with several ranges per container.** Rootless Podman gives a container one uid map; the
  files of two ranges cannot be owned consistently by one process.
* **Recording the group in `state.toml`.** Would be a schema change that older daemons cannot read for no gain:
  the Podman volume label already records which range its data belongs to, and it survives a lost state file.
* **Moving a volume between groups with a chown pass.** Rootless chown through the helper container is the
  `U`-flag dead end measured for 0009; refusing and exporting/importing is explicit and safe.
