# 0009 — File ownership of named volumes under rootless Podman

Status: proposed (iteration 2, step 0 spike, 2026-10-23). Needs Jacek's confirmation, see "Open questions".

## Problem

Iteration 2 adds named Podman volumes (first user: szklana.pogoda, SQLite in `/data`). Every deploy
*recreates* the container, so the user namespace of the new container must give the files in the volume
the same owner as before, otherwise the app cannot read or write its own data. The plan assumed
`--userns=auto` (what the MVP sends) and wanted two candidate fixes tested on Podman 6.1 in CI:
(a) a fixed uid range per instance (explicit maps), (b) `auto` plus ID-mapped volume mounts (`idmap`).

## What was measured

Real rootless Podman 6.1 from the alvistack OBS repository on `ubuntu-24.04` runners (kernel 6.17, ext4,
overlay, subuid pool `165536:65536`), driven through the libpod socket and, where noted, the CLI.
The experiment code went through five CI rounds; its final form is `weglarka-podman/tests/volumes.rs`.

| # | Finding | Evidence |
|---|---|---|
| 1 | **`userns: {nsmode: "auto"}` — what the daemon sends since the MVP — is a no-op under rootless Podman.** The container gets libpod's default map `0→<podman user>`, `1..65536→subuids`, identical to leaving `userns` unset and identical for concurrent containers. Container root *is* the `weglarka` host user. | `/proc/self/uid_map` of two concurrent `auto` containers = `0 1001 1 / 1 165536 65536`, same as `unset`; files written by container root belong to host uid 1001. The CLI `--userns=auto` does engage (`0 1 1024`). |
| 2 | Real `auto` through the API needs `userns: {nsmode: auto}` **and** `idmappings: {AutoUserNs: true, AutoUserNsOpts: {Size: n}}`. | Round 4: that pair gives `0 1 1024`; `private` + AutoUserNs and `AutoUserNs` alone do not work (error / ignored). |
| 3 | With the default map (the MVP's actual behaviour) ownership is stable across recreation — the problem does not exist, **but there is no isolation**: all apps share one mapping. | Rounds 1–2: write → recreate → read/overwrite/import/export all pass. |
| 4 | With **real `auto`**, a recreate can land on another range (a neighbour took the freed one) and ownership breaks: the new container cannot overwrite its own file. The premise of the task is true once `auto` really engages. | Round 5: second range `0 1025 1024`, `c2 overwrites /data/f -> FAIL`. |
| 5 | **(b) `idmap` is dead rootless:** `crun: mount_setattr /data: Operation not permitted`. The kernel (6.17 here, 6.8 on the host) only allows ID-mapped mounts to a process with `CAP_SYS_ADMIN` in the filesystem's user namespace, which a rootless user does not have. | Round 5, both image users. Not a Podman bug; no configuration fixes it. |
| 6 | **(a) fixed explicit range works:** `userns: {nsmode: private}` + `idmappings: {UIDMap, GIDMap}` (`container_id:0, host_id:N, size`), ownership identical after recreate, root and non-root image users. `private` without maps is rejected, maps without `private` are **silently ignored** — always send the pair. `host_id` is an offset in the rootless namespace (0 = the user, `1..` = its subuids in order), so offset 1 = first subuid. | Rounds 1–3 and the asserting test. |
| 7 | (a) isolates: a container with a disjoint range cannot read a `0600` file of another range nor create files in its volume. | Test `fixed_range_keeps_ownership_across_recreate_and_isolates`. |
| 8 | **Import/export run in the service's namespace, not the container's.** `volumes/{name}/import` extracts with namespace uids: a tar owned by uid 1000 lands on namespace uid 1000 = container uid 999 (range offset 1). `volumes/{name}/export` writes namespace uids (container uid + range start). Our own export → import into the same range is lossless; a *foreign* tar is not. | Rounds 1–3. |
| 9 | `PUT /containers/{name}/archive?path=` **does** map ids through the container's namespace: a foreign tar owned by uid 1000 (or 0) is owned by the container user afterwards. Works on a created container too (same code path as `podman cp`). `GET .../archive` returns namespace ids, so it is no better than `volumes/export`. | Round 3 and the asserting test. |
| 10 | The `U` volume option chowns the volume to the container user **when the container is created**, not on restart or after a later import. It fixes ownership under real `auto` (round 5: `c2` owned correctly at the shifted range) at the cost of a recursive chown on every deploy. | Rounds 3 and 5. |

## Options

- **(a) Fixed range per instance** *(recommended)* — Węglarka allocates a range from the user's subuid
  pool once, stores it in `state.toml`, and every container of that instance is created with the
  explicit map. Needs: pure allocator (done, `weglarka-core/src/uid_range.rs`), state field (done,
  `AppState::uid_range`), wire (done), import/export handling (below).
- **(b) `auto` + `idmap`** — impossible rootless (finding 5). Rejected.
- **(c) Real `auto` + `U`** — no allocator or state. But a recursive chown on every deploy and every
  rollback, ranges chosen by Podman (non-deterministic, host-visible uids change per deploy, exports
  carry arbitrary uids), and `auto` cannot be mixed safely with explicit ranges. Viable fallback.
- **(d) Status quo (default map)** — works for ownership, but gives no isolation between apps and runs
  every container root as the daemon's own user. Not acceptable for a deploy tool whose first rule is
  security.

## Decision (proposed)

Use **(a)**. Rationale, in the project's priority order:

1. **Security.** (a) and (c) both give each app its own subuid range, which the MVP does not
   (finding 1). Only (a) makes the mapping explicit and stable, so file ownership on disk is
   deterministic and auditable; (c) leaves it to Podman and a chown.
2. **Simplicity.** (c) is less code up front, (a) is less to *operate*: no chown storms, no
   surprises on rollback, restorable backups. The allocator is a 60-line pure function with tests and
   `state.toml` already exists.
3. **RAM.** Equal.

Rules for session 1:

- **Range size** `DEFAULT_RANGE_SIZE = 65536` (images use uids up to 65534/65532). The production pool
  (2 000 000) holds 29 instances after the reserved prefix; the pool is read from `/etc/subuid`.
- **Reserved prefix.** Offsets `1..=65536` stay with libpod's default map, which non-instance containers
  (the ingress nginx) keep using; `allocate(.., reserved = DEFAULT_MAP_RESERVED)` skips them.
- **Every instance gets a range at its first deploy**, with or without volumes (uniform rule; fixes the
  isolation gap). Existing instances (ntfy.zig) adopt it on the next recreate — the range must then
  enter the container-identity check, but not `spec_hash` (it is state, not spec).
- Never mix real `auto` containers with explicit ranges on the same host.
- `ContainerSpec::userns_auto` stays only for non-instance containers and is documented as a no-op
  rootless; do not "fix" it to real `auto`.

### Import and export

- **Own backups** (`volume_export` → later `volume_import` into the same instance): lossless, because the
  range is stable. Use the raw volume endpoints (streamed).
- **Foreign tars** (Coolify migration): `volume_import` is wrong for them (finding 8). Use
  `container_archive_put` on the instance's container (created, not started, is enough) — ids are
  mapped correctly (finding 9). The deploy/CLI flow for szklana.pogoda: `apps add` → `deploy` →
  `volumes import --foreign` (archive put) → restart.
- If a volume must be restored into a *different* range, session 1 can shift tar headers by the range
  difference; not needed for iteration 2.

## Consequences

- Behaviour change for running apps: the next recreate moves them from the shared default map to their
  own range. Anything depending on container root == the `weglarka` host user (bind mounts of files
  owned by it) must be world-readable or re-owned; the ingress nginx conf mount is unaffected because
  nginx keeps the default map.
- The CI pool is 65 536 subuids, so the integration tests use 4096-uid ranges; production uses 65536.
- `idmap` and real `auto` stay documented dead ends; the `plain_userns_auto_is_a_noop_rootless` test
  fails loudly if Podman changes the behaviour.

## Open questions (Jacek)

1. Confirm (a) over (c). (c) is a one-day-simpler fallback if the allocator feels like too much state.
2. Is a 29-instance ceiling on the production host acceptable, or should the range size be per-instance
   configurable (a smaller range is enough for images that stay below uid ~1000)?
3. Finding 1 means every app and the ingress nginx on `niechybnie` currently runs container root as
   the `weglarka` user. Confirm with `podman exec ntfy cat /proc/self/uid_map` (expect `0 <uid> 1`).
   Should adopting ranges for existing apps be part of iteration 2 (recommended) or later?
