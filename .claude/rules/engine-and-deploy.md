---
paths:
  - "crates/weglarka-engine/**"
  - "crates/weglarka-podman/**"
  - "crates/weglarka-model/src/{podman,uid_range,shared_volumes,shared_networks,depends,environments,labels,limits,secrets,secret_store,secret_ops,host_ports,history,fsutil}.rs"
  - "crates/weglarka-daemon/src/{service,volumes,shared_volumes,shared_networks,images,sites,forward,push,update,settings}.rs"
  - "docs/guides/{volumes,shared-volumes,shared-networks,host-configs,host-mounts,blue-green,site-environments,crash-detection,image-retention,port-forward,one-off-commands,push-local-images,secrets-cleanup,data-import,dependencies,stopped-apps}.md"
---

# Engine, deploy and Podman

Reconcile loop, deploy, volumes, secrets, configs, host mounts, images, blue-green, sites, crash detection and
the one-off/forward/push commands.

## Invariants

- **Secrets never appear in logs, `Debug` or app TOML** (apps hold only references by name).
- **libpod sometimes returns 500 instead of 404** (e.g. `no such container` while it is being removed) — the client maps
  it to `NotFound`; cleanup operations (disconnect, remove) are best effort and idempotent.
- **SQLite data import:** WAL — `volumes import --replace`, verify together with `-wal`/`-shm`; copy with `.backup`.
- **Shared volume (ADR 0017):** declared as `[shared_volumes.<name>]` in `apps.toml`, mounted via `shared_volumes = [...]`
  in the app spec; the volume owns **one UID range** for all members, and its `wg-shared-<name>` carries the label
  `weglarka.shared-volume` and never `weglarka.instance`. `apps remove --purge-volumes` of a member while other members
  exist = 409 (nothing removed), an import requires stopped members, and changing the range while private data exists
  is rejected (`RangeChangeWithData`). Details: [`docs/decisions/0017-shared-volumes.md`](../../docs/decisions/0017-shared-volumes.md),
  [`docs/guides/shared-volumes.md`](../../docs/guides/shared-volumes.md) and [`volumes.md`](../../docs/guides/volumes.md).
- **Secrets are scoped per instance (ADR 0024, `<app>.<name>` in `secrets.toml`)** — `apps remove` **keeps** them by
  default (data and credentials are separate decisions), so a new app under an old name inherits the old values. Cleanup
  on removal: `apps remove --purge-secrets` (the whole `<app>.*` scope, including `webhook-hmac`, independent of
  `--purge-volumes`, before `apps.toml` is written). `secrets remove` works **also after the app is gone** (cleans up
  after an instance rename), and `doctor` warns with the check `state.orphan_secrets`. Details:
  [`docs/decisions/0024-secret-removal-and-purge.md`](../../docs/decisions/0024-secret-removal-and-purge.md) and
  [`docs/guides/secrets-cleanup.md`](../../docs/guides/secrets-cleanup.md).
- **Owner of a mounted secret (ADR 0037, #55):** `mode`/`uid`/`gid` in a `kind = "mount"` binding are **container**
  values (the same namespace as the image's `USER`; Podman maps them through the instance range, ADR 0009); `uid`/`gid`
  are numbers in `0..=65535` (user names are rejected by parsing). Unset fields do not enter `spec_hash` (an update
  recreates nothing), set/changed ones recreate the container, and `--secret-mount` binds anew and resets those options
  to defaults. New `apps.toml` fields → `schema_version = 7` (a no-op step), so before a downgrade remove `uid`/`gid` from
  mounted secrets or restore the state files from a backup.
- **Host configs (ADR 0028):** one `config_root` in `weglarka.toml` (mounted **read-only** into the daemon container by
  `platform install` — reinstall after an upgrade), `configs = [{ source, target }]` in the app spec (source relative to
  the root, syntactic validation in `validate_app`; start and write check only `config_root` itself, and the
  canonicalize/containment of the source happens in reconcile and at container creation). **File contents are outside
  `spec_hash`** (editing recreates nothing), **the `configs` list is in the hash**; `reload_signal` is outside it. A
  content change is applied by `apps reload` (signal or restart), and a single-file bind mount after write-and-rename
  needs `--recreate`. Both TOML files have `deny_unknown_fields`, and `apps.toml` gets `schema_version = 2`
  (`state::SCHEMA_VERSION` + a no-op `SCHEMA_STEPS`, ADR 0023) → before a downgrade remove `config_root`, `configs`,
  `reload_signal` and the `schema_version` marker (or restore the files from a backup). Runtime user files appear in the
  app's UID range as `nobody` → 0644/0755. Details:
  [`docs/decisions/0028-config-root-mounts.md`](../../docs/decisions/0028-config-root-mounts.md) and
  [`docs/guides/host-configs.md`](../../docs/guides/host-configs.md).
- **Crash detection (ADR 0022):** the crash-loop watcher runs inside the reconcile pass — `container_list` already
  inspects every container, so the restart counter (`RestartCount` → `ContainerInfo.restarts`) costs no extra libpod
  call. State is in memory (after a daemon restart the first observation only sets the baseline), under the engine
  mutex, and the baseline boundary is the label `weglarka.generation`. Thresholds live in `[monitor]` (a new section →
  another downgrade caveat); events go through the same `EventSink` as deploys.
- Rollback restores the digest, not the spec — see [state-and-schema.md](state-and-schema.md).
- Contract changes (`app.rs`, `podman.rs`, `weglarka-api`) are additive only and always update `FakePodman`.

## Entry points

| Area | Files |
|---|---|
| reconcile loop | `crates/weglarka-engine/src/reconcile.rs` — pure `plan()` (`Target`/`Action`) + `execute()` (the only state writer) |
| deploy | `crates/weglarka-engine/src/deploy.rs` — `deploy_locked`: pull → stop → create+start → gate → rollback; `provision_locked` |
| volumes and UID | `crates/weglarka-engine/src/volumes.rs`, `crates/weglarka-model/src/uid_range.rs` (ADR 0009); shared volumes: `crates/weglarka-model/src/shared_volumes.rs` + `crates/weglarka-engine/src/volumes.rs` (ADR 0017) |
| secrets | `crates/weglarka-model/src/secrets.rs` (`FileSecretStore`) and `crates/weglarka-engine/src/secrets.rs` (delivery to containers), `crates/weglarka-model/src/secret_store.rs` |
| host configs and reload | `crates/weglarka-engine/src/config_mounts.rs` (resolve/fingerprint/host validation), `crates/weglarka-engine/src/deploy.rs` (`launch` mounts a `BindMount` ro, `reload_locked`/`reload`), fields `configs`/`reload_signal` in `crates/weglarka-model/src/app.rs`, hash in `crates/weglarka-model/src/hash.rs`, `crates/weglarka-daemon/src/settings.rs` (`Paths.config_root`) + the mount in `crates/weglarka-daemon/src/service.rs` (`service_spec`), route `crates/weglarka-api/src/endpoints.rs` → `crates/weglarka-daemon/src/admin.rs`, check `configs.*` in `crates/weglarka-daemon/src/doctor.rs`, CLI `crates/weglarka-cli/src/commands.rs`/`spec_flags.rs` (ADR 0028) |
| host mounts and groups (`host_mounts`, `group_add`) | `crates/weglarka-engine/src/host_mounts.rs` (allowlist `[runtime] host_mounts`, exact match + no symlinks, `describe`), `HostMount`/`valid_host_source` in `crates/weglarka-model/src/app.rs`, validation in `crates/weglarka-model/src/state.rs`, hash in `crates/weglarka-model/src/hash.rs`, `Reconciler::resolve_mounts` in `crates/weglarka-engine/src/deploy.rs`, allowlist mount into the daemon container in `crates/weglarka-daemon/src/service.rs`, 400 in `crates/weglarka-daemon/src/admin.rs`, check `host_mounts.apps` in `crates/weglarka-daemon/src/doctor.rs`, `group_add` → `ContainerSpec::keep_groups` → crun annotation in `crates/weglarka-podman/src/wire.rs` (ADR 0045: keep-groups, not a gid), CLI `--host-mount`/`--group-add` in `crates/weglarka-cli/src/spec_flags.rs`, `docs/guides/host-mounts.md` (ADR 0045) |
| image retention | `crates/weglarka-engine/src/images.rs` (pure `plan()` + `execute()`), calls after a deploy in `crates/weglarka-engine/src/deploy.rs`, API `crates/weglarka-daemon/src/images.rs`, check `runtime.images` in `crates/weglarka-daemon/src/doctor.rs` (ADR 0020) |
| blue-green deploy (`strategy`) | `crates/weglarka-engine/src/deploy.rs` (`launch_blue_green`, `challenger_gate`, `launch_with_strategy`), `Strategy` in `crates/weglarka-model/src/app.rs` + `validate_strategy` in `crates/weglarka-model/src/state.rs`, `.next`/`.prev` names and the staging network in `crates/weglarka-model/src/labels.rs`, their exception in `plan()` (`crates/weglarka-engine/src/reconcile.rs`), `container_rename`/`network_connect_aliased` in `crates/weglarka-model/src/podman.rs` + `crates/weglarka-podman/src/{client,wire}.rs`, `resolver valid=1s` in `crates/weglarka-ingress/src/nginx.rs`, flag `--strategy` in `crates/weglarka-cli/src/spec_flags.rs`, tests in `crates/weglarka-engine/src/engine_tests.rs` (mod `blue_green`), `docs/guides/blue-green.md` (ADR 0046) |
| sites with environments (`[sites]`, `weglarka promote`) | `crates/weglarka-model/src/environments.rs` (`SiteSpec`/`EnvSpec`, `expand`, name collisions), `AppsFile`/`RawAppsFile` in `crates/weglarka-model/src/app.rs` (expansion on read, `origins` is not written), `crates/weglarka-engine/src/promote.rs` (`Reconciler::promote`, `declare_site`/`remove_site`, `ensure_unmanaged`), the `PromoteOnly` guard in `crates/weglarka-engine/src/deploy.rs`/`push.rs`, skipped in `crates/weglarka-engine/src/reconcile.rs`, `NginxOptions::unreleased` → `return 503` in `crates/weglarka-ingress/src/nginx/location.rs`, routes `crates/weglarka-daemon/src/sites.rs`, CLI `crates/weglarka-cli/src/sites.rs`, check `sites.unpromoted` in `crates/weglarka-daemon/src/doctor.rs`, tests `engine_tests.rs` (mod `environments`) and `crates/weglarka-daemon/tests/it/sites.rs`, `docs/guides/site-environments.md` (ADR 0050) |
| crash detection | `crates/weglarka-engine/src/crash.rs` (`Policy` + the `Watcher` state machine), called in `crates/weglarka-engine/src/reconcile.rs` (`Reconciler::with_monitor`, once per pass), section `[monitor]`: `crates/weglarka-model/src/config.rs`, events: `crates/weglarka-model/src/events.rs`, tests: `crates/weglarka-engine/src/engine_tests.rs` (ADR 0022) |
| temporary port forward (`weglarka forward`) | `crates/weglarka-engine/src/forward.rs` (`prepare_forward`/`PendingForward::hold`, `remove_stale_forwards`), labels `weglarka.forward`/`forward-for` in `crates/weglarka-model/src/labels.rs`, `published_ports` in `ContainerInfo` (`crates/weglarka-model/src/podman.rs` + `crates/weglarka-podman/src/wire.rs`), frame stream `crates/weglarka-api/src/forward.rs` (frame codec shared with run/logs: `crates/weglarka-api/src/frame.rs`), route `crates/weglarka-daemon/src/forward.rs` (ends with the token: `StreamDeadline`), CLI `crates/weglarka-cli/src/forward.rs` + user file `crates/weglarka-cli/src/user_config.rs` (`cli.toml`), `docs/guides/port-forward.md` (ADR 0041) |
| one-off containers (`weglarka run`) | `crates/weglarka-engine/src/run.rs` (`prepare_run`/`PendingRun::drive`, `remove_stale_runs`; preparation shared with deploy: `prepare_instance` in `crates/weglarka-engine/src/deploy.rs`), labels `weglarka.run`/`run-for` in `crates/weglarka-model/src/labels.rs`, `container_logs`/`container_wait`/`entrypoint` in `crates/weglarka-model/src/podman.rs` + `crates/weglarka-podman/src/{client,wire}.rs`, frame stream `crates/weglarka-api/src/run.rs`, route `crates/weglarka-daemon/src/admin.rs` (`run_app`; stream body: `crates/weglarka-daemon/src/stream.rs`), CLI `crates/weglarka-cli/src/run.rs`, `docs/guides/one-off-commands.md` (ADR 0040) |
| deploying a local image (`weglarka push`) | `crates/weglarka-engine/src/push.rs` (`push_reference`/`push_archive`, one upload slot, tag `pushed`), digest source `DigestSource` in `crates/weglarka-engine/src/deploy.rs` (`deploy_locked_from`/`provision_from`), `image_load`/`LoadedImage` in `crates/weglarka-model/src/podman.rs` + `crates/weglarka-podman/src/{client,wire}.rs`, route `PUT /v1/apps/{name}/image` in `crates/weglarka-api/src/endpoints.rs` → `crates/weglarka-daemon/src/push.rs`, `deploy` with `image_ref` in `crates/weglarka-daemon/src/admin.rs`, CLI `crates/weglarka-cli/src/push.rs`, tests `engine_tests.rs` (mod `push`), `crates/weglarka-daemon/tests/it/push.rs`, `crates/weglarka-podman/tests/image_load.rs`, `docs/guides/push-local-images.md` (ADR 0042) |
