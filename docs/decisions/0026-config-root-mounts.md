# 0026 — Host config mounts (`config_root`) and app reload

Status: proposed (2026-10-24, issue #118)

## Problem

Infra and supporting apps (Authelia #88, Prometheus, Grafana, Loki) need configuration files. An app
spec today can mount named volumes, shared volumes, Podman secrets and tmpfs — but no host paths and no
config objects. The workarounds all fall short when a config changes often:

- **A config file as a secret:** invisible in `apps show`, no diff, and the file is labelled secret when
  it is not.
- **Baking the config into an image:** every edit needs a CI build, and files Węglarka generates itself
  cannot be included.
- **A volume plus `volumes import`:** not declarative, and Węglarka does not notice changes.

We need one narrow, auditable way to hand a host file or directory to an app as **read-only**
configuration, plus an explicit way to make a running app pick up an edit without recreating its
container.

The security question dominates: this is the first host path Węglarka mounts into an app container. A
wrong rule turns "the operator can edit configs" into "a spec can mount `/etc/shadow`" or "a symlink
escapes the config tree", and both must be impossible by construction, not by review.

## Decision

### One `config_root`, owned by the runtime user

`weglarka.toml` gains an optional top-level `config_root` (absolute, or relative to the directory of
`weglarka.toml`, like `[state] dir` and `ingress.nginx_conf_dir`). Unset = the feature is off. There is
exactly one root: a single boundary is easier to audit, back up (`git`), chmod and mount than a list of
paths, and it keeps the validation rule ("inside the root after resolving symlinks") simple.

The daemon mounts `config_root` into **its own** container **read-only** (`platform install`): it only
reads configs (fingerprints, resolution, `doctor`). The app containers get their own read-only bind
mounts, created by libpod on the host — the same path the ingress `nginx.conf` mount already uses.

### `configs` in the app spec

```toml
configs = [
  { source = "prometheus/prometheus.yml", target = "/etc/prometheus/prometheus.yml" },
  { source = "grafana/provisioning", target = "/etc/grafana/provisioning" },  # a directory
]
```

`source` is always relative to `config_root`; `target` follows the existing `valid_mount_target` rules.
Every config mount is **always read-only** — there is no `read_only` flag to get wrong. Secrets do not
belong in `config_root`: configs refer to them through `*_FILE`/env, and the values stay in the secret
store.

### Two-layer validation

`state::validate_app` stays pure (no I/O; it runs on every `load_apps`/`save_apps`) and enforces the
syntactic rules: `source` non-empty, relative, no `.`/`..` segments, no control characters; `target`
valid and unique across volumes, shared volumes and configs.

The filesystem side is split by who can act on it. At startup and on `apps add/update` Węglarka checks
only the **root**: it must be configured and be a usable directory. A source the operator has not created
yet must not keep the daemon from booting or block adding the app (the natural workflow is "add the app,
then write its config"). Per-source resolution — canonicalize the root and the source, require the result
to stay inside the root and to be a regular file or a directory — runs in the reconcile pass, in `launch`
(before the old container is touched) and in `apps reload`. An unresolvable source blocks that instance
instead of failing a deploy and its rollback, and `doctor` reports it. The **canonical** path is what gets
mounted, so a symlink swapped between the check and the mount cannot redirect the bind.

An app that declares `configs` while `config_root` is unset is an error at write time and at startup.

### What the hash covers

The **content** of config files is deliberately outside `spec_hash`: otherwise every edit would
recreate the container. The **list** of mounts (source + target) is inside the hash — changing what is
mounted is a container setting, exactly like `volumes`. `configs` is appended at the end of `HashInput`
and skipped while empty, so an app without configs keeps its current hash (`HASH_FORMAT` stays v1 and
upgrading does not recreate anything). `reload_signal` is outside the hash: it only affects reload.

### `apps reload`

New engine operation and admin endpoint (`POST /v1/apps/{name}/reload`):

- `reload_signal` set (e.g. `"SIGHUP"`, stored without the `SIG` prefix by the engine) → send that
  signal to the running container with the existing `container_kill` primitive;
- no signal set → restart the container (`stop` + `start`, same container, no recreate);
- `--recreate` → recreate the container from the pinned digest through the existing forced deploy path.
  This is the escape hatch for editors that save with write-and-rename: a single-file bind mount keeps
  the old inode, so the edit is invisible until the container is recreated. Directory mounts are the
  documented preference for files edited often.

Reload does not change desired state, does not touch `apps.toml`/`state.toml`, and refuses an app whose
container is not running (409 with a hint to `apps start`). It takes the engine mutex, so it serializes
with deploys.

### Visibility

`GET /v1/apps/{name}` additively carries the resolved config mounts: source, target, a status
(`ok`/`missing`/outside root/not a file or directory/no root) and a content fingerprint (sha256 over the
file bytes, or over sorted relative paths + contents for a directory; `.git` excluded, directory
symlinks not followed, with an entry/size cap). `weglarka apps show` renders it, so the operator sees
what the running app currently sees.

`weglarka doctor` checks the root exists and is a directory (and mounted into the daemon container),
and for every app's sources: missing, escaping the root, and the permission hint. Files owned by the
runtime user appear as `nobody` inside the instance's uid range (ADR 0009), so `0644` files and `0755`
directories are what the app needs; `doctor` warns when the "other" bits are missing and when the root
is group/world-writable.

## Consequences

- New `weglarka.toml` key and two new optional `AppSpec` fields. `apps.toml` gained a field, so
  `state::SCHEMA_VERSION` goes to 2 with a no-op `SCHEMA_STEPS` entry (the fields have defaults and
  need no data migration; ADR 0023). From the first save afterwards the file carries
  `schema_version = 2` and an older daemon refuses to start with the schema message instead of a TOML
  parse error. Rolling back across the bump means restoring `apps.toml`/`state.toml` from before the
  upgrade, or removing the new fields **and** the marker. `weglarka.toml` stays unversioned
  (human-written config), so `config_root` must be removed by hand. Documented in `docs/install.md`
  ([the install guide](../install.md#wersja-schematu-plików-stanu-rollback-między-wersjami) and its
  section 6k) and in the PR.
- No `spec_hash` change for apps that do not use configs (golden snapshot stays); adding `configs`
  recreates the container on the next deploy.
- Existing installs must re-run `weglarka platform install` to gain the read-only `config_root` mount
  in the daemon container; without it `doctor`/`apps show` report the root as unavailable and deploys
  that use configs fail validation.
- Config content is not restored by an image rollback (rollback restores the digest, not the spec, and
  never the files): the config rollback is `git checkout` in `config_root` + `apps reload`.
- A signal-based reload trusts the app to handle it; a signal it does not handle can terminate the
  process. That is the operator's explicit choice; the alternative (restart) is the default.
- Tests: pure validation, hash stability, symlink escape, fingerprint determinism, engine tests on
  `FakePodman` for mounts/blocks/reload/recreate, daemon API and doctor tests, CLI tests.

## Rejected alternatives

- **Config files as secrets.** The secret store is for values, not files: no diff, no `apps show`,
  misleading labels, and secret rotation semantics would apply to plain config.
- **Baking configs into images.** Breaks the edit loop and cannot carry files Węglarka generates.
- **Volume + `volumes import`.** Not declarative, no change detection, and import requires a stopped app.
- **Multiple config roots / arbitrary host paths per mount.** Every extra root weakens the single
  containment rule and multiplies what root has to own and audit.
- **Detecting content changes and restarting automatically.** Non-deterministic, expensive on large
  directories, and it would fight the operator's git workflow; reload stays explicit.
- **Węglarka-managed config content (`configs set`, content in `spec_hash`).** Deliberately later: it is
  a different feature (declarative content, generated `file_sd` #36) and would bake content into the
  hash, recreating containers on every edit.
