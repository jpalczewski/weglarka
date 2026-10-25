# Host config files (config_root) and apps reload

Infrastructure apps (Authelia #88, Prometheus, Grafana, Loki) need configuration files. Instead of baking them into the image, putting them in secrets, or importing them into a volume, Węglarka mounts them **read-only** from one directory on the host and lets you say how the app should reload them. Decision: [ADR 0028](../decisions/0028-config-root-mounts.md); ready-made example: [`configs.toml`](../examples/configs.toml).

**1. The directory.** Add `config_root` to `weglarka.toml`, either absolute or relative to the directory of that file:

```toml
# config_root = "/var/lib/weglarka/config"
```

The directory belongs to the runtime user (usually kept as a git repo: commit changes, `git checkout` is the rollback). The daemon mounts this directory into **its own** container read-only (it needs it for `apps show` and `doctor`), and app containers get their own read-only bind mounts from libpod. Without `config_root` the feature is off; an app with `configs` is rejected on write when `config_root` is empty. If `config_root` is set, it must exist and be a directory, otherwise the daemon does not start.

After upgrading Węglarka, **run `weglarka platform install` again** (the quadlet gets the new mount). Without it the daemon cannot see the directory and `doctor` reports it.

**2. App spec.** `source` is always relative to `config_root`; `target` is a path inside the container. The mount is always read-only (there is no rw flag). The `configs` list is part of the `spec-hash`: changing **what** is mounted recreates the container; changing the **content** of the files does not.

```toml
# apps.toml / --spec
configs = [
  { source = "prometheus/prometheus.yml", target = "/etc/prometheus/prometheus.yml" },
  { source = "prometheus/rules", target = "/etc/prometheus/rules" },   # a directory
]
reload_signal = "SIGHUP"   # optional: without it `apps reload` restarts the container
```

Through CLI flags: `weglarka apps update prometheus --config-mount prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
--reload-signal SIGHUP` (a flag replaces the entry with the same `source`; `--config-mount none` clears the list). This is an app-spec flag: the global `--config file.toml` (the host configuration file) does not collide with it and works as before.

Security: `source` must be relative, without `.`/`..`, and after resolving symlinks it must stay inside `config_root`; `target` is subject to the volume rules. Do not keep secrets in `config_root`; the app should read them through `*_FILE` or env. Validation has two layers: syntactic rules (`source` relative, no `..`, unique `target`) on every `apps.toml`, and filesystem rules (symlinks, containment, file/directory) in reconcile, before the container is created, and on `apps reload`. A missing file therefore does not block adding the app or starting the daemon; it blocks only that app (`weglarka doctor` shows it).

**3. Changing and reloading.** File content is not part of the `spec-hash`, so the reconcile loop recreates nothing. Apply a change explicitly:

```sh
vim /var/lib/weglarka/config/prometheus/prometheus.yml
weglarka apps reload prometheus        # SIGHUP (the spec has reload_signal) or a container restart
git -C /var/lib/weglarka/config commit -am "scrape a new target"
```

`apps reload` takes the engine mutex (it is serialized with deploys), does not change `apps.toml`/`state.toml`, and refuses (409) when the container is not running; in that case use `weglarka apps start`. Rolling back a config is `git checkout` plus `apps reload`; an image rollback restores the digest, not the files.

**4. Editors, inodes and `--recreate`.** Editors that save through write-and-rename leave a single-file bind mount on the old inode, so the app keeps seeing the previous content even though `git status` is correct. Either mount a **directory** (`source = "prometheus"`, `target = "/etc/prometheus"`), or after such a save run:

```sh
weglarka apps reload prometheus --recreate   # recreate the container from the pinned digest (no pull)
```

**5. Permissions and visibility.** Runtime-user files appear as `nobody` inside the app's UID range ([ADR 0009](../decisions/0009-volume-ownership.md)), so `0644` for files and `0755` for directories are enough:

```sh
chmod -R u=rwX,go=rX /var/lib/weglarka/config
```

`weglarka apps show prometheus` prints every mount with the current content fingerprint, and `weglarka doctor` warns about a missing source, an escape outside the directory, overly loose permissions, and the directory itself being group/world-writable.

## Rollback

`weglarka.toml` and `apps.toml` have `deny_unknown_fields`, and `apps.toml` now carries `schema_version = 2` ([ADR 0023](../decisions/0023-state-schema-version.md); the reason is `configs`/`reload_signal` from #118): an older daemon refuses to start with a schema-version message. Before a downgrade, (1) remove `config_root` from `weglarka.toml`, (2) remove `configs`/`reload_signal` from the apps, and (3) remove the `schema_version` line from `apps.toml` and `state.toml`. Or, more simply, restore both files from a backup taken before the upgrade (see [state schema version](state-schema.md)). The config files stay on disk; they are just not mounted.
