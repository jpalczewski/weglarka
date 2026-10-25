# Read-only host paths

Some apps need to read a path that exists only on the host: a log collector reading the journal
(`/var/log/journal`, `/run/log/journal`, `/etc/machine-id`). `host_mounts` mounts such a path **read-only**, and only if
the operator has allowlisted it ([ADR 0045](../decisions/0045-host-mounts.md)). For files you manage yourself, use
[host config files](host-configs.md) instead.

**1. Allow the paths** in `weglarka.toml`. Entries are absolute, normalized paths; an app's `source` must equal an entry
exactly (a child of an allowed directory is refused). Keep the file writable by root only, because it is the allowlist:

```toml
[runtime]
host_mounts = ["/var/log/journal", "/run/log/journal", "/etc/machine-id"]
```

```sh
sudo chown root:root /etc/weglarka/weglarka.toml && sudo chmod 0644 /etc/weglarka/weglarka.toml
weglarka platform install        # the daemon container mounts every entry read-only to canonicalize it
```

**2. Mount them in the app:**

```sh
weglarka apps update alloy \
  --host-mount /var/log/journal:/var/log/journal \
  --host-mount /run/log/journal:/run/log/journal \
  --host-mount /etc/machine-id:/etc/machine-id
```

or in `apps.toml`: `host_mounts = [{ source = "/var/log/journal", target = "/var/log/journal" }]`. There is no
read-write option. A path that is not allowlisted is rejected with a 400 when the spec is written.

**3. What is checked.** The `source` must be an allowlist entry, must exist and must resolve to itself: a symlink anywhere
in the path is refused, so what you approved is what is mounted. A failing mount blocks only that app (the running
container stays) and fails a deploy before the old container is touched. `weglarka apps show alloy` prints a
`[host_mounts]` block and `weglarka doctor` reports `host_mounts.apps`.

**4. Journal groups.** Journal files are `root:systemd-journal 0640`, so a path alone is not enough to read them. The group
half of this feature (`group_add`) is not available yet; it is waiting for a measurement of rootless Podman with an
explicit user-namespace mapping ([ADR 0045](../decisions/0045-host-mounts.md), "Open").

Changing `host_mounts` of an app recreates its container; changing the allowlist alone recreates nothing.

## Rollback

`apps.toml` now carries `schema_version = 8` and `weglarka.toml` has `deny_unknown_fields`. Before downgrading to an older
daemon, remove `host_mounts` from the apps and `[runtime] host_mounts` from `weglarka.toml`, and remove the
`schema_version` line from `apps.toml` and `state.toml` — or restore both files from a backup taken before the upgrade
(see [state schema version](state-schema.md)).
