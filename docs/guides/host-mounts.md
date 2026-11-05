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

**4. Journal groups.** Journal files are `root:systemd-journal 0640`, so the app also needs the group. Allowlist the name and
request it:

```toml
[runtime]
group_add = ["systemd-journal"]
```

```sh
sudo usermod -aG systemd-journal weglarka            # the runtime user must be a member
sudo systemctl restart user@<uid>                    # `id -u weglarka`; see below why this and not podman.service
weglarka apps update alloy --group-add systemd-journal
```

A restart of `podman.socket`/`podman.service` is **not** enough. Every unit of a user inherits its credentials from the
systemd **user manager** (`systemd --user`), and that process keeps the groups it was started with: after `usermod -aG`
a restarted `podman.service` still lacks the new group, and so does a `keep-groups` container (measured on rootless
Podman 6.1.3). Only a restart of `user@<uid>` — or a reboot — gives the user manager, `podman.service` and the units
the new credential set. A fresh login (`sudo -u weglarka id -G`) is not a proof either: PAM applies the new group
there, not to the running user manager.

Verify the credential set of the user manager itself:

```sh
getent group systemd-journal                                   # the gid the runtime user must hold
grep Groups /proc/$(pgrep -u weglarka -x systemd)/status       # must list it
```

Restarting `user@<uid>` stops **every** container of that user, the Węglarka daemon included. Its own unit is enabled
with the user manager, so it comes back on its own, and its next reconcile starts the app containers that are down
(they are started, not recreated). Apps with `start = false` ([stopped apps](stopped-apps.md)) stay stopped. This
relies on `podman.socket` being **enabled** (`systemctl --user -M weglarka@ enable podman.socket`, see
[install](../install.md)): a socket that was only started does not come back with the user manager, and the daemon
then has no Podman to talk to.

The commands above are for systemd. On OpenRC there is no user manager: restart the services of the runtime user
(`weglarka-podman` and `weglarka`) after `usermod`, and check the `Groups:` line of the running `podman system service`
process instead.

`group_add` makes the container keep **all** supplementary groups of the runtime user (crun `keep-groups`); the name
list is a gate, not a selector. Keep the runtime user out of groups apps do not need. Inside the container the group
shows as `nobody`, which is expected. A numeric gid does not work in a mapped user namespace, hence names only.

The daemon container has no `/etc/passwd`, `/etc/group` or user manager, so it cannot check this itself — and checking
inside the container is misleading, because an unmapped supplementary gid shows up as the overflow gid there. Instead
the host-side watchdog (`weglarka-daemon supervise`, the `weglarka-watchdog.timer` that `platform install` sets up)
compares the groups `/etc/group` records for the runtime user with the credentials the user manager really holds
(`/proc/$MANAGERPID/status`, the manager systemd names when it starts the unit), once a minute, and `weglarka doctor`
reports `host_mounts.groups` as a warning (`user manager credentials are stale: restart user@<uid>`) while a group an
app requests in `group_add` is missing. It clears on its own within a minute of the restart. The warning names only the
requested groups, never the runtime user's other memberships.

The check is systemd-only: run by hand or from cron it has no `MANAGERPID` and records nothing (a fresh login gets the
new groups and would hide the problem). When the watchdog has not refreshed its record for five minutes (timer
removed, job disabled), `doctor` shows an `info` that it cannot tell instead of the old answer.

It only detects a group the user manager **lacks**. The other direction — `usermod -rG` removing the runtime user from
a group — is not reported yet: until `user@<uid>` restarts, the user manager and every `group_add` container keep the
removed gid. Restart `user@<uid>` after removing a group as well.

**Alternative without a new group.** If the files are only for one app and you would rather not change group
membership, give the runtime user's **primary** group read access with a POSIX ACL: the primary group is already in
every credential set, so no restart is needed. This works only when the app's process runs as **root inside the
container** (its gid 0 is the runtime user's primary group on the host). A non-root image user runs with a gid from the
subgid range, which the ACL does not name, so for such an app the ACL grants nothing — use `group_add` instead.

```sh
sudo setfacl -R  -m g:$(id -gn weglarka):rX /var/log/journal   # existing files and directories
sudo setfacl -dR -m g:$(id -gn weglarka):rX /var/log/journal   # default ACL for new (rotated) files
```

Re-apply the first command if the directory itself is replaced (a new mount, a fresh machine): an ACL lives on the
inode, not on the path.

Changing `host_mounts` or `group_add` of an app recreates its container; changing an allowlist alone recreates nothing.

## Rollback

`apps.toml` now carries `schema_version = 8` and `weglarka.toml` has `deny_unknown_fields`. Before downgrading to an older
daemon, remove `host_mounts` and `group_add` from the apps and `[runtime] host_mounts`/`group_add` from `weglarka.toml`, and remove the
`schema_version` line from `apps.toml` and `state.toml` — or restore both files from a backup taken before the upgrade
(see [state schema version](state-schema.md)).
