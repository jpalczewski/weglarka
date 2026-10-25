# Shared volumes

Several apps (containers) can work on **one** volume. The typical case is SQLite and the processes around it (api, mcp, worker). This guide covers declaring shared volumes, volume groups that share one UID range, the CLI, cleanup, moving an existing app into a group, and rolling back. The decision and the rejected alternatives are in [ADR 0017](../decisions/0017-shared-volumes.md); groups are in [ADR 0029](../decisions/0029-shared-volume-groups.md); UID ranges are explained in [ADR 0009](../decisions/0009-volume-ownership.md). For private volumes and UID ranges see [volumes.md](volumes.md); for import/export in general see [data-import.md](data-import.md).

## Declaring a shared volume

A volume is declared **once**, in a top-level section of `apps.toml`, and an app mounts it by name:

```toml
[shared_volumes.notes-data]   # declaration: no fields yet (room for future volume options)

[apps.notes-api]
image = "ghcr.io/example/notes-api:latest"
shared_volumes = [{ name = "notes-data", target = "/data" }]

[apps.notes-worker]
image = "ghcr.io/example/notes-worker:latest"
shared_volumes = [{ name = "notes-data", target = "/data", read_only = true }]   # read-only
```

A ready-made file (declaration plus two apps): [`docs/examples/sqlite-shared-volume.toml`](../examples/sqlite-shared-volume.toml).

## Groups

Two volumes, one group (for example a SQLite database in `/data` and git working trees in `/workspaces`, mounted by the same processes):

```toml
[shared_volumes.notes-data]
group = "notes"            # optional; by default the volume is its own group

[shared_volumes.notes-workspaces]
group = "notes"

[apps.notes-api]
image = "ghcr.io/example/notes-api:latest"
shared_volumes = [
  { name = "notes-data", target = "/data" },
  { name = "notes-workspaces", target = "/workspaces" },
]
```

From the CLI: `weglarka volumes add notes-data --group notes`. **A volume's group is fixed for as long as the volume exists**: its files belong to the group's UID range, so `volumes add` with a different group (or a manual change of `group` in `apps.toml`) ends with `409` / a refused deploy, and `doctor` warns about the mismatch. To move a volume to another group: `volumes export`, `volumes remove --purge`, `volumes add --group …`, `volumes import`. The group's range is released only when the **last** volume of the group (and its last member) goes away; purging a single volume does not release a range that holds the other volumes' data.

`weglarka volumes add <name>` writes the `[shared_volumes]` section. `apps.toml` is the daemon's file, so do not edit it while the CLI is running.

- The Podman volume is named `wg-shared-<name>` and carries the label `weglarka.shared-volume=<name>`, **without** `weglarka.instance`. That is why `apps remove --purge-volumes`, orphaned-volume cleanup and the per-instance volume filters never touch it.
- **One UID range per group:** all members get the same `UIDMap`/`GIDMap` and the same `weglarka.uid-range` label, so the same file has the same owner in every container. A member does **not** get its own `uid_range` in `state.toml`; each member still has its own container, network and domains.
- The declaration protects against typos: `shared_volumes` with a name that is not in `[shared_volumes]` is rejected by validation (HTTP 400, with the hint `weglarka volumes add <name>`), and an `apps.toml` with such an entry does not load at daemon start.
- **Several volumes per app, from one group only** (issue #129, [ADR 0029](../decisions/0029-shared-volume-groups.md)): the UID range belongs to the **group** of volumes, not to a single volume. Without the `group` field a volume is its own group (the pre-groups behaviour), so existing files lose nothing. An app can mount any number of volumes from **one** group; volumes from different groups in one app are rejected by validation (HTTP 400, "belong to different groups"). Private volumes (`volumes`) can be combined with a shared one. They are created in the group's range, so the other members can read them (a deliberately weaker isolation inside the group; a convenient way to give one process its own cache).
- A member with `start = false` provisions the range and the volume **without a container** (see [stopped-apps.md](stopped-apps.md)), so data can be imported before the first start.
- **A UID-range change with data present is rejected even without a container:** joining a group with an app that has private volumes (or leaving one) ends with `409` (`PUT /v1/apps/<name>`) or a failed reconcile action, even when the app is only provisioned or stopped, because the guard reads the last range from `state.toml` (`effective_uid_range`). Provisioning and deploy share a prologue, so a manual edit of `apps.toml` with the daemon stopped does not get through either. Changing the range is safe only after the data is gone (`apps remove --purge-volumes` or manually deleted volumes).
- **`doctor`:** `state.shared_volumes` reports group membership (the volumes and members of every group with more than one volume), a volume that exists in a different group than `apps.toml` declares, data without a declaration (with the hint `weglarka volumes remove <name> --purge`), a declared but not yet created volume, a `weglarka.uid-range` label mismatch, and a reminder that all images in a group must run as the same `USER`. `doctor` does not compare the users for you.

## Cleanup

- `apps remove` (without `--purge-volumes`) **does not delete data**: the volume and the range stay, and a later `apps add` finds the same files.
- `apps remove --purge-volumes` of a member while **other** members exist in the group ends with `409` with the list of members and **deletes nothing**. Remove the app without `--purge-volumes` (the data stays for the rest of the group), or first move the data out of Węglarka (`volumes export`).
- Purging the **last** member removes the group's volume and releases the range. The declaration in `apps.toml` **stays**, and the next member gets a new, empty volume.

## CLI

Declaring and cleaning up from the CLI (through the API, like `apps`):

```sh
weglarka volumes add notes-data                 # declaration in apps.toml (idempotent; PUT /v1/volumes/<name>)
weglarka volumes add notes-data --group notes   # ...in a group that shares one UID range (PUT ...?group=notes)
weglarka volumes list                           # without an app: all shared volumes
                                                # (NAME, GROUP, PODMAN NAME, MEMBERS, RANGE, EXISTS)
weglarka volumes remove notes-data              # 409 while any app mounts the volume; without data it removes
                                                # the declaration (without --purge it leaves a volume with data alone)
weglarka volumes remove notes-data --purge      # removes the group's volume (data!) and its entry in state.toml;
                                                # 409 while members exist (remove/detach the apps first)
```

`weglarka volumes list <app>` works as before and also shows shared volumes (the `SHARED` column). `apps add` / `apps update` accept `--shared-volume notes-data=/data` (a trailing `:ro` means read-only; the same name replaces the entry, like `--volume`; the flag is mutually exclusive with `--spec`). `weglarka apps update <app> --remove-shared-volume notes-data` detaches the mount without deleting data; the declaration and `wg-shared-notes-data` stay (see [volumes.md](volumes.md)).

## Moving an existing app into a group

Joining a group changes the app's effective UID range, so the files in its existing private volumes would become unreadable. Węglarka guards against this: if the old container had a `weglarka.uid-range` label different from the new one, and the instance already has private volumes (label `weglarka.instance`), the deploy is rejected with an error about a range change with data present, and `PUT /v1/apps/<app>` returns `409`. **The old container keeps running.** Migration order:

1. Stop the app and take a backup: `weglarka apps stop <app>`, then `weglarka volumes export <app> <volume> --out backup.tar` for every private volume (best take a SQLite database through `.backup`/`VACUUM INTO`).
2. Remove the private data so the guard lets the range change through: `weglarka apps remove <app> --purge-volumes` (or `podman volume rm <app>.<volume>`). This is irreversible, hence the backup first.
3. Add the app with the shared volume mount and `start = false` (provisioning without a container).
4. `weglarka volumes import <app> notes-data --from backup.tar`. The default mode (foreign tar) flattens owners to the container user, which is correct for the group's range.
5. `weglarka apps start <app>` and verify the data.

Leaving a group (removing the mount) is the same range change under the same guard. When a member has its own private volumes, `apps remove --purge-volumes` is blocked by the other members, so: export, then `apps stop <app>`, then `podman volume rm <app>.<volume>` (manually), then `apps update --spec` without the shared volume.

## SQLite and import/export with shared volumes

**SQLite in a shared volume (several writers).** A shared UID range aligns file owners only if **all member images run as the same container user**. Węglarka does not override the image's `USER`; uid 1000 in the container is `range.start + 1000`, uid 999 is `range.start + 999`. Check before adding the group: `podman inspect <container> --format '{{.Config.User}}'` (an empty result means root, uid 0, which also has to be the same across the whole group). `doctor` (`state.shared_volumes`) only reminds you of this and lists the members.

On top of that, the usual SQLite rules apply: `journal_mode=WAL` is stored in the database file and survives restarts; SQLite serialises writes anyway (one writer at a time), so set `busy_timeout`, otherwise the second process gets `SQLITE_BUSY` instead of waiting. The volume must be on a **local** disk (POSIX locks are unreliable on NFS), and the backup should be taken through `.backup`/`VACUUM INTO` with the group stopped, or from inside a container. Litestream assumes a single writer; that is issue #37, and only the requirements are listed here, not a configuration.

**Import/export of a shared volume.** `volumes export <app> <volume>` works, but for a consistent SQLite copy stop the **whole group** first (`apps stop` on every member). Import is rejected (`409`, with a message listing the running members) while any member is running, because writing to the database under live processes corrupts it. `--replace` removes and recreates the group's volume (so it is even riskier in a group), and `--own` is correct only for an export from the **same** UID range, that is, the same group; import a foreign tar in the default mode. The volume name in these commands is the declared name (`notes-data`), not `wg-shared-notes-data`. The general import and export rules are in [data-import.md](data-import.md).

## Rollback

Rolling back to a Węglarka without shared volumes. `[shared_volumes]` in `apps.toml` and the `shared_volumes` section in `state.toml` are new fields, and both files have `deny_unknown_fields`, so **an older daemon will not read them**. Before the downgrade:

1. Remove all `shared_volumes` entries from the apps (or `apps remove` the members first), the `[shared_volumes.*]` sections from `apps.toml` and the `shared_volumes` section from `state.toml`. Alternatively just restore both files from a backup taken before shared volumes were deployed.
2. The old Węglarka does not see `wg-shared-*` volumes (no `weglarka.instance` label), and **you cannot point it at** such a volume as an app's private volume. If the data is not needed: `podman volume rm wg-shared-<name>`. If it is, copy it into an app's private volume before the downgrade (remember that the old Węglarka recreates the container in its own UID range), or leave the volume for later.
3. Member containers run in the group's range until the old daemon recreates them, and it recreates them in their own ranges, which makes the data in the volume unreadable. Before the downgrade, run `volumes export` and stop the apps (`apps stop`).
