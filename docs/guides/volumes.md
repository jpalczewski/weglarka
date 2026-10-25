# Volumes and UID ranges

How Węglarka assigns UID ranges to containers, how to declare volumes in an app spec, and how to detach or remove them. Background and measurements: [ADR 0009](../decisions/0009-volume-ownership.md). Importing data before the first start (provisioning with `start = false`) is covered in [data-import.md](data-import.md) and [stopped-apps.md](stopped-apps.md); volumes shared by several apps are in [shared-volumes.md](shared-volumes.md).

## UID ranges

**Every Węglarka container runs in an explicit UID range** taken from the runtime user's subuid pool (`userns: private` plus explicit `UIDMap`/`GIDMap`):

- a regular app has its own range (65 536 UIDs);
- a **shared volume** has one range for its whole group of apps (see [shared-volumes.md](shared-volumes.md));
- the ingress nginx has its own range (4 096).

The range is stored in `state.toml` (`uid_range`, `shared_volumes.<name>.uid_range`, `ingress_uid_range`) and **does not change as long as data exists**: an app gets its range on its first deploy, a shared volume on the first deploy/provisioning of its first member. As a result, files in a volume have the same owner after every deploy and rollback, and a group of N apps costs **one** range instead of N.

Węglarka asks Podman for the pool (`GET /info`) and does not read `/etc/subuid` (the daemon in its container cannot see it). A pool of 2 000 000 fits the ingress range and 30 apps or groups. When there is no room left, the instance is blocked with a message in the reconcile log: enlarge `subuid` in your host provisioning (the range size does not change).

Each range also costs a one-off copy of the image layers with shifted owners (time and space in `~/.local/share/containers` on the first start of an image in a new range).

`state.toml` also stores `effective_uid_range`: the last range in which the app's container and volumes were prepared (its own, or the range of a shared volume). The range-change guard uses it when there is no container (an app provisioned with `start = false`, or after `apps stop`), so data in private volumes does not silently change owner ([#75](https://github.com/jpalczewski/weglarka/issues/75)).

## Volumes in the app spec

```toml
# apps.toml / --spec
volumes = [{ name = "data", target = "/data" }]   # read_only = true mounts it read-only
resources = { memory = "128m", pids_limit = 256 } # optional; no limits by default
```

The same with `apps add` / `apps update` flags (no spec file): `--volume data=/data` (a trailing `:ro` means read-only; the same name replaces the entry), `--memory 128m`, `--pids-limit 256`, `--cpus 0.5`; `none` removes a limit (`--memory none`). A typo in a spec-file field (e.g. `memory` instead of `resources.memory`) produces an error listing the valid fields.

A volume `<instance>.<name>` (e.g. `weather.data`) is created on deploy with the label `weglarka.instance`. `weglarka volumes list <app>` shows the declared volumes.

## Detaching volumes

A volume can be detached without replacing the whole spec: `weglarka apps update <app> --remove-volume data` detaches a private volume, and `weglarka apps update <app> --remove-shared-volume notes-data` detaches a shared one (both flags are repeatable and both exclude `--spec`). **Neither of them deletes data:**

- the data of a private volume stays in the Podman volume (`<app>.<name>`) until `weglarka apps remove <app> --purge-volumes` or a manual `podman volume rm`; after detaching, the next reconcile recreates the container without that mount, and `--volume data=/data` again attaches the same files;
- detaching the **last** member of a shared volume removes neither the `[shared_volumes.<name>]` declaration nor the `wg-shared-<name>` volume (data and UID range stay); the declaration is cleaned up only by `weglarka volumes remove <name> --purge`;
- a typo in the name is a usage error (code `64`, nothing is sent), and `--dry-run` shows the removed lines of the spec diff.

## Removing apps and data

`apps remove` **does not delete data** (the volumes and UID range stay; running `apps add` again with the same name finds them with the correct owner). To delete data: `weglarka apps remove <app> --purge-volumes` (removes the container and volumes and releases the UID range, with no way back). The UID range is also released when a removed app was left without volumes. The app network (`net-<instance>`) is removed by the daemon on the next reconcile pass after `apps remove`, once nothing uses it any more.

## Upgrade and rollback notes

### Upgrading Węglarka to a version with UID ranges (one-off)

Containers created by an older Węglarka (ntfy, nginx) run on Podman's shared default map (root in the container = the `weglarka` user on the host). After the update the daemon assigns them ranges and **recreates them once**:

1. Run `podman ps` and note the state; make sure you have a fresh rollback (the previous Węglarka image).
2. Update Węglarka (`podman pull … && systemctl --user restart weglarka.service`).
3. On start, nginx gets a range (`ingress_uid_range`) and is recreated: **a short traffic interruption** (a few seconds); the first start of an image in a new range is slower (layer copy).
4. Reconcile assigns `ntfy` a range, notices the missing `weglarka.uid-range` label on its container and recreates it once (no rollback, same digest; ntfy has no volumes). Later passes change nothing.
5. Check: `podman exec ntfy cat /proc/self/uid_map` (expected: `0 <start> 65536`, where `<start>` is `uid_range.start` from `weglarka apps show ntfy`), `weglarka doctor`, and `scripts/acceptance.sh` (mandatory).
6. If ntfy does not come up after the health gate: `journalctl --user -u weglarka` / `weglarka apps show ntfy`. Returning to the previous Węglarka leaves the containers with their ranges: nginx and ntfy go back to the default map only when the old version next recreates them.

Files mounted from the host (`nginx.conf` in `/var/lib/weglarka/nginx`) must be readable by "foreign" UIDs (0644 in a 0755 directory, which is how the daemon writes them).

### Rollback to a Węglarka without `effective_uid_range`

`effective_uid_range` in `state.toml` is a new `AppState` field, and `state.toml` has `deny_unknown_fields`, so **an older daemon will not read the file**. The value is derived (a copy of the app's `uid_range` or of `shared_volumes.<name>.uid_range`), so before a downgrade it is enough to:

1. Stop the apps (`apps stop`) and back up `state.toml`; a newer daemon recreates the field on the next provision/deploy.
2. Remove the `effective_uid_range` lines from `state.toml` (or restore the copy from before the rollout) and start the older daemon. Without this, the daemon refuses to start with a state parsing error.
3. **Update the CLI together with the daemon:** an older CLI cannot read the responses of `apps show`, `apps add`, `apps update` and `apps start`/`apps stop`, because `AppState` in the API also has `deny_unknown_fields`. A newer CLI reads an older daemon without changes.

For the rollback to a Węglarka without shared volumes, see [shared-volumes.md](shared-volumes.md).
