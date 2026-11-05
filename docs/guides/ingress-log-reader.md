# Reading the ingress logs from a collector

nginx writes the access and error logs (visitor addresses) to `<state dir>/ingress-logs`, owned by the daemon and
kept for the [retention period](log-retention.md). One app per host can read those files, read-only, without a
`host_mounts` workaround. This is how a log collector (for example Grafana Alloy) ships them.

## Configuration

Two settings, and both are required:

```toml
# weglarka.toml: the one app that may read the logs (omit = nobody may)
[logs]
reader = "collector"
```

```sh
weglarka apps add collector --image ghcr.io/example/collector:1 --ingress-logs
# or, for an existing app:
weglarka apps update collector --ingress-logs
```

`ingress_logs = true` in the app spec is refused (HTTP 400, a blocked app in reconcile, `doctor` check `logs.reader`
FAIL) for any app whose name is not `[logs] reader`. `doctor` warns when `reader` names an app that does not exist or
does not set `ingress_logs`.

The reader container gets the log root mounted **read-only** at `/var/log/weglarka-ingress` and keeps the runtime
user's groups (`keep-groups`), because the directory is `0750` and only that group can read it
([ADR 0072](../decisions/0072-ingress-log-reader.md)). Check that the runtime user's primary group has no other
members (`getent group <name>`); every member can read visitor addresses. No `platform install` re-run is needed.
Changing `ingress_logs` recreates the app once.

## The files

Under `/var/log/weglarka-ingress` (the log root, so subdirectories added later are covered too):

- `access.log` and `error.log`: the files nginx is writing now.
- `access-YYYY-MM-DD.log` and `error-YYYY-MM-DD.log`: completed days (UTC), made by renaming the current file.

Point the collector at a glob such as `/var/log/weglarka-ingress/access*.log`. Rotation is a **rename**, so follow by
inode and keep the offset; a collector that tails by name sees the file shrink to zero once a day. Files past retention
are deleted, but a deleted file stays on disk until the collector closes it, so close handles for files that
disappeared.

## Your collector's retention is part of the promise

The [retention guarantee](log-retention.md) covers the files in the state directory only. Whatever the collector
stores (Loki, for instance) holds the same visitor addresses and must be configured with a retention that matches
what you promise your visitors.

## Rollback

`ingress_logs` and `[logs] reader` break a downgrade: the state schema is 22 and both files use
`deny_unknown_fields`.

1. `weglarka apps update collector --no-ingress-logs` and remove `reader` from `[logs]` in `weglarka.toml`
   (the section can stay for `retention`).
2. Restore `apps.toml` and `state.toml` from a backup taken before the upgrade, or remove the `schema_version`
   marker after the fields are gone, before starting an older daemon (see [state schema](state-schema.md)).

See [verification and rollback](verify-and-rollback.md).
