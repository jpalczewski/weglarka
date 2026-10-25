# State schema version and rollback

`apps.toml` and `state.toml` may carry a `schema_version` field ([ADR 0023](../decisions/0023-state-schema-version.md)).
It lets an older daemon refuse a file that is newer than it understands instead of failing with a parse error.

## Rules

- **A file without `schema_version` is version 1** — the shape from before versioning. The daemon does not write
  `schema_version = 1`; the marker appears from the first real bump. **The current version is 7**: a v1 file loads
  unchanged, and the first ordinary write stamps `schema_version = 7`.
- The marker is introduced only in a release that really changes the schema (adds or changes a field of
  `apps.toml`/`state.toml`). Such a version runs a migration on read, and the first ordinary write stamps the new
  number. Each bump has a matching step in `SCHEMA_STEPS` (`crates/weglarka-core/src/state.rs`); a compile-time assert
  keeps the number of steps equal to `SCHEMA_VERSION - 1`.
- **An older daemon refuses to start** when a file has a newer version than it understands:

  ```text
  /var/lib/weglarka/state.toml: schema version 4 is newer than this daemon supports (3); written by
  a newer Węglarka — roll forward to that version, or restore apps.toml and state.toml from before
  the upgrade
  ```

  This is not a file error; it signals that the Węglarka image is older than the state. Ways out: return to the
  newer image (roll forward), or restore `apps.toml` and `state.toml` from the backup taken before the upgrade.
  `weglarka doctor --preflight` reads `apps.toml` on its own and shows the same message before the daemon restarts.
- **Before every Węglarka upgrade**, back up the state directory (or at least `apps.toml`, `state.toml` and
  `secrets.toml`). The backup is the only way back across a schema version boundary: a newer daemon migrates the
  files and an older one cannot read them afterwards.
- After restoring an older `state.toml`, reconcile fills in the UID ranges from container labels, but apps without a
  pinned `current` may be deployed anew (pull + health gate).

## Versions

Rollback to a release that predates a version requires removing the listed fields (see
[verification and rollback](verify-and-rollback.md)) or restoring both files from before the upgrade. The first
write after upgrading stamps the new number even if you do not use the feature.

| Version | Introduced by | Fields | ADR | Guide |
|---|---|---|---|---|
| 1 | — (implicit, no marker) | the shape before versioning | — | — |
| 2 | #118 | `configs` and `reload_signal` in app specs (with `config_root` in `weglarka.toml`) | [0028](../decisions/0028-config-root-mounts.md) | [host configs](host-configs.md) |
| 3 | #129 | optional `group` in `[shared_volumes.<name>]` | [0029](../decisions/0029-shared-volume-groups.md) | [shared volumes](shared-volumes.md) |
| 4 | #128 | `[shared_networks.<name>]` and `shared_networks` in app specs | [0030](../decisions/0030-shared-networks.md) | [shared networks](shared-networks.md) |
| 5 | #130 | `paths` and `ingress.strip_prefix` | [0031](../decisions/0031-path-prefix-routing.md) | [path routing](path-routing.md) |
| 6 | — | optional `ingress.max_body_size` | [0033](../decisions/0033-ingress-max-body-size.md) | [max body size](max-body-size.md) |
| 7 | #55 | optional `uid`/`gid` on a mounted secret | [0037](../decisions/0037-secret-mount-ownership.md) | [first app](first-app.md) |

Fields introduced before versioning existed (`start`, `depends_on`, `host_ports`, `command`, `shared_volumes`,
`streaming`) are part of v1 and are not covered by the marker; remove them by hand before downgrading to a release
that predates them.
