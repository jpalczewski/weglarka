# State schema version and rollback

`apps.toml` and `state.toml` may carry a `schema_version` field ([ADR 0023](../decisions/0023-state-schema-version.md)).
It lets an older daemon refuse a file that is newer than it understands instead of failing with a parse error.

## Rules

- **A file without `schema_version` is version 1** — the shape from before versioning. The daemon does not write
  `schema_version = 1`; the marker appears from the first real bump. **The current version is 15**: a v1 file loads
  unchanged, and the first ordinary write stamps `schema_version = 15`.
- The marker is introduced only in a release that really changes the schema (adds or changes a field of
  `apps.toml`/`state.toml`). Such a version runs a migration on read, and the first ordinary write stamps the new
  number. Each bump has a matching step in `SCHEMA_STEPS` (`crates/weglarka-model/src/state.rs`); a compile-time assert
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
| 8 | #178 | `host_mounts` and `group_add` in app specs (with `[runtime] host_mounts`/`group_add` in `weglarka.toml`) | [0045](../decisions/0045-host-mounts.md) | [host mounts](host-mounts.md) |
| 9 | #39 | optional `strategy` in app specs | [0046](../decisions/0046-blue-green-deploy.md) | [blue-green](blue-green.md) |
| 10 | #181 | optional `ingress.access_log_skip_paths` | — | [access log](access-log.md) |
| 11 | #180 | optional `ingress.streaming_paths` | [0047](../decisions/0047-ingress-streaming-paths.md) | [streaming](streaming.md) |
| 12 | #48 | optional `kind = "static"` | [0049](../decisions/0049-static-sites.md) | [static sites](static-sites.md) |
| 13 | #205 | optional `[sites.<site>]` with environments | [0050](../decisions/0050-site-environments.md) | [site environments](site-environments.md) |
| 14 | #42 | optional `oidc`, `ingress.auth*` and `[oidc_clients]` (accepted by the parser, every non-default value rejected until the feature lands) | [0051](../decisions/0051-identity-provider-integration.md), [0052](../decisions/0052-forward-auth.md) | — (not enabled yet) |
| 15 | #43 | optional `oidc.device_flow` and `[oidc_clients.<id>] device_flow`; `redirect_uris` may be empty with it | [0060](../decisions/0060-remote-cli-device-login-via-the-panel.md) | [identity provider](identity-provider.md) |

Fields introduced before versioning existed (`start`, `depends_on`, `host_ports`, `command`, `shared_volumes`,
`streaming`) are part of v1 and are not covered by the marker; remove them by hand before downgrading to a release
that predates them.
