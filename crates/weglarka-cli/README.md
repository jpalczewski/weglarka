# weglarka-cli

The `weglarka` binary — a thin client for the daemon's admin API (HTTP/JSON over a unix socket)
plus a local `doctor --preflight`. Command descriptions (`--help`) are in Polish.

## Configuration

Socket: `--socket` / `WEGLARKA_SOCKET`, otherwise `admin.socket` from `weglarka.toml`
(`--config` / `WEGLARKA_CONFIG`, default `/etc/weglarka/weglarka.toml`).

## Conventions for agents

- `--json`: exactly one document on stdout — a type from `weglarka-api` (`ListAppsResponse`,
  `ShowAppResponse`, `DeployResponse`, `StatusResponse`, `ListSecretsResponse`, `SecretInfo`,
  `DoctorReport`). CLI exceptions: `apps remove` → `{"removed","existed"}`, a no-op of
  `apps update`/`start`/`stop` → `{"changed":false,"app"}`, `--dry-run` →
  `{"dry_run":true,"method","path","body"}`.
- Errors go to stderr; with `--json`: `{"error":{"code","message","hint","exit_code"}}`.
- `--dry-run` (`apps add/remove/update/start/stop`, `deploy`, `secrets set`): nothing is sent that would
  change state; `remove`/`deploy`/`start`/`stop` only check that the app exists (GET). The secret value is
  masked.
- `apps update <name>`: read-modify-write of the whole spec (`GET`, apply flags, `PUT`); `--dry-run` shows the
  diff (`{"dry_run","method","path","changed","diff","body"}`), a no-op sends nothing (`{"changed":false,…}`).
  Output: `UpdateAppResponse`; exit 6 when the image change was rolled back. A spec bound to unset secrets shows
  runtime `waiting-for-secret` (`waiting_for_secret` in JSON) with `state.waiting_for_secrets`.
- Spec flags without `--spec`: `--host-port [IP:]HOST:CONTAINER` (repeatable) publishes a container port
  directly on the host (issue #34): omitting `IP` binds loopback (`127.0.0.1`), `--host-port 0.0.0.0:2222:22`
  exposes it, `none` clears the list. TCP only, and the port bypasses the ingress (no TLS, no routing, no
  access log) — the host firewall has to allow it. The mapping is part of `spec_hash`, so a change recreates the
  container; host ports < 1024 need `[runtime] allow_privileged_host_ports = true`. Conflicts with `--spec`,
  like `--volume` and the limit flags.
- Lifecycle: `start` is a spec field (default `true`), not a one-shot flag. `apps add --no-start` provisions
  only — the image digest is pinned, the network, uid range and volumes are created, **no container**;
  `apps start` / `apps stop` flip the flag with the same read-modify-write as `apps update`
  (`apps update --start`/`--no-start` do it inside a spec edit). `stop` removes the container and keeps the
  volumes, the uid range and the pinned digest; a `start = false` app is not routed by ingress and gets no
  webhook deploys. Output: `UpdateAppResponse` (a deploy that only provisions reports outcome `provisioned`); a
  flip that is already in place sends nothing (`{"changed":false,"app":…}`). Runtime state: `not-started`
  (`not_started` in JSON). `start = true` is the default and is omitted from the `AppSpec` TOML/JSON, so a spec
  without `start` means the app runs.
- Idempotency: `apps remove --ignore-missing`. `apps add --spec file.toml` takes a whole `AppSpec`.
- Secret: `secrets set <app> <name>` reads stdin or `--from-file`; passing the value as an argument
  is impossible. One trailing `\n` is trimmed by default (`--raw` keeps the bytes).

## Exit codes

| code | meaning |
|---|---|
| 0 | success |
| 1 / 2 | `doctor`: worst result is `warn` / `fail` |
| 3 | not found |
| 4 | already exists / conflict |
| 5 | the daemon rejected the request (`invalid_request`) |
| 6 | `deploy`: `rolled_back` |
| 64 | invalid invocation / input data |
| 69 | daemon unreachable |
| 70 | internal error (I/O, protocol, 5xx) |
| 78 | missing / invalid `weglarka.toml` |

## `doctor --preflight`

Checks (`id`): `config.file`, `runtime.user`, `runtime.subuid`/`subgid` (fail < 65,536,
warn < 1,000,000 — headroom for `userns=auto`), `runtime.cgroups`, `runtime.linger` (systemd only),
`runtime.socket`, `runtime.podman_version` (libpod ≥ 6.0), `runtime.podman_source` (alvistack),
`runtime.netavark` (≥ 2, nftables), `runtime.pasta`, `runtime.apparmor_userns` (with
`kernel.apparmor_restrict_unprivileged_userns=1` the `podman` profile must be loaded; the profile
list is readable only by root — as a regular user the result is `warn`; no AppArmor = ok),
`ingress.traefik_file` (`behind` only), `ingress.bind`, `ingress.bind_free` (the port from `bind` is
not held by a socket of a uid other than the runtime user; read from `/proc/net/tcp*`),
`ingress.traefik_sync` (`behind` + systemd only: if `/etc/weglarka/traefik-policy.json` exists, the
unit `weglarka-traefik-sync.path` is `active`, and the domains from `apps.toml` — if available
locally — are on the policy allowlist, key `allowed_domains`; the paths and the unit name are
constants from the convention of the Ansible role `weglarka_host`), `apps.host_ports_free` (ports published via
`host_ports` — read from `apps.toml` if available locally — are not held by a socket of another uid, same
`/proc/net/tcp*` technique as `ingress.bind_free`, and no port < 1024 without
`[runtime] allow_privileged_host_ports`), `state.secrets_file` (0600).
Firewall rules (UFW) are not checked — they require root.
A new check = a type implementing `Check` in `src/preflight/checks.rs` + an entry in `all_checks()`.
Host access goes exclusively through the `Host` trait (tests: `FakeHost`).
`secrets.toml` has no path in `weglarka.toml` — by default it sits next to the config file,
override: `--secrets-file` / `WEGLARKA_SECRETS_FILE`.
