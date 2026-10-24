# weglarka-cli

The `weglarka` binary — a thin client for the daemon's admin API (HTTP/JSON over a unix socket)
plus a local `doctor --preflight`. Command descriptions (`--help`) are in Polish.

## Configuration

Socket: `--socket` / `WEGLARKA_SOCKET`, otherwise `admin.socket` from `weglarka.toml`
(`--config` / `WEGLARKA_CONFIG`, default `/etc/weglarka/weglarka.toml`).

## Conventions for agents

- `--json`: exactly one document on stdout — a type from `weglarka-api` (`ListAppsResponse`,
  `ShowAppResponse`, `DeployResponse`, `StatusResponse`, `ListSecretsResponse`, `SecretInfo`,
  `ListVolumesResponse`, `ListSharedVolumesResponse`, `DoctorReport`). CLI exceptions: `apps remove` →
  `{"removed","existed"}`, `secrets remove` → `{"removed"}` (the removed `<app>.<name>`), `volumes add` →
  `{"declared"}`, `volumes remove` → `{"removed","purged"}`, a no-op of `apps update`/`start`/`stop` →
  `{"changed":false,"app"}`, `--dry-run` → `{"dry_run":true,"method","path","body"}`.
- Errors go to stderr; with `--json`: `{"error":{"code","message","hint","exit_code"}}`.
- `--dry-run` (`apps add/remove/update/start/stop`, `deploy`, `secrets set/remove`, `volumes add/remove`):
  nothing is sent that would change state; `apps remove`/`deploy`/`start`/`stop` only check that the app
  exists (GET), while `secrets remove --dry-run` sends nothing at all (the app need not exist). The
  purge flags are part of the printed path (`?purge_volumes=true&purge_secrets=true`). The secret value
  is masked.
- `apps update <name>`: read-modify-write of the whole spec (`GET`, apply flags, `PUT`); `--dry-run` shows the
  diff (`{"dry_run","method","path","changed","diff","body"}`), a no-op sends nothing (`{"changed":false,…}`).
  Output: `UpdateAppResponse`; exit 6 when the image change was rolled back. A spec bound to unset secrets shows
  runtime `waiting-for-secret` (`waiting_for_secret` in JSON) with `state.waiting_for_secrets`.
- Spec flags without `--spec`: `--volume NAME=/PATH[:ro]` (repeatable) adds a private named volume;
  `--shared-volume NAME=/PATH[:ro]` (repeatable) mounts a volume shared with other apps (issue #33).
  A shared volume must be declared first (`weglarka volumes add NAME`); an app may mount several,
  but only of one group (`volumes add NAME --group G`, issue #129); a mount
  of the same name is replaced; `--shared-volume` conflicts with `--spec` like `--volume`. Omitting
  the flags keeps the volumes already in the spec (read-modify-write).
- Spec flags without `--spec`: `--host-port [IP:]HOST:CONTAINER` (repeatable) publishes a container port
  directly on the host (issue #34): omitting `IP` binds loopback (`127.0.0.1`), `--host-port 0.0.0.0:2222:22`
  exposes it, `none` clears the list. TCP only, and the port bypasses the ingress (no TLS, no routing, no
  access log) — the host firewall has to allow it. The mapping is part of `spec_hash`, so a change recreates the
  container; host ports < 1024 need `[runtime] allow_privileged_host_ports = true`. Conflicts with `--spec`,
  like `--volume` and the limit flags.
- Spec flags without `--spec`: `--depends-on NAME` (repeatable, `none` clears the list) on `apps add`/`apps update`
  sets the start order (issue #35): the app is started only once every app it names is running — and healthy, if
  that app has a healthcheck — on boot, first deploy, `apps start`, deploy or a recreate with a missing container.
  `apps update --remove-depends-on NAME` drops one entry (a usage error when absent). The relation is ordering only:
  the apps do not share a network and cannot reach each other by name. `depends_on` is not part of `spec_hash`, so
  changing it never recreates a container, while `apps remove` of a dependency is refused (409 Conflict, listing the
  dependents) until the dependents or their entries are gone. Conflicts with `--spec`, like the other spec flags.
- `--streaming` / `--no-streaming` (`[ingress] streaming` in `--spec`): serve streaming responses — SSE,
  chunked, long polling — with no nginx response/request buffering and a long idle timeout (issue #64).
  Ingress-only: a change re-renders nginx.conf and reloads nginx (no deploy, no traffic gap), the container is
  untouched and `spec_hash` does not change. `apps add --streaming` sets it, `apps update --streaming` turns it
  on; `apps update --no-streaming` resets the streaming settings, a custom timeout included (`strip_prefix` is kept), and sends
  nothing (a no-op) when the app is not streaming. `stream_timeout_secs` — default 180, allowed 1..=3600 — has
  no flag in v1: set it through `apps update --spec` (validation rejects it unless `streaming = true`).
  Conflicts with `--spec`.
- `--path PREFIX` (repeatable; `paths` in `--spec`) and `--strip-prefix` (`[ingress] strip_prefix`): serve only a
  path prefix of the app's domains, so several instances can share one domain (issue #130, ADR 0031). Prefixes
  must be disjoint between instances (`/` is the catch-all). `apps update` also has `--remove-path` and
  `--no-strip-prefix`. Ingress-only like `--domain`: nginx reload, no recreate. Conflicts with `--spec`.
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
- Secrets: `secrets set <app> <name>` reads stdin or `--from-file`; passing the value as an argument
  is impossible. One trailing `\n` is trimmed by default (`--raw` keeps the bytes). `secrets remove
  <app> <name>` refuses (409) while the app's spec still binds the secret — drop the binding with
  `apps update <app> --unbind-secret <name>`, or pass `--force` (the app then waits for the secret; a
  running container keeps the old value). The app need not exist, so the leftovers of a removed or
  renamed app can still be removed (`doctor` names them, `secrets list` needs a live app). `apps
  remove` keeps the stored secrets by default (a new app under the same name inherits them); `apps
  remove --purge-secrets` deletes them together with the app and is independent of `--purge-volumes`.

## Volumes

- `volumes list [app]` — with an app: the app's volumes (private and shared) with a `SHARED`
  column; without an app: the shared volumes declared in `apps.toml` — `NAME`, `GROUP`,
  `PODMAN NAME`, `MEMBERS`, `RANGE` (`<start>+<size>`, `-` before the first deploy), `EXISTS`.
- `volumes add <name> [--group G]` — declare a shared volume (`PUT /v1/volumes/{name}`, idempotent,
  204). Volumes of one group share a uid range, so one app can mount several of them; the default
  group is the volume itself. The group is fixed while the volume exists (409 otherwise). Names are
  validated locally before anything is sent; `--dry-run` prints the request including `?group=`.
- `volumes remove <name> [--purge]` — remove a declaration (`DELETE /v1/volumes/{name}`; with
  `--purge` the query is `?purge=true` and the Podman volume is deleted with its data). Refused with
  409 while an app still mounts it; without `--purge` also while the volume holds data.
  `--dry-run` prints the request including the query.
- `volumes export <app> <volume>` / `volumes import <app> <volume>` — stream a tar to/from a file or
  stdin/stdout; a shared volume is resolved through a member app (the import helper runs in the
  group's uid range). An import into a shared volume is refused while another member runs.
- Shared volume groups (`docs/decisions/0017-shared-volumes.md`, `0029-shared-volume-groups.md`) own one uid range: `wg-shared-<name>`,
  created on the first member's deploy. `apps add/update --shared-volume NAME=/PATH[:ro]` mounts
  one; `apps remove` keeps the data, while `apps remove --purge-volumes` on a member is refused
  (409) while other members exist.

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
`ingress.traefik_file` (`behind` only), `ingress.config` (the `[ingress]` keys match the mode: `edge`
requires `https_bind` and forbids `traefik_dynamic_file`/`trusted_proxies`, and a publish port below 1024
requires `[runtime] allow_privileged_host_ports`), `ingress.tls` (`edge` only: every routed domain has a
`<domain>.crt` + `<domain>.key` pair under `<nginx_conf_dir>/tls`; missing is a `warn`, issue #96 will
automate it), `ingress.privileged_ports` (`edge` with a port below 1024: `net.ipv4.ip_unprivileged_port_start`),
`ingress.bind`, `ingress.bind_free` (every publish from `publish_sockets()` — one in `behind`, two in
`edge` — is not held by a socket of a uid other than the runtime user; read from `/proc/net/tcp*`),
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
