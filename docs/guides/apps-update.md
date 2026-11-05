# apps update: what happens after a change

`weglarka apps update <app> [flags]` reads the current spec, applies the flags and sends the **whole** spec (a full
replacement; `--spec file.toml` replaces it entirely from a file — a missing `start` in the file means
`start = true`; `--spec -` reads the file from stdin, e.g. `ssh myhost weglarka apps update web --spec - < web.toml`).
`--dry-run` shows the diff and sends nothing. `weglarka apps diff <app> --spec file.toml` prints the same diff and
answers with the exit code (0 identical, 8 differs); both name the `env` keys that exist only in the live spec and that the
file would drop.

When the daemon is busy with another deploy (the health gate can take tens of seconds), the CLI does not return a
"busy" error immediately; it retries the request for up to 3 minutes (the message "daemon is busy … waiting…" on stderr).

| Change | Effect |
|---|---|
| `--domain` / `--remove-domain` | ingress only (nginx reload, Traefik file); the container is unchanged |
| `--path` / `--remove-path`, `--strip-prefix` / `--no-strip-prefix` | ingress only (nginx reload); the container is not recreated — see [path routing](path-routing.md) |
| `--streaming` / `--no-streaming`, `--max-body-size` / `--unset-max-body-size` | ingress only (nginx reload); the container is not recreated — see [streaming](streaming.md) and [max body size](max-body-size.md) |
| `ingress.security_headers` in `--spec` (no flag) | ingress only (nginx reload); the container is not recreated and `spec-hash` is unchanged — see [security headers](security-headers.md) |
| `--env`/`--unset-env`, `--port`/`--unset-port`, `--secret-env`/`--secret-mount`/`--unbind-secret`, volumes, limits, `health.command` | changes `spec-hash` → the next reconcile recreates the container from the pinned digest (no pull) |
| `--shared-volume` (`shared_volumes` in `--spec`) | like volumes: changes `spec-hash` → the next reconcile recreates the container within the shared UID group range (a change of `target`/`read_only` too). A range change with existing private volumes is rejected — see [shared volumes](shared-volumes.md). An empty list hashes as before |
| `--shared-network` (`shared_networks` in `--spec`) | changes `spec-hash` → the next reconcile recreates the container — see [shared networks](shared-networks.md) |
| image (`apps update <app> <image>`) | deploys immediately: pull, health gate, rollback on failure |
| `--auto-update` / `--no-auto-update` | write only; affects subsequent webhooks |
| `--start` / `--no-start` (`start` in `--spec`) | `start = false` removes the container (the volume and UID range stay), `start = true` deploys immediately: pull, health gate, rollback on failure. `spec-hash` unchanged — see [stopped apps](stopped-apps.md). A write that turns `start` off on a running app is refused without `--allow-stop` — see below |
| `--command` (`command` in `--spec`) | changes `spec-hash` → the next reconcile recreates the container from the pinned digest (no pull); the flags replace the whole argument vector, and `--command none` restores the image's `CMD` — see [container command](container-command.md) |
| `--host-port` (`host_ports` in `--spec`) | changes `spec-hash` → the next reconcile recreates the container from the pinned digest (no pull); the published port is recreated together with the container — see [host ports](host-ports.md) |
| `internal_hosts` in `--spec` (no flag) | changes `spec-hash` → the next reconcile recreates the container from the pinned digest (no pull); the `/etc/hosts` entries are fixed when it is created — see [reaching your own domains](internal-hosts.md) |
| `--config-mount` (`configs` in `--spec`), `--reload-signal` | the `configs` list changes `spec-hash` → the next reconcile recreates the container from the pinned digest (no pull); file **contents** are not in the hash, so apply content changes with `weglarka apps reload`. `reload_signal` is outside the hash and only affects reload — see [host configs](host-configs.md) |

## `start` in a spec file is persisted desired state

`start` is not an option of `apps add`: it is the desired state that the reconciler converges to (see
[stopped apps](stopped-apps.md)). A spec file written for provisioning — `start = false`, so that the first `apps add`
creates the volumes, the UID range and the pinned digest but no container — therefore still means "stopped" when the same
file is reused for `apps update --spec`, and that update would take a running app down. The flip is not part of
`spec-hash` either, so nothing else in the output would hint at it.

`apps update` therefore refuses a write that turns `start` from `true` (the live spec) to `false` (the new spec):

```console
$ weglarka apps update web --spec provisioning.toml
error: this stops web: the new spec sets `start = false`
hint: pass `--allow-stop` if that is intended, or stop the app explicitly with `weglarka apps stop web`
```

- The refusal covers both forms: a spec file (`--spec`) and the flag edit (`--no-start`). It is decided from the specs
  alone — a running app loses its container, and one whose container is `stopped`/`missing` (with `start = true`, so the
  reconciler would restart it) would never come back. Nothing is sent: the check runs after the current spec is read and
  before the `PUT`, with exit code 64.
- `--allow-stop` writes the spec as it is. On its own it is not an edit (`nothing to change`).
- `weglarka apps stop <app>` / `weglarka apps start <app>` are the explicit way to flip the flag and are not affected by
  the guard.
- Keeping one spec file for provisioning and updates: remove the `start = false` line once the app is meant to run, or
  keep a separate file for provisioning.
- `--dry-run` never fails on this: `start` appears in the spec diff (`+ start = false`) and the run prints
  `would stop web (start: true -> false): a real run is refused without --allow-stop`. In JSON the additive field is
  `would_stop: true`, absent when the write stops nothing.
- `weglarka apps diff <app> --spec file.toml` is unchanged: the same diff, exit code 8 when it differs.

## Waiting for the result: `--wait`

`apps update`, `apps start` and `apps stop` accept `--wait [--timeout SECS]` (default 300). After the change is saved the
CLI polls `GET /v1/apps/{name}` until the daemon reports `reconciled: true` (the running container carries the hash of the
stored spec: the reconciler has nothing left to do) and the container health check is no longer `starting`. Exit codes:
0 reconciled, 6 a deploy failed or rolled back (the daemon's failure text is printed), 9 timeout or the app waits for a
secret. `reconciled` is part of the `admin` view only (a `read` token never sees it), absent from add/update answers, and
a `--wait` against an older daemon is refused with a hint. It is not part of `spec-hash` or any state file.

Before downgrading Węglarka, remove the fields these flags set — see [verification and rollback](verify-and-rollback.md).

## Relation to auto-update

A webhook fans out a deploy to apps whose `image` (repo + tag) matches the package, that have `auto_update` and are
not stopped (`start = false` — see [stopped apps](stopped-apps.md)). Pinning a `sha-…` tag or `--no-auto-update` is
therefore a manual "pin": the webhook does not touch it until you return to `:latest`. Rollback (retention 1) works as
for any deploy: it returns to the previous digest, and the failed digest is remembered (a repeated deploy skips it
until you force `deploy`).
