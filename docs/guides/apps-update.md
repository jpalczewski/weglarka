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
| `--env`/`--unset-env`, `--port`/`--unset-port`, `--secret-env`/`--secret-mount`/`--unbind-secret`, volumes, limits, `health.command` | changes `spec-hash` → the next reconcile recreates the container from the pinned digest (no pull) |
| `--shared-volume` (`shared_volumes` in `--spec`) | like volumes: changes `spec-hash` → the next reconcile recreates the container within the shared UID group range (a change of `target`/`read_only` too). A range change with existing private volumes is rejected — see [shared volumes](shared-volumes.md). An empty list hashes as before |
| `--shared-network` (`shared_networks` in `--spec`) | changes `spec-hash` → the next reconcile recreates the container — see [shared networks](shared-networks.md) |
| image (`apps update <app> <image>`) | deploys immediately: pull, health gate, rollback on failure |
| `--auto-update` / `--no-auto-update` | write only; affects subsequent webhooks |
| `--start` / `--no-start` (`start` in `--spec`) | `start = false` removes the container (the volume and UID range stay), `start = true` deploys immediately: pull, health gate, rollback on failure. `spec-hash` unchanged — see [stopped apps](stopped-apps.md) |
| `--command` (`command` in `--spec`) | changes `spec-hash` → the next reconcile recreates the container from the pinned digest (no pull); the flags replace the whole argument vector, and `--command none` restores the image's `CMD` — see [container command](container-command.md) |
| `--host-port` (`host_ports` in `--spec`) | changes `spec-hash` → the next reconcile recreates the container from the pinned digest (no pull); the published port is recreated together with the container — see [host ports](host-ports.md) |
| `--config-mount` (`configs` in `--spec`), `--reload-signal` | the `configs` list changes `spec-hash` → the next reconcile recreates the container from the pinned digest (no pull); file **contents** are not in the hash, so apply content changes with `weglarka apps reload`. `reload_signal` is outside the hash and only affects reload — see [host configs](host-configs.md) |

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
