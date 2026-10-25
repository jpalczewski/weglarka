# Blue-green deploys

With the default `recreate` strategy a deploy stops the running container before the new one starts, so every deploy is a short outage (about 4 s measured on a live host). For a **stateless** app, `blue_green` starts the new container next to the old one, waits for its health gate, moves traffic and only then stops the old one. It costs twice the memory for the duration of the switch. Decision, measurements and rejected alternatives: [ADR 0046](../decisions/0046-blue-green-deploy.md).

```toml
# apps.toml / --spec
[apps.web]
image = "ghcr.io/example/web:latest"
port = 8080
strategy = "blue_green"
health = { command = ["wget", "-qO-", "http://127.0.0.1:8080/health"] }
```

Or with the CLI: `weglarka apps update web --strategy blue_green` (`--strategy recreate` goes back).

## What it requires

- **A stateless app.** The spec is rejected (HTTP 400, and at daemon start) when it has `host_ports` (two containers cannot bind one host port) or a read-write volume, private or shared (two writers; SQLite has a single one). Read-only volumes and [host configs](host-configs.md) are fine.
- **A health check inside the container**: `health.command`, or a `HEALTHCHECK` in the image. The new container is gated on a separate network, before it receives any traffic, and `health.http` goes through the ingress, which still reaches the old container, so it cannot judge the new one. Without a container check the swap is refused and the deploy fails with a message that says so. `health.http`, if set, still runs once after the switch as a confirmation.
- Memory for two containers at once. A `resources.memory` limit applies to each of them.

## What happens in a deploy

1. The new container (`<app>.next`) starts on a staging network (`net-<app>.next`) and must pass the health gate there. If it does not, it is removed and **the old container was never touched**: a bad image causes no outage, and the failure is reported like any failed deploy (it is not a rollback, there was nothing to roll back).
2. It joins the app network under the app's name. For a moment both containers answer to that name.
3. The names are swapped (the old container becomes `<app>.prev`, the new one `<app>`).
4. After a drain of 3 s, which outlasts the ingress DNS cache (`valid=1s`), the old container is stopped and removed, and the staging network goes away.

The first deploy of an app, and a deploy when no container is running, take the ordinary path: there is nothing to run next to.

## Limits

- **Not strictly zero.** The first measurement through nginx showed a few failed requests right around the moment the old container stops (see the ADR). Expect the window to be far below the `recreate` outage, not zero. Long-lived connections (websocket, SSE) on the old container are cut when it stops.
- A container that crashes between steps 2 and 4 (daemon killed mid-deploy) can leave `<app>.next` or `<app>.prev` behind. Reconcile does not remove them; the next blue-green deploy of the app does, and so does `apps remove`.
- `strategy` is not part of the spec hash: changing it recreates nothing, it only decides how the next deploy swaps the container.
- Mounted [secrets](first-app.md) and the app's other settings are the same for both containers; the `depends_on` gate runs before the deploy as always, and dependents see the app's container running throughout.

## Rollback

`strategy` is a new field in `apps.toml`, which has `deny_unknown_fields`, and the file gets `schema_version = 9` on the first write after the update. Before going back to an earlier Węglarka version, set `strategy` back to `recreate` and remove it from the file (or restore `apps.toml` and `state.toml` from a backup taken before the update); see [State schema](state-schema.md).
