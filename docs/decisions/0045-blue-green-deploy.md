# 0045 — Blue-green deploys for stateless apps (issue #39)

Status: proposed (2026-10-25, issue #39).

## Problem

`recreate` stops and removes the running container before the new one exists (`begin_instance` in
`deploy.rs`), so every deploy is an outage (~3.8 s measured for ntfy). A failed deploy is an outage too: the
old container is already gone when the health gate fails, and the rollback has to start it again. For a
stateless app the new container can be started and gated *next to* the old one, and traffic moved only after
the gate has passed, at the price of 2x memory for the duration of the switch.

Constraints: the serving container's name (`labels::container_name`) is the DNS name nginx proxies to and is
used by reload, the crash watcher, `depends_on`, `forward`, `run` and reconcile, so it must keep meaning "the
container that serves". nginx resolves the upstream at runtime (`set $upstream` + `resolver ... valid=5s`) in
both `behind` and `edge`, so the switch is the same hop in both modes.

## Decision

*Draft — filled in as the implementation lands. Recommended shape, to be confirmed by the spike below:*

* **Opt-in strategy.** `strategy = "recreate" | "blue_green"` on the app, default `recreate`. It does not change
  the container, so it stays out of `spec_hash`.
* **Naming.** The serving container is always `<instance>`. The challenger is `<instance>.next` (`.` cannot occur
  in an instance name). Reconcile does not treat the challenger as a duplicate while a deploy is in flight and
  sweeps a leftover one otherwise.
* **Switch.** The challenger starts without the `<instance>` alias and passes the health gate on its own. Only
  then does it join the app network with the alias `<instance>`; the old container keeps serving for at least the
  nginx resolver TTL, then the names are swapped (old to `.prev`, challenger to `<instance>`) and the old one is
  stopped and removed. `<instance>` exists and runs throughout.
* **Stateless.** Validation rejects `blue_green` with a read-write volume (private or shared) or `host_ports`.
  Read-only volumes and `configs` are allowed. Aliases from shared networks are attached at the switch, not before.
* **Health gate.** `blue_green` requires a container-side gate (`health.command` or the image healthcheck):
  `health.http` goes through nginx by `Host` and would probe the old container. `health.http` still runs after the
  switch as a confirmation.
* **Rollback.** A challenger that fails the gate is removed and the old container was never touched (no outage on a
  bad deploy). A failure after the switch uses the existing rollback (previous digest). Keeping the old container
  stopped until the next deploy is out of scope (separate issue).
* **Dependents.** `dependency_ready` inspects `<instance>`, which runs throughout; nothing cascades.

Open until the spike on a real Podman 6 passes: does `podman rename` of a running container keep DNS and aliases
in aardvark, and does `network connect --alias` on a running container give both addresses.

## Consequences

*To be completed with the implementation:* `apps.toml` gets `strategy` (`schema_version` bump, no-op step, rollback
note in `docs/guides/blue-green.md` and `verify-and-rollback.md`); `PodmanClient` gains `container_rename` and
`network_connect` with aliases (`FakePodman` updated); long-lived connections (websocket, SSE) are cut when the
old container stops.

## Rejected alternatives

* **Rewrite the nginx upstream and reload.** Gives a harder no-dropped-requests guarantee, but couples every
  deploy to the ingress writer for a hop that alias DNS already covers.
* **Generation-suffixed names for every container.** Touches every `container_name` call site and the reconcile
  contract for no gain over a temporary challenger name.
* **Probing the challenger by IP from the daemon.** The daemon is not on app networks; joining them weakens
  isolation.
