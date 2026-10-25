# 0046 — Blue-green deploys for stateless apps (issue #39)

Status: proposed (2026-10-25, issue #39). Implemented; moves to accepted once the open points below are measured on a host.

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

*Shaped by a spike on a live host (rootless Podman 6.1.3, `edge` nginx) — see Evidence. Still `proposed`: the
no-dropped-requests goal is not met by the first sequence and is decided after the implementation is measured.*

* **Opt-in strategy.** `strategy = "recreate" | "blue_green"` on the app, default `recreate`. It does not change
  the container, so it stays out of `spec_hash`.
* **Naming.** The serving container is always `<instance>`. The challenger is `<instance>.next` (`.` cannot occur
  in an instance name). Reconcile does not treat the challenger as a duplicate while a deploy is in flight and
  sweeps a leftover one otherwise. Renames are bookkeeping only (see Evidence): the DNS name is carried by the alias.
* **Staging network.** `network connect --alias` fails on a network the container already belongs to, so the
  challenger cannot start on the app network and gain the alias later. It starts on a per-instance staging network
  (`net-<instance>.next`, labelled with the instance so purge and orphan cleanup find it), together with the
  shared networks it needs for its own gate, and passes the health gate there.
* **Switch.** After the gate the challenger is connected to the app network with the alias `<instance>`. The names
  are swapped (old to `.prev`, challenger to `<instance>`) so that `container_name` keeps meaning "the container
  that serves" and a container with that name exists throughout. The old container keeps serving through its old
  DNS entry for a drain (`ReconcilerOptions::switch_drain`, 3 s: the resolver TTL plus a margin), then is stopped
  and removed, and the staging network goes away. The order (alias, renames, drain, stop) is the one the spike ran
  without a failed request on plain DNS.
* **Resolver TTL.** The generated nginx lowers `resolver ... valid=5s` to `valid=1s` in both modes (aardvark is
  local, so the extra lookups are negligible). This is a change to every generated `nginx.conf` (snapshots).
* **Stateless.** Validation rejects `blue_green` with a read-write volume (private or shared) or `host_ports`.
  Read-only volumes and `configs` are allowed. The challenger joins the shared network (and its aliases) when it
  is created, since an alias cannot be added to a network the container is already on; during the overlap both
  containers carry those aliases, and aardvark answers with the old one first.
* **Health gate.** `blue_green` requires a container-side gate (`health.command` or the image healthcheck):
  `health.http` goes through nginx by `Host` and would probe the old container. `health.http` still runs after the
  switch as a confirmation.
* **Rollback.** A challenger that fails the gate is removed and the old container was never touched (no outage on a
  bad deploy). A failure after the switch uses the existing rollback (previous digest). Keeping the old container
  stopped until the next deploy is out of scope (separate issue).
* **Dependents.** `dependency_ready` inspects `<instance>`, which runs throughout; nothing cascades.
* **Leftovers.** Reconcile's `plan()` does not treat `<instance>.next` / `<instance>.prev` as duplicates (they carry
  the instance label and live only inside a deploy, which holds the engine lock). A leftover of a crashed deploy
  is removed by the instance's next blue-green deploy, or with the app; it is not swept on its own.

## Evidence (spike, 2026-10-25)

* `podman rename` of a running container does **not** update aardvark: the new name does not resolve within 5 s and
  the old one keeps resolving. The old container leaves DNS only when it is stopped and removed. The "drain" after
  the renames therefore drains nothing by itself; the old container serves until `stop`.
* `connect --alias` on a network the container is already on fails (`network is already connected`); it works from
  a separate staging network, and the alias resolves after ~160-190 ms.
* With two containers behind one alias aardvark returns both addresses in a **fixed order** (no rotation): a plain
  client always reaches the old one, so the overlap is not a load split.
* The full sequence on plain DNS: 65 requests at 100 ms, 0 failed.
* Through nginx the sequence is **not** clean: 3 failed requests of 89 with `valid=5s` and a 7 s drain (two runs);
  with `valid=1s` and a 3 s drain, one failed request per run. The failures cluster at `stop` and in the cache
  window after it: nginx keeps the old address for up to `valid`, and a connection to a removed container does not
  fail fast (the client sees timeouts).
* Baseline `recreate` on a live app: 3 of 315 requests failed, a 4.2 s window (in line with the ~3.8 s above).

## Open

* **Goal.** The first target ("zero non-2xx") is not met by the sequence above. Candidates, to be measured on the
  implementation: `proxy_next_upstream` with a short `proxy_connect_timeout` for `blue_green` apps (nginx retries
  the next resolved address), a stop that first closes the old listener, or the rejected alternative below. The
  acceptance test asserts the best of these; until then the criterion is "far below the `recreate` window, and no
  outage on a failed deploy".
* Does an alias added by `connect` survive a container restart (`restart = always`, host reboot)? If not, the
  challenger must be created with the alias on the app network after all and the staging step is moot.

## Consequences

* `apps.toml` gets `strategy`: `state::SCHEMA_VERSION` 8 → 9 with a no-op step, the image label moves with it
  (`Containerfile`), and the rollback note is in [`docs/guides/blue-green.md`](../guides/blue-green.md) and the table
  in `verify-and-rollback.md`. The field is outside `spec_hash`.
* `PodmanClient` gains `container_rename` and `network_connect_aliased` (`FakePodman` updated: a connected
  network refuses a second connect, like libpod; a rename moves scripts and network membership).
* Every generated `nginx.conf` changes (`valid=1s`): the ingress reloads on the next apply, no container is recreated.
* `blue_green` needs a container healthcheck; without one a swap is refused at deploy time (the image's own
  `HEALTHCHECK` is only known then, so it cannot be a validation rule).
* Long-lived connections (websocket, SSE) on the old container are cut when it stops.
* Tests: `engine_tests::blue_green` (order of the swap, a failed challenger leaves the old container untouched,
  refusal without a container check, transient containers survive reconcile); validation in `state.rs`; the
  Podman-level assumptions in `weglarka-podman/tests/blue_green.rs`.

## Rejected alternatives

* **Rewrite the nginx upstream and reload.** Gives a harder no-dropped-requests guarantee, but couples every
  deploy to the ingress writer. Rejected for now; the spike's failures through nginx make it the fallback if the
  retry options under Open do not reach the goal.
* **Generation-suffixed names for every container.** Touches every `container_name` call site and the reconcile
  contract for no gain over a temporary challenger name.
* **Probing the challenger by IP from the daemon.** The daemon is not on app networks; joining them weakens
  isolation.
