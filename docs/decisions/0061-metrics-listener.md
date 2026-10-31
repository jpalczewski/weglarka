# 0061 — Metrics: an optional listener on a dedicated network

Status: accepted (2026-10-31, issue #350, epic #331). Narrows ADR 0056 decision 2 ("no TCP surface") for one
listener that has no admin route. Builds on #348 (`PodmanClient::container_stats`).

## Problem

Operators want Prometheus to scrape Węglarka: per-app resource use, daemon counters, host numbers. The epic (#331)
builds those in three later issues; this ADR fixes the part they all share: where the numbers come from, which process
serves them, how Prometheus reaches it, and what labels mean. Getting it wrong has three failure modes: a metrics path
that widens the admin attack surface, a feature that costs memory or a socket when it is off, and a label set that leaks
data or explodes in cardinality and cannot be changed once dashboards depend on it.

Constraints, in order: security, then extensible code (traits, adapters), then RAM.

## Decision

1. **Container data comes from one libpod stats call, not from cgroup files.** The daemon is a container: its
   `/sys/fs/cgroup` shows only its own cgroup, so reading the apps' files would need a new host mount (and an install
   change for every existing host). `PodmanClient::container_stats` already returns what the daemon is allowed to see
   through the socket it has anyway.
2. **The daemon serves the metrics itself.** A separate exporter needs the Podman socket, and a socket holder has full
   power over the host's containers. Putting it on the token listener (ADR 0056) does not work either: that listener
   admits human logins and no grant today is meant for a machine, and `weglarka-identity` knows only
   `authorization_code`, `device_code` and `refresh_token`. The daemon already holds the socket and the state, so the
   cheapest and narrowest option is to compute the text in the daemon.
3. **Opt-in and free when off.** `[metrics]` in `weglarka.toml` is `Option`; absent means no listener, no network, no
   task, no memory, and `GET /v1/config` shows nothing. It is host config, not an `AppSpec` field, so an app cannot
   switch it on. Values are computed at scrape time; nothing is sampled in the background.
4. **A narrow exception to ADR 0056 decision 2.** That decision protects the admin API: no TCP surface for whatever else
   joins a network. This listener has **no admin route**: it is built from its own router that holds exactly one route,
   `GET /metrics`, and shares no code path with `admin::api_routes`, so it cannot serve an admin endpoint by mistake or
   by a later edit that adds one to the shared table. Every other path answers `404`, every other method `405`.
5. **TCP on a dedicated Podman network.** Prometheus cannot scrape a unix socket. The daemon creates the network
   (default name `metrics`) idempotently and joins its own container to it with `network_connect`, so enabling metrics
   needs no `platform install` and no quadlet change. Prometheus (and later an app, #36) joins the same network.
   Nothing is published on a host address. The network is **`internal`**, like the shared networks: nothing on it needs
   a route out, and joining a second non-internal network would give the daemon another default route. Name resolution
   still works on an internal network (`crates/weglarka-podman/tests/networks.rs`, which also covers a live
   `network_connect` of a running container).
6. **It listens on `0.0.0.0` inside the container, like the webhook listener.** The daemon is also on `net-weglarka`, so
   nginx could reach the port, but nginx never routes it (the generators emit only the webhook and app routes). Binding
   to the daemon's address on the `metrics` network alone would be tighter in theory, but that address is assigned by
   Podman and changes when the container is recreated, so the listener would have to be re-bound on every connect; the
   network boundary, not the bind address, is the control, and a rebind loop is more code and a new failure mode for
   little gain.
7. **No authentication in the first version.** Isolation is the network: only containers an operator put on it can
   connect. The text carries no secrets by the label contract below. An optional bearer can be added later without
   changing the exposition contract.
8. **Label contract for #351, #352, #353.**
   - Labels are `app` (a validated instance name) and `role` (`active`, `challenger`, `retiring`). One-off containers
     (`weglarka run`, forward relays) are skipped.
   - A label value is a fixed enum or a validated name, **never free text** such as a failure reason, an image
     reference, a command line or an env value. The encoder still escapes `\`, `"` and newline, as the format requires.
   - Metric names are prefixed `weglarka_`; counters end in `_total`, sizes in `_bytes`.
9. **The encoder is hand-written.** Values are computed at scrape time from the engine's state and one stats call, so a
   registry of long-lived collectors (`prometheus-client`) would add a dependency and a second copy of every value for
   nothing. The encoder takes `Family` values with a name, help, type and samples, sorts families and samples for stable
   output, writes `# HELP` and `# TYPE`, and is independent of where the values come from: a source returns families,
   so the later issues add sources without touching it.
10. **Startup never depends on the network.** The listener is bound synchronously at start (it needs no Podman) and
    serves `/metrics` from then on. Creating the network and joining it runs in a background task that retries with a
    backoff (5 s doubling to 60 s) until it works or the daemon stops, so a slow or briefly unavailable Podman delays
    neither the daemon nor reconcile, and metrics become reachable without a restart. The first failure is a warning,
    the retries are debug lines. A bind failure is permanent until restart and is logged. `doctor` shows
    `metrics.listener`: `ok` once joined, `warn` with the last error while retrying, `fail` after a bind failure.
    Absent `[metrics]` adds no doctor line.
11. **The network name is validated** like the other network-name components (the instance alphabet), and may not start
    with `net-` or equal `net-weglarka`: those are per-app and ingress networks, which reconcile may prune. The metrics
    network carries `weglarka.managed=metrics` and is never an instance network.

## Consequences

- New `[metrics]` table (`listen`, `network`) in `weglarka.toml`; `GET /v1/config` shows it (allowlist projection).
  `apps.toml`, `state.toml`, `AppSpec`, `spec_hash`, the quadlet and `SCHEMA_VERSION` are unchanged.
- **Rollback:** `weglarka.toml` has `deny_unknown_fields`, so an older daemon refuses a file with `[metrics]`. Remove the
  table before downgrading; the network and the membership disappear with the container, and `podman network rm` removes
  the empty network. Documented in `docs/guides/metrics.md`.
- Tests: an encoder snapshot with label escaping, daemon integration tests (off by default, on serves `/metrics`
  only, a join that fails and then succeeds without a restart, a bind failure), and a real-Podman test of a live join of
  an internal network.
- A self-update recreates the container; the network join is repeated at every start, so it comes back.
- Until the join succeeds the page is served but not reachable from the network; scrapers see a connection error.

## Rejected alternatives

- **Read cgroup files.** Needs a new host mount and an install change; a daemon in a container sees only itself.
- **A separate exporter container with the Podman socket.** Full power over every container for a read-only job.
- **Serve it on the token listener.** No machine grant exists; and it would put metrics behind the admin route table.
- **Publish the port on the host.** Reachable by every local user and, with a wrong bind, by the network.
- **Bind to the metrics-network address.** See decision 6.
- **`prometheus-client` or a registry crate.** See decision 9.
- **Bearer authentication now.** Adds a secret to distribute for no gain over network isolation; additive later.
