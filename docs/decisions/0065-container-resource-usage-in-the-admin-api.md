# 0065 — Container resource usage in the admin API

Status: proposed (2026-10-31, issue #405, epic #404). Builds on ADR 0061 (the resource families and the label contract),
ADR 0057 (the panel, `read` allowlist views, streams) and ADR 0063 (the access-log stream).

## Problem

The panel and the CLI should show what each app container uses right now: memory against its limit, CPU, pids, block and
network I/O. The daemon already gathers exactly this for Prometheus (`crates/weglarka-daemon/src/metrics/resources.rs`,
ADR 0061), but only when `[metrics]` is on and only as metric families. A second code path that asks Podman again would
double the work on a small host; a view that copies the metrics code would drift from it. Several choices below have
real alternatives and code will depend on them, so they are recorded first.

Threats and constraints, in priority order:

- **A new `read` surface leaks data.** Container ids, image references and the names of one-off containers
  (`weglarka run`, forward relays, import helpers; their names hold tokens) must not reach a `read` caller.
- **Several viewers multiply the load.** A panel, a CLI and `doctor` polling at once must not each call libpod: one
  `container_stats` already costs the daemon a round trip per running container.
- **Wrong numbers look right.** The stats `MemLimit` is the host's RAM when a container has no limit; a CPU counter
  restarts at zero when a container is recreated; `0` is how libpod reports "no data".
- **RAM.** Nothing may be sampled in the background, and a feature nobody uses must cost nothing.

## Decision

1. **`read` scope, an allowlist projection.** The stats response is built by one constructor that destructures every
   field of the snapshot entry **without `..`** (the rule of ADR 0057 decision 8), so a new field does not compile until
   someone decides what a `read` caller sees of it. The view holds `app`, `role` (the ADR 0061 label contract), the
   numbers, `restarts` and `oom_killed`. It never holds a container id, a container name other than the validated
   instance name, an image reference, a command or a label. One-off `run`, `forward` and import containers are dropped
   first, as `identify` in `resources.rs` already does. The numbers are not free text, and who may see an app's state is
   already decided (`read`), so this is not a new class of data; `admin` is not needed. The first view covers app
   containers; showing the ingress, the forwarder and the daemon itself is #420.
2. **One resource snapshot in the daemon, independent of `[metrics]`.** The collection moves out of the `metrics`
   module into a shared snapshot owned by the `Daemon`. The Prometheus families, the API view and the `doctor` check are
   projections of it; none of them calls Podman. A refresh is one `container_list` plus one unfiltered `container_stats`
   under the existing timeout (8 s), at most once per TTL window (10 s). A request inside the window, or one that
   arrives while a refresh runs, gets the same snapshot, so any number of viewers and scrapers cost one pair of libpod
   calls per window. The refresh runs on demand only, in the request that finds the snapshot stale; with `[metrics]` off
   and nobody asking there is no task, no socket and no call. The holder is a small TTL cell shared with the
   metrics cache (#406), replacing the metrics-only `Cache`.
3. **The daemon computes the CPU rate; clients stay stateless.** The rate is `Δcpu_seconds / Δwall_seconds` between the
   previous snapshot and the current one, in cores (`1.0` is one fully used core). The comparison key is the **container
   id**, which stays inside the daemon: a recreated container keeps its name but restarts its counter. The rate is
   `None` when the id changed, the counter went back, either side has no CPU sample, there is no previous snapshot, or
   the previous snapshot is older than 300 s (a rate over a long gap hides every peak and would be read as current). The
   response carries `cpu_window_secs` (the Δwall actually used) next to the rate, and the raw `cpu_seconds_total`
   counter, so a client can judge the window or compute its own. The retained state is the previous
   `(id, cpu_seconds, instant)` per container, a few bytes each. Prometheus keeps exposing only the raw counter:
   `rate()` is its job.
4. **The memory limit comes from the spec and container inspect, never from stats `MemLimit`.** `ContainerInfo` already
   carries `memory_limit` from inspect; with no limit set the field is absent and the view shows no limit (`null`), not
   the host's RAM. A percentage is the client's division, and only when a limit exists.
5. **The panel polls a fragment every 10 s with htmx; no SSE.** `hx-trigger="every 10s"` matches the TTL, so the
   panel's polling is served from the same snapshot as everyone else's. A stats stream would take one of the
   `MAX_STREAMS_PER_SESSION` (4) per-session slots (`crates/weglarka-panel/src/live.rs`), which events and logs already
   compete for, to push a value that changes at most every 10 s. A plain request takes no slot, and the polling stops
   when the fragment leaves the page.
6. **No history in the daemon.** The snapshot is the current value plus the previous counters for the rate. A ring buffer
   of samples would grow with apps and window length, and graphs over time are Prometheus' job (#331, #81).
7. **Log and access-log streams on the app page start on demand.** A stream opens when the operator asks for it (a
   button that loads the stream element), not on page load. Each open stream holds one session slot, one Podman stream
   and, for the access log, a scan of the log shared by every app (ADR 0063). A page that opens both on load would spend
   half of a session's slots on something the viewer may never read, and a few tabs would exhaust them. The stream is
   released when the viewer closes it or leaves the page.

Invariants for implementers: no `apps.toml`, `state.toml`, `AppSpec` or `spec_hash` change; contract changes are
additive and update `FakePodman`; the container id and the image never leave the daemon; one-off containers are
filtered before anything else; the Prometheus output stays byte-compatible with ADR 0061's label contract; a missing
value is no value, never zero (`resources.rs` module comment).

## Consequences

- New `read` stats endpoint(s) in `weglarka-api` with a response type per app (exact paths decided in #407), a
  `weglarka stats` command (#412), a panel fragment (#413) and a `doctor` check on memory (#416). All additive; an older
  daemon answers `404` and the clients say the versions may differ.
- `resources.rs` splits into the snapshot (always compiled in, used without `[metrics]`) and the family projection;
  `Cache` becomes the shared TTL cell (#406). `docs/guides/metrics.md` and `.claude/rules/api-and-cli.md` follow.
- Operators see what the TTL means: values are at most 10 s old, and `cpu_window_secs` is at least the TTL in steady
  state. The first request after a quiet period has no CPU rate; the next one, 10 s or more later, does.
- Rollback needs nothing: no config or state field is added. A downgrade removes the endpoints and the clients get `404`.
- Tests: the projection (a snapshot with a one-off container, a stray copy and an image reference yields none of them),
  the rate (recreated id, counter going back, gap over 300 s, missing sample), the TTL cell (one libpod pair for
  concurrent API and metrics callers), `read` scope on each endpoint, and a snapshot of the response.

## Rejected alternatives

- **An SSE stats stream.** Takes a per-session stream slot for data that changes every 10 s, and a long-lived stream per
  viewer is exactly the load the shared snapshot avoids.
- **A client-side CPU rate.** Needs the previous value, so every client (panel session, CLI) would keep state and
  reimplement the id and counter-reset rules; a wrong rate would differ per client.
- **A separate exporter app with a scoped socket.** A second container and a second Podman holder for a read-only job
  the daemon already does (the reasoning of ADR 0061 decision 2); a socket scoped to stats does not exist in Podman.
- **The panel reading `/metrics`.** Ties the panel to the optional listener and its network, and makes it parse
  Prometheus text to rebuild what the daemon already has as typed values.
- **A history ring buffer in the daemon.** RAM grows with apps and window; Prometheus stores and graphs history.
- **`admin` scope for stats.** The view carries no credential, no free text and no identifier of a container; `admin`
  would hide the memory use of an app from the viewers who may already see its state.
- **Sampling in the background.** Costs libpod calls and memory while nobody looks, against the RAM priority.
