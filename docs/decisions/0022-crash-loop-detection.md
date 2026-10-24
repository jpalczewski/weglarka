# 0022 — Crash-loop and unhealthy detection

Status: accepted (2026-10-24, issue #112). Notifications that deliver these events: ADR 0021.

## Problem

A container that keeps dying is invisible. Every app container runs with `restart = always`, so conmon restarts
it before the next reconcile pass sees anything wrong: the app is "Running" with an unchanged `spec-hash`, the
health gate only runs at deploy time, and the operator learns about the loop from a user. The same holds for an
app whose own healthcheck turns unhealthy after a successful deploy: nothing in the engine looks at
`ContainerInfo.health` outside the gate and `doctor`.

What the detector must not do: add load to the hot path, invent a second source of truth, or alert on every
observation. Węglarka runs one reconcile pass per minute by default; the detector has to live inside that
rhythm, survive nothing (in-memory is fine) and stay quiet about normal deploys, recreates and restarts of the
daemon itself.

## Decision

**Detect in the reconcile pass, from libpod's `RestartCount`, with an in-memory state machine in
`weglarka-core/src/crash.rs`.**

- `ContainerInfo` gains `restarts: u32`, mapped from `RestartCount` in `GET /containers/{name}/json`
  (`weglarka-podman/src/wire.rs`). `LibpodClient::container_list` already inspects every listed container
  (the Docker-compatible list has neither health nor exit code), so the reconcile pass sees the counter
  **without any additional libpod call**. A real-Podman test (`weglarka-podman/tests/podman.rs`) is the proof
  that libpod 6 reports the field; a fixture alone cannot show it, because a missing field silently reads 0.
- **Placement:** `Reconciler::reconcile()` calls the watcher right after it has fetched the containers and
  `apps.toml`, inside the existing engine lock, and emits through the same `EventSink` as deploys. Alternatives
  (a daemon task, a separate monitor loop) were rejected: each would fetch and inspect every container a second
  time per period, and the engine is already the component that observes the runtime.
- **Policy in `[monitor]`** (`weglarka.toml`, optional, defaults): `crash_loop_restarts = 3`,
  `crash_loop_window_secs = 600`, `unhealthy_observations = 2`. `0` disables that detector. Detection is
  independent of notification delivery: with no channel configured the events still reach the daemon log
  (`TracingSink`), so the thresholds are host policy, not channel policy.
- **State per instance, in memory:** container generation (`weglarka.generation` label), restart baseline and
  window, whether a crash alert is active and when the last restart happened; a consecutive-unhealthy counter and
  whether a health alert is active. A changed generation (deploy, recreate, rollback) resets the restart side:
  the new container starts at `RestartCount = 0`, so the baseline is re-established and no alert carries over.
  A missing container forgets the instance. Nothing is persisted: after a daemon restart the first observation
  sets the baseline, so a loop that is still running alerts again after `crash_loop_restarts` new restarts.
- **Restart rule:** within a rolling window, `restarts - baseline >= crash_loop_restarts` emits
  `Event::CrashLooping { instance, restarts }` **once**; when no new restart arrives for a full window the
  watcher emits `Event::Recovered { instance }` and resets. Occasional restarts therefore never accumulate into
  an alert, and a loop produces one critical event plus one recovery, not one event per restart.
- **Health rule:** `health == unhealthy` raises a consecutive counter; at `unhealthy_observations` the watcher
  emits `Event::Unhealthy { instance }` once; a later `healthy` emits `Event::Recovered` once. Transitions only —
  no event on every pass, so the notification dedup windows (ADR 0021) are not used as a substitute for state.
  `starting` and a container without a healthcheck reset the counter.
- **Severity:** `CrashLooping` critical, `Unhealthy` warning, `Recovered` info (the notification channel routes
  and dedups them like any other engine event; message text in `weglarka-notify/src/message.rs`).
- **Ignored:** containers that do not carry `weglarka.instance`, instances absent from `apps.toml` (about to be
  pruned), `start = false` and secret-waiting apps (no container), and the non-main container of an instance.
- **Windows use `tokio::time::Instant`**, never `SystemTime`: the engine tests run on virtual time
  (`#[tokio::test(start_paused = true)]`) and can advance a window in microseconds.

An implementer must keep two invariants: **the watcher performs no I/O** beyond the observation it is handed
(no extra libpod calls, no state-file writes) and **it runs only under the engine lock**, where deploys cannot
interleave with an observation.

## Consequences

- Three new engine events in the notification table (`crash loop`, `unhealthy`, `running again`) with the dedup
  keys `crash:<instance>`, `unhealthy:<instance>`, `recovered:<instance>`; snapshots of the rendered messages.
- A new `[monitor]` section in `weglarka.toml` (defaults apply when absent) and `docs/examples/monitor.toml`;
  `docs/install.md` gets its own section. `weglarka.toml` uses `deny_unknown_fields`, so an older daemon refuses
  to start with `[monitor]` — same downgrade caveat as `[notify]` (ADR 0021).
- `Reconciler::with_monitor(Policy)` builder; `ReconcilerOptions` is untouched. The engine's tests override the
  policy (`Policy::disabled()`) so existing event assertions stay stable; the new scenarios enable it and drive
  `FakePodman::set_restarts` / `set_health`.
- Tests: unit tests of the state machine, engine scenarios on `FakePodman`, the wire fixture plus the real-Podman
  `RestartCount` test, message snapshots and one daemon integration test (`restarts → event → ntfy`).
- `doctor` does not report crash loops yet; it keeps its container/health view (a follow-up can read the same
  counter or the watcher state).

## Rejected alternatives

- **A daemon-side watcher task** (as first sketched in #112): `container_list` already inspects every container,
  so a second loop doubles the libpod traffic; the engine is the component that already owns observation, the
  clock and the event sink, and tests on `FakePodman` come for free.
- **Absolute threshold on `RestartCount`** (e.g. "more than 5"): an app that crashed once a week would alert
  forever after five weeks. The counter is only meaningful as a delta inside a window, which is what the
  baseline/window pair computes.
- **Reacting to the libpod event stream** (`PodmanClient::events`): the action names (`start`, `die`, `restart`)
  are not verified on Podman 6 here and `FakePodman` would have to script a stream; polling the counter is
  deterministic and testable now.
- **Persisting the watch state** in `state.toml`: extra format surface for monitoring data that is cheap to
  re-establish, and it would make `state.toml` (a `deny_unknown_fields` file) churn for alerts.
- **An unhealthy threshold knob**: the health transition plus two consecutive observations is the smallest rule
  that ignores a single flaky probe; a third config knob buys tuning nobody asked for. `unhealthy_observations`
  exists only to allow switching the check off (`0`) and to express "one is enough".
- **Reporting only in `doctor`**: `doctor` is on demand; a crash loop at 3 a.m. needs a push (ADR 0021).
