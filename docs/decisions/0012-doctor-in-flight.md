# 0012 — `doctor` and an operation in progress: `info` status instead of false drift

Status: accepted (2026-10-24, issue #30).

## Problem

`state.toml` is the only source of truth about runtime state, but deploy/recreate/provision write it **only
after** the new container is created, started and passes the health gate (`launch()` → `save_state`).
Throughout that time (a fraction of a second for a plain recreate, up to `health.window_secs` with the gate)
the live container and `state.toml` disagree, and `doctor` does not sit behind `Reconciler::lock` — it compares
exactly those two sources:

- a new container with a new `spec-hash` vs the old `spec_hash` in the state → “spec-hash drift”,
- no container between `stop`/`remove` and `create` → “no container”,
- a first deploy with no `state.toml` entry → “not deployed yet”.

All three land in `state.drift` as `warn`, so `weglarka doctor` exits with code 1 and alarms during a normal
operation (issue #30: a few seconds after `apps update` or a secret change). Once the state is written everything
agrees again, so the problem is a **false alarm about a transient state**, not drift.

## Decision

**An in-engine registry of operations in progress.** `Reconciler` holds
`activity: Mutex<Option<InFlight>>` (`InFlight { instance, kind }`, `ActivityKind` = `Deploy` / `Recreate` /
`Provision`). `begin_activity()` returns an RAII guard that clears the entry in `Drop` — this covers early `?`
returns and panics, so an instance cannot be left stuck in the “in flight” state. The entry is set by exactly
three paths, the ones where `state.toml` temporarily lags behind the container: `deploy_locked` (after the
`start = false` branch), `recreate_locked`, `provision_locked`. `Reconciler::in_flight()` is the public,
read-only accessor for `doctor`; operations are serialized by `lock` anyway, so at most one instance is in
flight.

**`doctor` skips the in-flight instance and reports it separately.** The per-instance checks (container exists,
runs, `spec-hash` matches) are skipped for that one instance; in their place a new `state.deploying` check
appears with the `info` status (`deploy w toku: <inst> (<kind>) — pominięto w ocenie dryfu`). `state.drift` then
assesses only the remaining instances, so real drift is still a `warn`, and `doctor` exits with code 0 during a
deploy. The check exists only while something is in flight — when idle, the report is exactly as before.

**A new `CheckStatus::Info` variant.** It sits between `Ok` and `Warn` in `Ord`, so `worst()` still raises a real
warning/error above “in progress”, and `exit_code()` maps `info` → 0. The CLI renders it as `[INFO]` and counts
it in the summary (`N ok, N info, N warn, N fail`).

**Invariants.** `state.toml`, `apps.toml`, `spec_hash` and the TOML schemas stay unchanged (no new
`deny_unknown_fields` fields, no migration). The registry lives in process memory only: after a daemon restart it
is empty — deliberately, because then the state really is temporarily inconsistent and showing drift is correct
(the startup reconcile fixes it right away). Backward compatibility: a new CLI reads an older daemon without
changes; an **older CLI does not know the `"info"` variant** (the enum is closed), so while a deploy is running
`weglarka doctor` fails to parse the response — the CLI and the daemon are upgraded together (same
image/release). Noted in [the stopped apps guide](../guides/stopped-apps.md).

**Tests.** `in_flight_is_visible_during_a_deploy` / `in_flight_is_cleared_when_the_deploy_fails` (core) guard the
registry and the RAII behaviour; `doctor_reports_a_recreate_in_progress_instead_of_state_drift` (daemon, real unix
socket + `FakePodman`) reproduces the recreate window with a slow health gate and checks that in flight there is
`state.deploying: info` and `state.drift: ok`, and that after it finishes the check disappears and the state is
consistent.

## Consequences

- `weglarka doctor` during a deploy/recreate/provision shows `[INFO] state.deploying …` instead of
  `[WARN] state.drift …`; the exit code is 0, so monitoring stops alarming about a normal operation.
- Operators see **which** instance and **which** operation is running — clearer than “drift” without context.
- `CheckStatus` gains a variant; this is the only change to the admin API contract. Rolling the daemon back to a
  version without `info` is safe (the new CLI reads the old response), but rolling back only the CLI against a new
  daemon breaks `doctor` during an operation — upgrade the CLI and the daemon together, as before.
- A daemon restart in the middle of a deploy does not show “in progress” (the registry is volatile): `doctor`
  reports real drift until the startup reconcile brings the instance back in line. That is correct behaviour, not
  a regression.
- New code must preserve the invariant “the guard is taken only in the paths that delay the `state.toml` write”;
  adding it to operations that write the state before touching the container would only silence real drift.

## Rejected alternatives

- **An “in progress” message inside `state.drift` with the `ok` status**: no new check and no contract change, but
  `doctor` cannot be monitored by `id` alone (the text has to be parsed) and the `ok` status is misleading — “OK”
  for a change that is happening right now. The `info` variant expresses the intent of issue #30 and stays
  machine-recognisable.
- **A “deploy in progress” flag in `state.toml`**: breaks a rollback to an older daemon (`deny_unknown_fields`),
  and after a crash it remains as a durable “stuck” marker that would have to be cleaned up — a new failure mode
  in a file that is supposed to stay simple.
- **Inferring from `apps.toml` (comparing the hash with the desired spec)**: recognises only the “new container, old
  state” moment; the `stop`/`remove` windows (no container) and the first deploy cannot be told apart from a real
  problem at all.
- **A global “engine busy” flag (`try_lock` on `Reconciler::lock`)**: does not name the instance and silences
  `state.drift` for **all** apps throughout a reconcile pass (including genuinely drifted ones), so a real problem
  could disappear from the report.
- **`CheckStatus::Info` without a registry, based on the `state.toml` mtime only**: a heuristic built on the file
  modification time is non-deterministic and goes wrong on every slow write; the in-engine registry knows the exact
  instance and the kind of operation.
