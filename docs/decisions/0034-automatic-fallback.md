# 0034 — Automatic fallback to the previous daemon image

Status: accepted (2026-10-24, issue #100) · part of #47; extends [0027](0027-self-update.md)

## Problem

[0027](0027-self-update.md) switches Węglarka's own image from the host: the switcher pulls the configured tag,
verifies the cosign signature of the digest Podman resolved, applies the state-schema gate, pins the digest in the
quadlet and restarts `weglarka.service`. The daemon then confirms at its next start which image it really runs and
records `current`/`previous` in `self-update.toml`; a switch that did not take effect is reported, never silently
assumed.

Nothing detects the failure mode that matters most for an unattended host: **the newly pinned image starts but never
becomes usable** — it crash-loops (systemd's `Restart=always` keeps restarting it and the unit never looks failed), it
hangs before the admin socket is bound, or it starts with a defect only visible from outside. The operator has to
notice the pending digest in `weglarka doctor` and run `weglarka-daemon self-update --rollback` by hand; #99
deliberately left that out of scope. A self-update feature that cannot recover from its own bad release is a liability
on an unattended host, which is the deployment Węglarka targets.

## Decision

**A host-side watchdog, a health endpoint, and one automatic fallback per switch.**

1. **Supervisor.** `platform install` writes two more user units:

   ```ini
   # weglarka-watchdog.service — oneshot
   [Service]
   Type=oneshot
   TimeoutStartSec=2min
   ExecStart=<host binary> --config <config> supervise

   # weglarka-watchdog.timer
   [Timer]
   OnBootSec=1min
   OnUnitActiveSec=1min
   Persistent=false
   ```

   The switcher's own units and cadence stay as they are (`weglarka-self-update.service`/`.timer`, every 10 minutes,
   the registry touched only when `[self_update] interval_secs` is due). Both entry points take an exclusive lock on
   `<state dir>/self-update.lock` (`std::fs::File::try_lock`, no new dependency): a busy lock means another run is
   already working and the watchdog exits successfully without touching anything.
2. **Health** means: the admin API answers `GET /v1/health` on `[admin] socket`. The endpoint is additive in the v1
   contract and deliberately cheap — `200 {"status":"ok","daemon_version":…,"uptime_secs":…}`, no Podman call, because
   a `/v1/status` probe would turn a Podman hiccup into a false rollback. The socket is bound only after every startup
   precondition passed (state/secrets/config validation, `[notify]`, host ports, config mounts, the self-update
   confirmation), and its directory is bind-mounted at the same path in the container, so the answer is a real
   readiness signal reachable from the host. Probe timeout: 5 s.
3. **State.** `self-update.toml` (tolerant, unversioned, 0600) gains the in-flight switch — `switch_from`,
   `switch_to`, `switch_at`, `switch_attempts` — and the last automatic fallback — `fallback_from`, `fallback_to`,
   `fallback_at`. There is **no** `state.toml`/`apps.toml` schema bump: ADR 0023 is untouched, and the file's
   tolerance (unknown fields ignored, missing fields defaulted) keeps older and newer daemons working.
4. **The decision is pure and lives in `weglarka-core`** next to `decide()`:
   `supervise(state, healthy, now, policy) -> Supervision`, with `Idle` (no switch in flight), `Healthy` (the probe
   answered — forget the attempt), `Waiting { remaining }` (inside the deadline), `FallBack { target }` (deadline
   passed, not healthy) and `GiveUp { reason }` (nothing may be corrected automatically). Configuration:
   `[self_update] fallback_timeout_secs` (default 180 s, accepted 30..=3600) and `fallback = true|false`. The attempt
   budget is fixed at **one** (`FallbackPolicy::DEFAULT_MAX_ATTEMPTS`): the fallback target is the single digest that
   ran before the switch, so a second automatic attempt cannot help and is not allowed.
5. **The action is the manual rollback path with an explicit target.** The watchdog restores `switch_from` — not
   `previous`, which may already point at the failed digest — and reuses `rollback()`'s guarantees: no registry access
   (a fallback must work when the registry does not), a local-store `image_inspect`, and the same state-schema gate
   (no fallback across a schema bump). It runs `systemctl --user reset-failed weglarka.service` first (a crash-looping
   unit has exhausted its start limit, and a plain restart would fail), then restarts. Before the restart it writes
   `pending = target` and the fallback record, so the next start confirms the restored image.
6. **Reporting.** The failed digest is recorded in `error`, so the existing `failed_for()` shortcut refuses to re-pin
   it until the tag moves (`--force` stays the deliberate override). The daemon's startup confirmation learns about the
   fallback from the record and emits `SelfUpdateFellBack` (warning) through the existing notification pipeline — the
   watchdog runs on the host without a notifier, and the image it falls back to is normally #100-capable as well.
   `doctor` reports the switch age, the fallback history and an exhausted budget (a failing check for the CLI exit
   code); a `GiveUp` also exits non-zero from `weglarka-daemon supervise`, so the watchdog unit shows a failed run in
   `systemctl --user list-timers` and the journal names the reason. There is deliberately no
   "fallback exhausted" notification event: when nothing could be restored, no daemon runs to deliver it.
7. **Invariants.**
   * No registry access on the fallback path.
   * No fallback across a state-schema bump (ADR 0023): the target's `io.weglarka.state-schema` label must still be
     readable by the state; otherwise `GiveUp` and a manual decision.
   * `previous` never points at the digest that just failed: confirming a fallback sets `current = target` and
     `previous = None`.
   * At most one automatic attempt per switch; a fallback that itself does not come up gives up loudly instead of
     restarting in a loop.
   * A reboot with an unresolved switch is handled by the first watchdog tick (`OnBootSec=1min`).
   * The quadlet — the service definition — is what gets restored, which is the point of the issue.

## Consequences

* **New units** `weglarka-watchdog.service`/`.timer`; existing hosts need one `platform install` re-run to gain them
  (the same upgrade step as the `config_root` mount, ADR 0028), and `platform remove` deletes them. The quadlet itself
  is unchanged, so a switch made by an older *host binary* cannot strip the mechanism the way a quadlet hook would be
  stripped by `render()`.
* **New `[self_update]` keys** (`fallback_timeout_secs`, `fallback`), validated both inside the container and by the
  host-side entry points. `[self_update]` uses `deny_unknown_fields`, so a pre-#100 binary refuses the section with
  the new keys: the downgrade step in [the self-update guide](../guides/self-update.md) is to remove the new keys, or the whole section.
* **New `self-update.toml` fields**; an older daemon ignores them, and one that rewrites the file through its own
  `confirm()` drops them — costing supervision for that one switch only, never correctness of the image pin.
* **New API surface**: `GET /v1/health` (additive; `API_VERSION` stays `v1`).
* **New CLI**: `weglarka-daemon supervise`, with the watchdog unit calling it; `FallBack`/`Healthy` exit 0, a
  `GiveUp` exits non-zero so `systemctl --user list-timers` shows the failure instead of pretending everything is fine.
* **Notifications**: `SelfUpdateFellBack` (warning), no click-through link — it names Węglarka itself.
* **Tests**: the decision table in `weglarka-core` unit tests; the watchdog on the existing
  `FakePodman`/`FakeRegistry`/`FakePlatform` harness; snapshot tests for the new units; a real unix-socket test for
  `/v1/health` and for the confirmation/event of a fallback. A real systemd trigger cannot run in CI (no user manager
  there), so [the self-update guide](../guides/self-update.md) gains a host drill: break an update on purpose and watch the fallback, reboot with a
  pending switch, and fall back with the registry offline.
* **Operators**: `doctor` changes from "pending stays until someone looks" to an actionable, usually self-healing
  state; the first release with this feature still needs the new host binary and a `platform install` re-run.

## Rejected alternatives

* **sd_notify + `Type=notify` + `TimeoutStartSec` + `OnFailure=`.** This makes `systemctl restart` a synchronous health
  gate, but it is a one-way door: quadlet only accepts `Type=notify`/`oneshot`, so a rollback target from before #100
  that never sends `READY=1` would fail its start — the fallback could brick the daemon. `OnFailure=` also fires on
  every failed start (reboot included) and would need the same persisted state gate, and the hook would live in the
  quadlet, which is re-rendered by the *host* binary on every pin — an older host binary would silently drop it.
* **`ExecStartPost=` health gate.** The same render-and-strip problem, plus the gate runs on every start (also at
  boot), so a slow start after a reboot would look like a failed update and trigger a needless fallback.
* **Waiting inside the existing `self-update` run.** It detects only the switch that run performed; a switch left
  behind by a crashed process or a reboot would wait for the next 10-minute wake, while the watchdog's 1-minute tick
  and `OnBootSec` cover both. It also keeps a network-touching process alive for the whole timeout.
* **Doing nothing (status quo).** A broken release then requires the operator to notice `doctor` and run `--rollback`.
* **Automatically retrying the failed digest.** The tag still resolves to it, so a retry would loop; recording the
  digest as failed and waiting for the tag to move is the recovery, exactly as #99 already handles a refused image.
