# 0034 — Automatic fallback to the previous daemon image

Status: proposed (2026-10-24, issue #100) · part of #47; extends [0027](0027-self-update.md)

## Problem

[0027](0027-self-update.md) switches Węglarka's own image from the host: the switcher pulls the configured tag,
verifies the cosign signature of the digest Podman resolved, applies the state-schema gate, pins the digest in the
quadlet and restarts `weglarka.service`. The daemon then confirms at its next start which image it really runs and
records `current`/`previous` in `self-update.toml`; a switch that did not take effect is reported, never silently
assumed.

Nothing detects the failure mode that matters most for an unattended host: **the newly pinned image starts but never
becomes usable** — it crash-loops (systemd's `Restart=always` keeps restarting it and the unit never looks failed),
it hangs before the admin socket is bound, or it starts with a defect only visible from outside. The operator has to
notice the pending digest in `weglarka doctor` and run `weglarka-daemon self-update --rollback` by hand, and #99
deliberately left that out of scope.

## Decision

Draft — this ADR is reserved early (numbers are shared across branches, see `scripts/adr.sh`) so the feature PR can
fill in the mechanism. The feature PR must decide, with the rejected alternatives listed:

- **the supervisor**: a host-side watchdog unit installed by `platform install` versus a `systemd` failure hook
  (`Notify=true` + `OnFailure=`) versus an `ExecStartPost=` health gate versus waiting inside the existing update run;
- **health**: what "healthy" means for a daemon inside a `scratch` container, and which host-observable signal
  proves it (the admin API answers `/v1/health` once every startup precondition passed);
- **the deadline and the attempt budget**: how long after the switch restart the new digest gets, how many automatic
  attempts are allowed, and what happens when the target itself is unusable (no loop, a critical report instead);
- **the invariants**: no registry access on the fallback path (it must work when the registry does not), no fallback
  across a state-schema bump, the failed digest recorded so it is not re-pinned until the tag moves, `previous` never
  pointing at the digest that just failed, and no `state.toml`/`apps.toml` schema bump (`self-update.toml` is
  deliberately tolerant and unversioned).

## Consequences

To be written together with the decision: new units, `[self_update]` keys, `self-update.toml` fields, the doctor
report and the `docs/install.md` upgrade/rollback steps.

## Rejected alternatives

To be written together with the decision.
