# 0016 — `depends_on`: start ordering and health gating between apps

Status: accepted (2026-10-24, issue #35).

## Problem

Węglarka plans and executes every app on its own: `plan()` walks the app list and each app is deployed, started or
recreated without looking at any other app. That is the right default — an app that is down must not hold its
neighbours hostage — but it breaks the most common multi-app setup, a service and the database it needs. After a
boot, on the first deploy and on `apps start`, an app and its database are reconciled in the same pass, so the
service can reach its health gate before the database has a running container, fail the gate and roll back: a
deploy that "sometimes works", depending on which image unpacks first. The same missing relation shows up on the
way out: `apps remove db` deletes the container, volumes and uid range under an app that is still running.

Neither the deploy order nor the removal rule can be inferred from the image or the domains — Węglarka would be
guessing. Issue #35 has two halves: the ordering + health gating decided here, and a shared Postgres / network
attachment, which stays the unimplemented remainder of the issue. This iteration deliberately ships only the
ordering.

## Decision

**A per-app `depends_on` list of app names**, next to `domains` and `port`:

```toml
# apps.toml: `api` is only started once `db` is running — and healthy, if `db` has a healthcheck
[apps.db]
image = "ghcr.io/example/postgres:16"
health = { command = ["pg_isready", "-U", "app"] }

[apps.api]
image = "ghcr.io/example/api:latest"
depends_on = ["db"]
```

The field is optional, lives in `AppSpec` next to `health` and `volumes`, is available in `apps.toml` and in
`--spec` like every other spec field, and is serialized only when non-empty (`skip_serializing_if`) — an app
without dependencies keeps its current file shape. A name must refer to an app that already exists in
`apps.toml`; `depends_on` expresses a relation between app names, not image tags or domains.

**Ordering and health gating only — not networking.** Every app keeps its own `net-<instance>` network (0009):
`depends_on` does not attach the dependent to the dependency's network and does not make `db` resolvable by name
from `api`. The relation is about lifecycle, not connectivity; a shared Postgres reachable over a shared network is
the other half of #35, still to be designed.

**Where the gate applies.** Węglarka checks the dependencies before it *starts* a container: boot reconcile, the
first deploy, `apps start`, any deploy (manual or webhook) and a recreate whose container is missing. It does not
apply when an already running container is replaced for spec drift — the app is up, a recreate must not be blocked
by an unrelated app — and it does not apply to provisioning (`start = false` creates no container).

**The gate itself.** The dependency's container must exist and be running. If the dependency has a healthcheck
(`health.command` or the image's own `HEALTHCHECK`) it must also be healthy; a `health.http` probe goes through the
ingress, exactly like the deploy health gate (0010). Ordering by container status alone would start the dependent
against a database that is still initialising.

**A bounded wait, then a reported status — never a stuck loop.** If a dependency container exists but is not ready
yet (its own deploy was just commanded), the gate waits up to 10 s, polling every 1 s. When the budget expires —
including the case where nothing could become ready (no container, or a dependency with `start = false`) — the
admin API answers **409 Conflict** listing every unmet dependency with its reason, and reconcile reports "waiting
for dependencies" and retries in the next pass **without marking the app failed**: no error status, no rollback.
Waiting is bounded on purpose — reconcile must remain a finite pass that always reports.

**Validation: at the write and at startup, so the graph is always acyclic and complete.** An unknown name, a
self-reference, a duplicate entry and a cycle are rejected when the daemon writes a spec (`apps add` /
`apps update` → HTTP 400 `invalid_request`) and when it loads `apps.toml` at startup (the daemon refuses to start,
naming the apps involved). Because the reference must already exist, `apps add api --depends-on db` requires `db`
to be in `apps.toml`; `apps update` cannot point an app at a name that is not there.

**Removal is blocked by dependents.** `apps remove db` while any app has `depends_on = ["db"]` answers **409
Conflict** listing the dependents and deletes nothing — the volumes and the uid range stay too, so
`--purge-volumes` follows the same rule. Remove the dependents (or their `depends_on` entries) first: the operator
has to see the relation instead of discovering it after the fact.

**A dependency with `start = false` (0011) blocks its dependents.** There is no container to become ready, so the
dependent cannot start: reconcile reports it as waiting and `doctor` warns; `apps start db` is the fix.

**`spec_hash`: never part of the container identity.** `depends_on` changes no container setting, so it is not
added to `HashInput`: changing, reordering or clearing the list never recreates a container, and `state.toml` does
not change. Folding it into the hash would turn a pure ordering edit into a restart of the app and its health gate,
and would make `state.toml` carry a relation that is a property of `apps.toml` alone.

**CLI: a repeatable flag next to `--host-port`.** `--depends-on NAME` on `apps add` and `apps update` (repeatable;
`none` clears the list), and `apps update --remove-depends-on NAME` to drop a single entry — a usage error when the
name is not in the list, so a typo cannot silently "succeed". Both flags conflict with `--spec`, like every other
spec flag: either the flags or a complete spec file.

**`doctor`: a new `state.dependencies` check.** Warn when a running app's dependency is missing, stopped or
unhealthy, or when the dependency has `start = false`; Info when the app itself is not deployed yet and is waiting
for its dependencies; Ok otherwise. It is a state check (admin API), not a preflight one: it needs the live
container statuses, which `doctor --preflight` does not have.

## Consequences

- Nothing changes for existing installs: the field is optional and omitted when empty, no hash format is bumped and
  no container is recreated on upgrade. The first write that sets `depends_on` only changes `apps.toml`.
- The ordering is visible where it matters: a first deploy, `apps start` and boot reconciles of a dependent can now
  take up to 10 s longer, and their outcome is either a started container or an explicit "waiting" status with the
  reasons — never a rolled-back deploy caused by a slow dependency.
- Operators see two new conflict cases, both actionable: a deploy rejected with its unmet dependencies, and
  `apps remove` rejected with its dependents. Neither leaves partial state.
- Rollback: `apps.toml` has `deny_unknown_fields`, so an older daemon cannot read a file containing `depends_on`.
  A downgrade requires removing the `depends_on` entries first — documented in `docs/install.md`
  (6d and the rollback section).
- Tests: validation (unknown name, self-reference, duplicate, cycle — at the write and at `apps.toml` load), the
  gate (`FakePodman` scenarios: dependency not started yet and starting within the budget, unhealthy, missing,
  `start = false`, and a plain recreate of a running app not blocked), the removal conflict, the hash (a changed
  `depends_on` is not a recreate), the CLI parser (`--depends-on`/`none`/`--remove-depends-on`, conflict with
  `--spec`) and the `state.dependencies` check.

## Rejected alternatives

- **An implicit dependency** (inferred from the image, or "everything the webhook fanned out together"): the order
  would be a guess from image names/tags and wrong as soon as two apps share an image; webhook fan-out is about
  update propagation, not start ordering. An explicit field is the only one a reader, a validator and the operator
  can see.
- **Putting the graph into `spec_hash`**: it would recreate (and health-gate) a container for a pure ordering edit,
  and `state.toml` would have to store a relation that belongs to `apps.toml`. The hash describes what the container
  is; `depends_on` describes when it may start.
- **`tier = "infra"` + cross-app networks + a shared Postgres now**: a tier would still not order anything, and the
  network attachment needs a model for one app joining another app's network, a naming story and a migration for
  existing networks. Combining it with the ordering would couple a small lifecycle fix to a network change and delay
  both; it stays the remaining part of #35.
- **Cascading restart/stop of dependents**: a dependency update would cascade through the graph, turning one app's
  deploy into an outage and forcing ordered shutdown — a much larger contract than "do not start before the
  dependency is up".
- **A multi-container `AppSpec`** (compose-style): collapses independent apps into one unit and loses per-app
  secrets, volumes, uid ranges and the per-app deploy/reconcile that Węglarka is built around.
- **Unbounded waiting in the reconcile loop**: a dependency that never comes up would pin the loop and starve every
  other app. The 10 s budget plus "waiting, retry next pass" keeps the pass finite and the state honest.

## Open questions

- Flag name: `--depends-on` (chosen, symmetric with the field) vs. something shorter like `--needs`.
- The 10 s budget: fixed here; should it become configurable in `weglarka.toml` if a slow database shows up?
- `apps start --with-dependencies`: starting the dependency as a side effect of `apps start` would be convenient,
  but it makes a lifecycle command recursive — intentionally left out.
