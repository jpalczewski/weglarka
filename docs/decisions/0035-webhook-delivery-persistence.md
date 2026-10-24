# 0035 — Persist webhook delivery dedup across restarts (issue #41)

Status: accepted (2026-10-24, issue #41)

## Problem

`Reconciler::handle_webhook` deduplicates deliveries by `X-GitHub-Delivery` / `X-Forgejo-Delivery` in a
bounded in-memory `DeliveryDedup` (ADR 0004). A daemon restart — routine since self-update (ADR 0027,
ADR 0034) — empties that set, so GitHub's redelivery of an already handled event is processed again:
at least another pull, and possibly a redeploy that undoes a manual pin. The engine has to remember
handled deliveries across restarts without touching the versioned state files.

## Decision

- Handled ids live in their own file in the state directory, `<state dir>/webhook-deliveries.toml`
  (`delivery::FILE_NAME`, reached through `state::StatePaths::deliveries`), mode 0600, written with
  `state::write_atomic` (tmp file → fsync → rename → directory fsync).
- Bounded by count (`delivery::DEFAULT_CAP` = 256, the size of the previous ring), oldest dropped
  first. The file stores the ids oldest first, so an over-long file keeps its newest ids on load. No
  timestamps and no TTL: the only question the set answers is "was this id handled", and a count cap
  keeps the file small.
- Loaded once in `Reconciler::new`; a missing file is an empty set. This file is **bookkeeping, not
  state**: an unreadable or malformed file is logged at `warn` and treated as empty (it is rewritten on
  the next accepted delivery). It never stops the daemon — unlike `state.toml`, whose corruption is
  fatal.
- Written while holding the existing dedup mutex, for every **new** id, before the fan-out. A duplicate
  does no I/O. A write failure is logged and degrades to the pre-#41 in-memory behaviour; a webhook is
  never failed because bookkeeping could not be saved.
- The id is remembered before the deploy, so a delivery whose deploy fails is not retried by a
  redelivery — the same at-most-once-per-id behaviour the in-memory set had.
- Deliberately **not** part of `state.toml`: a new field there breaks a rollback to an older daemon
  (`deny_unknown_fields`) and requires `state::SCHEMA_VERSION`/`SCHEMA_STEPS` (ADR 0023). A separate
  file needs no version marker because an older daemon ignores it; deleted, it costs only the dedup
  history.

## Consequences

- A redelivery of an already handled event after a restart, self-update or reboot is answered 202 and
  triggers no pull — the acceptance criterion of issue #41.
- One small `fsync`-backed write per accepted delivery, on the background webhook task, before any
  deploy starts. It is not offloaded to a writer task: serializing it under the dedup mutex is what
  keeps the file consistent with the in-memory order, and the payload is a few kilobytes.
- Operators may delete the file (dedup starts from scratch). It is not part of the backup story for a
  rollback across a state-schema version, and an older daemon simply ignores it.
- Tests: unit tests for eviction, round trip, tolerance and file mode; an engine test with two
  `Reconciler`s over one state directory; a daemon test that stops and restarts the daemon and asserts
  the same delivery no longer pulls.
- GitHub and Forgejo share one set: both adapters go through the same engine and their ids are UUIDs,
  so a cross-source collision is negligible and would only drop one event.

## Rejected alternatives

- **A field in `state.toml`** — breaks `deny_unknown_fields` rollback, needs a schema bump, and every
  older daemon would have to understand a field the containers do not depend on.
- **SQLite or another store** — a new dependency and a second data format for a few kilobytes.
- **Persisting after the deploy succeeds** — a crash mid-deploy would replay the delivery (pull, and
  possibly a redeploy after a manual pin); the current semantics are at-most-once per id.
- **Timestamped entries or a TTL** — more data and an expiry policy for no benefit; the count cap
  answers the only question the set is asked.
- **Off-loading the write to a dedicated task or thread** — a few kilobytes at most once per accepted
  webhook, and the extra machinery would still need ordering against the in-memory set.
