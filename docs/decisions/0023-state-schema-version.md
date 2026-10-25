# 0023 — State schema version and a startup compatibility check (issue #98)

Status: accepted (2026-10-24, issue #98).

## Problem

`apps.toml` and `state.toml` use `deny_unknown_fields`, and almost every iteration added a field to
them (`start`, `depends_on`, `shared_volumes`, `host_ports`, `command`, `uid_range`, …). A daemon
older than the file refuses to start with a TOML *parse* error, which reads like a typo in a
hand-edited file. Rolling the image back therefore depends on remembering which field belongs to
which version — exactly the step that is skipped in a hurry.

Two constraints shape the fix:

- Typos in `apps.toml` must still be caught (that is why the strict rule exists).
- A rollback must not get *worse* because of the change. Węglarka is updated often; the very next
  downgrade should keep working.

#47 (self-update) needs the same contract: #99 pins a new image and #100 falls back to the previous
digest, and both have to know *why* a daemon refused to start instead of guessing from a parse error.

## Decision

1. **A `schema_version` field in both files** (`Option<u32>`, first field so TOML values precede
   tables, `skip_serializing_if = "Option::is_none"`). One version covers both files: they are
   written by the same daemon and a startup is all-or-nothing. `weglarka_core::state::SCHEMA_VERSION`
   is the only place to bump.

2. **The first version is implicit.** A file without a marker is v1 — the shape written before
   versioning, which is also today's shape. `SCHEMA_VERSION = 1` and `IMPLICIT_SCHEMA_VERSION = 1`, so
   the daemon does **not** stamp `schema_version = 1`: the marker appears only when
   `SCHEMA_VERSION > IMPLICIT_SCHEMA_VERSION`, i.e. from the first real schema change. Writing it
   today would make the next downgrade to a pre-versioning daemon fail — the failure this ADR exists
   to remove. A marker that is already present is kept through load/save.

3. **The version gate runs before the strict parse.** Reading a file is: tolerant header parse
   (`schema_version` only, unknown keys ignored) → refuse if `found > SCHEMA_VERSION` with
   `StateError::SchemaTooNew { path, found, supported }` → migrate if `found < SCHEMA_VERSION` →
   strict `toml::from_str::<T>` (so a typo keeps its line and column). The too-new message names the
   file, both versions and the two remedies: roll forward, or restore the files from before the
   upgrade.

4. **Migrations are a checked chain.** `SCHEMA_STEPS[i]` upgrades `IMPLICIT_SCHEMA_VERSION + i` to the
   next version and transforms the parsed table; a compile-time assertion ties the slice length to
   `SCHEMA_VERSION - IMPLICIT_SCHEMA_VERSION`, so a bump without a step does not build. The migrated
   document is stamped with `SCHEMA_VERSION` in memory and written by the next ordinary atomic save —
   there is no separate migration pass or backup file. Steps must be idempotent: a hand-restored file
   can carry the new fields without the marker and is then treated as v1.

5. **One parser for the daemon and the host CLI.** `load_apps`/`load_state` are `read_optional` +
   `parse_apps`/`parse_state`; the pure functions are public and reused by
   `weglarka doctor --preflight`, which reads `apps.toml` itself. A too-new file is reported as a
   schema mismatch (with a "roll forward or restore" hint) instead of an unknown field. The daemon's
   `doctor` distinguishes the variant the same way, so it no longer suggests deleting a file that a
   newer version wrote.

6. **Boundaries.** `secrets.toml` is not versioned yet (its format has not changed since iteration 1;
   when it does, it gets the same gate). `weglarka.toml` is configuration written by a human, not
   state, and is not versioned. `notifications.toml` stays deliberately tolerant (ADR 0021).

**Invariants an implementer must preserve:** v1 files stay byte-for-byte unchanged (no marker until
the first bump); a new field in either file comes with a `SCHEMA_VERSION` bump, a `SCHEMA_STEPS` entry
and a [state schema guide](../guides/state-schema.md) note; the gate never lets a newer file reach the strict parser; a file is
only ever written by the daemon, atomically, through `save_apps`/`save_state`.

## Consequences

- The operator gets one clear message where there used to be a parse error, and a documented
  procedure: keep a copy of the state directory before upgrading, and restore it when a downgrade
  crosses a schema bump.
- **Rollback across a bump needs the copies**: from the first bump on, an older daemon refuses a file
  written by a newer one. That is deliberate (silently reading it could mis-handle uid ranges,
  digests or retention), and it is the design note for #99/#100: a self-update must not pin an image
  with a newer schema unless the previous state is restorable; #100's automatic fallback is safe
  only within one schema.
- Code surface: `StateError::SchemaTooNew` (additive public variant), `SCHEMA_VERSION`,
  `parse_apps`/`parse_state`. Each load parses the source twice (header + strict); the files are
  tiny.
- Tests: v1 files stay unmarked, an explicit current version survives, a too-new file wins over
  `deny_unknown_fields`, invalid versions (`0`, negative, non-integer) are rejected, empty and
  comment-only files load as empty, the migration path stamps the version, the daemon refuses to
  start on either file, and preflight reports the schema instead of an unknown field.

## Rejected alternatives

- **Drop `deny_unknown_fields` from the state files** (read them tolerantly): loses typo detection
  in hand-edited `apps.toml`, which is worth more than the automatic downgrade; the notification
  outbox stays the one deliberate exception.
- **The version in a separate file** (`<state dir>/schema.toml`): a daemon that predates versioning
  never reads it, so it cannot produce the clear message — and a partial restore would not be
  detected either.
- **The version in a TOML comment**: any rewrite drops it, which silently downgrades the marker and
  can run a migration on already-migrated data.
- **Writing `schema_version = 1` immediately**: simpler serialization, but the first rollback after
  the upgrade would need a manual edit of two files — exactly the failure mode being removed.
- **A separate version per file**: two migration chains and two gates for a startup that is
  all-or-nothing.
- **Warning instead of refusing**: a newer schema can change the meaning of existing fields, so
  continuing could corrupt state (uid ranges, digest retention) rather than fail loudly.
- **A `weglarka applications migrate` command**: the daemon is the only writer of these files;
  migrating in-process, on load, keeps the atomic-write rule and needs no extra operator step.
