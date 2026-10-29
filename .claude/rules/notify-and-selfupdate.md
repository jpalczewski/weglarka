---
paths:
  - "crates/weglarka-notify/**"
  - "crates/weglarka-registry/**"
  - "crates/weglarka-model/src/{self_update,delivery,events,webhook}.rs"
  - "crates/weglarka-daemon/src/{self_update,supervise,platform,webhook,github,forgejo}.rs"
  - "crates/weglarka-daemon/tests/it/{notify,self_update,forgejo}.rs"
  - "docs/guides/{notifications,self-update,webhooks}.md"
---

# Notifications, self-update, watchdog and webhooks

## Invariants

- **Notifications (ADR 0021):** `EventSink::emit` is called under the engine mutex, so the sink **only enqueues**
  (`try_send`, no I/O) — the worker does all the work. The source of truth about delivery is the durable outbox
  `<state dir>/notifications.toml` (tolerant `serde`, 0600); the `[notify]` section in `weglarka.toml` breaks rollback to
  an older daemon (`deny_unknown_fields`). A new channel = a `Channel` + its name in the outbox.
- **Self-update (ADR 0027):** the daemon sits in a `scratch` container (no `systemctl`, `/etc/passwd`, D-Bus) and has no
  write access to its own unit, so swapping the image is **host-side**: `weglarka-daemon self-update` + a user timer
  installed by `platform install`. Order: pull → signature verification (static cosign key from `cosign.pub` in the repo,
  `ring`, no Rekor/TUF) → schema gate (image label `io.weglarka.state-schema` vs `schema_version` in `state.toml`) →
  pin `repo@sha256:…` in the quadlet → `pending` in `<state dir>/self-update.toml` (tolerant, 0600) → restart; the
  daemon confirms at startup and sets `current`/`previous`. The registry is public only (anonymous GHCR token), and
  `[self_update]` in `weglarka.toml` breaks rollback to an older daemon.
- **Automatic fallback (ADR 0034, #100):** the timer `weglarka-watchdog.timer` runs `weglarka-daemon supervise` every
  minute; if the new daemon does not answer `GET /v1/health` within `[self_update] fallback_timeout_secs` (default
  180 s), the watchdog does `reset-failed` + pins `switch_from` in the quadlet and restarts, and the daemon emits
  `SelfUpdateFellBack` after the start and leaves the broken digest in `error` (no re-pin until the tag moves). One
  attempt: an exhausted budget is a report (`doctor`, journal, the watchdog unit "failed"), not a restart loop.
- **Webhook dedup survives a restart (ADR 0035, #41):** delivery ids are kept in `<state dir>/webhook-deliveries.toml`
  (`model/src/delivery.rs`; 0600, 256 entries, oldest drop out), written atomically by `fsutil::write_atomic` under the
  dedup mutex, only for a new id and **before** the fan-out. The file is deliberately outside `state.toml` (a new field
  breaks rollback through `deny_unknown_fields`), has no schema marker, and an older daemon ignores it. Reading is
  tolerant (missing = empty set, corrupt = warn + empty and rewritten at the next delivery), and a write error only
  warns — bookkeeping must not take down a webhook or daemon startup.

## Entry points

| Area | Files |
|---|---|
| notifications | `crates/weglarka-notify/src/{message,dedup,outbox,worker,ntfy,endpoint,settings}.rs`; the `[notify]` section: `crates/weglarka-model/src/config.rs`; `Severity`: `crates/weglarka-model/src/events.rs`; wiring: `crates/weglarka-daemon/src/lib.rs` (`Notifier::build`, sink, worker), route: `crates/weglarka-api/src/endpoints.rs` → `crates/weglarka-daemon/src/admin.rs` |
| Węglarka self-update | `crates/weglarka-model/src/self_update.rs` (state + pure `decide()`/`supervise()`), `crates/weglarka-registry/src/` (cosign signature and key verification), `crates/weglarka-daemon/src/self_update.rs` (host-side switcher + fallback action), `crates/weglarka-daemon/src/supervise.rs` (host-side watchdog: `GET /v1/health` probe, state lock), `crates/weglarka-daemon/src/service.rs` (spec shared with `platform install`), `crates/weglarka-daemon/src/platform.rs` (timers, `install_user_units`, `restart_service`, `reset_failed`), the `[self_update]` section in `crates/weglarka-model/src/config.rs`, check `self_update` in `crates/weglarka-daemon/src/doctor.rs` (ADR 0027, ADR 0034) |
