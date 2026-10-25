# 0024 — Removing secrets and purging them with the app (issue #80)

Status: accepted (2026-10-24, issue #80).

## Problem

Secrets live in `secrets.toml` under the per-instance scope `<app>.<name>`, and nothing ever deletes
an entry: `apps remove` drops the instance from `apps.toml` and leaves its whole secret scope behind,
and `secrets set` only overwrites a value. Failure modes:

- **Orphans accumulate forever.** Every removed app (and every renamed instance) leaves its scope,
  `webhook-hmac` included, in a 0600 file that keeps growing with credentials nobody uses.
- **A reused name inherits stale values.** `apps add` under a previously used name picks up the old
  secrets: an old `config`, an old `webhook-hmac` that no longer matches GitHub's webhook — the app
  silently runs with the wrong material. This is why the missing removal is a security bug, not just
  hygiene.
- **There is no way to un-bind a value.** `apps update --unbind-secret` removes the binding from the
  spec, but the stored value stays unreachable: the API has no read-back and no delete.
- **Data and secrets are different concerns.** Volumes hold user data and must survive `remove` +
  `add` by default; secrets are credentials and must not be kept just because someone wanted to keep
  the data.

Constraints: secret values never appear in the API, `Debug` or logs; `secrets.toml` stays 0600 and is
written atomically; no TOML format changes (the upgrade/downgrade rules of the project); the app in
question may already be gone. House order: security → elegant/extensible code → RAM.

## Decision

**A single-secret removal endpoint, a purge flag on app removal, and a doctor check that surfaces
what is left.**

1. **`DELETE /v1/apps/{name}/secrets/{secret}` → 204** (`RemoveSecretQuery { force }`), CLI
   `weglarka secrets remove <app> <name> [--force] [--dry-run]`.
   - **409 by default** while the app's spec still binds the secret (`--secret-env`/`--secret-mount`):
     removing it would leave an app that can never start. The operator unbinds first
     (`apps update --unbind-secret`) or passes `--force`.
   - **404** when the store has no such secret; **400** for an invalid instance/secret name.
   - **The app need not exist in `apps.toml`.** That is the point of the endpoint: it works on the
     store alone (scope `<app>.<name>`), which is how the leftovers of a removed app and the old
     scope of a renamed instance are cleaned up.
   - **`--force` on a bound secret** is the operator's explicit "I know": the value is gone, the next
     reconcile puts the app into `waiting-for-secret` (blocked, not failed — see
     [the first app guide](../guides/first-app.md)),
     and a running container keeps the materialized value it already holds until it is recreated.
     The removal itself **never triggers a deploy**.
2. **`weglarka apps remove <app> --purge-secrets`** deletes the entire `<app>.*` scope of
   `secrets.toml`, `webhook-hmac` included, in the same operation as app removal.
   - **Independent of `--purge-volumes` (data)** — either, both or neither; keeping data must not
     imply keeping credentials.
   - **Purge happens before `apps.toml` is written.** If the purge fails, the app is still registered
     and the operation can be retried; the state never says "app removed, secrets still there".
   - Works only for an app that is still in `apps.toml` (the removal path is unchanged otherwise); for
     leftovers after the fact the endpoint from (1) is the tool.
   - It does **not** touch the materialized Podman secret objects (named `<app>.<name>`). They are an
     implementation detail, re-created from the store on every deploy; a removed app's Podman secrets
     stay until a later cleanup path prunes them. That is a known gap, recorded here so nobody assumes
     `--purge-secrets` wipes Podman too.
3. **`doctor` gains a `state.orphan_secrets` warning**: secrets whose instance is not in `apps.toml`,
   with a hint naming `weglarka secrets remove <app> <name>` (and `apps remove --purge-secrets` for
   next time). Not emitted when nothing is orphaned. It is a **warn**, not a fail: orphans do not
   break anything at runtime.
4. **No schema change.** `secrets.toml`, `apps.toml` and `state.toml` keep their format; `AppSpec` and
   `spec_hash` are untouched — a removed secret changes no binding, only a missing value. Removal
   deletes map entries and rewrites the file atomically with mode 0600.

**Invariants an implementer must preserve:** a value never appears in an error, log or `Debug`; 409 is
the default for a spec-bound secret; the removal never deploys; `--purge-secrets` is independent of
`--purge-volumes`; the purge precedes the `apps.toml` write; `secrets remove` works without the app
existing; `doctor` only warns.

## Consequences

- New CLI surface (`secrets remove`, `apps remove --purge-secrets`), an additive API endpoint and a new
  doctor check. `RemoveAppQuery` gains `purge_secrets` with `#[serde(default)]`, so an older request
  (without the field) keeps the current keep-secrets behaviour.
- **Downgrade-safe:** no TOML format change and no `AppSpec`/`spec_hash` change, so upgrading and
  rolling back the daemon/CLI recreates nothing. A **new CLI against an old daemon** silently ignores
  `--purge-secrets` (the old daemon does not know the query field: the app is removed and its secrets
  stay) and gets 404 for the new `DELETE`. Upgrade the daemon first — documented in
  [the secrets cleanup guide](../guides/secrets-cleanup.md).
- After `--force` on a bound secret the app blocks at the next reconcile; setting the secret again
  (`weglarka secrets set <app> <name> < file`) clears the state and the deploy resumes by itself.
- The materialized Podman secrets of a removed app are not deleted by this change (known gap); the
  store is the source of truth and every deploy recreates them.
- Tests: API/daemon tests for 204, 404, 400, 409 without `force` and 204 with `force`; removal of a
  secret whose app is no longer in `apps.toml`; the whole `<app>.*` scope (including `webhook-hmac`)
  purged by `apps remove --purge-secrets`, with and without `--purge-volumes`; the doctor check
  present with an orphan and absent when clean; CLI tests for both commands and `--dry-run`.
  `scripts/acceptance.sh` adds the canary round trip (set → list → remove → list) and asserts that no
  `state.orphan_secrets` check mentions the canary after the purge.

## Rejected alternatives

- **`--purge-volumes` implying secrets**: data has to survive `remove` + `add` by default; credentials
  must not be kept just because the data was. Two explicit flags make the operator choose.
- **Deleting the materialized Podman secrets now**: they are a deploy-time implementation detail
  (names, labels, re-created on every deploy); a correct purge would have to handle containers still
  using them and Podman's own lifecycle. Out of scope — the store is what fixes the name-reuse bug.
- **Requiring the app to exist for `secrets remove`**: cleaning up after an already removed app is the
  main reason for the endpoint; requiring `apps.toml` would leave the operator the manual
  `secrets.toml` edit the ADR exists to prevent.
- **Only the proactive purge at `apps remove` time**: an app removed with an older CLI (or just without
  the flag) could then never be cleaned up except by hand; the doctor warning plus the standalone
  endpoint cover the after-the-fact case.
- **Always refusing `--force` (requiring an unbind first)**: unbinding changes `spec_hash` and recreates
  the container — the opposite of what a credential rotation wants to do before setting the new value;
  and for a stopped or already broken app there is no deploy to protect. Refuse by default, allow on
  an explicit flag.
- **A 204 with a warning on a bound secret** (remove anyway and report): a destructive operation must
  not silently change what the spec says; a conflict is exactly what 409 is for.
