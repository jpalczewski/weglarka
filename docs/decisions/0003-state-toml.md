# 0003 — Runtime state in a separate `state.toml`

Status: accepted (session b, 2026-10-23).

**Decision.** `apps.toml` contains only the *desired* state (changed from the API), while the *runtime*
state (pinned `current` and `previous` digest, `generation`, `spec_hash`, the last failed deploy) lives
in `state.toml` alongside it. Both files are written only by the daemon, atomically (tmp in the same
directory + `fsync` + `rename` + directory `fsync`), both are read with `deny_unknown_fields` and
invariant validation (e.g. `spec_hash` requires `current`, `previous != current`).

**Why.** Deploy changes state every few minutes; mixing that with the user's declaration would dirty
`apps.toml` (diffs, backup, a possible future manual editor) and risk a race between "the API writes
the spec" and "the deploy moves the digest". Reconcile converges to `apps.toml` + `state.toml`; deleting
`state.toml` is safe (instances get a fresh deploy with a pull).

**Other decisions.**
- Container name = instance name, per-app network = `net-<instance>` (`labels::container_name/network_name`).
- Change of a secret's value: the fingerprint enters the `spec-hash` (`SecretChangePolicy::Immediate`) or
  not (`NextDeploy`) — the choice is in `ReconcilerOptions`.
- A failed deploy writes `failed = { digest, reason }`: the webhook does not retry a known-bad digest,
  and a failed *first* deploy waits for a manual `deploy` (no retry loop).
- All mutating operations of the engine are serialized by one `tokio::sync::Mutex` (simplicity, no races
  on files); the health gate blocks other deploys for the duration of the window.
