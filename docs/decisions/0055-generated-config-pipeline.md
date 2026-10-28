# 0055 — Generated config pipeline

Status: accepted (2026-10-28, issue #212). Builds on ADR 0028 (host config mounts) and ADR 0051 (identity provider integration).

## Problem

The identity provider needs files Węglarka computes from `apps.toml`: access rules and OIDC clients (ADR 0051).
A file the operator writes by hand goes stale the moment an app is added, and a file written without a check can
take the provider — and with it every protected app — down. We need a way to render files, prove they are
acceptable to the consumer, switch to them atomically, and go back if the consumer does not survive them.

Constraints: security first (no secret value may reach a generated file, an event, a log or the state file), then
extensible code (the identity renderer must plug in without the pipeline knowing it), then RAM.

## Decision

**A generator is a pure, `dyn`-safe trait in the model crate** (`ConfigGenerator`): `render` turns `apps.toml` and
credential digests (`Pbkdf2Digest`, #213 — never a `SecretValue`) into `GeneratedFile`s, `validate_argv` names the
consumer's own validator. Same input, same bytes. The engine owns everything that touches Podman or the disk
(`Reconciler::apply_generated`, `weglarka-engine/src/generated.rs`); the daemon only decides when to run it.

**Layout.** `<state dir>/generated/<consumer>/v-<fingerprint12>/…` plus a relative symlink `current`. The
fingerprint is sha256 over the files sorted by name, each as `name \0 length bytes`. The consumer mounts the
*parent* read-only at `/weglarka/generated`, so a new version is visible inside its mount as soon as it is
written; validation needs no extra mount and `RunOptions` is unchanged.

**Pipeline**, under one acquisition of the engine lock (`prepare_run_locked` and `reload_locked`; the lock is not
re-entrant, and `EngineGuard` makes calling a `*_locked` operation without it a compile error):
render → equal to the applied, live version? stop → write the version (built as `<version>.tmp`, renamed) →
validate in a one-off container of the consumer when it has a deployed digest → swap `current` with one `rename`
→ apply → record. Applying a running consumer is `reload_locked` (a signal if the spec sets `reload_signal`,
otherwise a restart) followed by the consumer's own health gate; a stopped or never-deployed consumer counts as
applied, because the next start reads the files. A failed gate points `current` back once and applies again —
one attempt, no loop — and emits `GeneratedConfigRolledBack`. A rejected render leaves `current` alone and emits
`GeneratedConfigInvalid`. Only the live and the previous version are kept; a rejected version stays until the next
attempt.

**Failed renders are not retried every time.** A render that was rejected, rolled back or could not be applied is
remembered by fingerprint in `generated.toml` (`attempted` + `last_result`); the same render is skipped until it
changes or the pass is forced. Without this every `apps.toml` write would restart the consumer again.

**Bootstrap.** Authelia refuses to start without its access rules, so a consumer's *first* launch runs
render → write → swap before anything is created (`bootstrap_generated`, from both launch paths). Validation is
impossible without a deployed digest; the version is recorded as unvalidated and the provider's own start is the
validation — a bad render fails the deploy before the old container is touched. A render error stops the launch.

**Recovery.** If `current` already points at the rendered fingerprint but `generated.toml` does not record it as
applied (the daemon died between swap and apply), the next pass skips write and validate and applies once.

**Triggers** (`weglarka-daemon/src/generated.rs`): daemon start and `Daemon::changed()` — the same notification
the ingress worker listens to, not a second mechanism — with a 2 s debounce counted from the first change, so a
burst means one restart. The credential digests (`ensure`, #213) are produced by a provider the pipeline calls
under the engine lock, because minting is a read-then-write on the secret store.

**The consumer's container carries one more bind**, and `AppSpec` has no field for it. The mount is added in
`prepare_instance`, which deploys and one-off runs share (so the validation run sees the same versions as the
serving container), and `desired_hash` mixes `spec_hash_with_generated` into the hash **only** for an app a
registered generator renders for. Every other app keeps exactly the hash it had, so upgrading recreates nothing; a
consumer that was already running is recreated once to gain the mount.

**Secrets and the validator.** The validator runs with the consumer's secrets bound, so a parse error that quotes a
line could echo a value. The captured output (64 KiB window) is masked — every bound secret value, longest first,
also without trailing whitespace — and only then is the first 4 KiB dropped when the window cut it and the output
cut to its last 16 KiB. The event carries the last 1 KiB; the full tail is only in the 0600 state file and `doctor`.
Encoded forms of a value (JSON escapes, URL encoding) are not recognised.

**State.** `<state dir>/generated.toml` (tolerant serde, 0600, atomic), outside `state.toml` like
`webhook-deliveries.toml` (ADR 0035): no schema bump, and an older daemon ignores it. A failed write only warns.

Invariants an implementer must preserve: the lock is taken once and never re-taken inside the pipeline; `current`
only ever changes by `rename`; a generator output never contains a secret value; `spec_hash` is untouched for any
app that is not a consumer; a failed render is not retried unprompted.

## Consequences

* New events `GeneratedConfigApplied` (info), `GeneratedConfigInvalid` and `GeneratedConfigRolledBack` (warning —
  `Severity` has no error level), rendered by the notification channels. `doctor` gets `generated.<id>`.
* No `apps.toml` or `state.toml` field: no schema bump. The guide
  ([generated config](../guides/generated-config.md)) covers rollback.
* The validation run holds the engine lock for up to 60 s (the issue asks for a single critical section). Deploys
  queue behind it; the validator is a config parse, so this is a hang guard, not an expected wait.
* No generator is registered yet (`generated::registered` is empty): the feature is dormant until the identity
  renderer is wired (#42). Tests use a fake generator against `FakePodman`.

## Rejected alternatives

* **Render into the consumer's `config_root` mount (ADR 0028).** That directory is operator-owned and
  read-only to the daemon; generated files would mix with hand-written ones, and there is no atomic swap.
* **Write files in place, validate afterwards.** A rejected render would already be live, and a crash mid-write
  would leave the consumer reading a half-written file. A versioned directory plus one `rename` has neither.
* **An `ApplyMode` per generator.** The existing reload decision (`reload_signal` or restart, ADR 0028) already
  says how the consumer wants to be told; a second knob would disagree with it.
* **Retry a failed render on every trigger.** It turns a bad render into a restart loop. Skipping the same
  fingerprint costs one field in `generated.toml`.
* **Cut validator output first, mask second.** The text shrinks when masked, so a secret straddling the cut could
  survive; masking the whole capture first and dropping its edge afterwards cannot expose one.
