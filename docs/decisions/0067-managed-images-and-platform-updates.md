# 0067 — Managed image provenance and coordinated platform updates

Status: proposed (2026-11-02, issues #442, #203, #312, #46). Local draft; number must be checked before publication.

Maintainer-approved direction: host-side rollback with retained tool generations, signed OCI release-set
descriptors, and explicit panel enrollment under self-update. Also approved: a healthy new daemon may remain
with the restored old panel when that combination is compatible; an incompatible state-schema rollback stops
with an error rather than restoring a backup; Alpine/OpenRC needs root for installation only, not routine updates.
The remaining implementation gates below do not reopen these choices; the full ADR remains proposed until those
gates are specified and reviewed.

The [v1 implementation contract](../contracts/platform-update-v1/README.md) now specifies the wire format,
fixtures, launcher handoff, panel pin protocol, locks and systemd/OpenRC execution. It is the detailed contract
for the [implementation briefs](../contributing/briefs/platform-updates.md). An independent design review has been
carried out and its blockers and majors are resolved in the contract and briefs (identity and channel binding,
sequence allocation, reservation ownership, handoff failure states, capability gating, pin commit order and
bootstrap). Runtime validation and implementation evidence are still required, not additional product decisions.

## Problem

Image retention assumes that superseded images retain repository names. On the reported Podman host they retain
neither tags nor repository digests (#442). `ListedImage` additionally drops the standalone `Digest` field.
The engine mutex does not serialize cleanup with the host-side self-update process or archive loading.

Updating the daemon container leaves the host switcher and watchdog binaries behind (#203). Panel-only crate
releases do not publish a stable panel image, and the panel image version currently names the daemon version
(#312). The panel runs as an ordinary app; changing the daemon does not update it.

The design must cover systemd hosts and the target Alpine/OpenRC platform (#46). Only systemd is implemented
today. The existing `Platform` abstraction leaks systemd concepts through `UnitFile`, `install_user_units` and
`set_timer`. Issue #46's older suggestion to update by exiting is insufficient on its own: the next start must
use a verified, durably selected digest and retain a usable recovery path.

This draft defines implementation boundaries, proposed contracts and acceptance gates. It does not authorize
automatic adoption of unknown images or change an installed host. It supplements ADRs 0020, 0027, 0034 and 0057;
their current behavior remains in force until the corresponding implementation is released.

## Decision

### 1. Image identity, provenance and protection are separate

Place shared domain types and persistence rules in `weglarka-model`; orchestration remains in the engine and
daemon. Do not introduce dependencies from leaf crates to the engine.

Proposed domain contracts (names are provisional, semantics are binding for implementation briefs):

- `ImageIdentity`: canonical full local image ID plus a set of known manifest digests. IDs and manifest digests
  are distinct types/concepts; never compare an image ID as if it were a manifest digest.
- `ImageOwner`: `App(InstanceName)` or `PlatformDaemon`. An enrolled panel is still an app owner; its platform
  role is an explicit configuration binding, not a reserved instance name.
- `ManagedImage`: identity plus a set of owner/repository associations. Multiple apps and repositories may
  refer to one local image. Repository normalization uses the existing image reference parser.
- `Protection`: image ID and/or manifest digest with a reason: container, app current/previous, spec tag,
  platform current/previous, pending switch, fallback, or acquisition in progress.
- `RetentionScope`: all managed images or a selected owner/repository. Protection always covers all owners.
- `RetentionInput`: observed images/containers, provenance, protections and scope. `plan(input)` is pure;
  `execute(guard, plan)` removes by ID without force and reports per-image failures; the guard is a parameter so a
  stale plan cannot be executed after the lock is dropped.

The Podman adapter preserves standalone `Digest` as well as all `RepoDigests`; null name arrays are ordinary
input. An inspect fallback resolves missing identity only when needed. `doctor`, dry-run and deletion share
the same input builder. Dry-run and diagnostics do not adopt images or mutate bookkeeping.

### 2. A durable inventory, not a bounded recent-history list

Use `<state_dir>/managed-images.toml`, separate from `apps.toml` and `state.toml`, with its own `format_version`,
atomic writes and mode 0600. Each record contains a local ID, known digests and owner/repository associations.
Do not store credentials, full application specs or arbitrary image metadata.

Missing inventory means no provenance is known yet. Invalid/unsupported inventory disables destructive cleanup
and produces a diagnostic; it is not silently replaced with an empty file. Unknown fields may be tolerated
within a supported format; incompatible semantics require a format bump. Older binaries ignore this new file.

Record identity after successful acquisition, before deploy/verification outcomes can discard the reference.
This includes pulls, archive imports and unsuccessful deploy/update candidates. Before moving a known tag,
adopt its existing target while its provenance is still observable. Also seed images identifiable from current
names or saved current/previous state, preserving the existing repository-based adoption policy explicitly.
Names are adoption evidence, not a permanent requirement for later retention.

Never infer ownership of an anonymous historical image from its age, size, labels or digest alone. Report
unattributed images separately. An explicit adoption command is a possible follow-up, not implicit upgrade behavior.

Remove records only after successful deletion/NotFound or a successful complete inventory observation proving
absence, serialized with acquisition. Failed deletions retain their records. Do not evict old records merely to
meet an entry limit: that recreates the leak. Bound parsing resources and fail closed on oversized input; the
specific limits and diagnostic belong in the persistence implementation and tests.

Keep provenance after an app is removed or changes repository. Explicit global prune can collect those images;
automatic retention remains scoped to the owner/repository involved in the completed operation.

### 3. Cross-process coordination

A short metadata lock alone cannot prevent deletion between pull and publication of `current` or `pending`.
Use an image-operation guard shared by every cooperating process, backed by a file lock under `state_dir`.
The first implementation may serialize acquisition and pruning for simplicity; optimize only with evidence.

- Acquisition holds the guard from before pull/load/tag mutation until provenance and a durable protection
  have been published. An app deploy can instead retain the guard through its state commit, including that app's
  own health gate. A failed acquisition releases it; completed but unused images remain recorded candidates.
- Prune holds the guard across loading authoritative protection state, observation, planning and removal.
- Durable prepared-update reservations (`image-reservations.toml`) survive process death. They do not expire by
  wall-clock TTL; a reservation records its owner, phase and journal reference, and is reclaimed only when its
  owner's boot is gone with no referencing transaction, or by an explicit operator abandonment.
- Repository-known legacy images are covered by the same guard, including the archive load-to-deploy window; the
  reservation is published before loading and advanced before the image is tagged.
- Never wait for a daemon restart, daemon health endpoint or daemon API call while holding this guard. Publish
  protection, release the guard, then perform the external action. Startup must be able to confirm a pending switch.
- Lock ordering: engine operation guard when needed, then image-operation guard, then short state-file locks.
  No reverse acquisition. Host code must release image/state locks before calling the engine API.
- Existing host runner exclusion (`self-update.lock`) may serialize switcher/watchdog runs, but daemon startup
  must not need that long-lived runner lock. Separate runner exclusion from short transaction state updates.
- All read-modify-write participants, including startup confirmation, use the short state lock; atomic rename
  alone does not prevent lost updates. Failures reading protection state prevent deletion.

Guard contention uses asynchronous/bounded acquisition rather than blocking a runtime worker indefinitely.
The acquisition failure policy is conservative: if provenance cannot be saved, report degraded bookkeeping and
skip cleanup; never lose a required protection and continue destructive work. Platform activation requires a
successfully persisted recovery record. External manual Podman mutations are outside these locks; non-force
removal remains the final protection for images referenced by containers.

### 4. A release set with real component versions

Publish a signed release-set descriptor that selects tested component artifacts by immutable digest. Its identity
is the OCI manifest digest of the signed artifact, independent of the daemon crate version, so a panel-only change
can produce a new release set. Preserve crate versions and changelogs; `org.opencontainers.image.version` describes
the component actually inside the image on every channel, while the image revision label is informational and is
not compared with the set revision.

Publish the descriptor as an OCI artifact, signed with the same configured trust key as the images. Resolve
the channel reference to an immutable artifact digest and verify that artifact before consuming its descriptor.
The signature must bind the descriptor content through the OCI manifest/blob digests. Reuse the registry and
signature-verification infrastructure, extending it for this artifact type; do not assume image-only parsing
already supports release descriptors.

Descriptor v1 requires:

- format version, source revision and channel (`stable` or `main`); the immutable release-set ID is the OCI manifest
  digest that wraps the descriptor, not a descriptor field;
- explicit target OS/architecture/ABI (initially the Linux musl target already built by CI);
- daemon and panel repository, immutable image digest and actual component version;
- host tool artifact identity and per-file hashes for `weglarka-daemon` and `weglarka`;
- compatibility information required to preflight state schema and the panel/daemon API combination.

The descriptor and its artifact bindings must be authenticated with the configured release trust root. Verify
image signatures by digest as today; authenticate host file hashes through the descriptor or verified image.
Do not trust a mutable JSON download or a checksum served beside an unsigned binary. Reject unsupported formats,
targets and compatibility claims. Bound descriptor reads and apply the existing registry redirect/token policy.

Publish the channel pointer only after every referenced artifact and signature is available and the combination
passes CI. Serialize channel promotion so a delayed older workflow cannot overwrite a newer release, allocate the
sequence from the highest immutable tag as well as the channel pointer, and reconcile a superseded queued run
instead of dropping it. Both channels require the static-key signature; a missing key fails the release. A
panel-only release must not rebuild/relabel an unchanged daemon under its old immutable version tag. Reuse verified
existing artifacts or give a new build its own identity. `main` and stable never silently substitute for each
other: the host rejects a signed descriptor whose channel or sequence does not match its configured channel and
durable per-channel high-water mark.

The publisher and the host verifier share one implementation, the `weglarka-release` workspace binary, built on the
same model parser and registry client. The host accepts only a fully re-tested compatibility list for the selected
daemon digest, including the previous promoted panel when a fallback is claimed.

Wire serialization, OCI media types and legacy signature layout, per-channel sequence ordering and exact tested
panel-digest compatibility are specified in the v1 contract with positive/negative shared fixtures. Publisher
and updater implementations must consume those fixtures; changes require a shared contract update first.

### 5. Recoverable platform update stages

Use a separately versioned `platform-update.toml` journal rather than extending strict application state. It holds
a per-channel accepted pointer that survives journal cleanup, plus one transaction. The transaction records the
release-set identity, old/target component identities and schema sets, enrolled panel instance, prepared host-tool
generation, reservations, stage, owner identity and failure. Proposed stages:

`Preparing -> Prepared -> Handoff -> Ack -> SwitchingDaemon -> DaemonHealthy -> PanelTransition -> CommitPersisted ->`
`Committed | Degraded | BlockedRecovery | RolledBack`, plus `HandoffFailed`.

The handoff persists the candidate selection and a bounded deadline, then releases the runner lock; the candidate
acquires it and acknowledges. A missing acknowledgment is a failure owned by any later lock holder, so a candidate
that cannot exec never leaves the transaction locked. Every adapter call is bounded, and the runner lock is not
released into an unprotected switching window. Failures produce a recorded recovery state, not an unconditional
rollback of every component. Replaying a stage must be idempotent; record intent before each external side effect
and inspect actual state on resume. The terminal outcome chooses the tool generation whose compiled schema support
matches the actually running daemon, for every outcome, not only rollback.

Prepare and verify all enrolled artifacts before changing services. Protect old and target images. Stage host
binaries in immutable generation directories (`host-tools.toml` selects them) and select a generation atomically
through a stable entrypoint; do not overwrite running binaries in place. The updater/watchdog used after switching must be capable of reading
the new state, and recovery must remain available even when the new daemon fails before health confirmation.
Both the candidate and the recorded recovery generation pass preflight against the current host configuration and
state schema before activation, so a rollback target that would reject the new configuration is detected in
advance. The activation sequence, handoff failure handling and launcher bootstrap are specified in the v1 contract;
the bootstrap must be installed before coordinated updates are enabled.

Rollback is performed by the host tools, independently of the daemon container, using the systemd or OpenRC
adapter. Retain the current and previous tool generations, plus any generation needed by an unfinished update.
Persist old and target image digests before restart. The host watchdog checks daemon health and restores the old
digest when recovery permits it. Keeping the old binary is not enough: the recovery runner must understand the
journal and the actual state schema even if the new daemon never reaches its health endpoint.

After daemon health confirmation, deploy the enrolled panel through the engine's existing gate/rollback machinery,
using its exact descriptor digest. Do not infer enrollment from the name `panel` or `[admin.http] clients` (which
can contain other clients). Enrollment is an explicit one-time command over an existing app instance named by the
optional `panel_instance = "panel"` field in `[self_update]`; there is no implicit adoption of a running digest on
startup. Validate the binding before preparing an update, and again at transition POST. The panel pin is the
authority for the desired digest and `AppState` for the running one; a transition commits the pin before state so a
crash between them is resolved forward from the observed container, and startup reconciles before serving admin
requests. Legacy installations remain daemon-only until explicitly configured with a channel and bootstrap.

On panel failure, restore the panel using the engine and retain the healthy daemon if that pair is declared
compatible. This is an accepted partial success, recorded as `Degraded`, not as a committed target release set.
Persist the actual daemon/panel identities and retain the restored panel's effective pin, so reconciliation does
not immediately undo recovery. Report the failed target and an explicit retry action; ordinary timer ticks must
not repeatedly deploy the same failed panel digest. A newer release set or an explicit retry may resume updating.
Otherwise stop with an actionable recovery state; do not guess that independently rolled-back
components are compatible. A daemon rollback after a state-schema change must pass the existing schema gate;
image retention cannot make an incompatible state downgrade safe. On incompatibility, record `BlockedRecovery`,
stop automatic switching and report the actual schema, intended rollback target and reason through host logs and
doctor when available. Do not restore a backup automatically or claim that recovery succeeded. Protect recovery
artifacts until explicit resolution. Automatic state restoration is outside v1.

For an enrolled panel, the release set owns image-version selection; the engine still owns deployment, health
gates and rollback, and the app spec still owns domains, configuration and secrets. Ordinary webhook/tag
reconciliation must not replace the selected digest. Reject manual image-version overrides, including push,
with an explanation that platform management must first be disabled explicitly. Restart/redeploy of the selected
digest remains available. The v1 contract specifies the engine-owned `platform-pins.toml`, the durable
`platform-transitions.toml` terminal history and the idempotent transition protocol, with no hash change when
enrollment is absent.
Explicit removal of enrollment restores ordinary app behavior and warns that the configured spec image will
again determine the version. Do not implement platform deployment as a one-off `push` which the next reconcile
could silently undo.

Commit only after all enrolled components and the selected host tools are healthy/validated. Release reservations
after durable commit or explicit recovery; then invoke scoped best-effort retention. Preserve current, previous,
pending and active fallback targets independently of repository names. No periodic prune setting in this scope.

The following recovery outcomes apply identically to systemd and OpenRC. A recovery action is only considered
successful after inspecting actual identities and health; process exit or an accepted restart request is not proof.

| Failure point | Required outcome |
|---|---|
| Download, signature or preparation fails | Leave active components unchanged; report failure and preserve any journal needed to reconcile prepared artifacts. |
| Process dies after preparation or switch intent | Resume from journal plus observed state; do not repeat a completed switch blindly. |
| New daemon fails health, previous daemon can read actual state | Host watchdog restores the previous digest and verifies health within the bounded recovery policy. |
| New daemon fails health, previous daemon cannot read actual state | `BlockedRecovery`; no automatic downgrade or state-backup restoration. |
| New panel fails, old panel and new daemon are compatible and healthy | `Degraded`; retain new daemon and restored panel, with actual pins and visible failure. |
| Panel recovery fails or compatibility cannot be established | `BlockedRecovery`; preserve artifacts and report intervention needed rather than declaring partial success. |
| Restart or reboot interrupts any stage | Independent host recovery resumes; the daemon is not required to be healthy to run it. |

`Degraded` is a stable recorded outcome, not an in-flight transaction forever: once the actual healthy combination
and recovery protections are persisted, transient reservations can be released under the common lock protocol.
`BlockedRecovery` retains required protections until resolved. Neither outcome advances the last fully committed
release-set identity to the failed target.

### 6. Platform-neutral execution: systemd and Alpine/OpenRC

Keep `ServiceSpec` as the common description of the daemon container. Introduce a semantic scheduled-job contract
alongside service installation/status/restart/recovery operations. A job specifies executable + argument vector,
runtime identity, interval, overlap policy and enabled state; it does not contain unit filenames or shell text.
The coordinator requests operations, not quadlet writes, `systemctl`, D-Bus, timers or `/run/user` paths.

- The systemd adapter translates these operations into user services/timers and quadlets, including failure reset.
- The OpenRC adapter owns service scripts, `supervise-daemon`, the Podman socket lifecycle and periodic job
  scheduling. The validated container argument vector lives in the host-only `platform-service.toml`, never in the
  daemon's shared state or in a sourced user file. The v1 contract selects BusyBox crond with
  installer-provisioned runtime-user jobs; validate it on Alpine. The common interface does not assume an OpenRC
  equivalent of systemd user timers. Reporting unsupported capability is preferable to a silent no-op.
- Privileged installation and unprivileged runtime operations are distinct. In particular, OpenRC commonly has
  root-owned service definitions: a runtime user must not gain arbitrary service-editing or root command rights.
  Root is used during installation to provision the fixed services and required boot/scheduling integration.
  Routine pulls, tool-generation selection, daemon switching and rollback run as the Węglarka runtime user,
  without sudo, a setuid updater or a privileged update helper. The fixed service consumes the selected digest;
  the runtime user stops the rootless container and supervision restarts the foreground runner, as specified in
  the v1 contract. A service-definition change remains an explicit administrator installation task.
  Do not grant the daemon container write access to host init configuration or execute runtime-user-writable
  launchers as root. The adapter must prove this privilege boundary in an Alpine integration test.
- Platform adapters resolve socket/runtime paths and service-manager identity. Shared code does not require glibc,
  loginctl, a user D-Bus session or systemd. Host artifacts explicitly support the target ABI.
- Watchdog scheduling must remain independent of daemon health on both platforms. A stopped container must not
  stop recovery. Failed-start recovery and restart completion have the same observable contract on both.

Migrate systemd callers away from `install_user_units`/`set_timer` incrementally; keep rendered unit files private
to that adapter. A fake adapter verifies the common state machine. Real systemd and Alpine/OpenRC integration
tests are separate acceptance requirements; a passing fake does not establish Alpine support.

## Consequences

### Compatibility and migration

Inventory alone does not change the application state schema or recreate apps. New host configuration for channel
selection and panel enrollment is opt-in, mutually exclusive with the legacy `image` key when enabling coordinated
updates, and must document removal before downgrading a strict older parser. The v1 CLI writes these keys only when
both the active and the recorded previous daemon images are v1, so a strict pre-v1 rollback target never receives a
configuration it would reject. Any eventual `apps.toml`/`state.toml` field still requires the normal schema bump; do
not evade this through an undocumented overlay. The v1 contract defines pin persistence, explicit enrollment and the
requirement to unenroll before a legacy downgrade.

An upgrade from the old host binary needs an explicit bootstrap/install step before it can consume release sets.
Existing timers do not magically point at a generation selector. Bootstrap stages the current tools as generation
zero, retires the legacy runner units and `self-update.toml`, and writes a shared capability record. Old writers
also do not honor the new locks: do not enable daemon-image pruning until that record proves the participating host
tools implement the image lock and update protocol. Unknown, absent or legacy capability disables platform-image
deletion, with a diagnostic; lock-file presence is not evidence.

### Ownership and implementation order

1. Contract owner: freeze shared types, lock protocol, descriptor fixtures, recovery matrix, panel pin policy and
   semantic platform operations. Own this ADR and additive model/interface changes. No parallel edits to them.
2. Retention agent (#442): Podman mapping, inventory, engine acquisition/retention and doctor. Consume platform
   protections via the agreed interface; do not redesign the updater or release workflow.
3. Release agent (#312): release-plz/workflows, signed descriptor and artifact publication, the `weglarka-release`
   publisher/verifier and the compatibility re-test job. Own CI release files and the publisher; consume the frozen
   descriptor fixtures. No runtime state changes.
4. Platform adapter work (#46): semantic scheduling and service operations, systemd migration and OpenRC support.
   Own `engine/src/platform.rs` and `daemon/src/platform.rs` after the contract owner's interface change. This work
   precedes coordinator integration in those files; do not assign them to two simultaneous writers.
5. Update agent (#203 and panel integration): journal, host generations, switcher/watchdog and engine panel pin.
   Begin integration after retention interfaces and platform operations land. Engine deploy/push edits follow
   the retention agent's merge. Shared `config.rs`, module exports and `Cargo.lock` have one writer at a time.
6. Independent integration/security review: exercise partial updates, trust boundaries, lock ordering and both
   init systems. Each implementation PR supplies focused tests plus repository-required checks.

### Required acceptance scenarios

- Three moving-tag deploys with null names retain current/previous and remove only the older managed image.
- Shared images, stopped/foreign containers, removed apps, unknown legacy images and missing/corrupt inventory.
- Pull/load versus prune, startup versus switcher state writes, cancellation and crash at every persisted stage.
- Panel-only stable release; unsigned/missing artifact; out-of-order CI completion; unsupported target/format.
- Two consecutive updates across a state-schema bump using the newly selected host tools.
- Daemon failure before health; panel failure after daemon health; incompatible rollback refused explicitly.
- Compatible old panel/new daemon remains pinned as `Degraded`; no timer retry loop for the same failed digest.
- `BlockedRecovery` never restores state backups or releases required recovery images automatically.
- Restart/reboot while prepared; recovery offline; stale reservations; no automatic TTL deletion of rollback data.
- Legacy host switcher detected; no-panel installation; explicit panel enrollment and manual override behavior.
- Candidate exec failure before acknowledgment does not leave the runner lock held; a slow pull cannot resurrect the
  previous digest; respawn exhaustion stays recoverable as the runtime user.
- A rollback target that cannot parse the current host configuration is rejected before activation.
- A crash between pin and `AppState` writes is reconciled forward; a delayed completed-transaction retry returns the
  recorded result instead of redeploying; a second transaction cannot overwrite a running one.
- Hash-tag allocation after a crash between immutable-tag push and pointer move, and a superseded queued promotion.
- Reservation abandonment requires owner death or the explicit operator command; a full reservation file is
  recoverable without deleting live provenance.
- Identical transition tests against fake systemd/OpenRC adapters, then real service/reboot/watchdog tests on both.
- Alpine updates and rollback succeed as the runtime user after privileged installation, with no runtime sudo/helper.

The gates above now have concrete specifications and fixtures in the v1 contract. This ADR remains proposed
pending independent design review and implementation evidence, especially real Alpine supervision and host
recovery tests. A docs-only change runs `scripts/adr.sh lint`; runtime changes also require the repository's
formatting, clippy and workspace tests.

## Rejected alternatives

- Prune all dangling images: loses rollback targets and unowned images.
- Keep only the last N pulled digests: forgets exactly the old images cleanup needs to identify.
- Protect only daemon current/previous: ignores pending switches, fallback and platform panel deployment.
- Reuse the daemon version as the release-set and panel version: cannot represent a panel-only release honestly.
- A separate panel deploy implementation: duplicates the engine's health gates, state and rollback behavior.
- Hold locks while restarting/calling the daemon: can deadlock startup, confirmation or panel deployment.
- Treat service managers as command-name substitutions: ignores OpenRC ownership, scheduling and socket lifecycle.
- Claim atomic cross-component rollback: state-schema migration and external side effects make that promise false.
