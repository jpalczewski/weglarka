# Platform update implementation briefs

Context: [ADR 0067](../../decisions/0067-managed-images-and-platform-updates.md),
[v1 contract and fixtures](../../contracts/platform-update-v1/README.md); issues
[#442](https://github.com/jpalczewski/weglarka/issues/442),
[#203](https://github.com/jpalczewski/weglarka/issues/203),
[#312](https://github.com/jpalczewski/weglarka/issues/312),
[#46](https://github.com/jpalczewski/weglarka/issues/46).

These are implementation briefs, not running delegates. Each implementation uses its own worktree and PR.
The contract is frozen for v1 implementation; any behavioral change to it is a separate contract PR reviewed by
the contract owner before dependent branches rebase. Do not implement a different persistence/lock/signature
protocol inside one branch.

## 0. Shared contracts, parser and bootstrap interfaces

Goal: give later agents compiled shared types, the descriptor parser, fixture tests and the workspace skeleton.
Owner: one contract implementation agent.

Files: new model modules `image_inventory.rs`, `platform_update.rs`, `release_set.rs`,
`platform_transitions.rs`, their exports; additive engine `platform.rs` interfaces; the `weglarka-release` crate
skeleton (workspace registration, `assemble`/`verify` subcommands with unimplemented bodies); Podman trait
additions for `container_archive_get`; API types and endpoint constants for the unix-only panel transition. Own
`Cargo.toml`/`Cargo.lock` changes here first. Use existing model types; no production publisher/updater yet.

Deliver: descriptor parsing/validation per the result vocabulary, inventory/reservation (owner, phase, journal
reference)/journal (per-channel accepted pointer plus transaction)/pin/transition serialization, format/size
bounds, epoch/revision types, guard API, ScheduledJob/activation interfaces, strict lower-case digest
validation, fixtures and fake adapters. Document the capability record's schema (`host-capabilities.toml`) and
that retention must fail closed without it. Do not edit release workflows, actual deploy logic, systemd rendering
or self-update switching.

Acceptance: every `fixtures/cases.json` case passes, including the OCI negatives, uppercase digest, nested
duplicate key, channel mismatch and unexpected image path; unknown formats, duplicate fields at any depth and
invalid digests rejected; serialization roundtrips; `execute` cannot be called without the guard; unsupported
capability fails explicitly; old non-enrolled behavior remains unchanged.

## A. Image provenance and retention (#442)

Depends on 0. Own `podman/src/wire.rs`, the `container_archive_get` client implementation and image-list
fixtures/tests, engine `images.rs`, acquisition hooks in `deploy.rs`/`push.rs`, daemon `images.rs` and `doctor.rs`
image diagnostics, FakePodman image behavior, retention guide and ADR 0020 amendment. Shared model semantics
already belong to 0.

Deliver standalone Digest mapping, durable provenance, reservations with owner/phase/journal reference
(`image-reservations.toml`), global protections, scoped automatic cleanup, identical dry-run/doctor planning and
non-force execution. Archive upload
reserves before `image_load`, advances to `loaded` before `image_tag`, and leaves a recoverable reservation on
cancellation. Build protections from containers, inventory, `self-update.toml` and the platform journal, including
the daemon's previous image independently of reservations. Cover legacy adoption and unknown images; refuse
platform-image deletion when `host-capabilities.toml` is absent, older than v1 or lacks a required feature. Upsert
inventory records by unioning associations.

Do not alter CI publication, platform adapters or host updater state machine. No prune timer.

Acceptance: three nameless moving-tag generations leave current/previous; shared/stopped/foreign protection;
failed deletion retains record; corrupted inventory or missing capability blocks prune; cancellation cannot delete
a pending image; the tag-before-reservation window is gone under an injected disconnect; a full reservation file is
recoverable only through explicit abandonment; known images survive repo change/app removal until explicit eligible
cleanup.

## B. Signed release-set publication (#312)

Depends on 0; can run alongside A and C. Own `.github/workflows/release.yml`, relevant CI/release-plz changes,
Containerfile metadata changes, the `weglarka-release` implementation, registry descriptor transport/signature
extensions and registry tests. Coordinate single `Cargo.lock` ownership with 0; do not hand-edit crate
versions/changelogs.

Deliver separate truthful component image versions on every channel (pass the crate version explicitly; never
`meta.outputs.version`), panel-only and CLI-only release triggers, immutable OCI descriptor publication with
tag-based sequence allocation `max(pointer, highest set tag)+1`, serialized promotion that never overwrites an
immutable tag, non-cancelling queue semantics with a post-promotion reconciliation check, verification using the
runtime verifier, and test-only signed fixtures. Rebuild `compatibility.panel_digests` for each daemon digest and
run a real daemon × (new panel, previous promoted panel) compatibility job; never inherit entries untested. Make a
missing signing key fail the job for both channels rather than warn. Add the `weglarka-releases` package
visibility step to `docs/contributing/releasing.md`.

Do not implement host activation or panel deployment. Acceptance: panel-only release yields a new complete set with
an unchanged daemon artifact and truthful versions; signature/metadata mismatch, label/version mismatch, missing
artifact or image index prevents promotion; a crash between immutable-tag push and pointer move reuses the tag only
with identical bytes and allocates the next sequence otherwise; an older workflow completion cannot move the
channel backward; a superseded pending run is reconciled, not silently dropped; token isolation, size bounds and
repository binding survive artifact support.

## C. Host launcher, bootstrap and two platform adapters (#46, prerequisite for #203)

Depends on 0; can run alongside A and B. Own the new minimal launcher crate, daemon `platform.rs`, `service.rs`,
platform install/preflight integration, systemd/OpenRC renderers and their tests, and the installer side of
`platform bootstrap`/downgrade. Extend existing engine platform interfaces only through the agreed contract; own
Cargo workspace registration after 0 lands.

Deliver host protocol v1 bootstrap, generation selector/read-only preflight (protocol, schemas, journal and
current-config parse for both candidate and recovery generation), fixed roles including `recover` and `preflight`,
generation verify-and-reuse plus GC, semantic job installation, systemd adapters with a handoff-safe unit lifetime,
OpenRC fixed service plus unprivileged stop/respawn activation with epoch/digest labels, service argument-vector
persistence in `platform-service.toml` under the host-only directory, runtime-user cron jobs, `runtime-jobs.toml`
toggles, linger/`XDG_RUNTIME_DIR` provisioning and rootless Podman socket startup. Fake adapter tests alone are insufficient.

Do not implement release publication, application retention or coordinator policy (including when to run
`recover-v1`; C provides the mechanism, D owns the decision). Acceptance: root needed only for Alpine installation;
restart/fallback and scheduled recovery work after reboot as runtime user; no user-owned script executes as root;
launcher survives candidate exec failure and a slow pull cannot resurrect the previous digest; the supervisor never
becomes irrecoverably inactive after crash-loop exhaustion; installation keeps supervisor recovery available when
the container repeatedly fails. Run real systemd and Alpine/OpenRC tests covering crash-loop exhaustion, missing
sockets, disabled updates and reboot.

## D. Coordinator, host recovery and panel enrollment (#203)

Depends on A/B/C merged, or their frozen compiled interfaces for unit work. Own daemon `self_update.rs`,
`supervise.rs`, new coordinator module, host configuration and wiring; the coordinator half of bootstrap
(journal/handoff/capability writes, legacy unit retirement decision); panel-pin engine integration in
`reconcile.rs`/`deploy.rs` after A; API handler wiring after 0. Own diagnostics/config changes after A/C merge.

Deliver resumable host journal with owner identity, deadlines and the `Handoff`/`Ack`/`HandoffFailed` transitions,
recorded old/target state schemas, state-schema-aware recovery, actual-digest health checks, the capability record
writer, enrollment/pins with explicit enroll command and pin-first commit order, synchronous startup reconciliation
before admin bind, unix-only idempotent transitions with durable terminal records in `platform-transitions.toml`,
single-in-flight enforcement, Degraded/BlockedRecovery outcomes, `channel` config key and legacy migration. Keep the existing daemon-only
configuration supported until explicit migration; new launcher bootstrap is required before coordinated updates
and platform pruning. Include install/downgrade instructions.

Do not invent a second panel deploy engine or grant updater root privileges. Acceptance: consecutive updates across
schema bumps; daemon-down recovery offline using journal-recorded schemas; candidate exec failure before ack is
recovered without a stuck lock; a crash after `Committed` before selector update converges on the schema-matching
generation; enrollment is refused while a pre-v1 rollback target remains; compatible old panel retained without
timer retry loop; schema-incompatible rollback stops without
restoring backups; a stale panel deploy after restart waits for reconciliation and cannot move the version
backward; pin survives restart and blocks webhook overrides; a delayed retry of a completed transaction returns the
recorded result instead of redeploying; a second transaction cannot overwrite a running one; incompatible
transitional old-panel/new-daemon pair prevents activation; legacy units/`self-update.toml` are retired without two
runners.

## E. Independent integration/security review

Starts after the relevant changes exist; no implementation file ownership. Review the final diffs and tests,
not only this document. Report severity, file/line, reproduction and required fix. Do not silently redesign.

Focus: manifest/signature binding and channel/sequence identity; host extraction paths and modes; unprivileged
OpenRC boundary and the slow-pull/stop race; launcher recovery when candidate execution fails and the handoff lock
handoff; state-schema and host-config compatibility of the rollback target; lock inversion, re-entrant guard use and
image deletion races; reservation ownership/abandonment; panel pin/state crash windows, terminal-transition
idempotency and startup ordering; channel ordering and superseded runs; capability gating; migration with old host
tools; no-panel installs. Exercise power-loss simulations and both real init systems. Findings return to the owning
agent; integrated fixes are rechecked before merge.

## Common checks and merge order

For every runtime PR:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
bash scripts/adr.sh lint
```

Use the repository worktree-specific target directory and required CI from the contributing guide. B additionally
validates workflows and performs a non-production registry publication/verification round trip; C/D add real
Podman and init-system suites. Each brief's acceptance scenarios need tests beyond formatting/unit coverage.

Merge 0, then A/B/C independently, then D, then integrated review fixes. Never run more simultaneous agents than
available execution slots. `config.rs`, `lib.rs`, API routing, Cargo.lock, shared platform types and the contract
itself have one writer at a time; later branches rebase after the owner merges. A partial implementation references
its issue with Refs, and only a PR satisfying the entire issue uses Closes. No host deployment is part of these
briefs.
