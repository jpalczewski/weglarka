# Platform update contract v1

Implementation contract for [ADR 0067](../../decisions/0067-managed-images-and-platform-updates.md).
This specifies new behavior; it does not claim the runtime implements it. Changes to this contract must land
before dependent implementations. Fixture digests are synthetic, not downloadable release artifacts.

Result vocabulary used by `fixtures/cases.json`:

- `valid_descriptor` — descriptor JSON satisfies every rule in "Descriptor shape"; no signature or blob check.
- `valid_envelope` — OCI manifest structure satisfies "Transport"; referenced blobs are not hashed.
- `valid_blobs` — envelope plus exact layer/config sizes and digests of the referenced fixture files.
- every other value is a named rejection: the first failing rule reported by a conforming parser. Fixtures are
  single-fault by construction so a rejection name does not depend on check ordering. Where a rule needs host
  context (for example the configured channel), the case carries it in `context`.

Rejection names: `UnsupportedFormat`, `MissingField`, `DuplicateField`, `InvalidDigest`, `UnsupportedTarget`,
`ChannelMismatch`, `IncompatibleSelectedPanel`, `UnexpectedImagePath`, `HostImageMismatch`, `UnsupportedArtifactType`,
`ExtraLayer`, `ForeignUrl`, `NotAnImageManifest`, `ConfigMediaTypeMismatch`, `NonEmptyConfig`,
`LayerMediaTypeMismatch`, `SizeMismatch`. A parser may report an earlier structural failure before a later semantic
one only when the fixture violates exactly one rule; it must not invent names outside this list. In v1 the names are
deliberately coarse: `MissingField` also covers a present but invalid or unknown descriptor value, and `SizeMismatch`
also covers content that disagrees with its declared digest. A parser may attach detail text but not a new result
name. Sequence high-water comparison is not a parser rule; it belongs to the coordinator, which has the durable
per-channel pointer.

## Transport and identity

Publish an OCI image manifest with `mediaType = application/vnd.oci.image.manifest.v1+json`,
`artifactType = application/vnd.weglarka.release.v1+json`, an empty JSON config
(`application/vnd.oci.empty.v1+json`, bytes `{}`) and exactly one JSON layer whose media type equals
`artifactType`. Reject an image index, extra layers, `urls` on any descriptor, missing fields and duplicate JSON
keys at every nesting level. See the [OCI manifest specification](https://specs.opencontainers.org/image-spec/manifest/).

Publish in the dedicated `ghcr.io/jpalczewski/weglarka-releases` repository, which must be publicly readable so the
runtime user can pull anonymously. Channel tags are `stable` and `main`. Immutable tag:
`set-<channel>-<sequence>`.

`sequence` is a positive, monotonically increasing integer per channel, not a crate version or timestamp. Allocate
it inside the serialized promotion critical section as `max(current channel pointer sequence, highest existing
set-<channel>-N tag) + 1`; never reuse an `N` for different descriptor bytes and never overwrite an existing
immutable tag. A promotion crash after pushing `set-<channel>-N` but before moving the channel pointer leaves a
reusable orphan: the next run allocates `N+1` from the tag listing, not `N` from the pointer.

Release-set identity is the resolved **OCI manifest digest**. Journal, pins and API fields named
`release_set_digest` always mean that digest, never the descriptor layer digest. The descriptor `revision` is the
source commit that assembled the set; it is not required to equal the build revision of a reused daemon image.

Resolve a channel once, retain its manifest digest, verify the exact manifest bytes against that digest, verify its
key-based cosign simple-signing signature, then fetch and verify the descriptor layer by size and SHA-256. Use the
existing legacy `sha256-<hex>.sig` signature layout and repository identity check; do not silently switch to
OCI-referrer-only signatures. Both channels require the static-key signature; a missing key is a release failure, not
a warning. Publisher acceptance includes verification using the runtime verifier.

The signature binds the manifest to the descriptor, but it does not bind the descriptor's own `channel` to the
channel that was resolved. The host therefore rejects `descriptor.channel != configured channel`, and rejects a
`sequence` lower than the durable per-channel high-water mark. The immutable tag is publisher-side bookkeeping and
is not re-checked by the host; `(channel, sequence)` inside the signed descriptor is authoritative.

Limit the OCI manifest to 1 MiB and descriptor to 64 KiB; enforce advertised and streamed sizes. No decompression.
Existing registry HTTPS, redirect and bearer-token isolation rules apply. Verify component image signatures
separately using their exact repository and digest. Downloading descriptor bytes is not authorization to execute.

Component image versions must agree with verified image metadata. Name the labels explicitly:
`org.opencontainers.image.version` equals the component crate version on every channel (the workflow passes the
crate version to the build; a moving-tag or `meta.outputs.version` value is not acceptable), and
`org.opencontainers.image.revision` is informational and is not compared with the set `revision`. A version-label
mismatch rejects the set. A panel-only or CLI-only set reuses the unchanged component image and its immutable tag
without relabeling.

## Descriptor shape

`fixtures/release-valid.json` defines the complete v1 field shape:

- `format_version`: exactly 1; `channel`: stable/main; `sequence`: positive u64; `revision`: full 40-character
  lower-case source commit ID.
- `target`: exact `linux`, `amd64`, `musl` in v1. Unsupported targets fail before activation.
- `daemon` and `panel`: tag-free repository, SHA-256 manifest digest and real semver crate version.
- `host_tools`: source image repository/digest and exactly two file records with `name`, in-image `path`, `version`,
  `size` and SHA-256.
- `compatibility`: host protocol version, state schemas readable by the target daemon, the schema it writes, and
  the exact panel digests tested with that daemon. The selected panel must be listed.

`host_tools.files[].path` is the path **inside the source image**, not a host destination. It must equal one of
exactly two constants: `/usr/local/bin/weglarka-daemon` or `/usr/local/bin/weglarka`, and `name` must be exactly
`weglarka-daemon` or `weglarka`. The host install location is always
`<installation-configured host-only generation directory>/<name>`; no executable host path is supplied by the
descriptor. In v1 the source image is exactly the selected daemon image, which already contains both binaries.
Extract only these regular files with `GET /containers/{id}/archive?path=<constant>` from a created but never
started container; never execute its entrypoint. Reject symlinks, hardlinks, special files, unexpected paths and
files over 64 MiB; never unpack arbitrary tar paths. Accept mode `0755` only, with setuid, setgid and sticky bits
cleared; any other mode rejects the set.

`host_tools.digest` must equal `daemon.digest`. Component digests must match the verified image metadata; file hashes
must match after extraction.

`compatibility.panel_digests` is rebuilt for each daemon digest; entries are never inherited from a previous set
without a passing run. It must contain the new panel digest and, when one exists, the immediately previous promoted
panel digest, each tested against the selected daemon; additional older entries are allowed only after the same
test. The list is what makes a `Degraded` old-panel/new-daemon outcome permissible and what the transition gate
checks; a daemon change applied to an enrolled host requires the currently pinned panel's exact digest in this list.

V1 descriptor objects reject unknown fields and duplicate keys at every nesting level. Require exactly two host-file
records, unique names, nonzero sizes, lower-case SHA-256 hex digests, a 40-character lower-case hex revision, unique
schema numbers and panel digests. `state_write` must appear in `state_read`; the host protocol is exactly 1. Limit
readable schemas to 64 and tested panel digests to 32. Repository values contain no tag/digest, credentials, query
or fragment. Component versions are valid semver; tags are not a version substitute. Digest strings must be
byte-identical to their lower-case form; `Digest::new` alone is not sufficient validation.

## Publication ordering

Trigger assembly on daemon, panel or CLI releases; deduplicate tags from one release commit, wait for all artifacts
required by that commit, and never promote an older source revision over a descendant already promoted. CLI-only
changes rebuild the daemon artifact because it carries the host CLI; give that build an immutable revision identity
and truthful component versions, without overwriting a prior version tag.

Serialize promotion per channel with a concurrency group that does not cancel a queued successor
(`cancel-in-progress: false`). Ancestry and sequence checks must both pass. A superseded pending run must not be
silently dropped: after promotion, compare the promoted sequence with the newest complete release tag; if a newer
set exists, enqueue a reconciliation run (or fail with an actionable diagnostic) instead of leaving the channel
behind.

The publisher and the runtime verifier are one implementation: the `weglarka-release` workspace binary assembles,
signs and verifies sets using the same model parser and registry client the host uses. CI must parse and
re-serialize the published bytes with that parser and must not build the JSON with an ad-hoc shell/JQ pipeline.
Publish the channel pointer only after every referenced artifact and signature is available and the tested
combination passes. `main` and stable never silently substitute for each other.

## Persistent files and authority

All mutable files below use atomic write + file fsync + directory fsync and mode 0600. Each has
`format_version = 1`. Unknown format versions stop the affected mutation. Unknown fields may be ignored only when
they cannot change v1 semantics; required fields and invalid combinations fail.

`state_dir` is the runtime user's shared directory mounted into the daemon. The **host-only directory** is
outside every daemon bind mount, configured at installation time, and holds only host launcher state.

| File | Location | Writer/authority | Meaning |
|---|---|---|---|
| `managed-images.toml` | shared | Acquisition/retention under image lock | ID, digest set, owner/repository associations |
| `image-reservations.toml` | shared | Acquisition/coordinator under image lock | Operation ID -> owner, phase, protected identities, journal reference |
| `platform-update.toml` | shared | Host coordinator under the short transaction-state lock (runner exclusion is separate) | Per-channel accepted pointer (never cleared) and the transaction journal |
| `platform-transitions.toml` | shared | Engine under engine + image locks | Panel transition records, nonterminal and bounded terminal history |
| `platform-pins.toml` | shared | Engine under engine + image locks | Enrolled panel's effective/pending/previous digest, revision, active/archived state |
| `host-capabilities.toml` | shared | Installed host tools | Host protocol, supported coordination features, active generation |
| `host-tools.toml` | host-only | Host launcher/coordinator under host-selection lock | Active, previous and candidate generation; selector epoch |
| `platform-service.toml` | host-only | Host adapter under service-selection lock | Desired daemon digest, activation epoch and the immutable rendered argument vector |
| `runtime-jobs.toml` | shared | Daemon API/admin command; read by cron jobs | Runtime enable flags for update/watchdog jobs |

Separate files are not an atomic transaction. Each multi-file transition first persists protection/intent, then
changes authority, then removes obsolete intent. On restart, union the protections in every nonterminal journal and
reservation record. Never release an old reservation before replacement authoritative state is durable. Missing
optional files on a legacy install mean feature disabled; missing files on an enrolled/in-flight install are an
error, not permission to resume tag reconciliation or delete images.

`platform-update.toml` keeps two independent parts: `accepted[channel] = {sequence, release_set_digest, revision}`
and the current transaction. Terminal cleanup removes only the transaction; the accepted pointer survives journal
cleanup and is the rollback high-water mark. A per-channel pointer means an explicit channel change starts from the
new channel's own mark and is not mistaken for a downgrade.

A reservation records its owner (`component`, `pid`, `boot_id`, `started_at`), a phase (`loading`, `loaded`,
`deploying`, `coordinating`), its protected identities, an optional `journal_ref` and `created_at`. It has no TTL.
A reservation is abandoned only when its `boot_id` differs from the current boot **and** no nonterminal journal or
transaction references it, or through the explicit operator command
`weglarka images reservations abandon <operation-id>` after confirmation. Elapsed time alone never authorizes
reclamation. The limit must therefore be recoverable without deleting live provenance.

`platform-transitions.toml` retains every nonterminal transition and the last 32 terminal ones. A terminal record
carries transaction ID, status, requested and actual digest, pin revision, reason and timestamps. It is the source
for idempotent retry and `GET` after restart.

`platform-pins.toml` entries carry instance, repository, `enrolled_at`, `active`, effective digest, previous digest,
optional pending digest, transaction ID, release-set digest and monotonically increasing revision. Unenrollment sets
`active = false` and `archived_at`, and keeps the entry; it does not delete history.

`host-capabilities.toml` is written by the installed host tools during bootstrap and after each successful
generation switch. It records host protocol 1, the coordination features actually implemented (image lock honoured,
platform update lock, service activation, reservation phases), the active generation digest and writer boot ID.
Retention reads it and must treat absence, an older protocol or a missing required feature as "platform image
deletion disabled", with a diagnostic. Lock-file presence is not a capability signal.

Host tool generations live outside every daemon bind mount, under the installation-configured host-only directory.
Their `host-tools.toml` selector, candidate handoff/acknowledgment fields and lock also stay host-only. Image
inventory/reservations, the platform journal, transitions, pins and capabilities live under shared `state_dir`. The
host publishes image protections into the shared reservation file before activation; retention does not need to read
the private host-tool selector. The daemon reads `platform-update.toml` to validate a prepared panel transition but
never writes it. Generations are keyed by verified image digest; directory names are validated hex, never arbitrary
paths. An existing verified generation directory is reused after checking its file manifest, so replay is
idempotent. The updater, under the host-selection lock, deletes a generation directory only when no active, previous,
candidate or unfinished-journal reference names it; it never deletes the running generation or the last-known-good
recovery generation.

Initial persistence limits: inventory 8 MiB/32768 images, reservations 1 MiB/1024 operations, platform journal
1 MiB, transitions 1 MiB, pins 1 MiB, capabilities 64 KiB, host selector 64 KiB, service selection 256 KiB and
runtime jobs 64 KiB. Bound sets to observed/declared associations and reject duplicate IDs rather than
last-write-wins. At a limit, report bookkeeping unavailable and disable cleanup; never evict live provenance or an
active reservation to make room. The explicit abandonment command is the only way to free reservation capacity.
Resource limits are operational bounds, not retention policy.

## Runtime interfaces and locks

Place the following types and serialization in model modules `image_inventory`, `platform_update`,
`release_set` and `platform_transitions`. Use existing `Digest`, `InstanceName`, image-reference validation and
filesystem helpers. No new dependency on engine from model or registry. Signatures below specify
responsibilities, not boxed/dynamic-trait requirements.

```text
ManagedImage { image_id, digests: Set<Digest>, associations: Set<(Owner, Repository)> }
Owner = App(InstanceName) | PlatformDaemon
Protection { identity: ImageId | Digest, reason, operation_id? }
RetentionScope = AllManaged | OwnerRepository(Owner, Repository)
RetentionInput { images, containers, inventory, protections, scope }
plan(&RetentionInput) -> Plan
execute(&PodmanClient, &ImageGuard, Plan) -> PruneReport
InventoryStore::load(&ImageGuard) -> Result<Inventory>
InventoryStore::record(&ImageGuard, ManagedImage) -> Result<()>
ReservationStore::reserve(&ImageGuard, OperationId, &Reservation) -> Result<()>
ReservationStore::advance(&ImageGuard, OperationId, Phase, protections) -> Result<()>
ReservationStore::finish(&ImageGuard, OperationId) -> Result<()>
Platform::install_jobs(&[ScheduledJob]) -> Result<()>
Platform::set_job_enabled(JobId, bool) -> Result<()>
Platform::activate_service(ServiceSpec, ActivationEpoch) -> Result<ActivationReceipt>
Platform::observe_service(ServiceName) -> Result<ObservedService>
PodmanClient::container_archive_get(container_id, path) -> Result<TarEntryStream>
```

`execute` takes the guard so the plan cannot outlive the lock state it was computed under. `record` is an upsert
that unions digests and associations for one image ID under the image lock and rejects conflicting identities; it
never replaces another owner's association.

An activation receipt acknowledges a request, not readiness. Observation includes actual container ID, image ID,
digest, activation epoch and readiness when available. Existing install/remove/status operations remain. Scheduled
jobs have typed IDs (`Update`, `Watchdog`), argument vectors, runtime identity, cadence and `SkipIfRunning`;
arbitrary remote shell commands are not part of this API. `set_job_enabled` writes `runtime-jobs.toml`; cron entries
themselves are installer-owned and never rewritten at runtime. OpenRC installation changes require administrator
context; runtime enable/disable toggles the flag read by an already installed periodic job.

Lock order: engine mutex (if needed), then `images.lock`, then at most one short file lock. Never acquire engine
mutex while holding `images.lock`. Runner exclusion `platform-update.lock` is host-only, never needed by daemon
startup or the engine. Keep inventory, pins, transitions, reservations and prune coherent under `images.lock`; no
nested independently acquired file locks are needed for these. Journal/selector read-modify-write operations take
their respective short locks one at a time. Host selection and service selection have separate locks and no path
acquires both image and host locks.

HTTP and wait rule: registry pulls, archive loads, panel preflight and the deploying app's own health gate may run
under the image guard; daemon restarts, daemon `/v1/health` waits and daemon API calls must not hold image or short
state locks. The panel health gate must not require the daemon admin API while the engine mutex is held; a test
asserts this, and a health check that does is a configuration error detected at deploy preflight.

In v1, acquisitions serialize against prune from before pull/load/tag through publication of a durable reservation.
App operations already under the engine mutex can keep the image guard through state commit, passing the held guard
explicitly to helpers rather than reacquiring it. Archive upload reserves the operation before `image_load`
(phase `loading`), advances it to `loaded` with the loaded ID/digest immediately after load and before any
`image_tag`, then keeps the guard through deploy or releases it with the reservation intact. A disconnect or
cancellation therefore leaves a recoverable reservation, never a tagged but unrecorded image. Cancellation cleanup
first proves no active upload/deploy owns the operation; elapsed time alone is insufficient. Automatic retention
runs after commit with a fresh guard and fresh observations, after the deploy has dropped its acquisition guard;
the deploy must not reacquire `images.lock` re-entrantly.

App deploy provenance-write failure disables cleanup for that operation and reports an error/warning without
stopping a healthy app. Failure to persist required protection prevents releasing the guard into another
destructive path: abort before activation and retain existing authoritative state. Inventory corruption blocks
prune. Failed reservation cleanup may leak space temporarily but cannot authorize deletion.

Protections are built from observed containers, inventory, `self-update.toml`
(`current`/`previous`/`pending`/`switch_from`/`fallback_to`) and the platform journal. The daemon's previous image
is protected independently of reservations until a newer previous replaces it; releasing the acquisition
reservation at commit does not unprotect it. `BlockedRecovery` keeps every recovery artifact protected until
explicit resolution.

## Host launcher and generation handoff

Install a small static musl launcher with host protocol v1, independent of `apps.toml` and its schema. On Alpine
it is root-owned and never executes as root: OpenRC drops to the configured runtime user first. The launcher
accepts only installation-configured roots and fixed roles and fixed argument forms: `update`, `supervise`, `cli`,
`daemon-service`, `recover`, `preflight`. It validates generation IDs, paths and selectors, refuses unsupported
protocol versions and executes argument vectors directly. It is not an automatically overwritten bootstrap
executable. Future launcher protocol upgrades are explicit administrator installations; ordinary tool generations
can update without root.

The launcher keeps a parent process for update/supervise workers and observes exec errors/timeouts; it is not only
a symlink. `host-tools.toml` selects the normal generation and records a candidate and last-known-good recovery
generation. Candidate binaries must implement a bounded, read-only `host-preflight` command that reports host
protocol, compiled state-schema support, readiness to read the v1 journal, and whether the binary parses the
**current** `weglarka.toml` (including `[self_update]`). Run it for the candidate before selecting it and for the
recorded recovery generation before activation; a generation that cannot parse the current host configuration is
not an eligible rollback target.

Bootstrap and migration are part of the contract:

- `platform bootstrap` (root on Alpine; installer context on systemd) installs the stable launcher to the
  installation-configured host-only location, stages the current verified v1 tools as generation 0, writes
  `host-tools.toml` with the initial epoch, creates the host-only directory, and writes
  `host-capabilities.toml`.
- Ownership after bootstrap: root owns the code (the launcher and everything under `generations/`), the runtime
  user owns only the flat state files directly in the host-only directory, and that directory is
  `root:<runtime group>` mode `1770` so the sticky bit stops the runtime user from replacing root-owned entries.
  Ownership is changed with `lchown`; symlinks are never followed or descended into. Staging a new generation is
  therefore a root-side step, not something the runtime-user launcher can do in place.
- It disables or removes the legacy `weglarka-self-update`/watchdog units, imports `self-update.toml`
  (`current`/`previous`/`pending`) into protections, retires the legacy file, and repoints the timer at the
  launcher `update` role. Refuse to enable coordinated updates while any legacy runner unit or `self-update.lock`
  participant remains.
- Coordinated updates are enabled only when `platform-update.toml` has a channel pointer, bootstrap is marked
  complete and both the active and recovery generations pass preflight against the current configuration.
- The reverse command unenrolls, removes the launcher units and restores the legacy daemon-only units; it refuses
  while a transaction is nonterminal.

Stages, with the transaction owner (`pid`, `boot_id`) persisted: `Preparing`, `Prepared`, `Handoff`, `Ack`,
`SwitchingDaemon`, `DaemonHealthy`, `PanelTransition`, `CommitPersisted`, and terminal `Committed`, `Degraded`,
`BlockedRecovery`, `RolledBack`, `HandoffFailed`. At `Prepared` the journal records old/target daemon and tool
identities, old/target `state_read`/`state_write`, host protocols, verified release-set digest and reservations, so
offline recovery needs no descriptor or registry.

1. Verify the release set/images, extract files to a temporary directory, check sizes/hashes/modes and run
   preflight (candidate and recovery generation).
2. Atomically rename the complete generation directory into place and fsync its parent, or reuse an identical
   verified directory. Record `Prepared`; persist image reservations. All active components are still old.
3. Persist `CandidateSelected` inside the `Handoff` record with the owner identity and a bounded `handoff_deadline`,
   then release `platform-update.lock` and start the candidate through the launcher. The candidate must acquire the
   lock and persist `Ack` with the transaction ID and selector epoch before the deadline.
4. If the deadline passes without `Ack`, or the launcher reports an exec error, any worker that acquires the lock
   records `HandoffFailed` and runs `recover-v1`; a missing candidate never owns the failure path. If the candidate
   acknowledges and then dies before `SwitchingDaemon`, the same stale-owner rule applies.
5. The candidate persists `SwitchingDaemon`, invokes the platform adapter outside image/state locks but holding the
   runner lock, and checks actual digest and readiness. The adapter call is bounded; a timeout is a failure, not an
   indefinite hold. Persist `DaemonHealthy` only when digest and readiness both match; a healthy old daemon is not
   success.
6. The candidate requests the panel transition, observes the result and records Committed/Degraded/BlockedRecovery.
7. Persist `CommitPersisted`, then select the generation whose compiled schema support matches the actually running
   daemon, for **every** outcome (Committed, Degraded, BlockedRecovery, RolledBack). Record the selection in the
   journal. Retain the previous generation; release only obsolete reservations. On safe daemon rollback, choose
   tools from the recorded schema sets, never blindly from the restored image.

If candidate execution fails after activation, the stable launcher starts the previous recovery generation in
`recover-v1` mode. This mode reads the bounded v1 journal and the raw state-schema header without deserializing
newer app state. It may restore a recorded local image only when the journal's recorded `state_read` for that
generation includes the actual schema and no unrecognized journal transition is present; a disagreement with the
generation's preflight output is `BlockedRecovery`. Otherwise it records `BlockedRecovery`. The bootstrap
installation must supply this recovery mode before enabling coordinated updates. A damaged selector/journal
produces a visible error, never heuristic selection of the newest directory. A crash between writes is resolved
using transaction IDs/epochs and observed state; bootstrap/root-owned launchers contain no general deploy logic.

Full state restore is never automatic. Host logs remain available when daemon/API notification delivery is not.
Every recovery has a bounded attempt count persisted **by the launcher before each recovery exec**, so a failing
recovery binary cannot be restarted forever and a process restart cannot reset the budget. Exhaustion records
`BlockedRecovery` and leaves the supervisor available for a new selection.

For systemd, activation persists the selected digest/epoch, renders the quadlet from the immutable service spec,
atomically installs it, reloads the user manager and requests restart. The handing-off worker unit must not be
killed by a default start timeout: use `TimeoutStartSec=infinity` or a transient unit for the handoff, and keep a
separate bounded worker timeout. If any step fails, the journal retains the intended activation and the next worker
observes the actual container before retrying. On reboot the installed quadlet may still represent the old selection
if the process died before installation; recovery reconciles that discrepancy and does not misreport the old
healthy container as the new one. The same actual-digest health rule applies to both adapters. Neither adapter needs
the daemon API in order to restore a daemon image.

The installer enables linger for the runtime user (`loginctl enable-linger`) and, on Alpine where logind does not
exist, creates `/run/user/<uid>` with runtime-user ownership and mode 0700 at boot before the rootless Podman
service starts. Preflight checks `XDG_RUNTIME_DIR`, its ownership and the Podman socket. The rootless Podman API
service also uses `command_user`; a rootful `podman system service` is not an acceptable substitute.

## OpenRC without privileged runtime operations

The installer provisions three independent root-owned OpenRC services: rootless Podman API, daemon container
supervision, and the cron facility used by fixed user jobs. The daemon service uses `supervise-daemon` and
`command_user`; its fixed command runs the stable launcher in foreground `daemon-service` mode. The launcher reads
the selected digest/epoch and the immutable rendered argument vector as the runtime user and starts the rootless
container directly. `platform-service.toml` stores that validated argument vector plus its hash, written under the
service-selection lock; it lives in the host-only directory and is never mounted into the daemon. State files are
never sourced as shell scripts. Root-owned service scripts never evaluate user-owned configuration to construct
privileged commands. The daemon container cannot write host tool generations or the service selection.

Activation atomically writes the desired service selection (digest, epoch, argument vector), then stops the
existing daemon container via the runtime user's Podman socket. The foreground container runner exits; OpenRC
supervision restarts it and it reads the new selection. Activation epoch and target digest are applied as container
labels and in the launcher argv. Before stopping, the updater re-reads the selection under the service-selection
lock and observes the container; it stops by container ID only when the observed epoch equals the request epoch. An
obsolete request cannot stop a container confirmed at a newer epoch. "Already down" means no container is observed
**and** the selection still equals the request; otherwise the launcher's re-read after `podman create` uses
`--replace` or waits for the old container to exit, so a slow start cannot resurrect the previous digest.

`supervise-daemon` runs with `respawn_max=0` (unlimited) and a bounded `respawn_delay`/`respawn_period`. The
launcher, not the supervisor, owns the bounded start-attempt budget for one epoch and records `BlockedRecovery`
when it is exhausted, leaving the service active so a new selection can start. The runtime user never needs
`rc-service start`; the watchdog writes a new selection and the still-supervised launcher picks it up. Exhaustion
must not leave a permanently inactive service that only root can revive.

Use Alpine's BusyBox crond with installer-provisioned entries in the runtime user's crontab, invoking only the
fixed launcher roles once per minute. The updater enforces the configured longer interval; watchdog checks every
tick. Preserve unrelated crontab entries, mark the managed block, and remove only that block on uninstall. Jobs run
with the runtime UID; no root cron command reads a user-writable script. The installer enables crond at boot and
preflight verifies the selected scheduler. Runtime disabled flags live in `runtime-jobs.toml` and are read by the
jobs, so toggling updates does not require rewriting cron or root-owned init scripts. systemd uses user timers for
the same roles.

This design uses documented [OpenRC supervision](https://github.com/OpenRC/openrc/blob/master/supervise-daemon-guide.md)
and [Alpine cron](https://wiki.alpinelinux.org/wiki/Cron) as primitives. The specific Węglarka stop/respawn
handshake is a proposed integration and must pass real Alpine reboot, missing-socket, slow-pull and crash-loop
tests before shipping.

## Panel pin and engine protocol

Configuration: `[self_update] panel_instance = "panel"`; no implicit enrollment. Binding must exist, be a normal
started app (not a promote-only site), and its configured repository must equal the selected panel repository.
Enrollment is an explicit one-time command, `weglarka platform enroll panel`, which adopts the instance's currently
observed digest and writes `enrolled_at`; there is no implicit adoption on daemon startup. Until that command runs,
the instance is not enrolled: version-changing reconcile is blocked and diagnostics report enrollment as pending.
After a successful enrollment, a missing/corrupt pin is an error ("enrollment record missing") that prevents a
version-changing reconcile until recovery and never re-adopts a running digest. Changes to enrollment require a
daemon config reload/restart under the existing config lifecycle.

The `panel_instance` and `channel` keys are written only by the v1 CLI, and the CLI refuses to write them unless
both the active daemon image and the recorded previous (rollback) daemon image are v1 (host protocol 1). This is
what keeps a strict pre-v1 parser from being handed a configuration it rejects: enrollment is never configured while
a pre-v1 image remains the rollback target. Preflight verifies the same condition and blocks coordinated updates
when an enrolled configuration names a non-v1 recovery image. Editing the file by hand with a pre-v1 rollback
target is unsupported.

`[self_update] channel = "stable" | "main"` is the second opt-in key. It is mutually exclusive with
`[self_update] image`; both present is a config error. Absence of `channel` (legacy or daemon-only install) disables
coordinated updates and leaves the existing `image` tag behavior untouched. Presence of `channel` plus a completed
bootstrap is the enabling predicate; it does not by itself enroll a panel.

`platform-pins.toml` entry: instance, repository, `enrolled_at`, `active`, effective digest, previous digest,
optional pending digest, transaction ID, release-set digest and monotonically increasing revision. Only the engine
writes it. Its effective digest feeds every image-resolution path (reconcile, explicit deploy/restart, provision,
recreate and recovery) before tag pulls. Resolution functions take the effective digest explicitly; when enrolled,
`recreate_locked` and `ensure_image` must not re-derive a digest from `AppState`. App configuration remains
unchanged; the resolved digest enters the existing hash normally. Do not add a separate hash salt when enrollment
is absent. Show desired spec and effective pin distinctly in admin diagnostics. Ordinary webhooks cannot change the
digest; image edits/push/promote/manual rollback are rejected for enrolled instances, while redeploying the
effective digest is allowed.

`AppState` remains the record of what is actually running; the pin is the authority for what should run. Commit
order for a transition is: durable pending intent → deploy → durable pin effective/revision → `AppState` → complete
intent. If the process dies between the pin write and the `AppState` write, the pin wins: startup verifies the
container's actual digest and reconciles `AppState` forward, never backward. A missing or stale `AppState` entry for
an enrolled instance is recovered from the pin and the observed container, not treated as `UnknownInstance`.

Add full-trust unix-socket-only operations (not routed through token listeners or panel relay):

```text
POST /v1/platform/panel-transition
{ transaction_id, expected_pin_revision, release_set_digest, target_digest, retry_failed_release? }
GET /v1/platform/panel-transition/{transaction_id}
```

The engine loads the prepared journal/reservation and checks the request matches the enrolled instance, the verified
prepared target and the binding (kind, `start`, repository, active enrollment); the request accepts no arbitrary
image refs or host paths. POST validates under the engine mutex and durably records pending intent/reservations.

Idempotency and concurrency:

- Resolve an existing `transaction_id` from `platform-transitions.toml` **before** revision validation. Same
  ID/payload returns the recorded terminal result (or 202 while nonterminal) and never re-executes. A conflicting
  payload for the same ID returns 409.
- Reject a different transaction ID while any transition is nonterminal with 409 and the current transaction ID.
  A single engine-owned deployment runs; HTTP disconnect does not cancel it.
- Stale `expected_pin_revision` returns 409 only when the ID is not already terminal.
- GET reports Pending/Running/Succeeded/RolledBack/Failed with actual digest and pin revision, from the same durable
  record, including after restart.

Outcome mapping: `Deployed`/`Unchanged` → Succeeded; `KnownBad` → Failed with no pin change unless
`retry_failed_release` is true; `Provisioned`, `start=false`, a static site or a removed instance → reject the
transition before deploy. Startup runs pin/journal reconciliation synchronously in `start()`, after the engine is
constructed and **before** binding the admin socket or the first reconcile pass, and gates mutations until
`startup_reconciled` is set.

Persist old/current protections before starting the gate. On success write the pin, update `AppState`, then
complete intent; on failure restore the old effective pin only after engine rollback and record the actual digest.
A crash between the pin and `AppState` writes is recovered through pending intent and the observed container, never
resolved by pulling the configured tag. A failed old/new panel compatibility preflight blocks the platform switch unless the
operator accepts a separately designed migration; v1 requires the old panel digest to be listed as tested for the
new daemon before changing a daemon with an enrolled panel. This also covers the interval between daemon health and
panel deployment. For daemon-only installs this pair requirement is absent.

On explicit unenrollment, set the pin inactive (keep the entry) and resume the app's configured image on the next
deploy; diagnose the impending version-selection change. Downgrade to pre-v1 binaries requires unenrollment and
completion or explicit abandonment of every transaction first. Old binaries ignore the pin file, so they cannot
safely participate while enrollment remains active. Do not present the separate file as unrestricted downgrade
safety.

## Verification and delivery

`fixtures/cases.json` lists positive and negative descriptor and OCI expectations using the vocabulary above. These
are wire-contract examples, not cryptographic test vectors. Add signed vectors using a test-only key, including a
correct descriptor under the wrong repository/digest, byte tampering, missing artifact, image-index channel and
label/version mismatch cases. The state-machine tests must inject a crash before and after every durable write and
external action in the bootstrap, handoff and panel protocols, including the gap between pin and `AppState`, the
pre-ack candidate failure, the slow-pull/stop race and reservation abandonment. Both platform adapters run the same
transition suite plus real init-system tests. See
[implementation briefs](../../contributing/briefs/platform-updates.md) for ownership and merge order.
