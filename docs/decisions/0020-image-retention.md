# 0020 — Image retention: keep the current and previous image, prune the rest (issue #40)

Status: accepted (issue #40).

## Problem

The design says "one previous image per app" — that image is the rollback target when the health gate
rejects a new version. Nothing in the code ever called `image_remove`, so every deploy left the
previous image behind forever and the node's disk filled up. We need

1. retention of the *current* and the *previous* image of every app after a successful deploy,
2. a one-off cleanup for images left by deploys that happened before retention existed,
3. a `doctor` warning so the pile-up is visible before it becomes an outage.

The hard part is attribution: libpod records who pulled an image nowhere. An image is just a store of
blobs with names, and Węglarka pulls by tag (`repo:tag`) or by digest (`repo@sha256:…` for a rollback),
so the store also contains the ingress nginx image, anything an operator pulled by hand and the
intermediate layers of locally built images. Deleting the wrong image breaks a running app; deleting
too little brings the disk back. Security first: **never** remove an image a container uses.

## Decision

**An image is Węglarka-managed iff one of its names (`repo:tag`, `repo@sha256:…`) has a repository that
appears in `apps.toml`** (`image_repo` of a spec's `image`, compared case-insensitively). Untagged
leftovers of an earlier pull keep their `RepoDigests`, and an image whose tag moved away — a new build
under the same tag, or a spec that switched tags — is no longer named by any spec, so both kinds of
leftover are reachable. Everything else (the ingress image, another repository, a dangling layer) is
never touched.

**It is kept when any of these holds**, checked in this order and reported as the reason:

1. `in use` — an image id of any container from `container_list` (which asks libpod for `all=true`, so a
   stopped container protects its image too). Foreign containers and the ingress container count.
2. `current` — the image is an app's `AppState::current` digest (matched by `ImageInfo::digest`, or by a
   `repo@digest` entry when libpod reports no manifest digest).
3. `previous` — the same for `AppState::previous`, the rollback target. Always kept, even with no
   container: a rollback must not depend on the registry.
4. `tag in use` — one of its tags equals the `(repo, tag)` an app spec names right now. This is what
   keeps the image that just failed the health gate while it still holds the pulled tag.

Otherwise it is a candidate and `image_remove(id)` is called — **never with `force`**: libpod refuses
an image a container uses, which is the last line of defence if the planner is ever wrong. `NotFound`
counts as removed (the image vanished between plan and remove); any other error is collected in the
report and the remaining images are still processed.

**Scope.** After a successful deploy, rollback or provision the engine runs retention restricted to the
repository of the app it just deployed: deploying app A never touches app B's repository. The keep set is
always computed from *all* apps, so two apps sharing a repository (different tags, staging/production)
never lose each other's images. `weglarka images prune` (`POST /v1/images/prune`) is the explicit
operator action and covers **every** repository named in `apps.toml` — that is the one-off cleanup for
images left by earlier deploys.

**Automatic retention is best effort and never fails a deploy**: it runs after `state.toml` was saved
(the keep set already contains the new `current`/`previous`), errors are logged with `tracing`, and the
deploy outcome is unaffected. It happens on `Deployed`, `RolledBack` (the failed image is dead weight
unless it still holds the spec's tag) and `Provisioned`; not on `Unchanged`/`KnownBad`/`Failed`, where
nothing changed.

**`doctor` reports, it does not delete.** A new `runtime.images` check warns with the number of unused
images and the space "at most" (libpod's `Size` counts shared layers per image, so the sum is an upper
bound), with `weglarka images prune --dry-run` as the hint. While a deploy is in flight the check is
`info`: the freshly pulled image is not in `state.toml` yet and would look unused — the same reasoning as
ADR 0012 for drift.

**No schema change.** `state.toml`/`apps.toml` keep their shape and `deny_unknown_fields`, so upgrading
and rolling back a daemon stays safe. `spec_hash` is untouched: retention never recreates a container.

## Consequences

- New API surface: `POST /v1/images/prune` with an optional body `PruneImagesRequest { dry_run }` →
  `PruneImagesResponse { dry_run, removed: [PrunedImage], reclaimed_bytes, failed }`. No `GET
  /v1/images` yet: `--dry-run` already answers "what would go away".
- New CLI: `weglarka images prune [--dry-run]`. A non-empty `failed` exits non-zero (`exit::INTERNAL`)
  because those images need attention.
- New contract methods: `PodmanClient::image_list` and two additive `ImageInfo` fields (`repo_digests`,
  `size_bytes`), so `FakePodman` and the libpod client both implement them.
- The prune runs under the engine mutex, so it serialises with deploys and answers `busy` (503) after
  the admin API's 30 s mutation timeout instead of interleaving with a pull.
- Operators must run `weglarka images prune --dry-run` and then `weglarka images prune` once after
  upgrading ([the image retention guide](../guides/image-retention.md)).
- Tests: the pure planner in `core/src/images.rs`, engine tests on `FakePodman` (three deploys keep two
  images; a deploy ignores another app's repository), the admin API + `doctor` in
  `daemon/tests/it/images.rs`, and the libpod mapping in `weglarka-podman`.

## Known limitations (deliberate, follow-ups)

- A repository a spec **stopped** using (the image was changed to another repo) is no longer named in
  `apps.toml`, so neither retention nor `images prune` can attribute its images; same for an app removed
  from `apps.toml`. Fixing this needs provenance recorded somewhere (a separate file, not `state.toml`,
  to keep the rollback-safe schema), so it is left out of this change.
- An image pulled by hand from a repository Węglarka deploys, whose tag no spec names, is
  indistinguishable from a leftover and can be pruned. This is why `images prune` is an explicit
  command and the automatic pass is limited to one repository at a time.
- The reclaimed-space figure is an upper bound (shared layers).

## Rejected alternatives

- **Labelling images at pull time** — libpod has no "pull with labels"; a label would only survive if we
  pulled by digest and tagged ourselves, which changes the pull path for every deploy.
- **Recording the pulled digests in `state.toml`** — breaks `deny_unknown_fields` for a rollback to an
  older daemon, and it still cannot see images left by deploys that predate the field.
- **`podman image prune`/`system prune`** — deletes by age and dangling state, ignores our keep set and
  can remove another app's rollback target or the ingress image.
- **Pruning in every reconcile pass** — a periodic automatic sweep can delete an image between a manual
  `podman pull` and the deploy that would use it, and bulk deletion belongs to an operator's decision.

## Amendment: durable provenance, reservations and scoped cleanup (v1 platform update)

The "Known limitations" above are addressed by the platform update contract
([ADR 0067](0067-managed-images-and-platform-updates.md), [v1 contract](../contracts/platform-update-v1/README.md),
brief A of the [implementation briefs](../contributing/briefs/platform-updates.md)). This amendment supersedes the
repository-only attribution of the original decision; the safety rules (never force, any container protects, current
and previous stay) are unchanged.

- **`managed-images.toml` is the authority for attribution.** Each acquisition (pull or archive load) records the local
  image ID, its manifest digests and the `(owner, repository)` association before the reference is discarded. Recording
  is an upsert that unions digests and associations and never replaces another owner's. An image whose tag moved away
  and whose repository digests are gone (#442) is still known. The Podman list mapping keeps the standalone `Digest`
  next to `RepoDigests`, and `null` name arrays are ordinary input.
- **An image removed from `apps.toml` or moved to another repository survives automatic retention** because its record
  is out of the scoped `(owner, repository)`; the explicit `images prune` (`AllManaged`) collects it once nothing
  protects it. Images with no record are reported separately and never deleted; an explicit prune may still adopt an
  image that a current repository name identifies, which preserves the one-off cleanup policy of the original decision.
- **Protections are global and durable**: containers (any state), `state.toml` current/previous, spec tags,
  `self-update.toml` current/previous/pending/switch_from/fallback_to, a nonterminal platform journal (and every
  artifact of `BlockedRecovery`) and every durable reservation. The daemon's previous image stays protected
  independently of the reservation that acquired it.
- **`image-reservations.toml` closes the tag-before-record window.** An archive load reserves the operation before
  `image_load`, advances it to `loaded` with the ID/digest before `image_tag`, and holds the image lock through commit.
  A cancellation leaves a recoverable reservation; elapsed time never reclaims it. Reclamation requires a changed boot
  with no referencing transaction, or `weglarka images reservations abandon <operation-id> --yes`. The file's limit
  (1024 operations) is therefore recoverable without deleting live provenance.
- **Fail closed.** An invalid inventory disables cleanup and is not replaced with an empty file. Deleting platform-owned
  images requires `host-capabilities.toml` with host protocol 1 and the image-lock, platform-update-lock,
  service-activation and reservation-phase features; absence or an older record only prints a diagnostic. A failed
  deletion keeps its inventory record.
- **One planner.** `execute` still removes by ID without force; `plan` is pure and takes the contract's
  `RetentionInput`. Automatic retention runs with a fresh guard and fresh observations after a deploy releases its
  acquisition guard, and reconcile retains under the guard it already holds rather than reacquiring it. Dry runs and
  `doctor` use the same input builder.
- New API surface: `PruneImagesResponse.diagnostics` and `POST /v1/images/reservations/abandon`; new CLI:
  `weglarka images reservations abandon <operation-id> --yes`. No `apps.toml`/`state.toml` schema change.
