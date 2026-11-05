# Image retention, provenance and one-off cleanup

Previously every deploy left the previous image on disk forever (issue #40), so the disk filled up. Węglarka now records
which images it acquired, keeps the current and the previous one, and provides a one-off cleanup of what earlier deploys
left behind. Decision and rejected alternatives: [ADR 0020](../decisions/0020-image-retention.md) and the platform
update design in [ADR 0067](../decisions/0067-managed-images-and-platform-updates.md).

- **Provenance, not names.** Every pull and archive load records the local image ID, its manifest digests and the
  `(owner, repository)` association in `managed-images.toml` before the reference can be discarded. Recording unions
  associations, so two apps or a repository change never erase another owner's entry. A host that keeps neither tags nor
  repository digests for a superseded image (#442) therefore still has provenance. The file is `0600`, written
  atomically, and capped (8 MiB / 32768 images); invalid contents disable cleanup instead of being replaced.
- **What stays:** after a successful deploy (also after a rollback and for `start = false`) the app's current and previous
  image are kept. An image is also kept while any container (running **or stopped**, including foreign ones), any app's
  `state.toml` current/previous, a tag named by `apps.toml`, a durable image reservation, `self-update.toml`
  (`current`/`previous`/`pending`/`switch_from`/`fallback_to`) or a nonterminal platform journal references it.
  Protections cover every owner, even when the cleanup is scoped to one repository. The daemon's previous image is
  protected independently of reservations. `image remove` is never called with `force`, so Podman refuses an image in
  use as the last line of defence.
- **Scoped and explicit cleanup.** Automatic retention after a deploy only considers the `(owner, repository)` of that
  deploy, so deploying app A never touches app B's repository, and an image of a repository an app no longer names
  survives until an explicit prune. `weglarka images prune` is the explicit global action:
- **One-off, after upgrading** (images left by earlier deploys):

  ```sh
  weglarka images prune --dry-run   # list: ID, tag/digest, size; removes nothing
  weglarka images prune             # removes and reports how much space was freed (upper bound)
  ```

  The cleanup is **explicit**, not automatic at daemon startup: bulk image deletion is the operator's decision. The
  daemon serializes it with deploys (during a deploy it answers `busy`, like the other mutations). A dry run and the
  `doctor` check use the same planner as the real prune, so they report the same list. Neither adopts images nor writes
  any file: `managed-images.toml` and `image-reservations.toml` are byte-identical before and after a dry run.
- **Images with no provenance are reported, never removed — by a dry run or by the planner alone.** Their count
  appears as an informational `doctor` line. An image that matches a current repository name can be adopted, and then
  removed, by any **real** (non-dry-run) retention pass: an explicit `images prune`, or the automatic cleanup after a
  deploy of the same app (within that app's scope). That is the repository policy of ADR 0020; nothing is attributed
  by age, size, labels or digest alone.
- **Durable reservations.** An archive upload or pull publishes an operation in `image-reservations.toml` **before**
  `image_load`/pull, advances it to `loaded` with the image ID and digest before any `image_tag`, and holds the image
  lock through the deploy. A disconnect or cancellation therefore leaves a recoverable reservation, never a tagged but
  unrecorded image. Reservations have no TTL and elapsed time never frees one. What is reclaimed **automatically**, once
  when the daemon starts (the ids are logged), is a reservation written by a **previous boot** (the host restarted, so
  its writer is gone) that no nonterminal platform transaction references. A reservation of the current boot — for
  example after a cancelled upload, with the daemon still running — and any reservation a platform transaction
  references stay until an operator ends them. See what is held, with the operation IDs:

  ```sh
  weglarka images reservations list          # table: operation, phase, owner, age, when it is reclaimed
  weglarka images reservations list --json
  ```

  The `RECLAIM` column says `at next daemon start` (previous boot), `abandon (or host reboot)` (current boot) or `while platform
  transaction runs`. The list still works when `platform-update.toml` cannot be read: every reservation is shown, the
  reference state is unknown (`unknown (journal unreadable)` for previous-boot rows, `"referenced": null` in `--json`),
  and a warning names the file and the error. Startup reclamation, in contrast, fails closed on that file: it reclaims
  nothing and logs a warning until the file is fixed. Free one explicitly with:

  ```sh
  weglarka images reservations abandon <operation-id> --yes
  ```

  Use it only when the owner is known to be gone; it frees capacity (the file holds 1024 operations) without deleting
  provenance or an image. A failed deletion keeps its record — the next successful prune removes it.
- **A full reservation file blocks cleanup, not deploys.** At 1024 operations a pull or upload no longer fails: it
  proceeds **without** a reservation. Because such an image has nothing protecting it, every retention pass is
  `blocked` while the file is full: nothing is removed (automatic retention after a deploy, `images prune` and its dry
  run alike), and `doctor` warns on `runtime.images`. List the reservations and abandon those whose owner is gone;
  cleanup works again as soon as there is room.

  **Limitation.** An unreserved acquisition has no reservation to bridge the gap between the pull and the moment
  its provenance is recorded. Example: a deploy's first pull takes the last free slot, so the rollback image it pulls
  next runs unreserved; if recording that image's provenance fails, it has neither a reservation nor a record. When
  the deploy then releases its own reservation the file is no longer full, the retention pass after the deploy runs
  unblocked, and that unrecorded image can be adopted by repository name and removed — by that automatic pass or by a
  later explicit `images prune`. A container or `state.toml` entry that uses the image protects it until then. This
  is a deliberate exception to ADR 0067's rule that acquisition keeps its protection "until provenance and a durable
  protection have been published", traded for a full reservation file not failing deploys (a durable fix is tracked
  in #535).
- **Platform images need a capability record.** Deleting an image owned by the platform daemon requires
  `host-capabilities.toml` with host protocol 1 and the coordination features image-lock, platform-update-lock,
  service-activation and reservation-phases. A missing file, an older protocol or a missing feature keeps those images
  and prints a diagnostic; a lock file's presence is never used as evidence. `weglarka platform bootstrap` writes the
  record.
- **Corrupt bookkeeping fails closed.** An invalid `managed-images.toml`, `self-update.toml` or `platform-update.toml`
  disables destructive cleanup (`doctor` reports it) instead of being treated as empty.
- **A provenance error blocks the whole pass.** If the daemon cannot read or write the bookkeeping — the inventory, the
  reservations, the journal or `self-update.toml`, or the adoption records a prune persists before it plans — the pass
  removes **nothing** and forgets nothing, instead of pruning the images it could still attribute. `weglarka images
  prune` (also `--dry-run`) then reports the pass as **blocked** (see below); after a deploy the reason is logged as a
  warning and the deploy is unaffected. Fix the file or the disk (`doctor` shows the same condition) and run it again. The inventory is also
  checked writable before the first removal, so a read-only state directory cannot leave images deleted but still
  recorded. The check cannot rule out a disk that fills up during the removals: if the final write that forgets the
  removed images fails, those images are already gone, their records remain in `managed-images.toml`, and the answer
  is blocked while its `removed` list names exactly the images that are gone ("N image(s) had already been removed in
  this pass" among the diagnostics). Those records belong to deleted images; the image ID is a content
  hash, so pulling the same image again makes the old record apply to it again.
- **How a blocked pass is reported.** `POST /v1/images/prune` answers **200** with `"blocked": true`, the reason in
  `diagnostics` and the true `removed` list (empty unless only the final write failed); it is not an HTTP error. The
  field is additive: it is absent from the JSON when `false`, and a client that does not know it ignores it, so an old
  CLI against a new daemon prints the diagnostics but cannot flag the pass. `weglarka images prune` prints `image
  cleanup is BLOCKED: …` and exits non-zero, for a real prune and for a dry run (which could not plan).
- **A pull that is still `loading` disables adoption.** A reservation is published before the pull, when the image ID
  and digest are not known yet, so it cannot name an image to protect. Pulls and prunes are serialized by the image
  lock, so a `loading` reservation a prune can see belongs to a pull that was cancelled or failed early. The only image
  at risk is one that was (partly) pulled and is recorded nowhere: such an image is unattributed, and the only way it
  could ever be removed is adoption by repository name. While any reservation is `loading`, the pass therefore adopts
  nothing, and the rest of retention (images that already have records) runs normally. The diagnostic — in the prune
  output and in `doctor` — names the operation. A `loading` reservation left by a previous boot is reclaimed when the
  daemon starts; one of the current boot is not (a daemon restart alone does not end it: only a changed boot proves
  the writer gone). Find it with `weglarka images reservations list` and, once the owner is known to be gone, run
  `weglarka images reservations abandon <operation-id> --yes`. An acquisition that advances to `loaded` protects its
  image by ID and digest from then on.
- **Warning in `doctor`:** the `runtime.images` check reports `warn` with the number of unused images and their size
  ("at most", since shared layers are counted per image), and the `hint` points to `weglarka images prune`. During a
  deploy the check is informational (`info`).
- No changes to `apps.toml`/`state.toml`, so upgrading and rolling back the daemon are safe.
