# Image retention and one-off cleanup

Previously every deploy left the previous image on disk forever (issue #40), so the disk filled up. Now Węglarka keeps things tidy itself and provides a one-off cleanup of what earlier deploys left behind. Decision and rejected alternatives: [ADR 0020](../decisions/0020-image-retention.md).

- **What stays:** after a successful deploy (also after a rollback and for `start = false`) two images of the app's repository are kept: the current one (`current`) and the previous one (`previous`, the rollback target). Older images of the same repository are removed. An image used by **any** container (including a stopped one), an image pinned in any app's `state.toml`, and an image whose tag still appears in `apps.toml` is never removed; `image remove` is not called with `force`, so Podman refuses to remove an image in use. A deploy does not fail because of cleanup; a retention problem is only logged.
- **What Węglarka does not touch:** images outside the repositories listed in `apps.toml` (the nginx ingress, manual `podman pull`, intermediate layers) and images of a repository that no app lists any more (a removed app or a changed `image`); these cannot be attributed, see [ADR 0020](../decisions/0020-image-retention.md).
- **One-off, after upgrading** (images left by earlier deploys):

  ```sh
  weglarka images prune --dry-run   # list: ID, tag/digest, size; removes nothing
  weglarka images prune             # removes and reports how much space was freed (upper bound)
  ```

  The cleanup is **explicit**, not automatic at daemon startup: bulk image deletion is the operator's decision. The daemon serializes it with deploys (during a deploy it answers `busy`, like the other mutations).
- **Warning in `doctor`:** the `runtime.images` check reports `warn` with the number of unused images and their size ("at most", since shared layers are counted per image), and the `hint` points to `weglarka images prune`. During a deploy the check is informational (`info`): a freshly pulled image is not in `state.toml` yet, so it would look unused.
- No changes to `apps.toml`/`state.toml`, so upgrading and rolling back the daemon are safe.
