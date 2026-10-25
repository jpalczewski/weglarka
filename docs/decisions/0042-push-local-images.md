# 0042 — Deploying a locally built image (`weglarka push`)

Status: accepted (2026-10-25, issue #109)

## Problem

An image built on the operator's machine has to reach a Węglarka host without a CI round trip. Before this
decision the only way to deploy was the webhook path: `deploy_locked` always resolved the digest by pulling
the tag in `spec.image`, and `weglarka deploy --image` was rejected by the daemon (`image_ref override is not
supported yet`). Failure modes that matter: a pushed digest that a later reconcile silently replaces, an image
from a foreign repository that cannot be pulled again after a rollback, an upload that holds the engine lock or
buffers the whole archive in RAM, and a failed load that leaves the app half-changed.

## Decision

**`weglarka push` is an ordinary deploy whose digest comes from somewhere other than the spec's tag.** The
deploy itself (health gate, `current`/`previous`/`failed`, rollback, retention) is unchanged: `deploy_locked`
and `provision_locked` take a `DigestSource` — `Tag` (webhook, `apps deploy`, reconcile; the only source so
far), `Reference` (another reference, pulled now) or `Local` (a digest already in the image store).

- **Two sources.** `push <app> --image REF` is `POST /v1/apps/{name}/deploy` with `image_ref` (the field
  existed in the contract and was refused; it is now honoured). `push <app> ARCHIVE|-` is
  `PUT /v1/apps/{name}/image` with a streamed `application/x-tar` body; the answer is a `DeployResponse`.
  The CLI does not shell out to `podman`/`docker`: the operator pipes `podman save` in.
- **`apps.toml` is not touched.** Push changes the pin in `state.toml` only, so `spec.image` keeps its tag
  and the next webhook or `apps deploy` for that tag replaces a pushed image. That is deliberate and
  documented; the durable answer is `weglarka hold` (#107).
- **A reference must be in the repository of `spec.image`** (`normalize_image` compares repository, ignoring
  tag and digest). The pin is `image_repo(spec.image)@digest` and registry credentials are per instance, so
  another repository could not be pulled again after a rollback. Anything else is a 400, before a pull.
- **Pin the digest *after* the load, tag it into the app's repository.** Measured on Podman 6.1 (CI job
  `integration-podman`, `weglarka-podman/tests/image_load.rs`, for `oci-archive` and `docker-archive`, with
  and without a name in the archive): the loaded image reports a digest; `repo@digest` resolves to it once the
  image is tagged into `repo` (`image_tag`), which the daemon does for every archive with the tag `pushed`
  (an archive saved by id has no name at all, so this is what makes the pin resolvable); and loading the
  same archive twice gives the same digest. A docker archive carries no manifest, so libpod computes one and
  it differs from the digest the image had in a registry — equality with the registry digest is not
  assumed, and is not needed. So no fallback to the image id is required and none is built.
  The same archive again is therefore `Unchanged`.
- **Streamed, outside the engine lock.** The archive goes request body → libpod `images/load` without
  buffering (`PodmanClient::image_load(TarStream)`); the daemon caps it at 8 GiB, as for volume imports.
  The engine lock is taken only for the deploy, so deploys of other apps do not wait for a multi-gigabyte
  upload (ADR 0040 makes the same choice for runs). One upload at a time (`Reconciler::uploads`, a single
  permit; a second is a 409): disk and I/O a client can take are bounded.
- **Errors.** Unknown app 404 (checked before the stream is read), archive Podman cannot load 400
  (`PushLoad`, carries libpod's message), foreign repository 400 (`PushInvalid`), second upload 409
  (`PushBusy`). A failed load changes nothing: no state is written before the deploy.
- **Manual push forces.** A known-bad digest is tried again (as `apps deploy` does): pushing is the
  operator's explicit will. A failed health gate rolls back to the previous digest and the CLI exits with
  the rollback code, as `deploy` does.
- **`--static` is out of scope** (waits for #48, whose artifact format is undecided). The CLI accepts a
  hidden `--static` only to refuse it with a clear message; the request types carry no artifact kind yet, so
  adding one later is additive.

**Invariants:** no new `AppSpec`/`apps.toml`/`state.toml` field, no `spec_hash` change, no schema bump —
the image reaches the container through the same pinned `repo@digest` as every deploy. `FakePodman` gained
`image_load` (digest = hash of the bytes, so one archive is one image; scripted names and failures) and its
`image_tag` now also resolves `repo@digest` for the repository it tags into, like libpod.

## Consequences

- New API route `PUT /v1/apps/{name}/image`; `image_ref` of `deploy` is honoured; new CLI command `push`;
  one new `PodmanClient` method (`image_load`) and `LoadedImage`. Documented in [`docs/guides/push-local-images.md`](../guides/push-local-images.md).
- Rollback to an older daemon needs nothing: no state field was added. An older daemon has no image route and
  still rejects `image_ref`; an older CLI has no `push`.
- **A pushed image is not signed or verified.** Whoever holds the admin socket can already `run` arbitrary
  code, so push does not widen trust; cosign verification stays a property of the self-update (ADR 0027).
- **Narrow race.** Between the load (outside the lock) and the deploy (inside it) a deploy of another app of
  the same repository may prune the new image as unused (retention, ADR 0020). The deploy then fails on a
  pull of `repo@digest` and the push is repeated. Closing it would mean holding the lock for the upload.
- **A failed pushed image stays in the store** until the next successful deploy of the repository prunes it
  (retention keeps only the current and previous image).
- Tests: engine scenarios on `FakePodman` (pin, repository check, load + tag + deploy, same archive
  `Unchanged`, rollback and known-bad retry, `start = false`, broken archive frees the slot, busy slot,
  unknown app), daemon tests over the real admin socket, CLI parsing/stream/exit-code tests, a wire test for
  the load report and the opt-in integration test on real Podman.

## Rejected alternatives

- **`podman load` on the host from the CLI (SSH).** The CLI talks only to the admin socket; a second channel
  would bypass the uid-range guard, the engine and the health gate.
- **A registry on the host to push into.** Another service to run, secure and update, for what a streamed
  tar does.
- **Holding the engine lock for the upload.** Would stall every webhook and deploy for as long as a client
  uploads; the narrow race above is the price of not doing so, and a retry fixes it.
- **Buffering the archive (to disk or memory) before loading.** Doubles the disk use and, for memory,
  contradicts the RAM priority; libpod already extracts layer by layer.
- **Pinning by image id when `repo@digest` does not resolve.** Not needed: measured to resolve after the tag.
  An id pin would also not survive a prune-and-reload of the same archive.
- **Rewriting `spec.image` to the pushed reference.** Would make a temporary push permanent and turn the
  webhook's tag comparison (`instances_tracking`) against the operator.
- **A different repository for `--image`.** The pin could not be reproduced from the app's repository, nor
  pulled with its credentials, after a rollback.
