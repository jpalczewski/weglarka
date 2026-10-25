# 0042 — Deploying a locally built image (`weglarka push`)

Status: proposed (2026-10-25, issue #109)

## Problem

An image built on the operator's laptop has to reach a Węglarka host without a CI round trip. Today the
only way to deploy is the webhook path: `deploy_locked` always resolves the digest by pulling the tag in
`spec.image`, and `weglarka deploy --image` is rejected by the daemon (`image_ref override is not
supported yet`). Failure modes that matter: a pushed digest that a later reconcile or webhook silently
replaces, an image from a foreign repository that cannot be pulled again after a rollback, an upload that
holds the engine lock or buffers the whole archive in RAM, and a failed load that leaves orphaned layers.

## Decision

_Stub — reserved number. To be filled in once the spike below has run on real Podman 6._ Direction:

- **Two sources, one deploy path.** `--image REF` (the image is already in a registry) and an archive
  (`push <app> ARCHIVE` or `-` for stdin, e.g. `podman save --format oci-archive img | weglarka push app -`).
  Both end in the normal deploy: health gate, `current`/`previous`/`failed` in `state.toml`, rollback.
- **`apps.toml` is not touched.** Push changes the pin in `state.toml` only; `spec.image` stays.
- **A registry reference must have the same repository as `spec.image`.** The pin is
  `image_repo(spec.image)@digest` and registry credentials are per instance, so another repository could
  not be pulled again.
- **The archive is streamed**, never buffered; the load runs outside the engine lock, only the deploy
  takes it (as in ADR 0040). At most one upload at a time; a failed load removes what it created.
- **No state schema change.** No new field in `AppSpec`, `apps.toml` or `state.toml`, no `spec_hash` change.
- **`--static` is out of scope** (waits for #48); the artifact kind is an enum so it can be added later.

## Consequences

To be written with the decision. Known already: the next webhook for the tag replaces a pushed image
(`weglarka hold`, #107, is the real answer); no signature verification — whoever holds the admin socket can
already `run` arbitrary code.

## Spike (open question)

`crates/weglarka-podman/tests/image_load.rs` measures, on real Podman 6, for `oci-archive` and
`docker-archive`: what `POST /libpod/images/load` returns, whether the loaded image keeps its manifest
digest, and whether `image_inspect("repo@sha256:…")` finds it (which `ensure_image` relies on). If lookup
by `repo@digest` does not work, the fallback is the local image id, which `ensure_image` already accepts.

## Rejected alternatives

To be written with the decision.
