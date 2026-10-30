# 0061 — Publish the main image from CI through a reusable release workflow

Status: proposed (2026-10-30).

## Problem

On every push to `main`, ci.yml (`musl` job) and release.yml (`binaries` job) compiled the same static musl
binaries with the same profile, flags and cache entry, in parallel. The image job of release.yml only started after
its own copy finished, and the two workflows could not share the result because artifacts live inside one run.
`musl` took 160 s on `main` (the `release` profile) and the image job had to wait for `binaries` (about 100 s) on top
of that; the work was done twice for no gain in assurance.

## Decision

- release.yml gets a `workflow_call` trigger with an `artifact` input and keeps the `v[0-9]*` tag trigger. Its
  `push: branches: [main]` trigger is removed.
- ci.yml calls it on `main` from a `publish-image` job that `needs: musl` and passes the `musl-bin` artifact. The
  `binaries` job is skipped in that case; the `image` job downloads the caller's artifact, so what is published is
  exactly what CI built (ADR 0008 is unchanged: one build, used for tests, image and release).
- Tag pushes are unchanged: `binaries` builds both targets, `image` and `release` follow.
- `publish-image` does not wait for the smoke jobs, matching the old behaviour where the Release workflow ran
  independently of CI. Signing keys reach the called workflow with `secrets: inherit`, and only `push` events on
  `main` can call it.
- The `musl-release` cache entry is now written by the `musl` job on `main` (it was written by `binaries`); tag
  builds only read it.

## Consequences

- One compilation of the release profile per push to `main` and a shorter path to the published image.
- The run list shows the image jobs under CI (`publish-image / image …`) instead of a separate Release run for `main`.
- Branch-protection required checks are unchanged (`publish-image` is not required).
- A future gate on tests (`needs` the smoke jobs) is a one-line change if publishing should wait for them.

## Rejected alternatives

- **`workflow_run`:** waits for the whole CI run, so there is no time gain, and the tag path would still need its own build.
- **Cross-run `download-artifact` with `run-id`:** needs a token and run lookup; a reusable workflow keeps the artifact inside one run.
- **External S3 for handing over binaries:** an extra secret and a trans-Atlantic transfer for something GitHub already provides.
