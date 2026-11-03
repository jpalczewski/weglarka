# Releasing (maintainer checklist)

Release mechanics (release-plz, per-crate versions, the `vX.Y.Z` tag that starts `release.yml`) are described in
[commits and PRs](../../.claude/rules/commits-and-prs.md) and [ADR 0015](../decisions/0015-per-crate-versioning-and-changelogs.md). This page holds
the manual steps no workflow can do.

## One-time: make the panel package public

GHCR creates a package as **private** the first time an image is pushed to it. `ghcr.io/jpalczewski/weglarka-panel` is
pushed by `release.yml` (the `:main` and `:sha-<7>` tags on `main`, the version tags on a `v*` tag), so after the first
publish operators cannot pull it anonymously: `docker pull`/`podman pull` fails with `unauthorized`, although
[the install guide](../install.md) presents the image as published and verifiable.

1. GitHub → the repository owner's **Packages** → `weglarka-panel` → **Package settings** → **Danger Zone** →
   **Change visibility** → **Public** (a public package cannot be made private again).
2. Confirm the package is still linked to the repository (**Package settings** → **Manage Actions access**), so
   `GITHUB_TOKEN` keeps write access for later publishes.
3. Verify an anonymous pull from a host that is not logged in to GHCR, and the signature check from the install guide:

   ```sh
   podman logout ghcr.io
   podman pull ghcr.io/jpalczewski/weglarka-panel:latest
   ```

Repeat the visibility check for any new image the release workflow starts publishing. The release-set repository
`ghcr.io/jpalczewski/weglarka-releases` is an OCI artifact repository, not an image, but GHCR creates it private on
first push in the same way. The runtime user pulls it without credentials, so **before the first coordinated update**:

1. Make `weglarka-releases` public (Packages → `weglarka-releases` → Package settings → Change visibility → Public).
2. Keep its **Manage Actions access** link so `GITHUB_TOKEN` with `packages: write` can publish later sets.
3. Verify anonymously that both the channel manifest and the immutable `set-<channel>-<sequence>` tag resolve.

## Release sets (coordinated updates)

`release.yml` publishes one signed release set per run (`docs/contracts/platform-update-v1`):

- a push to `main` promotes channel `main`; the daemon tag `vX.Y.Z` promotes channel `stable`;
- `weglarka-panel-vX.Y.Z` is a panel-only release (the daemon image and its host files are reused, not rebuilt or
  relabeled); `weglarka-cli-vX.Y.Z` rebuilds the daemon image because it carries the host CLI and reuses the panel;
- the immutable tag is `set-<channel>-<sequence>`; the channel tag (`main`/`stable`) is the pointer and only moves
  forward, after the set, its blobs and its signature verify.

The first release of a channel has no pointer to read. A "not found" answer is accepted as "no release set yet" only
when the channel is listed in the repository variable `FIRST_RELEASE_SET_CHANNELS` (for example `main,stable`); clear
the variable after the first publish. Without it a 404 fails the run, because a pointer that is missing for any other
reason (a renamed package, a permission error) must never skip the ancestry and sequence checks and let a channel move
backwards.

Both the component images and the release set are signed with the static key in `COSIGN_PRIVATE_KEY`
(`cosign.pub` is the public half the daemon embeds). A missing key fails the run on both channels — there is no
warning-only path. The signature uses the legacy `sha256-<hex>.sig` layout, so do not change the cosign flags to the
referrer/bundle default.

Sequence allocation is `max(channel pointer, highest set-<channel>-N tag) + 1` inside a per-channel concurrency
group that does not cancel a queued successor. A crash after the immutable tag push is harmless: the next run
allocates the next sequence, and the post-promotion reconciliation step moves a superseded channel to the newest
complete set. Do not create, move or delete these tags by hand.

Inspect a published set with the same binary the host uses:

```sh
cargo run -p weglarka-release -- verify --channel stable
cargo run -p weglarka-release -- verify set-stable-3 --json
```
