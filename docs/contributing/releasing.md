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
first push in the same way. The runtime user pulls it without credentials, so before the first coordinated update:

1. Make `weglarka-releases` public (Packages → `weglarka-releases` → Package settings → Change visibility → Public).
2. Keep its **Manage Actions access** link so `GITHUB_TOKEN` with `packages: write` can publish later sets.
3. Verify anonymously that both the channel manifest and the immutable `set-<channel>-<sequence>` tag resolve.
