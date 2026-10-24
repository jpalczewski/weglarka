# 0006 — Packaging: the Węglarka image on `scratch`, official nginx, release on GHCR

Status: accepted (packaging session, 2026-10-23).

**Węglarka image** (`Containerfile`).
- Multi-stage build (locally from source; in CI/release from prebuilt binaries, 0008): `rust:1.99.1-alpine`
  (version = `rust-toolchain.toml`) → `scratch` with two static binaries (musl): `weglarka-daemon` (`ENTRYPOINT`,
  `CMD ["run"]`) and `weglarka` (CLI, for `podman exec … weglarka status`). Size ≈ 5 MB. No shell, no libc.
- **No CA bundle**: the daemon talks exclusively to the Podman socket (Podman pulls images, not us), and webhooks
  are incoming. `Cargo.lock` has no TLS crate at all. If outgoing HTTPS ever appears — add it then.
- **No `USER`** (we run as the container root). In rootless Podman the container root is *the host runtime user*
  (e.g. `weglarka`), not the host root. Only that user has access to the sockets mounted 1:1, the state directory
  and `secrets.toml` (0600). A non-root inside the container would map to a subuid and lose access to all mounts
  (fixing it would require `UserNS=keep-id` in the quadlet — a crate change with no security gain).
- OCI labels: `source`, `revision`, `version` (from `--build-arg VERSION/REVISION`), `licenses`.
- `platform install` (systemctl + `/etc/passwd`) **does not work in the image** — it requires a host. That is why
  `weglarka-daemon` is also in the release tarball (linux-musl) next to the CLI; `docs/install.md` uses it on the
  host.

**nginx: the official `docker.io/library/nginx` image (alpine), no own one.**
- Our own thin image would be another artifact to build, sign and patch for CVEs, and it adds nothing: the daemon
  mounts the whole `/etc/nginx` (ro) with a single `nginx.conf` file that is self-contained (no `mime.types`), the
  pid and temporary files go to `/tmp`, logs to stdout/stderr, listening on 8080 (unprivileged), reload via
  `SIGHUP`. The `docker-entrypoint.d` scripts of the official image have nothing to do (no `conf.d/default.conf`
  and no `templates/`).
- The default `ingress.nginx_image` value in the code stays a tag (`nginx:1-alpine`); **on the host we pin by
  digest** in `weglarka.toml` (example in `docs/install.md`). Reason: `IngressManager::ensure_image` pulls the image
  only when it is missing locally, so a moving tag does not update itself anyway — updating nginx is a deliberate
  operator action (changing `nginx_image` changes `weglarka.ingress-hash` → recreating the container), and a digest
  gives reproducibility and auditability at no cost.
- CI validates the generated config (`nginx -t`) on **the same image that the daemon runs by default**, and the
  smoke test of the Węglarka image starts a real nginx container and prints its logs.

**Release** (`.github/workflows/release.yml`).
- `main` → `ghcr.io/jpalczewski/weglarka:main` + `:sha-<7>`; tag `v*` → `:<version>` + `:latest`. `linux/amd64` only.
  The `v*` tag must match `workspace.package.version`.
- A keyless `cosign` signature (GitHub OIDC) by image digest; the SBOM (SPDX JSON, syft) attached as a cosign
  attestation (a separate artifact in the registry — the image tag remains a plain manifest, without a BuildKit
  attestation index).
- GitHub Release assets (only for `v*`): `weglarka-<version>-x86_64-unknown-linux-musl.tar.gz` (CLI + daemon),
  `weglarka-<version>-aarch64-apple-darwin.tar.gz` (CLI), `SHA256SUMS` (+ the cosign signature
  `SHA256SUMS.sig`/`.pem`).
- Verifying the image signature: `docs/install.md`.

**CI.** The image is built from the prebuilt binaries of the `musl` job, and the smoke test
(`.github/scripts/smoke-image.sh`) runs in `integration-podman` — details and rationale: 0008.

**Out of MVP:** `linux/arm64` (Alpine/aarch64), `AutoUpdate=registry` in the quadlet (Węglarka self-update),
automatic bumping of the nginx digest.
