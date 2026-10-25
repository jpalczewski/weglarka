# 0049 — Static sites (`kind = "static"`)

Status: accepted (2026-10-25, issue #48)

## Problem

A built static site (an Astro `dist/`, a Hugo `public/`) should be hosted by Węglarka without a container per
site, from the same CI → registry → webhook flow that deploys apps. Constraints, in priority order:

- **Security.** The artifact comes from CI and is unpacked by the daemon, so extraction is the attack surface:
  path traversal, links that escape the site directory, device files, decompression bombs. The ingress nginx is
  the most exposed process on the host and must not gain a new mount that widens its reach (ADR 0036: only
  `<nginx_conf_dir>` is mounted into it).
- **Extensibility.** A site should reuse the app machinery (webhooks, per-instance registry credentials, secrets,
  domains and paths, reconcile, `Plan::build`) instead of growing a parallel model.
- **RAM.** No resident process per site; the archive is streamed, never buffered.

Failure modes if we get it wrong: a malicious or broken artifact writes outside the site directory; a deploy
that is half extracted is served; a rollback that needs the registry; an upgrade of Węglarka that recreates or
rejects existing apps (`spec_hash`, `deny_unknown_fields`).

## Decision

**A site is an `AppSpec` with `kind = "static"`; its artifact is a one-layer OCI image `FROM scratch`; the
daemon extracts it into a per-release directory under `<nginx_conf_dir>/sites/` and switches a symlink.**

- **Artifact.** `FROM scratch` + `COPY dist/ /` — the CI contract. It travels through the existing pipeline: tag
  in `spec.image`, webhook (any `WebhookSource`, Forgejo included), digest pinned in `state.toml`, per-instance
  registry credentials (`<instance>.registry-auth`, so a private registry needs no new code). `weglarka push
  --static` (#109) later delivers the same artifact as a tarball; it is a second source, not a second format.
- **`apps.toml`.** `kind` is optional and defaults to the container kind; it is outside `HashInput` when unset,
  so no running app is recreated by the upgrade. A static site accepts `image`, `domains`, `paths`, `ingress`
  and the per-site options of #104; `validate_app` rejects the fields that need a process (`port`, `health`,
  `env`, `secrets` other than the webhook HMAC, `volumes`, `host_ports`, `resources`, `hardening`, `command`,
  `configs`). `depends_on` and the shared-network fields are rejected as well. A static site has no container, so
  reconcile never creates one and `doctor`/`list` show it as a site with a release instead of a container state.
- **Layout.** Sites live under `<nginx_conf_dir>/sites/<site>/`, not in a Podman volume: it is the one
  directory nginx already mounts (0036), so the trust boundary does not move and no uid-range rules (0009, 0017)
  apply to site data. Inside: `releases/<digest-prefix>/…` and a relative symlink `current → releases/<id>`.
  nginx serves `root /etc/nginx/sites/<site>/current` read-only; files are world-readable (0644/0755, like the
  ACME webroot).
- **Extraction (#102), fail closed.** The image is exported from Podman as a stream (a new `image_save`
  operation on `PodmanClient`, with a `FakePodman` implementation) and the daemon extracts the layer itself.
  Exactly one layer is accepted in v1. Rejected, with the release directory removed and nothing switched:
  absolute paths, `..` components, symlinks and hard links, device/FIFO/socket entries, any entry whose
  resolved path leaves the release directory, a file count or byte total over a limit (config, with a safe
  default), and an archive whose layer count is not one. Permissions are normalised (0644/0755), ownership is
  the daemon's. Extraction runs outside the engine lock like the upload in 0042; only the symlink switch and
  the nginx reload happen under it.
- **Atomic deploy and rollback (#103).** A release is extracted into `releases/<id>.partial`, renamed to
  `releases/<id>`, then `current` is replaced with `rename(2)` of a temporary symlink. The gate is
  `nginx -t` + reload succeeding with the new tree and `index.html` present (a per-site `health` path can come
  with #104); a failed gate restores the previous symlink. The previous release stays on disk (retention 1,
  like images in 0020), so rollback is a symlink switch that does not depend on the registry. `state.toml`
  records `current`/`previous`/`failed` digests exactly as for apps.
- **Ingress (#101).** `Plan::build` treats a site as a backend of kind "directory": the same domain/`paths`
  validation and conflict rules apply; the generators render `root`/`try_files` instead of `proxy_pass`, in both
  `behind` and `edge` modes and both entrypoints. A site never gets an upstream, so it cannot be reached through
  the proxy path. Per-site options (#104) and Basic auth (#169) extend this block; none enters `spec_hash`.
- **State schema.** The new `kind` field bumps `state::SCHEMA_VERSION` (11 → 12) with a no-op `SCHEMA_STEPS`
  entry (0023). Downgrade needs the site entries removed from `apps.toml` and the `schema_version` marker
  dropped, or the files restored from a pre-upgrade copy; the guide `docs/guides/static-sites.md` carries the
  `## Rollback` section and the field goes into the table in `verify-and-rollback.md`.

## Consequences

- New operator surface: `kind = "static"` in `apps.toml`, `apps add --kind static` (CLI flag in the same PR as the
  schema change), a guide `docs/guides/static-sites.md` and an entry in `docs/guides/README.md`.
- New code: `image_save` in `weglarka-core`/`weglarka-podman` (+ `FakePodman`), a site extractor and release
  manager in `weglarka-core`, a directory backend in `weglarka-ingress`, the `kind` branch in `reconcile` and
  `deploy`, checks in `doctor` (`sites.*`: directory writable, `current` resolves, disk usage).
- Tests that must exist before merge: malicious archives for every rejection above; atomic switch with a
  crash between rename and symlink (the previous release is still served); rollback with the registry
  unreachable; ingress snapshots for both modes; an `nginx -t` e2e with a site and an app on the same domain
  under different `paths`; an integration test on real Podman for `image_save`.
- Open measurements, to be settled before the first implementation PR (as in 0042, on Podman 6.1 in the
  `podman-tests` job): the archive format `images/{name}/get` returns for an image built `FROM scratch` (layer
  layout, one layer for `COPY dist/ /`), and whether the exported digest equals the one pulled from the
  registry. If the export turns out to be unusable, the fallback is a short-lived container created from the
  image and `GET /containers/{id}/archive`; the extractor's checks stay the same either way.
- Not decided here: multiple users for Basic auth (#169), `weglarka push --static` request shape (#109), and
  whether a site may have several release directories retained.

## Rejected alternatives

- **A container per site (nginx or static server).** Costs RAM per site and a health gate with nothing to
  gate; the point of the epic is to avoid it.
- **A shared Podman volume `sites` (the original wording of #101).** Needs a uid range shared by the daemon and
  nginx (0009, 0017) and a second nginx mount, which breaks the 0036 rule that only `<nginx_conf_dir>` is
  mounted. A directory under the existing mount gives the same result without either.
- **Tarball first (`push --static` only).** Skips the registry but not the extractor, and loses digest pinning,
  webhooks and signed provenance for the common CI path. It stays as a second source.
- **Extracting inside a helper container.** Adds a process and a second extractor to audit for no benefit: the
  daemon already writes into `<nginx_conf_dir>`.
- **Multi-layer images with whiteout handling.** A large part of the extractor's attack surface for a feature
  the CI contract (`COPY dist/ /`) never needs; reconsider only if someone has a real need.
- **A separate `SiteSpec` type.** Duplicates webhooks, secrets, domains, reconcile and `Plan::build`. The cost
  of the `kind` field is conditional validation, which `validate_app` already does for other combinations.
