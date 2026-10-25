# 0014 — Hardening the ingress nginx container (issue #31)

Status: accepted (2026-10-24, issue #31).

## Problem

App containers can be hardened since #28 (`AppSpec.security`, `--hardened`), but `weglarka-nginx` — the only
Węglarka container that faces outside traffic — still ran with a writable root filesystem and the default
capability set. ADR 0005 explicitly left that as a follow-up. The result was inverted from what the threat model
wants: the most exposed process on the host had the weakest profile, while the apps behind it could already run
with `read_only`, `cap_drop: [ALL]` and `no-new-privileges`. A bug in a generated route or in the proxy itself
would be exploitable from the outside with a writable rootfs and the default capabilities.

## Decision

**The profile is built in, not a spec field.** Węglarka owns this container (image, config, networks, uid range),
so the hardening is not opt-in and there is nothing to configure:

```rust
// crates/weglarka-daemon/src/ingress.rs
Security {
    read_only: true, tmpfs: [],
    cap_drop: ["ALL"], cap_add: ["CHOWN", "SETGID", "SETUID"],
    no_new_privileges: true,
}
```

- **Read-only root.** libpod mounts a writable tmpfs on `/tmp`, `/var/tmp` and `/run` when the root is read-only
  (`read_write_tmpfs`, the `podman run --read-only` default; the API defaults it to off, so the client sets it).
  **No extra `tmpfs` entry.** Everything nginx writes at runtime is already under `/tmp`: the generated config
  sets `pid /tmp/nginx.pid` and all five `*_temp_path` directives (`weglarka-ingress/src/nginx.rs`). The
  invariant is pinned by `writable_nginx_paths_stay_under_tmp`, so a future directive writing elsewhere fails a
  test instead of silently breaking the hardened container.
- **`cap_drop: [ALL]` with exactly three capabilities back: `CHOWN`, `SETGID`, `SETUID`.** They are not a safety
  margin. Although the generated config has no `user` directive, nginx falls back to the worker user compiled into
  the image (`nginx`, uid 101): it chowns its temp directories to that user (`CHOWN`) and the master drops to it
  (`SETGID`, `SETUID`). Measured on `nginx:1-alpine` with this exact profile: without `CHOWN` the container exits
  with `chown("/tmp/client_body", 101) failed (1: Operation not permitted)`; with `CHOWN` only, the worker dies
  with `setgid(101) failed` and nginx cannot serve. `NET_BIND_SERVICE` stays out — it listens on 8080.
- **`no_new_privileges`.** setuid binaries and file capabilities cannot raise privileges, even if a future image
  ships them.
- **Root in a private user namespace** maps to the instance's own subuid range (ADR 0009); the hardening is a
  layer on top of that isolation, not a replacement for it. Since [0036](0036-edge-mode.md) the *ingress*
  container's uid 0 maps to the runtime user instead (the TLS master must read `0600` keys); the worker keeps
  the ingress range and the capability set is unchanged.

**The profile is part of the container identity.** `weglarka.ingress-hash` now hashes the image, the publishing
(bind address + listen port), the uid range **and the security profile** (format bumped to
`weglarka.ingress-hash/v2`, hashed as serialized JSON like `spec_hash`). Upgrading Węglarka therefore recreates
`weglarka-nginx` once; without that, existing installs would keep the old, writable container forever.

## Consequences

- **One-time recreation on upgrade.** The nginx container is stopped and removed, then created and started with
  the new profile: a brief traffic gap (seconds; the image is already present). This is the same exposure as
  changing `ingress.nginx_image`, and it is the price of not leaving old containers unhardened.
- **Rollback works in both directions.** An older daemon computes the old hash, sees the mismatch and recreates
  nginx without hardening. No `weglarka.toml`/`apps.toml`/`state.toml` field was added, so `deny_unknown_fields`
  is not a hazard for a downgrade.
- **A custom `ingress.nginx_image` must tolerate the profile.** The official `nginx:*-alpine` image does: its
  entrypoint only writes `/etc/nginx`, which is already mounted read-only and skipped when unwritable; the pid and
  temp paths come from our generated config. An image that writes to its own rootfs at startup now fails — a
  deliberate constraint, documented in [the container hardening guide](../guides/container-hardening.md).
- **Verification** (the issue's list): `nginx -t` inside the container, `.github/scripts/test-forwarded-headers.sh`,
  `scripts/acceptance.sh`, and the smoke scripts (`.github/scripts/smoke-image.sh`, `smoke-quadlet.sh`), which now
  assert a read-only root, `no-new-privileges`, an effective capability set of exactly
  `CHOWN`+`SETGID`+`SETUID`, and a passing `nginx -t`. On a host:
  `podman inspect weglarka-nginx --format '{{.HostConfig.ReadonlyRootfs}} {{.EffectiveCaps}}'`.
  The capability numbers above were measured by reproducing the profile on plain Docker
  (`--read-only --tmpfs /tmp --cap-drop ALL --cap-add CHOWN,SETGID,SETUID --security-opt no-new-privileges`),
  which mirrors libpod's read-only tmpfs: with all three, `nginx -t`, a 200 through a backend and the generated
  `X-Forwarded-*` headers all behave as before.
- **App containers are untouched.** `AppSpec.security` and `spec_hash` do not change; `apps.toml` keeps its format.

## Rejected alternatives

- **A toggle (`[ingress] hardening = false`).** The container is ours, and a security default should not be the
  weakest one. A toggle also doubles the profiles every smoke and acceptance run would have to cover. An operator
  with a non-conforming image gets a clear failure and a documented constraint instead.
- **Dropping every capability (an empty `cap_add`, as first tried).** Measured to be impossible with the official
  image: nginx resolves the worker user from the image (uid 101), chowns its temp dirs to it and drops to it, so
  `CHOWN`, `SETGID` and `SETUID` are the minimum; the smoke scripts pin the effective set to exactly those three so
  a future image that needs more fails loudly.
- **Not bumping the hash** (relying on the next image change to recreate nginx). That leaves running installs
  unhardened for an unbounded time — exactly the failure mode the issue is about.
- **An explicit tmpfs list (`/var/cache/nginx`, `/run`) instead of libpod's read-only-tmpfs.** More writable
  surface than necessary, and it would mask a config change that moves writes out of `/tmp`; the generator test is
  the better guard.
- **An explicit `user nginx;` or an unprivileged nginx image.** The official image is already compiled with that
  worker user and the workers already run as it (uid 101) — the directive would change nothing. Going further (a
  non-root master, e.g. `nginx-unprivileged` or `--userns keep-id`) is a real improvement but a separate change
  with its own temp-directory ownership story and verification.
