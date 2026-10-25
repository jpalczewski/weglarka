# 0037 — Owner (`uid`/`gid`) of a mounted secret

Status: accepted (2026-10-24, issue #55)

## Problem

A secret bound as `kind = "mount"` is materialized by libpod as a file in the container, with mode `0444`
(when the spec sets none) owned by uid/gid `0` — root in the container. That works for the common case: the
file is world-readable and any `USER` of the image can read it.

It does not work for an image that runs as a specific non-root user **and** refuses a world-readable secret
(e.g. a token that must be `0400`). The operator can already tighten `mode`, but a `0400` file owned by root
is unreadable for the process that needs it. libpod's `specgen.Secret` (`SecretMount`) has `UID` and `GID`
fields next to `Mode` for exactly this, and `podman run --secret` exposes them; Węglarka never sent them, so
it always took libpod's zero value.

The failure mode is silent at spec time and loud at runtime (the app cannot read its secret), so the spec
model has to express the owner and validation has to catch mistakes before deploy.

## Decision

**A mount binding accepts optional numeric `uid` and `gid` next to `mode`.** They are ids **in the
container's namespace** — the same space the image's `USER` refers to (e.g. `1000`), not host ids. Podman
maps them through the instance's uid/gid range (ADR 0009), whose size is `uid_range::DEFAULT_RANGE_SIZE`
(65 536), so the container sees the id it asked for while the host file belongs to `range.start + id`.

```toml
secrets = [
  { secret = "config", kind = "mount", path = "/config.json", mode = 0o400, uid = 1000, gid = 1000 },
]
```

- **Defaults stay `0`/`0`** (root in the container), matching `podman run --secret`. The wire sends
  `uid.unwrap_or(0)` / `gid.unwrap_or(0)`.
- **Both fields are optional** (`#[serde(default, skip_serializing_if = "Option::is_none")]`). A spec that
  does not set them serializes byte-for-byte as before, so a rewrite of `apps.toml` does not churn existing
  files.
- **Validation** in `state::validate_app`: a mounted secret's `uid`/`gid` must be `< DEFAULT_RANGE_SIZE`
  (`0..=65535`), because the range cannot map anything wider (the bound is derived from the range size, not
  duplicated as a magic number). The error names the instance, the secret and the field. The type is `u32`,
  so a user name is a parse error, not a validation error.
- **No names, no host ids.** A user/group *name* would need the image's `/etc/passwd` at spec-writing time,
  which Węglarka does not have; a host id would leak the host's user database into a spec and be wrong in
  every instance's mapping. Numeric container ids are the only portable spelling.
- **`spec_hash`:** `None` is skipped, so an unset owner keeps today's hash exactly (`HASH_FORMAT` stays v1,
  no mass recreate on upgrade). A set or changed id makes the hash differ: the owner is applied at container
  create, so the next reconcile must recreate the container. An explicit `0` serializes and therefore hashes
  differently from an omitted field — a one-time recreate, harmless, and the same rule as every other
  optional field.
- **Spec-only, no CLI flag.** `--secret-mount SECRET=PATH` re-binds the secret and therefore resets `mode`
  (as it already did) and the new `uid`/`gid` to their defaults. Ownership is a rare, image-specific setting,
  so it is set in `apps.toml`/`--spec`; adding flags would widen the CLI for no everyday use.
- **State schema v7.** `apps.toml` gains fields, so `state::SCHEMA_VERSION` goes 6 → 7 with a no-op step
  `secret_mount_ownership_v7` (ADR 0023) and the image label `io.weglarka.state-schema` follows.

## Consequences

An operator deploying an image with a non-root `USER` can mount its config with `mode = 0o400` and the image's
`uid`/`gid`, and tighten the file at the same time (documented in [the first app guide](../guides/first-app.md)). The default
path is unchanged: no spec, no hash and no container changes.

The real-Podman engine test (`engine_ranges_volumes_secrets_import_migration_and_purge`,
`weglarka-podman/tests/volumes.rs`) sets `mode = 0o444, uid = 1000, gid = 1000` and asserts that
`stat -c '%u:%g' /run/secrets/tok` inside the container prints `1000:1000` — that is the check that libpod
indeed maps container-space ids through the instance range. It runs in the `integration-podman` CI job.

**Rollback:** files written by this release carry `schema_version = 7`, and an older daemon refuses to start
on them. Before a downgrade remove `uid`/`gid` from the mounted secrets (or restore `apps.toml` and
`state.toml` from the pre-upgrade backup); then the older daemon parses the specs again. Rolling back a
deploy is orthogonal: like any spec change, a wrong owner can make the app fail its health gate, and a
rollback restores the previous digest **with the new spec**, so fix the spec (ADR 0019 pattern).

## Rejected alternatives

- **User/group names instead of numbers.** Węglarka would need the image's `/etc/passwd` (or the container)
  to resolve them, and the reference could drift from the image; a name that resolves in one image version
  and not the next turns a spec into a deploy-time failure.
- **Host `uid`/`gid`.** They mean nothing inside the container (rootless Podman maps everything), differ per
  instance and would leak the host's ids into an apps spec — the mapping is exactly what the instance range
  exists to hide.
- **Implicit `chown` of the mounted file after start.** It needs an exec into the container (or a host path
  into the volume), races the app's startup, and repeats on every start; libpod already applies the owner
  atomically at container create.
- **Guess the owner from the image's `USER`.** Inspect would give a name or a number for one image layer, not
  a policy; a spec that changes with the image tag would recreate containers unexpectedly, and an image that
  runs as root would silently get root-owned secrets.
- **A CLI flag (`--secret-mount-uid`, …).** Rare, image-specific setting; flags would then have to mirror
  `mode` too, and the re-bind behaviour of `--secret-mount` would get a second, inconsistent reset rule.
