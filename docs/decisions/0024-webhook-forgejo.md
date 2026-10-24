# 0024 — Forgejo webhooks: `package` event, registry host from config, pulls via `auth.json` (issue #44)

Status: accepted (2026-10-24, issue #44). **Payload shape and moving-tag behaviour to be confirmed on a real push.**

## Problem

Private apps live on a Forgejo instance: a Forgejo Actions runner builds the image and pushes it to
the instance's container registry. Węglarka needs the same trigger it has for GHCR (ADR 0004) — an
authenticated "new image" event that ends in a deploy — plus a way to pull from a private registry.

## Decision

1. **Adapter next to GitHub.** `weglarka-daemon/src/forgejo.rs` implements `WebhookSource`. Route:
   `POST /webhook/forgejo/{instance}`; the listener now serves `/webhook/{source}/{instance}` and picks the
   adapter by `WebhookSource::name`. Nothing changes in nginx (the `/webhook/` prefix is already exposed).
   The secret stays per app (`<instance>.webhook-hmac`), the order of checks and the status codes are
   the ones from ADR 0004 (401 / 204 / 400 / 202 / 413). The adapter declares the headers it reads
   (`WebhookSource::headers`, `delivery_header`), so the listener knows nothing about a particular source.
2. **Event.** `X-Forgejo-Event: package` with `action == "created"` and `package.type == "container"`.
   `deleted` and everything else → 204. For container packages `package.version` is the **tag**; an
   empty version or a `sha256:…` version (untagged manifest) → 204. Of the two events a push produces
   (`main` and `sha-<commit>`), the `sha-…` one does not match an app tracking `:main` and ends in 204.
3. **Signature.** `X-Forgejo-Signature`, **plain hex** HMAC-SHA256 of the body (no `sha256=` prefix),
   constant-time comparison (`Mac::verify_slice`). Only this header is accepted: Forgejo may also send
   `X-Gitea-*` and `X-Hub-Signature-256` aliases, but accepting several would widen what an attacker can
   try for no gain. Dedup uses `X-Forgejo-Delivery` (same hygiene as GitHub: ≤ 64 chars `[A-Za-z0-9-]`).
4. **Registry host comes from configuration, never from the payload.** The payload names the owner and the
   package, not the host `podman pull` needs. `[webhook.forgejo] registry = "<host[:port]>"` in
   `weglarka.toml` supplies it; `image_ref = <registry>/<owner>/<name>:<tag>`, lower-cased, checked by the
   shared `valid_ref`. A host from the payload would let a signed event point a pull at another registry.
   Without the section the route answers 404. A bad value (scheme, path, spaces) refuses to start.
   A new `weglarka.toml` section breaks a rollback to an older daemon (`deny_unknown_fields`), like `[notify]`.
5. **Pulling from a private registry: (a), the podman user's `auth.json`.** `images/pull` sends no
   `X-Registry-Auth`; a private image works when the runtime user did `podman login` with a read-only token
   of a dedicated account. Zero code, one token serves every app on that registry. The cost: the token lives
   on the host outside the secret store. **(b)** — per-app registry credentials as secrets sent as
   `X-Registry-Auth` — is deliberately a separate issue (touches `PodmanClient` and `FakePodman`).
   What this ADR does add: a pull refused by the registry (HTTP 401/403 or `unauthorized` / `denied` in the
   pull stream) surfaces as `EngineError::RegistryAuth` with a message pointing at `podman login`, distinct
   from "image not found".

## To confirm on a real push

The adapter was written from the Gitea/Forgejo `PackagePayload` documentation, not from an observed
delivery. Verify and commit the captured payload as a snapshot (as ADR 0004 asks for GitHub):

- header names and which signature header is present;
- `package.owner.login`, `package.name`, `package.version` for a container push;
- **whether re-pushing an existing tag (`main`) to a new digest sends `package.created` again.** Forgejo may
  update the existing version instead. If it does not, the tracked-tag trigger cannot rely on this event and
  #83 (match by repository, resolve the tracked tag's digest) becomes the way; the adapter stays.
