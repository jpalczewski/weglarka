# 0004 — GitHub webhooks: events, per-app secret, 202 immediately

Status: accepted (daemon session, 2026-10-23). **Event choice to be confirmed on a real push.**

**Decision.**
- Endpoint: `POST /webhook/github/{instance}` (under the `/webhook/` prefix that nginx exposes).
  The instance is in the path because the HMAC is **per app**: the secret `<instance>.webhook-hmac` in
  `secrets.toml` (set with `weglarka secrets set <app> webhook-hmac`, the same string goes into the webhook
  settings on GitHub).
- Supported events: `registry_package` and `package`, `action == "published"`, `package_type`
  `CONTAINER` (or the field absent). `image_ref` = `repo(package_url) + ":" + container_metadata.tag.name`
  (without `package_url`: `ghcr.io/<namespace>/<name>`), lowercased. A version without a tag → ignored.
  Other events (`ping`, `push`, `workflow_run`, …) → **204**.
- Order: secret → signature (**401**, also for an unknown app / a missing secret — indistinguishable)
  → normalization (204 / **400** for a broken body) → the event must concern the image tracked by this
  app (otherwise 204) → **202** and `Reconciler::handle_webhook` in a separate task (tracked for the
  duration of shutdown).
- Signature: `X-Hub-Signature-256`, HMAC-SHA256, constant-time comparison (`Mac::verify_slice`).
  Rejections are logged (instance, delivery, reason) — without the body and without secrets.
- Dedup by `X-GitHub-Delivery` is done by the core; a duplicate gets 202 (the response is sent before
  the duplicate is known).
- Body limit: 1 MiB (consistent with nginx's `webhook_max_body_bytes`) → 413.

**To confirm on a real push.** We have not yet seen a GHCR payload for ntfy.zig. The parser is
tolerant (`#[serde(default)]`), but the field names
(`registry_package.package_version.container_metadata.tag.name`, `package_url`) come from the
documentation, not from observation. The ntfy.zig CI pushes two tags (`latest` and `sha-…`), so we
expect two deliveries per push; `sha-…` does not match an app tracking `:latest` and ends with 204.

**Fan-out (deliberate design decision).** A webhook for image X updates *all* instances tracking X with
`auto_update = true` (`Reconciler::handle_webhook`). Trade-off: the signature of one instance can trigger
deploys of other instances of the same image. The risk is limited: the event passes only when the payload's
`image_ref` matches the image/tag of the **authenticated** instance (otherwise 204, nothing happens), so
the signature of instance A will not start anything beyond what A itself tracks; the other instances track
the same `image_ref` anyway, and the health gate and rollback work per instance.

**Log and dedup hygiene.** The delivery identifier enters the logs and the dedup set only when it has
≤ 64 characters `[A-Za-z0-9-]`; untrusted values in the logs are formatted via `Debug`.
