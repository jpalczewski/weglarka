# 0047 — Per-path streaming locations (issue #180)

Status: accepted (2026-10-25, issue #180). Extends [0018](0018-ingress-streaming.md).

## Problem

`ingress.streaming = true` (0018) switches a whole app to long timeouts and unbuffered I/O. Some apps hold only
one endpoint open — Forgejo's `/user/events` (SSE) is idle until something happens, so the shared 180 s
`proxy_read_timeout` ends it in a 504 — while the rest of the app (git pushes, ordinary pages) should keep the
conservative defaults. Raising the limit for the whole app trades one problem for another.

## Decision

`ingress.streaming_paths = ["/user/events"]` (list of paths in the public URL space, `paths` syntax):

- Each entry renders `location = <p>` and `location ^~ <p>/` next to the app's `location /`, with
  `proxy_buffering off`, `proxy_request_buffering off` and `proxy_read_timeout`/`proxy_send_timeout` of a fixed
  **3600 s** (`AppIngress::STREAMING_PATH_TIMEOUT_SECS`, the same ceiling as `stream_timeout_secs`). Everything
  else (upstream, `max_body_size`) is inherited. The same generator serves `behind` and `edge`.
- Ingress-only: outside `spec_hash`, so a change is an nginx reload and never recreates the container. An empty
  list renders exactly as before.
- Validation: `paths` syntax, no `/` (use `streaming = true`), no duplicates, not together with
  `streaming = true` (redundant) and not on an app routed under non-root `paths` prefixes (the public path would
  need prefix arithmetic with `strip_prefix`; add it when someone needs it).
- `Plan::build` treats the entries as claims on the domain, so a streaming path cannot shadow a prefix that
  another app owns (`PathConflict`).
- `apps.toml` gets `schema_version = 11` (no-op step); the field is new for `deny_unknown_fields`.

## Consequences

CLI: `--streaming-path` (repeatable) on `apps add`/`apps update`, `--no-streaming-paths` on `update`;
`--no-streaming` leaves the list alone. Downgrade: remove `streaming_paths` (and the `schema_version` marker) or
restore the files from before the upgrade — see [streaming](../guides/streaming.md) and
[verify and rollback](../guides/verify-and-rollback.md). Tests: validation in `state.rs`, snapshot
`nginx_streaming_paths` plus an `edge` assertion and a conflict test in `weglarka-ingress`, CLI flag tests.

## Rejected alternatives

- **A per-path timeout value.** More surface for no known need; one hour matches the existing ceiling.
- **Regexes or globs.** The path alphabet is restricted because it lands in `nginx.conf`; exact + prefix covers SSE.
- **Reusing `streaming = true` with a path filter.** Changes the meaning of an existing, documented knob.
