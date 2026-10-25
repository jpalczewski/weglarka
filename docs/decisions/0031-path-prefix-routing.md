# 0031 — Path-prefix routing (several instances behind one domain)

Status: accepted (2026-10-24, issue #130)

## Problem

Ingress routes by `Host()` only, so a domain belongs to exactly one instance. A common layout splits one
public hostname by path (`/api/*` to a REST backend, `/mcp/*` to another service). Today that needs an extra
reverse proxy inside the stack. It is a routing rule, so the ingress should express it.

## Decision

`AppSpec` gets an optional `paths` list (default `["/"]`, today's behaviour) and `ingress.strip_prefix`
(default `false`).

- **Syntax.** A path is `/` or `/seg[/seg…]`: no trailing slash, no `//`, no `.`/`..` segment, characters
  `[A-Za-z0-9_.-/]`, at most 128 bytes (the `webhook_paths` rules). `paths` requires `domains`;
  `strip_prefix` requires a path other than `/`.
- **Matching.** For a prefix `/p` nginx gets `location = /p` and `location ^~ /p/` (a bare `location /p`
  would also match `/pxyz`); `/` stays the catch-all `location /`. Nginx picks the longest prefix.
- **Overlap.** Two instances may share a domain only when their prefixes are disjoint: an identical prefix
  (including a second `/`) and a nested prefix (`/api` vs `/api/v2`) are rejected with
  `IngressError::PathConflict`. `/` coexists with every other prefix — it is the catch-all by design. A
  domain without `paths` on both apps is still refused with the old "domain already used" error (`400`, like every ingress validation failure). The webhook domain stays exclusive.
- **Rendering.** Domains with an identical route set (same instances and paths) share one `server`, so an
  app whose domains are not shared renders byte-for-byte as before. Traefik is unchanged: one router per
  app with `Host(...)`; only nginx knows paths. `streaming` is per instance, hence per path.
- **Strip.** `strip_prefix = true` rewrites `/p/x` to `/x` and `/p` to `/` before `proxy_pass`; the query
  string is kept. Off by default: the app is expected to serve under its prefix.
- **Health probe.** `health.http` goes through nginx, so the request path is the app's first prefix joined
  with `health.http.path` (the prefix is kept with `strip_prefix` too, nginx strips it).
- **Invariants.** `paths` and `strip_prefix` are outside `spec_hash` and omitted when unset: changing them
  re-renders nginx (`nginx -t` + reload) and never recreates a container. They are new `apps.toml` fields,
  so `state::SCHEMA_VERSION` becomes 5 (ADR 0023).
- **Doctor.** `ingress.routes` lists the effective route table.

## Consequences

`doctor` adds the `ingress.routes` check; the list API is unchanged (`apps show` carries `paths`).
`apps.toml` with `paths`/`strip_prefix` is refused by an older daemon (`deny_unknown_fields`, schema gate):
before a downgrade remove both fields or restore the pre-upgrade files ([the path routing guide](../guides/path-routing.md)). New CLI flags
`--path` and `--strip-prefix`; the API app view gains `paths`. Tests: plan validation, nginx/Traefik
snapshots, hash stability, probe path, daemon refusal and reload-without-recreate.

## Rejected alternatives

- **Allow nested prefixes between apps** (nginx longest match would resolve them): the issue asks for
  disjoint paths, and a nested prefix is almost always a typo that silently steals traffic.
- **One `server` per domain always:** changes the rendered config of every existing app for no gain.
- **Path logic in Traefik rules:** would break the single-service/one-router-per-app policy and duplicate
  the matching in two places.
- **`strip_prefix` as a top-level field:** it only affects ingress, like `streaming`, so it lives in `ingress`.
