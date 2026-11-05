# 0076 — Security headers for container apps

Status: proposed (2026-11-05, issue #497)

## Problem

A static site can ask the ingress for hardening headers since ADR 0069
(`[apps.<x>.ingress.static.security_headers]`: a `baseline` preset, HSTS and a validated `csp`). An ordinary
container app has no such option, and its own framework may not send any of those headers (a small Go service, an
old Rails app, a static-file route inside a larger app). The operator then either sets them in the app, edits the
nginx config by hand outside Węglarka's model, or goes without.

The reason #104 was scoped to static sites is the one real design question here: a proxied app may already send the
same header. A static site has no upstream, so a blanket `add_header` is unambiguous; a container app can answer
with its own `Content-Security-Policy` (with a per-request nonce), its own `X-Frame-Options`, or a stricter
`Referrer-Policy`, and the ingress must have a policy for who wins.

Constraints, in priority order (CLAUDE.md): security → elegant, extensible code → RAM economy. The new field is
optional, outside `spec_hash` (state-and-schema.md), and adds an `apps.toml` field, so it bumps
`state::SCHEMA_VERSION` (ADR 0023).

## Decision

**`AppIngress` gets `security_headers: Option<SecurityHeaders>` — the same already-validated type as
`ingress.static.security_headers` — for `kind = "container"` only. The app wins on a conflict: the ingress adds a
header only when the upstream response does not already carry it.**

```toml
[apps.api.ingress.security_headers]
preset = "baseline"                   # X-Content-Type-Options, X-Frame-Options, Referrer-Policy
hsts_max_age_secs = 31536000          # Strict-Transport-Security: max-age=<n>
csp = "default-src 'self'"            # Content-Security-Policy
```

- **One type, one validation function.** `SecurityHeaders`/`SecurityHeadersPreset` and
  `state::validate_security_headers(name, prefix, headers)` are shared with the static table; `prefix` is the
  table the operator wrote (`ingress.static` or `ingress`), so an error names the key that is actually wrong.
  Nothing new is free-form: `csp` is the only operator string (printable ASCII, no `"`/`\`/`$`, ≤ 2048 bytes), the
  preset names constants the generator picks.
- **`kind` owns its key.** `ingress.security_headers` is rejected for `kind = "static"` with a message pointing at
  `ingress.static.security_headers`, and `ingress.static` stays rejected for `kind = "container"`
  (ADR 0069's allowlist, extended by one named field so a future `AppIngress` field still fails to compile until it
  is decided).
- **The app wins, via `map` on `$upstream_http_*`.** nginx cannot test a response header inside `add_header`, so
  each configured header gets an `http {}`-level map per app:

  ```nginx
  map $upstream_http_x_frame_options $wg_api_x_frame_options {
      "" "DENY";          # the app sent nothing → the ingress adds its value
      default "";         # the app sent its own → an empty `add_header` value adds nothing
  }
  ```

  and every proxy `location` of that app carries `add_header X-Frame-Options $wg_api_x_frame_options always;`
  next to the restated `add_header X-Request-Id $request_id always;` — the first `add_header` on a level drops the
  inherited set (ADR 0069's rendering rule), so both live together. The variable name embeds the instance name
  (`-` → `_`, injective over the instance alphabet), so two apps never share a `map` target (nginx refuses a
  duplicate `map`) or a value. Every proxy location of the app is covered: the main one, `streaming_paths`, the
  exact/prefix pairs of `paths`, forward-auth and `auth_exempt_paths` locations and websockets. The
  `authz` subrequest location is not the app's and gets none of them.
- **HSTS in both modes.** `hsts_max_age_secs` renders as configured in `edge` (nginx terminates TLS) and in
  `behind` (Traefik terminates TLS; the header still reaches the browser). The docs warn not to set it here when
  Traefik already sets HSTS for the domain: two `Strict-Transport-Security` headers are an error, and which one a
  browser honours is not something to rely on.
- **Outside `spec_hash`.** `AppIngress` is not part of `HashInput`, so adding or changing the table re-renders
  nginx (`nginx -t` + SIGHUP) and never recreates the container; the docs and a test say so.
- **Schema.** `state::SCHEMA_VERSION` 20 → 21 (`container_security_headers_v21`, a no-op `SCHEMA_STEPS` entry,
  ADR 0023) and the `STATE_SCHEMA` label in the Containerfile move with it. The field is optional, so a v20 file
  needs no data transformation; the first ordinary write stamps v21.

## Consequences

- New operator surface: `[apps.<x>.ingress.security_headers]`, documented in
  [security headers](../../docs/guides/security-headers.md) with the app-wins rule, the HSTS/Traefik note and a
  `## Rollback` entry (`deny_unknown_fields` rejects the table on a downgrade: remove it, or restore both state
  files from before the upgrade). A row in [verification and rollback](../../docs/guides/verify-and-rollback.md)
  and a version in [state schema](../../docs/guides/state-schema.md).
- No `spec_hash` change, no container recreate, no CLI flag in this change (the field is applied through
  `apps update --spec`, like the rest of the spec).
- Tests: model unit tests (parse/round trip, the static key rejected with the right name, the CSP alphabet and
  length, schema v20 file round trip), `spec_hash` assertions for the new field, ingress snapshots (`behind` and
  `edge`) for an app with all three headers plus `streaming_paths` and forward auth, a test that two apps get
  distinct map variables, and an `nginx-e2e` case with an upstream that sends its own `X-Frame-Options` (exactly
  one header, the app's value) and one that sends nothing (the ingress value).

## Rejected alternatives

- **The ingress wins: `proxy_hide_header` plus an unconditional `add_header`.** Hides the app's value and forces
  the operator's. That breaks the case the header exists for — an app-built CSP with a per-request nonce cannot be
  expressed in a static ingress value, so taking the app's policy away makes the app stop working rather than
  harder. It also silently discards the app's own decisions (`SAMEORIGIN`, a stricter referrer policy).
- **A per-spec override flag** (`override = true` next to the header). More surface for v1: two possible outcomes
  for the same conflict, a second behaviour to document and test, and no operator who has asked for it yet. The
  app-wins rule is the safe default; an app that wants the ingress to be final can set the header itself.
- **One key for both kinds, with `ingress.static.security_headers` as a deprecated alias.** A migration with no
  gain: two spellings for one thing, a deprecation window, and the `kind` distinction is exactly what makes the two
  behaviours (unconditional for files, app-wins for a proxy) understandable. Keeping the existing key avoids
  touching every static site and every site environment (ADR 0075) that already uses it.
- **Free-form headers** (`headers = { "X-Foo" = "..." }`). Already rejected in ADR 0069: an injection channel into
  `nginx.conf`, and an easy way to defeat `add_header` inheritance by accident.
- **Starting with CSP only** (the header that needs the app-wins rule most). The type already carries the preset
  and HSTS, the validation is shared, and splitting it would leave two nearly identical tables to document.
