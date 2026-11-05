# 0078 — OAuth-protected resource paths and generated discovery routes

Status: proposed (2026-11-05, issue #215)

## Problem

One host often mixes access modes. Take `app.example.com`: `/` and `/api` are a browser UI behind forward
auth (ADR 0052), `/mcp` is an API that checks bearer tokens itself (an MCP server), and the discovery
documents for that API must sit at the host root. Forward auth and `auth_exempt_paths` cover the first two.
Two things are still missing:

- **Discovery.** An MCP client (spec 2025-11-25) that gets a `401` from `https://app.example.com/mcp` looks
  for the protected resource metadata (RFC 9728) at `/.well-known/oauth-protected-resource/mcp` (path
  insertion), then at the root. Today every app has to serve that document at the host root itself. That's a
  routing workaround, and it collides with the app that owns `/` on a shared domain. Clients written against
  the 2025-03-26 spec instead fetch `/.well-known/oauth-authorization-server` from the API host.
- **A route that ends at the app's own token check.** It needs no `auth_request` even when the app uses
  forward auth, no redirect between `/mcp` and `/mcp/` (MCP clients treat one as a hard failure), and
  streaming settings (Streamable HTTP and SSE are long-lived). Today that takes an exempt path plus a
  streaming path: two lists that the plan forbids from overlapping.

Constraints, in priority order:
- No client-controlled byte in a generated document. Never weaken forward auth for the rest of the app.
- One implementation for `behind` and `edge`.
- Reload, never recreate.

## Decision

### Field

`AppIngress.oauth_resources`: a list of paths in the public URL space, e.g. `["/mcp"]`. Each entry declares an
**OAuth-protected resource**: the app checks the tokens, and Węglarka routes the path and publishes its discovery
documents. It's one field next to `auth_exempt_paths` and `streaming_paths`, not attributes on `paths` entries
(see Rejected alternatives).

**Lexical validation (model, `validate_app`):**
- `paths` syntax (ADR 0031): no trailing slash, since an entry always covers the exact path and everything below it.
- Not `/`. Not under `/.well-known/`, `/internal/weglarka/` or the admin relay prefix (`/_weglarka/`).
- No duplicates, and no entry nested in another (`/mcp` together with `/mcp/v2`).
- At most 16 entries.
- Only for `kind = "container"`, and the app needs `domains`.

**Plan validation (`weglarka-ingress::Plan::build`, host-aware):**
- `[identity]` is required, because the metadata names its issuer. Without it the plan is refused with
  `IngressError::OAuthResourceWithoutIdentity`, the same way as a forward app without `[identity]`. The last
  good `nginx.conf` stays.
- The identity provider's own instance can't declare resources.
- An entry may overlap neither the app's `streaming_paths` nor its `auth_exempt_paths`. Overlap is refused,
  because the entry already implies both.
- On an app routed under non-root `paths`, each entry must lie inside one of its prefixes. `strip_prefix = true`
  is refused for now: the public path would need prefix arithmetic, the same limit as `streaming_paths` (ADR 0047).
- Each generated well-known path is a claim on every domain of the app. Another app's prefix that covers it
  (`/.well-known` or `/.well-known/oauth-protected-resource`) is a `PathConflict`, and so is an identical
  resource path on a shared domain.

### Rendering (nginx, both modes, both entrypoints)

**1. Resource locations.** For each entry `/p` in the app's server: `location = /p` and `location ^~ /p/`. They
are full app locations:
- same upstream, `max_body_size` and `strip_prefix` handling;
- the streaming directives of `streaming_paths`: buffering off and `STREAMING_PATH_TIMEOUT_SECS`;
- **no `auth_request`** and no `Remote-*` re-emission, even when the app uses forward auth;
- in a forward app, the raw-URI guard of an exempt location (`exempt: true`). nginx matches the normalized path
  while the upstream gets the raw URI, so `/mcp/..;/admin` can't reach a protected path unguarded.

So the only gate is the app's own token check. This reuses the generator's one location model (`Location {
auth, long_lived, … }`); there is no second code path. The http-level `Remote-*` stripping (ADR 0052) still
applies, so a client can't inject an identity into the API.

**2. Protected resource metadata (RFC 9728).** For each entry `/p`, rendered once per server:

```nginx
location = /.well-known/oauth-protected-resource/p {
    if ($wg_oauth_origin = "") { return 404; }
    default_type application/json;
    add_header Cache-Control "public, max-age=300" always;
    add_header Access-Control-Allow-Origin "*" always;
    add_header Access-Control-Allow-Methods "GET, OPTIONS" always;
    add_header Access-Control-Allow-Headers "*" always;
    if ($request_method = OPTIONS) { return 204; }
    return 200 '{"resource":"$wg_oauth_origin/p","authorization_servers":["<issuer>"],"bearer_methods_supported":["header"]}';
}
```

- `$wg_oauth_origin` is an http-level `map $host` from every domain that serves a resource to the literal
  `https://<domain>`, with `default ""`. So the document never contains a byte the client sent, and a host
  outside the map gets `404`.
- The scheme is always `https`, in `behind` too. RFC 8707/9728 resource identifiers are `https`, and TLS ends at
  the edge (Traefik or nginx) either way.
- Domains, paths and the issuer are already validated to characters that need no JSON or nginx escaping
  (`[a-z0-9.-]`, `paths` syntax, `check_issuer`). The generator asserts that instead of escaping.
- `resource` has no trailing slash. A client's RFC 8707 `resource` (and the OIDC client's `audience`) must match
  it byte for byte.
- Nothing is rendered at the root `/.well-known/oauth-protected-resource`. Clients try the path-inserted URL
  first, and on a shared domain the root document would belong to no single resource.

**3. Legacy authorization server discovery.** Once per server that serves at least one resource:

```nginx
location = /.well-known/oauth-authorization-server { return 302 <issuer>/.well-known/oauth-authorization-server; }
```

This is a redirect, not a proxy. The app host never relays the provider's document, so the request needs no
second upstream and no Host/`X-Forwarded-*` rewriting. Clients that follow the 2025-11-25 spec go to the issuer
named in the metadata and never hit this location.

**4. Unchanged.** Traefik, the probe socket and the access-control file. The provider's `default_policy: deny`
never sees these paths, because they make no authz subrequest.

### Invariants

- `oauth_resources` is ingress-only. It's outside `spec_hash` (all of `AppIngress` is) and omitted when empty,
  so a change re-renders nginx (`nginx -t` + reload) and never recreates a container. An empty list renders
  byte for byte as before.
- New `apps.toml` field: `state::SCHEMA_VERSION` 22 → 23 with a no-op step `oauth_resources_v23` (ADR 0023).
- The types land before the rendering. Until the ingress PR lifts it, a non-empty `oauth_resources` is rejected
  ("oauth_resources is not enabled in this release"), because a field that's accepted but not rendered would
  silently serve nothing (the ADR 0052 P0 rule).
- `exposure` (#216) is out of scope. It's a separate listener, and the field lands with that issue.

### Surface

- API app view (allowlist projection) and `apps show` carry `oauth_resources`.
- CLI: `--oauth-resource <path>` (repeatable) on `deploy` and `apps update`, next to `--streaming-path`. Plus
  `--no-oauth-resources` on `apps update`, like `--no-streaming-paths`.
- `doctor ingress.oauth_resources`, per resource URL:
  - fetch the metadata through the probe socket (ADR 0054) and check that `resource` and
    `authorization_servers` match: an error otherwise;
  - warn when no OIDC client (`[apps.*.oidc]`, `[oidc_clients.*]`) lists the resource URL in `audience`. A
    token for it can't be issued with an RFC 8707 audience then, but opaque-token setups are legitimate, so it's
    not an error.

## Consequences

- `apps.toml` with `oauth_resources` is refused by an older daemon (`deny_unknown_fields`, schema gate). Before
  a downgrade, remove the field or restore the pre-upgrade files. This goes in the guide's `## Rollback` and in
  `verify-and-rollback.md`.
- Guide: `docs/guides/oauth-resources.md` (MCP example with forward auth on `/` and `oauth_resources = ["/mcp"]`),
  linked from `forward-auth.md` and `streaming.md`.
- Tests:
  - model validation and round trip, hash stability, schema step;
  - plan validation: without `[identity]`, overlaps, conflicts on a shared domain, the prefix rule;
  - nginx snapshots in `behind` and `edge` × http/https: a forward app with a resource, a non-forward app with a
    resource, two resources on a shared domain, the "no resource" config unchanged;
  - `nginx -t` (`nginx-e2e`) with the provider absent;
  - an extension of `test-forwarded-headers.sh`: a client `Remote-User` never reaches the upstream on a resource
    path, `/mcp` and `/mcp/` both reach the app without `30x`, the metadata JSON is exact, an unknown `Host` gets
    `404` on the metadata path.
- Implementation in three PRs: types (S1), ingress (S2), surface and docs (S3). The contract comment on #215
  holds the briefs.

## Rejected alternatives

- **Attributes on `paths` entries** (`paths = [{ path = "/mcp", auth = "oidc" }]`, the original #215 proposal).
  `paths` are the prefixes that one app claims on a shared domain, while the access mode is a property of a sub-path
  inside the app. Attributes on them would turn every `paths` reader into a string-or-table match and make the
  schema change non-additive. Another app on the same domain already has its own `ingress.auth`.
- **`auth = "oidc"` as a third app-level mode.** It would make the whole app public at the ingress to get one API
  path, the wrong default for the UI next to it.
- **Proxying the metadata from the app.** It would leave the root routing workaround in every app and depend on
  the app agreeing with Węglarka about `resource` and the issuer. Both are facts Węglarka already owns.
- **Building `resource` from `$host`.** Simpler, but it puts a client-sent value in the document. The map keeps
  it literal at no runtime cost.
- **Proxying `/.well-known/oauth-authorization-server` to the provider.** It needs Host and `X-Forwarded-*`
  rewriting so the provider names the right issuer, and a second upstream on every app server, all for a legacy
  client path. A redirect costs nothing.
