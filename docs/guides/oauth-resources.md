# OAuth-protected resource paths (ingress.oauth_resources)

One host often mixes access modes. `app.example.com` serves the browser UI behind
[forward auth](forward-auth.md), while `/mcp` is an MCP server that checks bearer tokens itself. The UI must not
be public, and the API cannot follow a login redirect. `ingress.oauth_resources` declares such a path: Węglarka
routes it as a long-lived stream without `auth_request`, and publishes the resource's discovery document at the
host root. Decision and rejected alternatives:
[ADR 0078](../decisions/0078-oauth-protected-resources.md).

```toml
# apps.toml — an MCP server on /mcp, the UI behind the provider's login
[apps.app]
image = "ghcr.io/example/app:latest"
domains = ["app.example.com"]
port = 8080

[apps.app.ingress]
auth = "forward"                 # the UI at / needs a login
oauth_resources = ["/mcp"]       # the API checks its own tokens
```

Via the CLI: `weglarka apps update app --oauth-resource /mcp` (repeatable; replaces the list),
`--no-oauth-resources` clears it, and `apps add` takes the same flag.

## What a resource path gets

- **Its own locations** (`/mcp` and `/mcp/`): the app's upstream, body limit and prefix handling, buffering off
  with the long streaming timeouts of [streaming](streaming.md), **no `auth_request`** — the app's own token check
  is the only gate — and, in a forward-auth app, the same unusual-URI guard as an
  [exempt path](forward-auth.md) (`/mcp/..;/admin` cannot reach a protected path unguarded).
- **The public metadata document** at `/.well-known/oauth-protected-resource/mcp` (RFC 9728 path insertion,
  rendered once per server that serves the resource):

  ```json
  {"resource":"https://app.example.com/mcp","authorization_servers":["https://auth.example.com"],"bearer_methods_supported":["header"]}
  ```

  The response is `application/json` with `Cache-Control: public, max-age=300` and permissive CORS headers
  (`GET`/`OPTIONS`, a `204` to a preflight). `resource` is built from a map of the domains that serve the
  resource, never from the request's `Host`: a host outside that map gets `404`, and no byte the client sent
  reaches the document. The scheme is always `https`, in `behind` and `edge` mode alike.
- **A legacy authorization-server redirect:** `/.well-known/oauth-authorization-server` on the same host answers
  `302` to `<issuer>/.well-known/oauth-authorization-server`. Clients written against the 2025-03-26 MCP spec
  fetch that URL from the API host; newer ones follow the `authorization_servers` entry instead.
- **Nothing else changes.** Traefik (in `behind` mode), the probe socket and the access rules are untouched, and
  the generated locations make no authorization subrequest, so the provider never sees these paths.

`oauth_resources` is ingress-only, like the rest of `ingress`: a change re-renders `nginx.conf`, runs `nginx -t`
and reloads. The container is not recreated and `spec-hash` does not change.

## Matching the audience byte for byte

A client that wants a token scoped to the resource sends `resource=https://app.example.com/mcp` (RFC 8707), and
the provider issues it only when an OIDC client lists that exact string in `audience`:

```toml
[apps.app.oidc]
audience = ["https://app.example.com/mcp"]
```

or, for a client Węglarka does not run:

```toml
[oidc_clients.mcp-cli]
name = "MCP CLI"
audience = ["https://app.example.com/mcp"]
```

The comparison is byte for byte and the metadata's `resource` has **no trailing slash**: `…/mcp/` is a different
resource and does not match. Only one string per resource URL is needed — a client id is shared by every
resource it may ask for.

## Validation rules and limits

Model (`apps.toml` loading and `--spec`), each error naming `<app>: ingress.oauth_resources …`:

- `paths` syntax ([path routing](path-routing.md)): `/seg[/seg…]`, segments of `[A-Za-z0-9_.-]`, no trailing
  slash, at most 128 bytes per entry; `/` is refused (it would take over the whole app).
- Not under the prefixes Węglarka's generated config owns: `/.well-known`, `/internal/weglarka`, `/_weglarka`.
- At most **16** entries per app; no duplicates, and no entry nested in another (`/mcp` with `/mcp/v2` is
  refused, `/mcp` with `/mcpx` is fine — entries are compared by whole segments, and one entry covers everything
  below it anyway).
- Only for `kind = "container"`, and the app needs at least one `domains`.

Ingress plan (crosses apps and the host config, so a bad combination refuses the render and the previous
`nginx.conf` keeps serving):

- `[identity]` is required — the document names its issuer; the identity provider's own instance cannot declare
  resources.
- An entry may overlap neither `streaming_paths` nor `auth_exempt_paths` (the entry already implies both), and on
  an app routed under `paths` prefixes each entry must lie inside one of them. `strip_prefix = true` is refused
  for now.
- A generated well-known path is a claim on every domain of the app: another app's prefix that covers it, or the
  same resource path on a shared domain, is a path conflict.

## Check

`weglarka doctor` runs `ingress.oauth_resources`: for every resource of every started app it fetches
`/.well-known/oauth-protected-resource<path>` through the probe socket with the app's domain as `Host`, and
reports an **error** unless the answer is `200` and its JSON names the expected `resource` and the `[identity]`
issuer as the only entry of `authorization_servers`. A mismatch means a discovering client gets a document it
cannot use.

When the metadata is right but **no OIDC client lists the resource URL in `audience`**, the check warns instead of
failing: a client cannot ask for an RFC 8707 token scoped to the resource then, but a setup with opaque tokens and
its own introspection is legitimate. Apps without resources (and a host without `[identity]`) add no line at all,
like `identity.forward`.

## Rollback

The nginx change is output only: removing the entry (`weglarka apps update <app> --no-oauth-resources`) and
reconciling restores the previous config, and the app's container is untouched.

`apps.toml` with `oauth_resources` is a schema change (version 23, [ADR 0023](../decisions/0023-state-schema-version.md)):
a daemon from before this stage **refuses the file** (`deny_unknown_fields`, and the newer `schema_version` read
as "written by a newer Węglarka"). Before downgrading, remove the field from `apps.toml` or restore `apps.toml`
and `state.toml` from the backup taken before the upgrade; see [state schema](state-schema.md) and
[verify and rollback](verify-and-rollback.md).
