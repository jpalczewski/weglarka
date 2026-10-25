# Path routing on one domain (paths)

By default a domain belongs to a single instance. When one public name has to serve several services (REST under
`/api`, a separate service under `/mcp`, an SPA as the rest), give each instance path prefixes — no extra reverse
proxy in the stack. Decision and rejected alternatives: [ADR 0031](../decisions/0031-path-prefix-routing.md).
Ready-made snippet: [`docs/examples/path-routing.toml`](../examples/path-routing.toml).

```toml
[apps.api]
domains = ["app.example.com"]
paths = ["/api", "/healthz"]     # defaults to ["/"] (the previous behaviour)
[apps.mcp]
domains = ["app.example.com"]
paths = ["/mcp", "/.well-known"]
```

CLI: `weglarka apps add … --path /api --path /healthz [--strip-prefix]`, `apps update <app> --path /x`,
`--remove-path /x`, `--strip-prefix` / `--no-strip-prefix`. The flags are mutually exclusive with `--spec`.

- **Syntax:** `/` or `/seg[/seg…]`, no trailing `/`, no `//` and no `.`/`..` segments, characters
  `[A-Za-z0-9_.-]`, up to 128 bytes. `paths` requires `domains`.
- **Matching:** for `/p` nginx gets `location = /p` and `location ^~ /p/` (so `/pxyz` does not match); `/` is the
  catch-all; the longest prefix wins.
- **Disjointness:** two instances can share a domain only with disjoint prefixes. Identical and nested prefixes
  (`/api` vs `/api/v2`) are rejected (400) with an `overlap` message; `/` coexists with other prefixes. Two `/`
  on one domain is the existing "domain taken" error. A webhook domain stays exclusive.
- **`strip_prefix`** (`[apps.X.ingress]`, default `false`): `/p/x?q=1` reaches the app as `/x?q=1`, and `/p` as
  `/`. Requires a prefix other than `/`.
- **`streaming`** works per instance, i.e. across that instance's paths. **`health.http`** goes through nginx, so
  the request carries the app's first prefix before `health.http.path` (for `/api` and `path = "/up"` the probe
  requests `/api/up`).
- **Ingress only:** changing `paths`/`strip_prefix` renders `nginx.conf`, checks it with `nginx -t` and sends
  SIGHUP; the container, digest and `spec-hash` are untouched. The Traefik file does not change (one router per
  app).
- **`weglarka doctor`:** the `ingress.routes` check prints the effective route table
  (`domain/path -> instance:port`).

## Rollback

This is a state-file schema change (version 5) — `apps.toml` and `state.toml` get `schema_version = 5` on the
first write after the update. Before a downgrade, remove `paths` and `ingress.strip_prefix` from the apps (or
restore the files **from a backup taken before the update**; see [state schema](state-schema.md)).
