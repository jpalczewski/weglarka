# 0075 — Static options shared by a site's environments, and a per-environment `robots`

Status: proposed (2026-11-05, issue #545, part of #548)

## Problem

A site declared with environments (ADR 0050) accepts only `track`, `promote_from`, `domains` and `paths` per
environment. The per-site rendering options of ADR 0069 (`not_found_page`, `cache_immutable_paths`,
`cache_revalidate`, `redirects`, `feeds`, `security_headers`) exist only for a plain `kind = "static"` app in
`[apps.<x>]`, so moving a real site (an Astro build with its own 404 page, hashed assets and security headers) to
`[sites]` today means losing all of them. The natural path — one static app now, a development and a production
environment with promotion at launch — is blocked by the choice of declaration shape, not by anything the ingress
cannot do.

Separately (#545), a preview of a site that will later live on its real domain must not be indexed. In a container app
that is one `map $host` in the app's own nginx; a static site cannot express it, because ADR 0069 rightly rejects
free-form headers. The only workaround is a build-time `<meta name="robots">`, which (a) does not cover non-HTML
files such as PDFs or images and (b) breaks the "one artifact, promote it" model of site environments: the
development and production environments serve the **same digest**, so the noindex has to come from the ingress, per
environment.

Constraints, in priority order (CLAUDE.md): security → elegant, extensible code → RAM economy. Every new field is
optional and outside `spec_hash` (state-and-schema.md); a new `apps.toml` field bumps `state::SCHEMA_VERSION`
(ADR 0023).

## Decision

**`[sites.<site>.ingress.static]` holds the ADR 0069 options once for the whole site; `robots` is the one field an
environment may override.**

```toml
[sites.blog]
kind = "static"
image = "ghcr.io/me/blog"

[sites.blog.ingress.static]          # shared by every environment
not_found_page = "/404.html"
cache_immutable_paths = ["/_astro"]
security_headers = { hsts_max_age_secs = 31536000 }

[sites.blog.env.dev]
track = "main"
domains = ["dev.example.com"]
robots = "noindex"                   # the only per-environment override

[sites.blog.env.prod]
promote_from = "dev"
domains = ["example.com"]
```

- **Model.** `SiteSpec` gets an optional `ingress` section holding a `SiteIngress { static_: Option<StaticIngress> }`
  (serde-renamed like `AppIngress::static_`), and `EnvSpec` gets `robots: Option<Robots>`. `SiteIngress` is a
  dedicated type rather than `AppIngress`: streaming, body limits and forward auth configure a proxy to a container,
  which a site environment never has — the allowlist rule of ADR 0069 applied to the site level.
- **`robots` is an enumerated preset**, `enum Robots { Noindex }` in `crates/weglarka-model/src/app.rs`, rendered as
  `add_header X-Robots-Tag "noindex, nofollow" always;`, exactly like `SecurityHeadersPreset`. It is a field of
  `StaticIngress`, so `[apps.<x>.ingress.static] robots = "noindex"` works for a plain static app too. Unset means no
  header. Nothing here accepts a free-form header name or value (ADR 0069's rejected alternative stays rejected).
- **Expansion, not a second renderer.** `environments::expand` copies the site's `StaticIngress` into each instance's
  `spec.ingress.static_` and then overrides `robots` with the environment's when set; an environment that sets only
  `robots` gets a `StaticIngress` carrying just that field. Engine, state, reconcile, deploy gate (`not_found_page`
  must exist in the release), `weglarka promote` and the ingress keep working on instances only — they learn no
  second unit of configuration.
- **Validation stays per expanded instance.** `state::validate_apps` → `validate_app` already checks
  `ingress.static` (paths, redirects inside the instance's own `paths`, the CSP alphabet). The message is wrapped to
  name the **site and environment** (`site blog, environment dev (instance blog-dev): …`), because the table the
  operator edited is `[sites.blog.ingress.static]`, not the derived instance.
- **`spec_hash` is unaffected.** `AppIngress` is outside `HashInput` (ADR 0069), so flipping `robots` on an
  environment only re-renders nginx; a test asserts it.
- **`nginx add_header` inheritance.** A `location` with its own `add_header` drops every header inherited from
  `server`/`http`, so `X-Robots-Tag` is emitted wherever the `security_headers` set is (the site's main location, each
  `cache_immutable_paths` location, each `feed`, each redirect location), always with the restated
  `X-Request-Id`. A site that sets only `robots` therefore restates `X-Request-Id` too.
- **Schema.** One bump, `state::SCHEMA_VERSION` 19 → 20 (`site_static_options_v20`, a no-op `SCHEMA_STEPS` entry,
  ADR 0023). Both fields are optional, so a v19 file needs no data transformation, and the first ordinary write
  stamps the new number.
- **`weglarka sites declare --spec <file>`** takes the same shape, since the request body is the `SiteSpec` body of
  `[sites.<site>]`.

`robots` is deliberately the only per-environment override for now. A whole per-environment `StaticIngress` would
make "one artifact, promote it" harder to reason about (the promoted digest would render differently for reasons
unrelated to the artifact), and `robots` is the field that exists *because* two environments serve the same digest.

## Consequences

- New operator surface: `[sites.<site>.ingress.static]` and `[sites.<site>.env.<env>.robots`, documented in
  [static sites](../../docs/guides/static-sites.md) (`robots`) and
  [site environments](../../docs/guides/site-environments.md) (shared options), with a `## Rollback` entry: an older
  daemon rejects both with `deny_unknown_fields`, so remove the `[sites.<site>.ingress]` table and every
  `robots` key, or restore `apps.toml`/`state.toml` from before the upgrade. A row is added to
  [verification and rollback](../../docs/guides/verify-and-rollback.md) and a version to
  [state schema](../../docs/guides/state-schema.md).
- A promotion never changes the target environment's `robots`: it comes from that environment's own spec, not from
  the digest (an engine test asserts it). That is the point of the feature — one digest, two search-engine
  treatments.
- A shared `not_found_page` is checked against every environment's served release by the existing deploy gate; an
  environment whose release lacks the page is refused exactly as before, with the instance name in the message.
- Tests: model unit tests (parse/serialize round trip, expansion with shared options plus an environment override,
  `robots` alone, unknown field and unknown enum variant rejected, a wrapped error naming site and environment),
  ingress snapshots (`behind` and `edge`) for a site with `robots` plus cache headers, a plain static app with
  `robots`, a `spec_hash` assertion, an engine test for promote, and a daemon integration test for `sites declare`.

## Rejected alternatives

- **A full per-environment `ingress.static` replacement** (`[sites.<x>.env.<env>.ingress.static]` as a whole second
  `StaticIngress`). Every environment would have to repeat the 404 page, cache prefixes and security headers; a site
  with two environments would carry the same block twice, and a hand edit of one half would silently diverge — the
  duplication ADR 0050 avoided for the declaration itself.
- **A field-level merge of a per-environment `StaticIngress` over the shared one.** Elegant at first glance, but it
  makes every future field a merge question (does an empty list mean "inherit" or "clear"?), and the operator can no
  longer tell which value wins without reading the code. A single, explicitly enumerated override is easier to reason
  about and to validate.
- **A free-form header** (`headers = { "X-Robots-Tag" = "noindex" }`). Already rejected in ADR 0069: a direct
  injection channel into `nginx.conf` and an easy way to defeat `add_header` inheritance by accident. An enumerated
  preset with one variant today can grow variants without a schema change.
- **`robots` in the artifact** (`<meta name="robots">` baked into the build). Does not cover non-HTML files, and the
  development and production environments serve the same digest, so the noindex could not differ between them.
- **Listing standalone static apps on the panel's `/sites` page** (item 2 of #548). A separate UI decision with its own
  tests; it is not blocked by this one and is left for its own change.
