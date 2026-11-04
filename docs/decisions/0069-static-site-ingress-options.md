# 0069 — Static sites: per-site rendering options

Status: accepted (2026-11-04, issue #104)

## Problem

#104 asks for a set of per-site rendering options for `kind = "static"` (ADR 0049): clean URLs, a custom 404
page, cache headers, real 301 redirects, MIME types for feeds, and security headers. All of them only make sense
for a directory backend (no upstream, no process), and none of them should widen what a static site can do beyond
serving files — a static site still has no secrets, no env, no command (ADR 0049's `validate_static`).

A related but separate question is `auth` for static sites (forward via #89, or HTTP Basic via #169): #104
originally listed `auth` in scope, but it is a different kind of decision — it needs a secret, a credentials file
on disk, and a resolution for forward-vs-basic precedence, none of which the six rendering options need. That
question is out of scope here; see "Rejected alternatives".

Constraints, in priority order (CLAUDE.md): security → elegant, extensible code → RAM economy. Every new
`AppSpec`/`AppIngress` field must stay optional and outside `spec_hash` when unset (state-and-schema.md); a new
`apps.toml` field bumps `state::SCHEMA_VERSION` (ADR 0023).

## Decision

**A new, optional `StaticIngress` struct lives under `AppIngress`, serialized as `[apps.<x>.ingress.static]`; it is
rejected for `kind = "container"` and, for `kind = "static"`, replaces the current blanket rejection of `ingress`
with an explicit allowlist.**

- **Where the options live.** `AppIngress` gets a new field:

  ```rust
  /// Per-site rendering options (#104), only for `kind = "static"`. `static` is a Rust keyword, hence the
  /// trailing underscore on the field (same convention as `RawJwk::use_` in `admin_auth.rs`).
  #[serde(default, rename = "static", skip_serializing_if = "Option::is_none")]
  pub static_: Option<StaticIngress>,
  ```

  This is a nested table inside `AppIngress`, not a new top-level `AppSpec` field and not a separate `SiteSpec`:
  ADR 0049 already rejected a separate type for static sites (duplicates webhooks/secrets/domains/reconcile/
  `Plan::build`), and `ingress` is already the home for everything that only changes nginx output without
  touching `spec_hash` (doc comment on `AppIngress`, `app.rs`). A flat set of fields directly on `AppIngress` was
  rejected too: half of them (`streaming`, `auth*`, `strip_prefix`) are meaningless for a directory backend, and
  spreading six more fields flat would make the "which fields apply to which `kind`" question harder to answer by
  reading the struct. The name `site`/`SiteOptions` is unavailable: `[sites]`/`SiteSpec`/`SiteName` already name
  site **environments** (issue #205).

- **Shape of `StaticIngress`** (all fields optional, all outside `spec_hash` — `AppIngress` already is):

  ```rust
  pub struct StaticIngress {
      /// `try_files $uri $uri.html $uri/index.html =404;` instead of the default `$uri $uri/index.html`.
      #[serde(default, skip_serializing_if = "std::ops::Not::not")]
      pub clean_urls: bool,
      /// `error_page 404 <page>;`. Must end in `.html`; same path alphabet as `AppSpec::paths`. The deploy
      /// gate checks the file exists in the release, like `index.html` (ADR 0049), fail closed.
      #[serde(default, skip_serializing_if = "Option::is_none")]
      pub not_found_page: Option<String>,
      /// Prefixes served with `Cache-Control: public, max-age=31536000, immutable` (hashed build assets).
      #[serde(default, skip_serializing_if = "Vec::is_empty")]
      pub cache_immutable_paths: Vec<String>,
      /// The rest of the site gets `Cache-Control: no-cache` instead of nginx's default heuristic.
      #[serde(default, skip_serializing_if = "std::ops::Not::not")]
      pub cache_revalidate: bool,
      /// 301 redirects, exact or prefix. `from` must be inside the site's own `paths`.
      #[serde(default, skip_serializing_if = "Vec::is_empty")]
      pub redirects: Vec<Redirect>,
      /// Extra `location`s with a fixed `Content-Type` for feeds nginx's static MIME table (issue #498)
      /// does not cover unambiguously (`.xml` is ambiguous with a sitemap).
      #[serde(default, skip_serializing_if = "Vec::is_empty")]
      pub feeds: Vec<Feed>,
      /// `add_header`s applied to every location of the site.
      #[serde(default, skip_serializing_if = "Option::is_none")]
      pub security_headers: Option<SecurityHeaders>,
  }

  pub struct Redirect {
      pub from: String,
      pub to: String,
      #[serde(default, skip_serializing_if = "std::ops::Not::not")]
      pub prefix: bool,
  }

  pub struct Feed {
      pub path: String,
      pub format: FeedFormat, // enum: Rss | Atom | Json
  }

  pub struct SecurityHeaders {
      /// Only variant in v1; reserved for future presets without a schema change.
      #[serde(default)]
      pub preset: SecurityHeadersPreset, // enum: Baseline
      #[serde(default, skip_serializing_if = "Option::is_none")]
      pub hsts_max_age_secs: Option<u32>,
      #[serde(default, skip_serializing_if = "Option::is_none")]
      pub csp: Option<String>,
  }
  ```

  No field accepts a free-form HTTP header name or value except `csp` (validated: printable ASCII, no `"`/`\`/`$`,
  ≤ 2048 bytes) — everything else is an enum or a constant the generator chooses, so nothing here is a channel to
  inject arbitrary `nginx.conf` directives. `redirects[].to` and `not_found_page` reuse `check_path_prefix`'s
  alphabet (`to` may also be an absolute `https://<domain>/...` using the same alphabet as `domains`).

- **Validation (`crates/weglarka-model/src/state.rs`).** Replace the single check
  `("ingress", spec.ingress != defaults.ingress)` in `validate_static` with an allowlist via destructuring
  `AppIngress` **without `..`** (the same convention as `read`-scope views, CLAUDE.md "Never break"):

  ```rust
  let AppIngress {
      streaming, stream_timeout_secs, strip_prefix, max_body_size,
      access_log_skip_paths: _,   // fine: identical meaning for files
      streaming_paths, auth, auth_policy, auth_groups, auth_exempt_paths,
      static_: _,                 // validated separately by `StaticIngress::validate`
  } = &spec.ingress;
  // reject every other field that is set, each with its own field name in the message
  ```

  so that a future field added to `AppIngress` without an explicit decision fails to compile instead of silently
  applying to static sites. Symmetrically, `validate_app` rejects `ingress.static` set on `kind = "container"`.
  `identity.rs`'s existing, now-redundant rejection of `ingress.auth = "forward"` on `kind = "static"` stays as is
  (owned by #169, not touched here).

- **Rendering (`crates/weglarka-ingress/src/nginx/location.rs`, `write_directory`).** Each option is additive to
  the existing `root`/`types`/`try_files` block, rendered for both `behind` and `edge`:
  - `clean_urls`: changes the `try_files` fallback chain.
  - `not_found_page`: `error_page 404 <prefix><page>;` with `recursive_error_pages off` (default), so a missing
    404 page itself is an ordinary 404, never a loop.
  - `cache_immutable_paths`/`cache_revalidate`: nested `location ^~ <prefix><p>` blocks before the catch-all.
  - `redirects`: `location = <from> { return 301 <to>$is_args$args; }` (exact) or `rewrite ^<from>(.*)$ <to>$1
    permanent;` (prefix); the server emits `absolute_redirect off;` so a redirect's `Location` reflects what the
    client sent, not nginx's internal `behind`-mode port (an existing gap, unrelated to `kind`, fixed here because
    `redirects` is the first feature that depends on it).
  - `feeds`: `location = <path> { types {} default_type <mime>; charset utf-8; }`.
  - `security_headers`: `add_header ... always;` in every location of the site, **repeating** `X-Request-Id`
    (`add_header` at a level drops every header inherited from `server`, so each new location must restate the
    full set — this was already true before #104, just not yet exercised by a second `add_header` source).

- **Schema.** One bump, `state::SCHEMA_VERSION` 17 → 18 (`static_ingress_options_v18`, a no-op `SCHEMA_STEPS`
  entry, ADR 0023), covering every `StaticIngress` field — all of #104 ships in one PR. If it is later split into
  several PRs, each one that adds a field bumps its own version instead (precedent: `ingress.max_body_size` v6,
  `access_log_skip_paths` v10, `streaming_paths` v11).

## Consequences

- New operator surface: `[apps.<x>.ingress.static]` in `apps.toml`, documented in `docs/guides/static-sites.md`
  (new sections per option) with a `## Rollback` entry (`deny_unknown_fields` rejects the table on a downgrade;
  remove it and the `schema_version` marker, or restore a pre-upgrade copy) and a row in
  `docs/guides/verify-and-rollback.md`.
- Tests before merge: snapshots (`behind` + `edge`) for a site with every option set, for a site with none set
  (byte-identical to pre-#104 output aside from issue #498's MIME table), for `Unreleased` with options set
  (still `503`, no `error_page`/redirects rendered), and for a site sharing a domain with a container app (its
  headers must not leak into the container's locations); model unit tests for every rejected field on both kinds,
  for `redirects[].from` outside the site's `paths`, for a malicious `csp`/`not_found_page`; a schema round-trip
  test (v17 file loads and re-saves as v18); an `nginx-e2e` check for `Content-Type` of a feed and for a relative
  `Location` on a redirect behind a proxy.
- `spec_hash` is unaffected (existing test + `HashInput` snapshot).

## Rejected alternatives

- **A separate `SiteSpec` type.** Already rejected in ADR 0049.
- **Flat fields directly on `AppIngress`.** Mixes options that only make sense for a directory backend with ones
  that only make sense for an upstream; a `kind`-specific nested table reads better and validates with one
  allowlist instead of two.
- **`auth` in this ADR.** Forward auth (#89) and HTTP Basic auth (#169) for static sites are a security decision
  with a secret, a credentials file and a forward-vs-basic precedence question, not a rendering option; #169 owns
  the whole topic (see its updated scope and the #104 description).
- **Free-form headers/MIME types** (e.g. `headers = { "X-Foo" = "..." }`). A direct injection channel into
  `nginx.conf` and an easy way to defeat `add_header` inheritance by accident. Enumerated presets and constants
  instead, with `csp` as the one validated free-form exception.
- **`include mime.types` from the nginx image for feeds.** Breaks the self-contained-config rule (ADR 0005/0006);
  a feed's content type is one more entry in the fixed table from issue #498, not a reason to reintroduce the
  include.
- **Security headers for container apps in the same change.** Deferred to #497: a proxied app may already set its
  own `Content-Type`/CSP/etc., which needs a `proxy_hide_header` policy a static site never has to resolve.
