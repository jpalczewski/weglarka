# Static sites

A static site (an Astro `dist/`, a Hugo `public/`) is hosted without a container: Węglarka unpacks the built site from
an image and the ingress nginx serves the files. Design and rejected alternatives:
[ADR 0049](../decisions/0049-static-sites.md).

## The artifact

CI builds the site and packs the output into an image `FROM scratch` with exactly one layer:

```dockerfile
FROM scratch
COPY dist/ /
```

Push it to your registry and let the webhook ([webhooks](webhooks.md)) announce it, as for any app. A private registry
works the same way as for apps (`<instance>.registry-auth`, see [first app](first-app.md)). The site must have an
`index.html` at its root, or the deploy is rejected.

## The spec

```toml
[apps.blog]
kind = "static"
image = "registry.example.com/me/blog:latest"
domains = ["blog.example.com"]
# paths = ["/docs"]   # optional, same rules as for apps (path-routing.md)
```

A static site has no process, so the fields that configure one are rejected: `port`, `command`, `env`, `secrets`,
`health`, `volumes`, `shared_volumes`, `shared_networks`, `host_ports`, `depends_on`, `resources`, `security`,
`configs`, `reload_signal` and `start = false`. `ingress` itself is allowed, but only its file-serving options
(below) and `ingress.access_log_skip_paths` — streaming, body-limit and forward-auth options stay rejected, because
a site has no upstream to apply them to.

## What happens on a deploy

1. The image is pulled and its digest is pinned in `state.toml`, as for apps.
2. Węglarka exports the image and unpacks the single layer into
   `<nginx_conf_dir>/sites/<site>/releases/<digest-prefix>/`. The unpacker refuses absolute paths, `..`, symlinks, hard
   links, device files, multi-layer images and archives over the size or file-count limit; nothing is switched when it
   refuses.
3. The relative symlink `current` is replaced with one `rename(2)`, so a visitor sees the old site or the new one,
   never a mixture.
4. The previous release stays on disk next to the new one; older releases are removed.

A failed deploy leaves the served release untouched and records the digest as failed (`weglarka apps show`).

## Per-site options

`[apps.<x>.ingress.static]` renders directly into nginx; every option is optional, outside the spec hash (editing
one only re-renders the ingress, never recreates anything), and rejected with `kind = "container"` ([ADR
0069](../decisions/0069-static-site-ingress-options.md)):

```toml
[apps.blog.ingress.static]
clean_urls = true
not_found_page = "/404.html"
cache_immutable_paths = ["/_astro/"]
cache_revalidate = true
redirects = [
  { from = "/old-post", to = "/blog/new-post" },
  { from = "/blog/", to = "/posts/", prefix = true },
]
feeds = [{ path = "/rss.xml", format = "rss" }]

[apps.blog.ingress.static.security_headers]
preset = "baseline"
hsts_max_age_secs = 31536000
csp = "default-src 'self'"
```

- **`clean_urls`** serves `/about` from `about.html` (`try_files $uri $uri.html $uri/index.html =404;`) instead of
  only `/about/` from `about/index.html`.
- **`not_found_page`** is a path relative to the release root, like `index.html`; it must end in `.html`. The deploy
  gate rejects a release that does not have this file (fail closed, same rule as `index.html`), so `current` is
  never switched to a release whose configured 404 page is missing.
- **`cache_immutable_paths`** gets `Cache-Control: public, max-age=31536000, immutable` — for a build's hashed
  asset directory (`_astro/`, `assets/`, …), never for `index.html`. **`cache_revalidate`** sends
  `Cache-Control: no-cache` for the rest of the site instead of nginx's own heuristic.
- **`redirects`** are real `301`s. `from` must be a path inside the app's own `paths` (or `/` when `paths` is unset);
  `prefix = true` also redirects everything below `from`, keeping the rest of the URL. `to` is either another path
  on the site or an absolute `https://<host>/...` URL.
- **`feeds`** gives a path a fixed `Content-Type` (`rss`, `atom` or `json` → the JSON Feed type,
  `application/feed+json`) that the ingress's own MIME table cannot assign unambiguously from the extension alone
  (an RSS feed and a sitemap are both `.xml`).
- **`security_headers`** adds `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` and a strict
  `Referrer-Policy` to every location of the site (the `baseline` preset, the only one today), plus an optional
  `Strict-Transport-Security` (`hsts_max_age_secs`, without `includeSubDomains`/`preload` — those apply beyond this
  one site's own domain) and an optional `csp` (printable ASCII, no `"`/`\`/`$`, at most 2048 bytes).

Forward auth (#89) and HTTP Basic auth for static sites are tracked separately in
[#169](https://github.com/jpalczewski/weglarka/issues/169); `ingress.auth*` stays rejected on a static site until
that lands.

## A development and a production version

A site that needs both is declared once with environments, and the production one changes only by an explicit
promotion: see [site environments](site-environments.md).

## Limits of this release

- Rolling back to the previous release by command is tracked in #103.
- HTTP Basic auth, and forward auth, for static sites are tracked in #169.
- Static sites are served only by Węglarka's own nginx; the host must run with ingress enabled.

## Rollback

`kind` raised the state schema to version 12; `[apps.<x>.ingress.static]` (per-site options, #104) raised it again to
18 ([state schema](state-schema.md)). Before downgrading Węglarka below schema 12, remove the `kind = "static"` apps
from `apps.toml`; before downgrading below schema 18, remove every `[apps.<x>.ingress.static]` table — either way,
restoring `apps.toml` and `state.toml` from the pre-upgrade backup works too. Drop the `schema_version` marker
afterwards; an older daemon rejects the unknown field or table. Files under `<nginx_conf_dir>/sites/` are ignored by
older versions and can be deleted by hand.
