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
   `<nginx_conf_dir>/sites/<site>/releases/<digest-prefix>/`. The archive itself is streamed into a
   daemon-private scratch directory (`<state dir>/sites-tmp`), never into the directory nginx mounts. The unpacker
   refuses absolute paths, `..`, symlinks, hard links, device files, multi-layer images and archives over the size or
   file-count limit; nothing is switched when it refuses.
3. The relative symlink `current` is replaced with one `rename(2)`, so a visitor sees the old site or the new one,
   never a mixture.
4. The previous release stays on disk next to the new one; older releases are removed.

A served site has no container, so its runtime state is `serving` (`runtime: "serving"` in the API, `serving` in the
CLI): `apps show` and `apps list` would otherwise call a site that is up `missing`. A site that is pinned but whose
`current` link is gone or points at another release is `missing`, and `weglarka doctor` reports it once, in
`sites.current` (the container drift check does not repeat it).

A deploy whose digest already has a complete release on disk does not export the image again — it only switches
`current`. Redeploying the previous release therefore does not need the image store or the registry (both
`weglarka apps rollback` and `weglarka promote --rollback` use the same path); with `--force` and the same digest
the release being served is kept.

A failed deploy leaves the served release untouched and records the digest as failed (`weglarka apps show`).

## Extraction limits

The unpacker bounds an untrusted archive ([ADR 0049](../decisions/0049-static-sites.md), #102). The defaults are
100 000 files and directories and 1 GiB of content; set `[sites]` in `weglarka.toml` to change them:

```toml
[sites]
max_files = 100000
max_bytes = "1g"    # bytes or <n>[k|m|g]; both values must be greater than zero
```

`max_files` counts the files and the implicit parent directories a release needs. A release that trips a limit is
rejected, its partial directory is removed and `current` stays untouched.

## Health checks

`weglarka doctor` reports two static-site checks (only while at least one `kind = "static"` app is declared):

- `sites.directory` — the sites root exists, is a directory, is owned by the daemon's user and is writable by it;
  otherwise the check fails with the path and mode (doctor never creates or repairs it). A group- or world-writable
  root is a warning: anyone who can write it decides what nginx serves.
- `sites.current` — for every static app with a pinned digest, `current` points at `releases/<digest-prefix>` and that
  release has the required files (`index.html` and a configured `not_found_page`). A broken link is a warning;
  `weglarka deploy <app> --force` switches `current` (re-exporting the image only when the release is missing or
  incomplete). It is the one place a broken link is reported: the site shows as `missing`, but `state.drift` stays
  quiet so the same problem is not listed twice.

## Per-site options

`[apps.<x>.ingress.static]` renders directly into nginx; every option is optional, outside the spec hash (editing
one only re-renders the ingress, never recreates anything), and rejected with `kind = "container"` ([ADR
0069](../decisions/0069-static-site-ingress-options.md)):

```toml
[apps.blog.ingress.static]
clean_urls = true
not_found_page = "/404.html"
cache_immutable_paths = ["/_astro"]
cache_revalidate = true
redirects = [
  { from = "/old-post", to = "/blog/new-post" },
  { from = "/blog", to = "/posts", prefix = true },
]
feeds = [{ path = "/rss.xml", format = "rss" }]
robots = "noindex"          # X-Robots-Tag: noindex, nofollow on every location

[apps.blog.ingress.static.security_headers]
preset = "baseline"
hsts_max_age_secs = 31536000
csp = "default-src 'self'"
```

- **`clean_urls`** serves `/about` from `about.html` (`try_files $uri $uri.html $uri/index.html =404;`) instead of
  only `/about/` from `about/index.html`.
- **`not_found_page`** is a path relative to the release root, like `index.html`; it must end in `.html`. The deploy
  gate rejects a release that does not have this file (fail closed, same rule as `index.html`), so `current` is
  never switched to a release whose configured 404 page is missing. An ingress-only `weglarka apps update` deploys
  nothing, so it checks the same files against the release being served: naming a page that release lacks is
  refused with a 400 (`the release blog currently serves cannot satisfy the new spec: …`) and nothing is written —
  deploy a release that contains the file first (`weglarka deploy blog`), then add the option.
- **`cache_immutable_paths`** gets `Cache-Control: public, max-age=31536000, immutable` — for a build's hashed
  asset directory (`_astro/`, `assets/`, …), never for `index.html`. **`cache_revalidate`** sends
  `Cache-Control: no-cache` for the rest of the site instead of nginx's own heuristic.
- **`redirects`** are real `301`s. `from` must be a path inside the app's own `paths` (or `/` when `paths` is unset);
  `prefix = true` also redirects everything below `from`, keeping the rest of the URL. `to` is either another path
  on the site or an absolute `https://<host>/...` URL.
- **`feeds`** gives a path a fixed `Content-Type` (`rss`, `atom` or `json` → the JSON Feed type,
  `application/feed+json`) that the ingress's own MIME table cannot assign unambiguously from the extension alone
  (an RSS feed and a sitemap are both `.xml`).
- **`robots`** sends `X-Robots-Tag: noindex, nofollow` on every location of the site, so nothing it serves (HTML,
  PDF, images) is indexed (`robots = "noindex"`; the only value today). Unset sends no header. It is an enumerated
  preset rather than a free-form header string ([ADR
  0075](../decisions/0075-site-level-static-options.md)); the main use is a preview domain serving the same build as
  production, see [site environments](site-environments.md) for the per-environment override.
- **`security_headers`** adds `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` and a strict
  `Referrer-Policy` to every location of the site (the `baseline` preset, the only one today), plus an optional
  `Strict-Transport-Security` (`hsts_max_age_secs`, without `includeSubDomains`/`preload` — those apply beyond this
  one site's own domain) and an optional `csp` (printable ASCII, no `"`/`\`/`$`, at most 2048 bytes).
  An ordinary container app uses the same table as `[apps.<x>.ingress.security_headers]`, where the app's own
  response header wins over the ingress value — see [security headers](security-headers.md).

Forward auth (#89) and HTTP Basic auth for static sites are tracked separately in
[#169](https://github.com/jpalczewski/weglarka/issues/169); `ingress.auth*` stays rejected on a static site until
that lands.

A standalone static app has no `[sites]` entry. The panel's **Sites** page and `weglarka sites list` still show it,
in a section after the declared sites (with a link to its app page), so moving a site to a plain `kind = "static"`
app never looks like the site disappeared.

## A development and a production version

A site that needs both is declared once with environments, and the production one changes only by an explicit
promotion: see [site environments](site-environments.md).

## Rolling back

`weglarka apps rollback blog` returns the site to the release in `state.toml`'s `previous` and records the release
it left as failed (`rolled back by the operator`). With the previous release still on disk — retention keeps two —
this is a pure `current` symlink switch: neither the image store nor the registry is used. When only the release
directory is missing but the image is still local, Węglarka exports and extracts it again; it pulls only when the
image is gone too.

The digest left behind stays `failed`, so a webhook redelivery or a plain `weglarka deploy blog` does not undo the
rollback (it is reported as a known bad digest). Go forward again deliberately with `weglarka deploy blog
--force`; a newly pushed digest is not marked and deploys normally. A site without a `previous` release is refused
with a 409.

The command applies to a `kind = "static"` site that is not owned by a site environment. A container app is refused
(400): it rolls back automatically when its health gate fails, and manually with `weglarka apps update` (see
[verification and rollback](verify-and-rollback.md)). An environment of a `[sites]` site is also refused (400) with
the hint `weglarka promote <site> <env> --rollback` (see [site environments](site-environments.md)).

## Changing `kind`

`kind` is fixed when the app is added: `weglarka apps update` refuses to switch between `container` and `static`
(409) and changes nothing. To switch, remove the app and add it again with the new spec. If you edit `kind` in
`apps.toml` by hand, reconcile deploys the site first and removes the old container only once the site is served; a
failed release is reported as blocked until you run `weglarka deploy`.

## Limits of this release

- HTTP Basic auth, and forward auth, for static sites are tracked in #169.
- Static sites are served only by Węglarka's own nginx; the host must run with ingress enabled.

## Rollback

`kind` raised the state schema to version 12; `[apps.<x>.ingress.static]` (per-site options, #104), `robots` and the
shared `[sites.<site>.ingress.static]` table (#545/#548) raised it to 20 ([state schema](state-schema.md)). `[sites]` in `weglarka.toml` is not part of the state schema, but
`weglarka.toml` also uses `deny_unknown_fields`: **remove the `[sites]` table before downgrading** to a release that
does not know it (or restore `weglarka.toml` from before the upgrade). Before downgrading Węglarka below schema 12,
remove the `kind = "static"` apps from `apps.toml`; before downgrading below schema 18, remove every
`[apps.<x>.ingress.static]` table, and before downgrading below schema 20 also remove `robots` and the shared
`[sites.<site>.ingress]` table — either way, restoring `apps.toml` and `state.toml` from the pre-upgrade backup works
too. Drop the `schema_version` marker afterwards; an older daemon rejects the unknown field or table. Files
under `<nginx_conf_dir>/sites/` and the daemon-private `<state dir>/sites-tmp` are ignored by older versions and can
be deleted by hand.
