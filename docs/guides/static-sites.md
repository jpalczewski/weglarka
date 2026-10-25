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
`configs`, `reload_signal`, non-default `ingress` and `start = false`.

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

## Limits of this release

- Rolling back to the previous release by command, per-site options (404 page, redirects, cache headers) and HTTP
  Basic auth are tracked in #103, #104 and #169.
- Static sites are served only by Węglarka's own nginx; the host must run with ingress enabled.

## Rollback

`kind` raises the state schema to version 12 ([state schema](state-schema.md)). Before downgrading Węglarka, remove the
`kind = "static"` apps from `apps.toml` (or restore `apps.toml` and `state.toml` from the pre-upgrade backup) and drop
the `schema_version` marker; an older daemon rejects the unknown field. Files under `<nginx_conf_dir>/sites/` are
ignored by older versions and can be deleted by hand.
