# Site environments

A static site often needs two versions: a development one that follows the newest build, and a production one that
changes only when you decide. `[sites]` in `apps.toml` declares both in one place, and `weglarka promote` moves the
exact digest the development environment runs into production — without pulling it again. Design:
[ADR 0050](../decisions/0050-site-environments.md). This release supports `kind = "static"` sites
([static sites](static-sites.md)); container environments are a follow-up.

## Declaring a site

```toml
[sites.blog]
kind = "static"
image = "ghcr.io/me/blog"          # the repository only; no tag, no digest

[sites.blog.env.dev]
track = "main"                     # the webhook for ghcr.io/me/blog:main deploys here
domains = ["dev.example.com"]

[sites.blog.env.prod]
promote_from = "dev"               # changes only through `weglarka promote`
domains = ["example.com"]
```

Each environment sets exactly one of `track` (a tag the webhook follows) or `promote_from` (the environment whose
digest it receives); `domains` and `paths` work as for any app ([path routing](path-routing.md)). The same can be
done with the CLI from a file holding the body of `[sites.blog]`:

```sh
weglarka sites declare blog --spec blog.toml
weglarka sites list
weglarka sites show blog
```

At load every environment becomes the ordinary instance `<site>-<env>` (`blog-dev`, `blog-prod`), so secrets scope,
`state.toml`, `weglarka status` and the ingress all see plain instances; `weglarka apps list` shows the site and
environment in its `SITE` column. Rules checked when `apps.toml` is read:

- the expanded name must not clash with an `[apps]` entry or with another site's expansion (`a` + `b-c` and `a-b` + `c`
  both give `a-b-c`);
- `promote_from` must name another environment of the same site, with no cycles — every chain ends in a `track`
  environment;
- the instances are **not** written back to `apps.toml`: change a site with `weglarka sites declare` (or by editing the
  `[sites]` section), not with `apps update` or `apps remove`, which answer 409 and name the site.

## What the webhook does

A push of `ghcr.io/me/blog:main` deploys `blog-dev` only. A promote-only environment never resolves a tag: it has
`auto_update = false`, `weglarka deploy blog-prod` and `weglarka push` to it are refused, and the reconcile loop does
nothing for it. Until its first promotion its domain is reserved but answers `503`, and `weglarka doctor` warns
(`sites.unpromoted`).

The route switches from 503 to the site as soon as the release exists when a webhook, `weglarka promote`, `deploy` or
`push` made it; a first release made by the periodic reconcile pass is picked up by the next ingress refresh, at most
one `reconcile_interval_secs` later. Changing a `track` tag with `sites declare` takes effect on the next webhook or
`weglarka deploy <site>-<env>`, not immediately. `weglarka apps list` shows an environment that has no release yet
as `missing`; the `SITE` column and the `sites.unpromoted` check explain why.

## Promoting

```sh
weglarka promote blog prod --dry-run   # the digests on both sides; changes nothing
weglarka promote blog prod             # deploys dev's current digest to prod
weglarka promote blog prod --digest sha256:…
weglarka promote blog prod --rollback  # back to prod's previous digest
```

A promotion is a deploy of `blog-prod`: it keeps the usual `current` / `previous` / `failed` bookkeeping and switches the
`current` symlink atomically. The release is built from the image already in Podman's store (it is `current` or
`previous` of the source environment), so there is no second pull. Details:

- A digest that failed to deploy in the source environment is refused.
- `--digest` takes any digest of the site's repository. If the image was pruned, it is pulled with the credentials of
  the target instance ([private registries](first-app.md)); otherwise nothing is pulled.
- `--rollback` returns to the target's `previous` digest; promoting again toggles back.
- Only the artifact moves. Domains and paths stay per environment.
- The dry run reports digests and generations; Węglarka does not record deploy times.

## Removing a site

```sh
weglarka sites remove blog            # refused while an environment serves a release
weglarka sites remove blog --purge    # also forgets their state
```

Like `apps remove`, this leaves the unpacked releases under `<nginx_conf_dir>/sites/` on disk.

## Rollback

`[sites]` raises the state schema to version 13 ([state schema](state-schema.md)). Before downgrading Węglarka, remove
the `[sites.*]` sections from `apps.toml` and drop the `schema_version` marker, or restore `apps.toml` and `state.toml`
from the pre-upgrade backup; an older daemon rejects the unknown section. To keep the environments running, first add
them as plain apps, for example `weglarka apps add blog-prod --spec …` with `kind = "static"` and the digest you want
pinned via `weglarka push blog-prod --image ghcr.io/me/blog@sha256:…` — the state entries of `blog-dev` and `blog-prod`
are ordinary instance state and carry over.
