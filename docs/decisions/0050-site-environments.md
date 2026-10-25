# 0050 — Sites with environments and promotion

Status: accepted (2026-10-25, issue #205)

## Problem

A static site (ADR 0049) is one instance on one domain. A development and a production version of the same site
are two unrelated apps today: the operator copies the digest by hand (`weglarka deploy <app> --image repo@digest`),
and a plain `apps deploy` of the production app pulls its spec tag past the promotion. Nothing records that the two
instances belong together, so nothing can check that what reaches production is what was tested.

Constraints, in priority order: production must change only on an explicit promotion of a known digest (security);
the engine, state and ingress already work on instances and should not learn a second unit of deployment
(extensible code); no extra pulls or copies of a release that is already local (RAM and disk).

## Decision

- `[sites.<site>]` declares `kind` (v1: `static` only) and a repository-only `image`; `[sites.<site>.env.<env>]`
  sets `domains`/`paths` and exactly one of `track = "<tag>"` (webhook-driven) or `promote_from = "<env>"`.
  `promote_from` must name another environment of the same site and chains must not cycle.
- Each environment **expands at load** into the ordinary instance `<site>-<env>` (instance names allow only
  `[a-z0-9-]`; `.` separates scopes in `secrets.toml`). Collisions with `[apps]` or another site's expansion are
  rejected when the file is read. `AppsFile` deserializes through `RawAppsFile` (`try_from`/`into`): the expansion
  fills `apps` and an in-memory origin map (`origins`, never serialized); saving strips the expanded instances
  again, so a file without `[sites]` round-trips unchanged. Editing or removing an expanded instance through
  `apps update`/`remove`/`add` is a 409 that names the site (`EngineError::ManagedBySite`).
- A `track` environment becomes `image = "<repo>:<tag>"`; a promote-only one keeps the bare repository with
  `auto_update = false`. It **never resolves a tag**: no webhook match, a tag-sourced deploy (`apps deploy`,
  `push`) is refused (`EngineError::PromoteOnly`), and reconcile treats it as blocked (quietly) while it has no
  release. Its domain is reserved from the start; until the first release the static route renders `return 503`
  (`NginxOptions::unreleased`, filled by the daemon from state) and `doctor` warns (`sites.unpromoted`).
- `weglarka promote <site> <env>` deploys the source environment's `current` digest (or `--digest`, or
  `--rollback` to the target's `previous`) through the existing static deploy with `DigestSource::Local` — the same
  path `weglarka push` uses — so the health/release gate and `current` / `previous` / `failed` are unchanged and the
  image already in the local store is not pulled again (an image that was pruned is pulled with the target's
  credentials). A digest marked `failed` in the source environment is refused; `--dry-run` reports the digests on
  both sides (state records no deploy times, so none are shown).
- Only the artifact moves; domains, paths and every other per-environment setting stay where they are.
- `[sites]` raises `state::SCHEMA_VERSION` to 13 (no-op step, ADR 0023).
- API: `GET /v1/sites`, `GET|PUT|DELETE /v1/sites/{site}`, `POST /v1/sites/{site}/envs/{env}/promote`; CLI:
  `weglarka sites list|show|declare|remove`, `weglarka promote`.

## Consequences

- Engine, state, reconcile, webhook matching and ingress still see only instances; the one new engine concept is the
  origin of an instance, read from `AppsFile`.
- A site is declared in one place, and what reaches production is exactly a digest that ran in the source
  environment. Production cannot move by accident: no tag, webhook or reconcile pass reaches it.
- Downgrade: an older daemon rejects `[sites]` (`deny_unknown_fields`) and schema 13 with the readable message of
  ADR 0023; see `docs/guides/site-environments.md` (`## Rollback`).
- Expanded instances are invisible in `apps.toml`, so `apps list` carries a `SITE` column and the admin API a
  `site` field on app summaries.
- A first release of a plain static site now also answers 503 (not 404) until its first deploy.
- Container environments (per-environment secrets scope, volumes, data copy from #110) and PR previews as
  short-lived environments (#105) are left for follow-ups on this shape.

## Rejected alternatives

- A `promote_from` field linking two ordinary `[apps]` entries: lighter, but no place for settings shared by the
  environments of a site, no unit that names "the site" in the API and CLI, and PR previews (#105) would have to
  invent one later.
- Naming expansions `<site>.<env>`: the dot is the secret scope separator and is not allowed in instance names.
- Writing the expansion back to `apps.toml`: the file would carry the same fact twice and a hand edit of one half
  would silently diverge from the site.
- Promoting by re-pulling `repo@digest` (`push_reference`): a registry round trip and a second place where the pull can
  fail, for an image that is already local; `DigestSource::Local` gives the same deploy path without it.
