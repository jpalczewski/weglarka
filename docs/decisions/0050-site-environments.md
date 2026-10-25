# 0050 — Sites with environments and promotion

Status: proposed (2026-10-25, issue #205)

## Problem

A static site (ADR 0049) is one instance on one domain. A development and a production version of the same site
are two unrelated apps today: the operator copies the digest by hand (`weglarka deploy <app> --image repo@digest`),
and a plain `apps deploy` of the production app pulls its spec tag past the promotion. Nothing records that the two
instances belong together, so nothing can check that what reaches production is what was tested.

Constraints, in priority order: production must change only on an explicit promotion of a known digest (security);
the engine, state and ingress already work on instances and should not learn a second unit of deployment
(extensible code); no extra pulls or copies of a release that is already local (RAM and disk).

## Decision

*Stub — reserved number. The full text follows in the implementing PR; the shape agreed in #205 is:*

- `[sites.<site>]` declares `kind` (v1: `static` only) and a repository-only `image`; `[sites.<site>.env.<env>]`
  sets `domains`/`paths` and exactly one of `track = "<tag>"` (webhook-driven) or `promote_from = "<env>"`.
- Each environment **expands at load** into the ordinary instance `<site>-<env>` (instance names allow only
  `[a-z0-9-]`; `.` separates scopes in `secrets.toml`). Collisions with `[apps]` or another site's expansion are
  rejected. Expanded instances are never written back to `apps.toml`; editing or removing one through `apps` is
  a 409 that names the site.
- A promote-only environment **never resolves a tag**: no webhook, no `apps deploy`, no reconcile pull. Its domain
  is reserved from the start and answers 503 until the first promotion.
- `weglarka promote <site> <env>` deploys the source environment's `current` digest (or `--digest`, or
  `--rollback` to the target's `previous`) through the existing deploy path — health gate, `current` /
  `previous` / `failed` — without a second pull. A source digest marked `failed` is refused.
- Only the artifact moves; domains, paths and every other per-environment setting stay where they are.
- `[sites]` raises `state::SCHEMA_VERSION` to 13 (no-op step, ADR 0023).

## Consequences

To be completed with the implementation: new `sites` endpoints and CLI, `doctor` check `sites.unpromoted`,
guide `docs/guides/site-environments.md` with `## Rollback` and a row in `verify-and-rollback.md`.

## Rejected alternatives

To be completed. Considered so far: a `promote_from` field linking two ordinary `[apps]` entries (lighter, but no
place for shared site settings or for PR previews as short-lived environments, #105); naming expansions
`<site>.<env>` (clashes with the secret scope separator).
