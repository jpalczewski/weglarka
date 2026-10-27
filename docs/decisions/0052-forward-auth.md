# 0052 — Forward auth in nginx

Status: proposed (2026-10-27, issue #42)

## Problem

Apps that have no login of their own, or whose login is not trusted, need authentication in front of them.
Węglarka's nginx is in the request path in both ingress modes, but today a client can send any header to an
upstream, including an identity header (`Remote-User`) an app might trust.

Constraints, in priority order: fail closed (provider down or deny means no access, never open access); a client
can never inject an identity; one implementation for `behind` and `edge`; reload, never recreate.

## Decision

The contracts live in the comments on #89 (forward auth), #90 (access control) and #42 (map). Summary:

- `AppIngress` gets `auth` (`none` default, `forward`), `auth_policy`, `auth_groups` and `auth_exempt_paths`.
  They change nginx output only and stay outside `spec_hash`.
- nginx performs `auth_request` against the provider in both modes; the Traefik generator is unchanged.
  `Remote-*` headers are stripped once at `http {}` level and re-emitted from the authz result only in
  protected locations, always as the full proxy header set.
- Exempt paths are structural (a location without `auth_request`), never a `bypass` rule. The daemon's health
  probe needs no exemption: it arrives on the probe socket (ADR 0054), which the authz location lets through.
- Access control is generated with `default_policy: deny` and a constant portal rule, so it never flips with the
  number of forward apps (#90).
- **P0 adds only the fields, their lexical validation and the schema bump, and rejects `auth = "forward"` and
  every `auth_*` value** ("forward auth is not enabled in this release"). The nginx work landed in P5, which
  lifts the gate for `auth` and `auth_exempt_paths`; `auth_policy` and `auth_groups` stay gated until #90 turns
  them into provider access rules.

- `auth_policy` and `auth_groups` stay gated after P5: nginx cannot enforce them, and an accepted-but-unenforced
  restriction would be worse than a refusal. They are lifted when the provider's access rules are rendered (#90).
- The `unix:` probe exemption relies on the probe socket's `0700` directory being mounted only into nginx (the
  forwarder's socket directory is a different one), so nothing else can speak on that listener.

## Consequences

- `apps.toml` gains the four `ingress` fields (schema 14); see ADR 0051 for compatibility and rollback.
- A forward app needs `[identity]` and domains (host-aware validation, P4).
- Tests in P5: snapshots in both modes, `nginx -t` with the provider absent, header tests next to
  `test-forwarded-headers.sh`.

## Rejected alternatives

- Traefik `forwardAuth`: covers only `behind`, and leaves `edge` with a second implementation.
- Per-path attributes on `paths` entries and `exposure`: deferred (#215 shrinks to app mode plus exceptions, #216).
- A `bypass` rule for exempt paths: an ACL mistake would open the whole domain instead of one location.
