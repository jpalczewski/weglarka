# 0051 — Identity provider integration

Status: accepted (2026-10-27, issue #42); OIDC clients and the provider wiring landed 2026-10-28 (#91, #88)

## Problem

Apps behind Węglarka authenticate users on their own, or not at all. Operators who run an OIDC provider
(Authelia) keep its clients, secrets and access rules in a hand-written config that drifts from `apps.toml`,
and Węglarka itself (the admin panel, #43) needs a login that is not a shared token. The provider's list
sections (`identity_providers.oidc.clients`, `access_control`) are replaced wholesale by the last config source,
so a partially generated config silently drops whatever the operator kept in them.

Constraints, in priority order: a field that is accepted but not enforced must never leave an app public
(security); the provider is the host's root of trust, so who declares it is an operator decision; the adapter
must be replaceable; no new long-running process.

## Decision

The contracts live in the comments on #42 (map), #88 (provider), #91 (OIDC clients), #212 (pipeline) and #213
(credentials). Summary of what this ADR fixes:

- The provider is an ordinary app instance named in `weglarka.toml` `[identity]` (`provider`, `instance`,
  `issuer`, optional `upstream`). The section is operator-owned like `[acme]`; a change needs a host edit and a
  daemon restart.
- Węglarka owns `identity_providers.oidc.clients` and `access_control` as whole sections. It renders them into a
  versioned directory mounted read-only into the provider, switched by an atomic `current` symlink. The
  provider's command must load that directory as its last `--config`.
- Clients come from `AppSpec.oidc` (apps Węglarka runs) and `[oidc_clients.<id>]` in `apps.toml` (external apps,
  operator-supplied digest). Generated files contain digests only, never secrets.
- Everything behavioural (`oidc` injection, pipeline, credentials, renderer crate) lands in later PRs. **P0 adds
  only the types, their lexical validation and one schema bump (13 to 14), and rejects every non-default value**
  with "<feature> is not enabled in this release". Each later PR lifts exactly its own gate.
- None of the new fields enters `spec_hash` in P0; when `oidc` is wired, the injected env and secret bindings go
  through the same path as ordinary `env`/`secrets`.

## Consequences

- `weglarka.toml` gains `[identity]`; `apps.toml` gains `oidc`, `ingress.auth*` and `[oidc_clients]`. Schema 14
  and `deny_unknown_fields` break a downgrade: remove the fields or restore the state files from a copy
  (`docs/guides/verify-and-rollback.md`, `docs/guides/state-schema.md`).
- The operator guide is [identity provider](../guides/identity-provider.md), added with the wiring PR (#91, #88).
- Tests: round trip of default files byte for byte, unchanged `spec_hash`, one gate test per field.

## Rejected alternatives

- `class = "infra"` on `AppSpec`: every planned behaviour derives from the one name in `[identity].instance`.
- Declaring the provider in `apps.toml`: it would let anyone with API access choose who decides authentication.
- Merging with the operator's lists instead of owning them: the provider's config merge cannot do it.

## Implementation notes (wiring, #91 and #88)

- `effective_spec(instance, spec, identity)` in the model is the one overlay of everything the integration injects
  (client id and issuer env, the client-secret binding, the implicit `depends_on` on the provider). The engine reads it at
  every place that used to read `spec.env`/`spec.secrets` (hash, materialisation, container creation, waiting check,
  `weglarka run`), so none can miss an injected value.
- The generator (`AutheliaGenerator` in `weglarka-identity`) is registered when `[identity]` is set and emits both files.
  The generated mount is part of the consumer's hash (ADR 0055), so enabling `[identity]` recreates a running provider once.
- Provider rules (issuer host among its domains, generated directory loaded last, `auto_update = false`) are enforced on
  every write of that instance; at startup they are only reported by `doctor identity.provider`, so a misconfigured provider
  degrades the integration without blocking the admin API.
- Rotation is synchronous: rotate, apply the provider's files, then recreate the app.
- `doctor identity.base_config` (scanning host config files for sections that would be discarded) is left for a follow-up;
  the guide tells the operator to delete them.
