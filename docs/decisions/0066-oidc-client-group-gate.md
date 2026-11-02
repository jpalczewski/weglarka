# 0066 — Group gate on an OIDC client through authorization policies

Status: proposed (2026-11-02, issue #446). Builds on ADR 0051 (identity provider integration) and ADR 0052 (forward auth).

## Problem

`ingress.auth_groups` restricts who reaches an app through forward auth, but an OIDC client has no equivalent: any
account of the identity provider can complete the authorization request of any client. The admin panel relied on forward
auth as its group gate; without it, a user outside `viewers`/`admins` can finish the panel's login and is refused only
later by the daemon. A gate on the client itself is needed before forward auth in front of the panel can become optional.

## Decision

- **A separate field, `allowed_groups`**, on `[apps.<name>.oidc]` and `[oidc_clients.<id>]`: a list of group names with the
  same shape as `ingress.auth_groups`. It is not inherited from `ingress.auth_groups`: external clients have no ingress,
  the forward-auth gate and the OIDC gate may differ on purpose, and inheriting would change the rendered file (and
  restart the provider, signing everyone out) on upgrade for existing installs.
- **Authelia authorization policies.** For a client with a non-empty list, `weglarka-identity` renders
  `identity_providers.oidc.authorization_policies.weglarka-<client id>` with `default_policy: deny` and one rule that
  carries the client's own factor policy (`one_factor`/`two_factor`) and every group as an alternative; the client's
  `authorization_policy` then names that policy. A matched `deny` yields `access_denied` without a consent screen.
- **Węglarka owns the whole `authorization_policies` section**, like `clients` and `access_control`: Authelia merges
  config files key by key and warns against splitting a section across files, so policies cannot be safely added to a
  map from the base config. The section is emitted only when a client uses `allowed_groups`; otherwise the rendered
  file is byte for byte what it was. `weglarka doctor` (`identity.base_config`) warns about a copy in the base config.
- **Fail closed.** The renderer re-checks every group name and refuses to render on an invalid one.
- **Invariants.** The field is render-only and never part of `spec_hash`; it is a new `apps.toml` field, so
  `state::SCHEMA_VERSION` goes 16 → 17 with a no-op step (ADR 0023).

## Consequences

- Authelia evaluates client policies only at the authorization request, not on refresh. Removing someone from a group does
  not end an existing session at once; the panel's daemon refuses the first access token without a mapped group.
- An older Węglarka refuses an `apps.toml` that carries `allowed_groups` (`deny_unknown_fields`): remove it before
  downgrading ([identity provider](../guides/identity-provider.md)).
- Tests: model validation, renderer snapshot and error, daemon integration, `identity-config` CI validation with the
  pinned Authelia image.

## Rejected alternatives

- **Inherit from `ingress.auth_groups`.** Rejected for the reasons above.
- **Add policies to a map in the base config.** Authelia's file merge makes a split section unsafe.
- **Gate only in the relying party.** The panel's post-login code stays reachable for every account.
