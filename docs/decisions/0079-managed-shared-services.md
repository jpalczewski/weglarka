# 0079 — Managed shared services: model, wiring and per-kind rollout

Status: proposed (2026-11-06, issues #590, #591, #592)

## Problem

Apps need a Redis or a Postgres that Węglarka runs for them. Today an operator declares one by hand: an app for
the database, a shared network (ADR 0030), a `depends_on` entry (ADR 0016), a password set as a secret in both
apps, and a config file kept in sync by hand. Each step can drift from the others. Nothing stops a second app
from using the first app's password, or the database from being published on the host.

The implementation contracts are managed Redis v1 (#593) and managed Postgres v1 (#596). Both share one model: a
**shared service** is an ordinary app instance that Węglarka manages for other instances, its **members**. This ADR
records how that shared part is built and rolled out, so the kind-specific PRs only add a generator.

Constraints, in priority order:
- Credentials are per member and minted by Węglarka. A generated file holds digests only (ADR 0055); the plaintext
  reaches only the member, as a Podman secret.
- One way to express each relation. What a service implies (network, start order, owned fields) is derived and
  never written back to `apps.toml`.
- Nothing half-built can be switched on in production.

## Decision

### Declaration and membership

- `[shared_services.<name>]` in `apps.toml` with `kind` (`redis` | `postgres`), `instance` and the kind's options.
  Members list services by name in `AppSpec.shared_services`. This is schema 24 (#590).
- `<name>` follows instance-name rules and must not end in `-digest` or `-pgpass`. The secret names derived from it
  (`svc-<name>`, `svc-<name>-digest`, `svc-<name>-pgpass`) must not collide with those of another service.
- The service shares a namespace with `[shared_networks]` (`NameTaken`), because both become `net-shared-<name>`.

### Rules (pure, in `weglarka_model::shared_services`)

Every rule has the name the contracts use, so fixtures are checked by name:
- `UnknownInstance`: the service instance must exist.
- `UnknownService`: a member's entry must name a declared service.
- `ServiceIsMember`: the service instance cannot be a member of its own service.
- `TooManyServicesOfKind`: a member uses at most one service per kind (v1).
- `ServiceSpecOwned`: the service instance is owned while it is declared. Its spec must not set `command`,
  `domains`, `paths`, `port`, `host_ports`, `shared_services`, `reload_signal` or `auto_update = true`. It must not
  be `kind = "static"` or come from `[sites]`.

The rules run on every load and save (`validate_apps`), like the shared-volume and shared-network rules.

### Wiring through `effective_spec`

The overlay that already adds the identity provider's env and secret (ADR 0051) also adds the service relations:
- Each member gets the service instance in `depends_on` (start order and health gate).
- The service and each member join `net-shared-<service>`, an internal network created lazily (ADR 0030). A
  container may now join several shared networks: its own `[shared_networks]` group and one per service.
- Network pruning and `doctor` count service names as declared groups.

Every consumer — hash, secret materialization, container creation, `weglarka run` — reads the overlaid spec, so none
of them can miss a relation. Removing the service instance while any member lists it is refused with 409
(`ServiceHasMembers`). With no members it is refused as well, until the declaration is removed. In v1 a declaration
is changed by editing `apps.toml`; a CLI for it is a follow-up (#599).

### Credentials (#591)

- Per (member, service) pair one 48-character password is minted into the member's scope as `<member>.svc-<service>`
  (ADR 0024).
- `SecretOps` gains one digest kind per consumer (`DigestKind`): `RedisAclSha256` for Redis ACL files and
  `ScramSha256Verifier` for Postgres roles, next to `Pbkdf2Digest`.
- A digest is stored next to its value and changes only on mint or rotation, so the same secret renders the same
  bytes.
- The Redis digest is unsalted. That is acceptable only because every value is minted with high entropy; no
  operator-chosen password ever gets that kind.

### Rollout: a gate per kind

- #590 rejected every declaration.
- From #592 the rules above run first, then a gate per kind rejects a declaration of a kind that is not released yet,
  with "shared services are not enabled in this release". Each kind's PR (#593 Redis, #596 Postgres) opens its own
  gate.
- The engine and daemon tests of the shared wiring need declarations that load, before any kind is released. For
  those tests the model has `shared_services::testing::open_kind_gates()`, behind the crate's `testing` feature. Only
  `[dev-dependencies]` enable that feature, so a production binary does not contain the function. The flag is
  process-global and is never closed again: the gate tests live in the model crate's own tests, which never open it.

## Consequences

- The schema stays at 24 for the shared part. The kind PRs add generators and, where they need one, their own schema
  step.
- `apps list` and `doctor` show each service with its members. The `read` view of a service is an allowlist
  projection: name, kind, profile, instance and member names; never digests or secret names.
- Removing a member leaves its secret scope behind (ADR 0024); `secrets purge` removes it.
- Tests that must exist: fixture rejections by name from both contracts; an engine test with an open gate that
  checks the networks and `depends_on` of a member; the 409 on removal; the read projection; an unchanged
  `spec_hash` for apps outside every service.

## Rejected alternatives

- **A separate network namespace (`net-svc-<name>`).** It would allow a shared network and a service with the same
  name, but `doctor`, pruning and the operator would then track two kinds of groups. One namespace with `NameTaken`
  is simpler.
- **Writing `depends_on` and the network into `apps.toml`.** The relation would be stored twice and could drift.
  Removing a membership would also need a cleanup that the overlay never does.
- **Opening the gate through a runtime setting** (a `weglarka.toml` key or an environment variable). Any operator
  could switch on an unfinished kind, and the setting would need its own downgrade note. A test-only feature
  cannot reach production.
- **Shipping the shared wiring together with the Redis PR.** That would be one very large security-relevant PR.
  Splitting it lets the wiring be reviewed and tested on its own, behind the gate.
- **One password per service, shared by its members.** Members could read each other's data and could not be
  revoked one at a time. That defeats per-member ACLs and roles.
