# 0030 — Shared networks: opt-in connectivity for a group of instances (issue #128)

Status: proposed (2026-10-24, issue #128)

## Problem

Every instance gets its own Podman network `net-<instance>`; only the ingress nginx joins it, and only for
apps with domains. Apps therefore cannot reach each other, and `depends_on` is a start order that "implies no
network connectivity" (ADR 0016). That rules out a class of real deployments split over several containers:
a task runner that talks to a broker in the main container (n8n external runners), an internal reverse proxy
in front of stateless API containers, an app next to its database or cache.

The failure modes of getting it wrong are security ones: a flat host-wide network lets any compromised app
reach every other app on every port, and an implicit group (derived from `depends_on`) would silently widen
the blast radius of an unrelated edit.

## Decision

Connectivity is **opt-in and declared**, mirroring shared volumes (ADR 0017). Isolation stays the default.

### Desired state (`apps.toml`)

```toml
[shared_networks.notes]            # declaration; the Podman network is created lazily

[apps.notes-api]
shared_networks = ["notes"]        # joins net-shared-notes; the instance name is a DNS name there

[apps.notes-proxy]
shared_networks = [{ name = "notes", aliases = ["gateway"] }]
```

* `AppsFile.shared_networks: BTreeMap<SharedNetworkName, SharedNetworkSpec>` — declared once, no owner.
  `SharedNetworkSpec` is empty and `deny_unknown_fields`: the declaration is the guard against typos (an
  undeclared name is rejected on every load and save) and the home of future per-network options.
* `AppSpec.shared_networks: Vec<SharedNetworkRef>`, written either as the bare name or as
  `{ name, aliases }`. **At most one network per app in v1** (mirrors shared volumes; a second group would
  need a story for transitive reachability and DNS name clashes).
* `aliases` are extra DNS names inside the group. They use the instance-name alphabet and must be unique
  within a group and distinct from every member's instance name — two containers answering to one name would
  make the resolver pick one at random.

### Podman side

* Network `net-shared-<name>` with label `weglarka.shared-network=<name>` and **no** `weglarka.instance`
  label, created idempotently by `begin_instance` (the prologue shared by `launch` and `provision_locked`)
  before the old container is touched.
* The network is created `internal`: group traffic gets no route out. Egress and ingress stay on the
  instance's own network, which remains the container's **first** (primary) network, so published ports and
  the ingress nginx behave exactly as before. The group network never carries published ports and the
  ingress never joins it.
* The container is created with `Networks: { net-<instance>: {}, net-shared-<name>: { aliases: [...] } }`.
  The container name is already a DNS name on every network it joins (netavark/aardvark-dns), so the instance
  name needs no alias. `ContainerSpec.network_aliases` is an additive field (network → aliases).
* Cleanup is keyed on the **label**, never on the `net-` prefix: `net-shared-notes` also parses as the
  per-app network of an instance called `shared-notes`. `prune_networks` removes a labelled network only when
  its declaration is gone (best effort; a network that still has containers is left for a later pass), and
  never because a member left — the group outlives its members like the shared-volume declaration does.

### `spec_hash`

Membership is part of the hash **while set** (name plus sorted, deduplicated aliases): it changes the
container's networks, so joining, leaving or changing an alias recreates the container once. A spec without
`shared_networks` hashes exactly as before (`skip_serializing_if`, `HASH_FORMAT` stays `v1`), so upgrading
Węglarka recreates nothing.

### State schema

`apps.toml` gains a field, so `state::SCHEMA_VERSION` goes 3 → 4 (ADR 0023) with an empty migration step.
From the first write after the upgrade both files carry `schema_version = 4`,
and an older daemon refuses them with the schema message instead of a `deny_unknown_fields` parse error.
Rolling back across the bump needs the copy of the state directory from before the upgrade
([the shared networks guide](../guides/shared-networks.md)).
The image label (`ARG STATE_SCHEMA` in the Containerfile) moves with it, so the self-updater (ADR 0027)
refuses a rollback to an image that writes schema 3 or older.

### Surface

* API: `GET /v1/networks`, `PUT|DELETE /v1/networks/{network}`. Removal is refused with 409 while any app
  joins the network; `PUT /v1/apps` validates membership and aliases against the candidate app set.
* CLI: `weglarka networks list|add|remove`, `apps add|update --shared-network NAME[:ALIAS,..]|none`.
* `doctor`: `state.shared_networks` — warns about a labelled network nobody declares and about a member whose
  container is not attached to its group network; notes a declared group without members.

### Security trade-off (documented for operators)

Members of a group reach each other on **every port**; there is no per-pair or per-port policy. Non-members
cannot resolve or route to them. An app should join a group only with apps it already trusts at that level.
Group membership does not grant any data access: volumes, secrets and uid ranges stay per instance (or per
shared volume).

### `depends_on`

Unchanged: a start order and a health gate. It now *composes* with a shared network (start the broker first,
then the runner that dials it) but never implies one.

## Consequences

* New optional fields in `apps.toml`; schema version 4; operators must back up the state directory before
  upgrading if they may roll back ([the shared networks guide](../guides/shared-networks.md)).
* `FakePodman` records network aliases, spec and membership; `ContainerSpec` gains `network_aliases`.
* Tests: pure validation and hash tests, engine scenarios on `FakePodman` (lazy creation, outsiders excluded,
  member removal, recreate on join/leave, label-keyed pruning), the admin API, and an integration test on a
  real rootless Podman (`weglarka-podman/tests/networks.rs`) that pins down name and alias resolution over an
  `internal` network and the isolation of outsiders.

## Rejected alternatives

* **Pods / multi-container instances.** One shared network namespace per instance would make a group a single
  unit: one lifecycle, one health gate, one rollback. That rewrites the one-app-one-container model that
  reconcile, deploy, hashing and rollback are built on (ADR 0001 territory) and couples unrelated image
  updates. Rejected as a much larger change for a connectivity-only need.
* **A host-wide flat network.** Simple, and removes the per-app network entirely, but every app could then
  reach every other app on every port, and a compromised app becomes a pivot to the whole host. It also breaks
  the "ingress joins only the networks of apps with domains" property. Isolation must stay the default.
* **Per-pair links (`links = ["db"]`).** Finer grained, but the N-way case (proxy → api, mcp, worker) needs N
  declarations plus direction semantics, an alias story per link, and a graph validator. The group is the
  simpler model and is the one shared volumes already use.
* **Deriving the group from `depends_on`.** It would make an unrelated ordering edit change what can reach
  what. Connectivity is a security decision and must be written down explicitly.
* **Joining the ingress to group networks.** Not needed: apps with domains keep their own network for that,
  and a group network is east-west traffic only.
