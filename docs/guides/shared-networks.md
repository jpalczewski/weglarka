# Shared networks (shared_networks)

By default apps are isolated: each has its own `net-<instance>` network. When a deployment consists of several
containers that talk to each other over the network (a worker and a broker, a reverse proxy in front of an API,
an app and its database), declare a group. Decision and rejected alternatives:
[ADR 0030](../decisions/0030-shared-networks.md). Ready-made snippet:
[`docs/examples/shared-network.toml`](../examples/shared-network.toml).

```toml
# apps.toml
[shared_networks.notes]          # declaration; the Podman network is created when the first member is deployed

[apps.notes-api]
shared_networks = ["notes"]      # joins net-shared-notes; the instance name is its DNS name in the group

[apps.notes-proxy]
shared_networks = [{ name = "notes", aliases = ["gateway"] }]   # extra DNS names in the group
```

CLI: `weglarka networks add notes`, then `weglarka apps add notes-api … --shared-network notes` (or
`apps update … --shared-network notes:gateway`; `--shared-network none` takes the app out of the group). List:
`weglarka networks list` (members and whether the network already exists); `weglarka networks remove notes` fails
with 409 while any app still joins it. The flag is mutually exclusive with `--spec`, like the other spec flags.

- **Security trade-off:** group members see each other on **every port** — there is no per-pair or per-port
  policy. Apps outside the group cannot resolve their names and cannot reach them. Add only apps you already
  trust at this level to a group. Membership grants no access to data: volumes, secrets and UID ranges stay
  per instance (or per shared volume, see [shared volumes](shared-volumes.md)).
- The group is an **additional** network: the container keeps its own `net-<instance>` as the first one (ingress
  traffic, outbound access, published ports), while the group network is `internal` — no route to the outside —
  and never carries published ports. Ingress does not join it; only the app with `domains` is reachable from
  outside (the proxy in the example).
- **At most one group per app** (v1). Aliases must be valid DNS names (`[a-z0-9-]`), unique within the group and
  different from the member instance names; the daemon rejects a conflict when the spec is saved (400).
- **Membership is part of the `spec-hash`** (group name and aliases): joining, leaving or changing an alias
  recreates the container once. An app without `shared_networks` keeps the same hash as before, so updating
  Węglarka recreates nothing.
- Removing an app from the group leaves the group and the other members alone; the network disappears only after
  `networks remove` (reconcile removes an empty network without a declaration once nothing is attached to it).
- Check: `weglarka doctor` — check `state.shared_networks`: Warn when the group network exists without a
  declaration, or when a member container is not attached to the group network (e.g. the spec changed and the
  recreate has not happened yet); Info when a declaration has no members.

## Rollback

This is a state-file schema change (version 4) — `apps.toml` and `state.toml` get `schema_version = 4` on the
first write after the update, whether or not you use group networks. An older daemon refuses to start with a
schema-version message; when going back to the previous version, restore `apps.toml` and `state.toml` **from a
backup taken before the update** (see [state schema](state-schema.md)).
