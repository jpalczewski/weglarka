# 0011 — `start = false`: provision without starting (issue #29)

Status: accepted (iteration 3, issue #29).

## Decision

**`start` is a spec field, not a one-shot flag.** `AppSpec.start: bool`, default `true`, written to
`apps.toml` only as `start = false` (the default is not serialized, so existing files and snapshots keep
their shape). `apps add --no-start`, `apps update --start/--no-start` and `apps start`/`apps stop` only
edit this field; the daemon then takes the ordinary deploy/reconcile path. Desired state stays in one
place, so a daemon restart, `apps list` and reconcile all agree.

**Provisioning path (`start = false`).** Pull the image and pin its digest in `state.current`, assign the
uid range (0009), create the app network and ensure the declared volumes — and make sure **no container
exists** (a container left over from before the flag flip is stopped and removed). No secret is
materialized and no health gate runs: nothing will run, so a missing secret must not block provisioning,
and `AppState::waiting_for_secrets` never applies to a provisioned app. The path is idempotent, and
"`start = false` ⇒ no container" is an invariant, not a best-effort.

**`spec_hash` deliberately unchanged.** `start` says whether a container exists, not what it is made of,
so it is omitted from the hash (`HASH_FORMAT` stays v1). Flipping the flag must not by itself recreate a
container or pull anything; `apps start` is the deploy (pull the tag, health gate, rollback on failure)
and `apps stop` is the provision (remove the container). Keeping `start` out of the hash also means flipping
it never recreates the container from the pinned digest behind the command's back: the visible effect is
always the deploy/provision the command itself triggers.

**Reconcile.** New `Action::Provision { instance }`, planned when a `start = false` app has a container or
no pinned digest; it runs `Reconciler::provision_locked` and reports
`ActionOutcome::Provisioned(DeployOutcome::Provisioned { digest })` plus `Event::Provisioned`. Secret
lookup is skipped for `start = false` apps. The webhook fan-out (`instances_tracking`) filters on
`spec.start`, so a stopped app is never pulled or deployed by a package event; `apps start` deploys the
newest image itself.

**Ingress.** `AppRoute.active = spec.start`. `Plan::build` still validates domains and ports of inactive
apps and still reserves their domains (duplicates between any two apps, and collisions with the webhook
domain, stay errors); nginx and Traefik simply render no `server`/router for an app with `active = false`.
Validation is a property of the spec (a bad domain stays bad), routing is a property of a running
container (a route to a missing container is a 502). Reserving the domain is what makes the migration
path safe: the domain can still point at Coolify while Węglarka already imports the data.

**Commands.** `apps start` = `start = true` plus a synchronous deploy; `apps stop` =
`start = false` plus provisioning (removes the container, keeps volumes, uid range and secrets);
`apps update --start/--no-start` = spec update, deployed like any other update (`--start` deploys,
`--no-start` provisions). Runtime state `not_started` (`RuntimeState::NotStarted`, CLI `not-started`) is
shown when there is no container **by design**; it is derived (no container + `start = false`), never
stored, so a `start = true` app without a container keeps meaning "deploy pending"/`missing`.

**Volumes.** Import and export work on a provisioned app: a foreign import extracts through a helper
container of the same pinned image (0009), so the container of the app itself is not needed. The old
"deploy it once before importing" round trip disappears; `state.current` and `uid_range` come from the
provision path.

## Consequences

- `apps update --spec file.toml` replaces the whole spec: a file without `start` means `start = true`, so
  the app starts. A stopped app needs `start = false` in the file as well.
- The provision path pins the digest of the tag, but the next `apps start` re-resolves the tag (pull):
  a stopped app does not freeze its image, and the webhook only resumes mattering after the start.
- While stopped, the domain is reserved in `apps.toml` but absent from nginx/Traefik; traffic can be
  served by Coolify until the switch. Moving the domain to another app still requires dropping it from
  the stopped spec (`--remove-domain`), like for a running app.
- `apps stop` is not `podman stop`: the container is removed, and the state survives a daemon restart
  and a host reboot as "stopped", not as "crashed" (a `start = true` app whose container disappeared is
  recreated by reconcile).
- Only `apps remove --purge-volumes` frees the uid range and deletes data; a stop keeps both.
- Ingress still rejects an invalid spec of a stopped app (fail early); the error is not deferred to
  `apps start`.

## Rejected alternatives

- **A one-shot CLI flag** (`apps add --no-start` without a spec field): reconcile would converge to the
  running state anyway, so the flag could not survive a restart, and `apps.toml` — the source of truth —
  would claim something the daemon does not do.
- **New start/stop API endpoints holding the desired state**: a second source of truth next to the spec;
  it would need its own conflict rules against `apps update --spec`, rollback and reconcile, and every
  consumer (ingress, webhook, doctor) would have to check both.
- **`replicas = 0`**: implies a scheduler and kube-like semantics Węglarka does not have; a container
  would still be created (and would need cleaning up), and it would promise scale-out we do not offer.
- **`apps remove` + re-add later**: loses the uid range, volumes and secrets — exactly what provisioning
  is supposed to prepare before the first start.
- **`podman stop` as the implementation**: an imperative runtime action with no trace in the spec;
  reconcile would start the container again on its next pass.
