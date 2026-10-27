# App dependencies (depends_on)

Some apps need another app to be running already: a service and its database, a worker and its queue. Without a declaration both start in the same reconcile pass, so the dependent app can hit the health gate before its dependency has a container: a deploy that "works sometimes and rolls back sometimes". Decision and rejected alternatives: [ADR 0016](../decisions/0016-depends-on.md).

```toml
# apps.toml / --spec: `api` starts only once `db` is running (and healthy, if it has a healthcheck)
depends_on = ["db"]
# several dependencies at once, order in the list does not matter:
# depends_on = ["db", "redis"]
```

Apply it with `weglarka apps add api --depends-on db` (or `apps update api --depends-on db`); `db` must already be in `apps.toml`. A ready-made file: [`docs/examples/depends-on.toml`](../examples/depends-on.toml), a fragment of `apps.toml` with two apps (not for `--spec`: a spec file describes one app). Flags: `--depends-on` is repeatable, `--depends-on none` clears the list, and `apps update api --remove-depends-on db` removes a single entry (a usage error if it is not there); like `--host-port`, they are mutually exclusive with `--spec`.

- `depends_on` is **start order and a health gate only**, not networking: every app has its own network `net-<instance>` ([ADR 0009](../decisions/0009-volume-ownership.md)), so `api` will not resolve the name `db` and cannot connect to it. Connectivity comes from a separate, explicit declaration: the [shared network of a group](shared-networks.md). The two compose (`db` starts first, then the `api` that connects to it), but neither implies the other.
- The order applies wherever Węglarka **starts** a container: reconcile after the daemon starts, the first deploy, `apps start`, deploys from the CLI and from a webhook, and a recreate when the container is missing. It does not apply to replacing a running container after a spec-hash change (the app is already running) or to provisioning (`start = false`: there is no container).
- **The gate:** the dependency's container must be **running**, and if the dependency has a healthcheck (`health.command` or the image's `HEALTHCHECK`) it must be **healthy**; `health.http` is checked through the ingress, as in the deploy gate ([ADR 0010](../decisions/0010-health-http-probe.md)). For probes, upstreams see `X-Real-IP` and `X-Forwarded-For` = `unix:` ([ADR 0054](../decisions/0054-health-probe-socket.md)). The mere existence of the container is not enough.
- **Waiting is bounded:** when the dependency's container exists but is not ready yet (e.g. its deploy is in progress), Węglarka waits up to 10 s, polling every 1 s (the optional `[runtime] dependency_wait_secs` in `weglarka.toml` changes the budget; `0` is a single check; the daemon's own tests set it to 1 s). After that, and also when waiting makes no sense (no container, `start = false`), the admin API returns **409 Conflict** with the list of unmet dependencies and reasons, and reconcile reports "waiting for dependencies" and retries on the next pass, **without marking the app as failed** (no rollback and no error in the state).
- **Validation:** an unknown name, a reference to itself, a duplicate and a cycle are rejected when the spec is saved (`apps add`/`apps update` → HTTP 400 `invalid_request`) and when `apps.toml` is loaded at daemon startup (the daemon refuses to start; the message names the apps). This is why `apps add api --depends-on db` requires `db` to be in `apps.toml` already.
- **Removal:** `apps remove db` while another app has `depends_on = ["db"]` ends with 409 Conflict and the list of dependent apps; nothing is removed, even with `--purge-volumes`. Remove the dependent apps or their `depends_on` entries first.
- A dependency with `start = false` ([stopped apps](stopped-apps.md)) has no container, so the dependent app will not start: reconcile reports the wait and `doctor` warns. `weglarka apps start db` fixes it.
- `depends_on` is **not part of the `spec-hash`**: changing, reordering or clearing the list does not recreate the container, and `state.toml` does not change.
- `apps update --spec` replaces the **whole** spec, so a file without `depends_on` silently removes the list, like any other field.
- Check: `weglarka doctor`, check `state.dependencies`: Warn when a dependency of a running app does not exist, is stopped or is unhealthy, or when the dependency has `start = false`; Info when the app is not deployed yet and is waiting for its dependencies; Ok otherwise.

## Rollback

`depends_on` is a new field in `apps.toml`, and that file has `deny_unknown_fields`, so an **older daemon** cannot read it. Before going back to an earlier Węglarka version, remove the `depends_on` entries (`weglarka apps update <app> --remove-depends-on <dependency>`), otherwise the daemon refuses to start with a parse error.

`[runtime] dependency_wait_secs` is a new optional field in `weglarka.toml`, which also has `deny_unknown_fields`. If you set it, remove it before a downgrade as well.
