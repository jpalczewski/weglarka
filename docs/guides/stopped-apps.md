# Stopped apps: start = false

`start` in the app spec (default `true`, written to `apps.toml` only as `start = false`) says whether the app should be **running** or only **prepared**. Decision and rejected alternatives: [ADR 0011](../decisions/0011-start-false-provisioning.md).

```sh
weglarka apps add legacy-app ghcr.io/example/legacy:latest --domain legacy.example.com --port 8080 --no-start
weglarka apps start legacy-app               # start = true: pull the tag, health gate, container and router
weglarka apps stop legacy-app                # start = false: removes the container, keeps volumes and the UID range
weglarka apps update legacy-app --no-start   # same as `apps stop`, via a spec update
weglarka apps update legacy-app --start      # same as `apps start`
```

- An app with `start = false` is **provisioned**: pinned image digest, app network, UID range and volumes, but no container. `weglarka status` / `apps show` then report `not_started`, which is a correct state (no container by design), not an error and not "waiting for a secret".
- `apps stop` **removes** the container (it does not merely stop it); volumes, the UID range and secrets stay. The range and the data are released only by `apps remove --purge-volumes`.
- While the app is stopped, the webhook and auto-update are paused: a GitHub package event triggers neither a pull nor a deploy for it. `apps start` pulls the latest tag itself, so the app comes up with the current image (stopping does not freeze the version).
- An app with `start = false` **gets no router** in nginx/Traefik, because there is nowhere to send traffic. Its domains stay reserved and validated, though: a duplicate domain (including one shared with a running app) is still an error. This lets you keep the domain in Coolify, prepare Węglarka ahead of time, and switch over without router collisions.
- `apps update --spec file.toml` replaces the **whole** spec: if the file has no `start`, the default `true` applies and the app starts. Describe a stopped app in the file with `start = false`.
- Rollback note: `start` is a new field in `apps.toml`, which has `deny_unknown_fields`, so an **older** daemon/CLI cannot read the spec of a stopped app (`start = false`). Before going back to an earlier Węglarka version, remove `start = false` from `apps.toml` (or run `weglarka apps start` first), otherwise the daemon refuses to start with a parse error.
- Mixed-version note: `doctor` reports an operation in progress with status `info` (`state.deploying`). An older CLI does not know this variant and cannot parse the response when a deploy/recreate is running during `weglarka doctor`. Update the CLI together with the daemon (a new CLI reads an older daemon without problems).
