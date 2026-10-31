# Verification and rollback

How to check that a deployment is healthy, how to roll an app back to an older image, and what to remove before
downgrading Węglarka itself.

```sh
weglarka status && weglarka apps show ntfy      # digest, generation, last deploy
curl -fsS https://ntfy.example.com/             # from outside, through Traefik
podman logs weglarka-nginx                      # JSON access log with the app field
podman inspect weglarka-nginx --format '{{.HostConfig.ReadonlyRootfs}} {{.EffectiveCaps}}'  # true [] (ADR 0014)
```

## Memory use

`weglarka doctor` reports `runtime.memory`: the working set of every running container (one Podman stats call,
matched to containers by name) against its `resources.memory` limit.

| Status | When |
|---|---|
| `ok` | every container with a limit is below 80% of it; the message gives the container count, the total in use and the container closest to its limit |
| `warn` | a container is at or above 80% of its limit; the message names it with the percentage |
| `info` | `weglarka-nginx` runs without a memory limit (there is no setting for it yet) |
| `info` | a running container reports no memory data, usually because the cgroup memory controller is not delegated to the runtime user; such a container is never counted as idle |
| `info` | the stats call failed; the rest of `doctor` is unaffected |

When several conditions hold the highest status wins and the message mentions all of them. The check never fails.
Raise `resources.memory` of an app that warns (`weglarka apps update <app> --memory 256M`; the blue-green `.next`/`.prev`
containers share the app's setting). If the daemon's own container warns, its limit is `[platform] memory` in `weglarka.toml`.

## Automatic rollback

A deploy that fails the health gate returns to the previous digest (retention 1). The result is reported by
`weglarka deploy` (exit code 6 = `rolled_back`).

## Manual rollback to a specific version

`deploy --image` is rejected by the daemon in the MVP (400, [ADR 0005](../decisions/0005-ingress-i-platforma.md)), so
pin a `sha-…` tag with `apps update` (secrets, volumes and the rest of the spec stay):

```sh
weglarka apps update ntfy ghcr.io/jpalczewski/ntfy.zig:sha-<previous> --no-auto-update
```

Changing the image through `update` deploys immediately (pull, health gate; a failed gate = automatic rollback to the
previous digest, exit code 6). Return to `:latest` the same way, with `--auto-update`:
`weglarka apps update ntfy ghcr.io/jpalczewski/ntfy.zig:latest --auto-update`.

## Rolling Węglarka back to an older version

The TOML files use `deny_unknown_fields`, and `apps.toml` and `state.toml` may carry a `schema_version`. A daemon that
finds a file newer than it understands refuses to start with a readable message (see
[state schema version](state-schema.md)). Before downgrading to a release that predates a given field, remove that
field by hand — otherwise the daemon fails to start with a parse error. Keep a backup of the state directory from
before the upgrade: it is the only way back across a schema version boundary.

**Before downgrading, remove:**

| Where | Remove | Guide |
|---|---|---|
| `apps.toml`, apps | `start = false` | [stopped apps](stopped-apps.md) |
| `apps.toml`, apps | `depends_on` entries | [dependencies](dependencies.md) |
| `apps.toml`, apps | `shared_volumes` entries; the `[shared_volumes]` section; the `shared_volumes` section in `state.toml` | [shared volumes](shared-volumes.md) |
| `apps.toml`, apps | `shared_networks` entries; the `[shared_networks.<name>]` declarations | [shared networks](shared-networks.md) |
| `apps.toml`, apps | `strategy` (`weglarka apps update <app> --strategy recreate`, then remove the key) | [blue-green deploys](blue-green.md) |
| `apps.toml`, apps | `command` | [container command](container-command.md) |
| `apps.toml`, apps | `host_ports` | [host ports](host-ports.md) |
| `apps.toml`, apps | `[apps.X.ingress]` blocks — `streaming`, `streaming_paths` (`weglarka apps update <app> --no-streaming-paths`) | [streaming](streaming.md) |
| `apps.toml`, apps | `paths` and `ingress.strip_prefix` | [path routing](path-routing.md) |
| `apps.toml`, apps | `ingress.max_body_size` (`weglarka apps update <app> --unset-max-body-size`) | [max body size](max-body-size.md) |
| `apps.toml`, apps | `ingress.access_log_skip_paths` (`weglarka apps update <app> --remove-access-log-skip-path <path>`) | [access log](access-log.md) |
| `apps.toml`, apps | `configs` and `reload_signal` | [host configs](host-configs.md) |
| `apps.toml`, apps | `host_mounts`, `group_add` | [host mounts](host-mounts.md) |
| `apps.toml`, secret bindings | `uid`/`gid` on mounted secrets (`kind = "mount"`) | [first app](first-app.md) |
| `apps.toml`, apps | `kind = "static"` | [static sites](static-sites.md) |
| `apps.toml` | the `[sites.<site>]` sections (declare the environments as plain `kind = "static"` apps if the sites must keep running) | [site environments](site-environments.md) |
| `apps.toml`, apps | `ingress.auth`, `ingress.auth_exempt_paths` (enforced by nginx since this stage; remove them before downgrading) | [forward auth](forward-auth.md) |
| `apps.toml`, apps | `oidc` (with `device_flow`); the `[oidc_clients.<id>]` sections (with `device_flow`) | [identity provider](identity-provider.md) |
| `apps.toml`, apps | `metrics_port`, `metrics_path` (`weglarka apps update <app> --metrics-port none`) | [metrics](metrics.md) |
| `apps.toml`, apps | `ingress.auth_policy`, `ingress.auth_groups` (generated into the provider's access rules since this stage; remove them before downgrading) | [forward auth](forward-auth.md) |
| `weglarka.toml` | `[runtime] allow_privileged_host_ports` | [host ports](host-ports.md) |
| `weglarka.toml` | `[runtime] dependency_wait_secs` | [dependencies](dependencies.md) |
| `weglarka.toml` | `[metrics]` | [metrics](metrics.md) |
| `weglarka.toml` | `[metrics] scraper` (the section can stay for a version that has it) | [metrics](metrics.md) |
| `weglarka.toml` | `[notify]` | [notifications](notifications.md) |
| `weglarka.toml` | `[monitor]` | [crash detection](crash-detection.md) |
| `weglarka.toml` | `[self_update]`, together with `systemctl --user disable --now weglarka-self-update.timer weglarka-watchdog.timer` | [self-update](self-update.md) |
| `weglarka.toml` | `[runtime] host_mounts`, `[runtime] group_add` | [host mounts](host-mounts.md) |
| `weglarka.toml` | `config_root` | [host configs](host-configs.md) |
| `weglarka.toml` | `[webhook.forgejo]` | [webhooks](webhooks.md) |
| `weglarka.toml` | `[identity]` | [identity provider](identity-provider.md) |
| `weglarka.toml` | `[admin.http]` (the unix socket keeps working; remove the panel app first and `[identity]` last) | [admin API tokens](admin-api-tokens.md), [admin panel](admin-panel.md) |
| `weglarka.toml` | `[acme]` (or set `enabled = false` before rolling back to a release that knows it) | [ACME certificates](acme.md) |
| `weglarka.toml` | `[acme.dns]` | [wildcard certificates](wildcard-certificates.md) |
| `weglarka.toml` | `[ingress.cdn]` | [edge behind a CDN](edge-cdn.md) |
| `weglarka.toml`, edge mode | set `mode = "behind"`, remove `https_bind`, restore `traefik_dynamic_file` | [edge mode](edge-mode.md) |

**Upgrading to the release with the probe socket ([ADR 0054](../decisions/0054-health-probe-socket.md)):** the nginx
container gets one more mount (`<nginx_conf_dir>/probe`), so the daemon recreates it **once**, in `behind` and `edge`
alike (in `edge` the forwarder holds connections meanwhile). Nothing changes in `apps.toml`, `state.toml` or
`weglarka.toml`, so there is no field to remove. On a downgrade the older daemon recreates nginx with the old mounts
and the unused `probe/` directory stays in `<nginx_conf_dir>`; remove it if you like.

Notes:

- The order of the rows does not matter; the schema-versioned fields (those in `apps.toml` and `state.toml`) can
  alternatively be handled by restoring both files from the backup taken before the upgrade — see
  [state schema version](state-schema.md).
- `weglarka.toml` sections that are not part of the state schema (`[notify]`, `[monitor]`, `[self_update]`,
  `[acme]`, `[acme.dns]`, `[ingress.cdn]`, `[webhook.forgejo]`, `[admin.http]`) are not covered by `schema_version`; they always have to be removed by hand.
- Settings that need no action: webhook delivery dedup (`webhook-deliveries.toml`) is ignored by an older daemon,
  and `weglarka run` ([one-off commands](one-off-commands.md)) writes no state.
