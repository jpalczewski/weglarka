# Guides

Operator guides for Węglarka, one topic per file. Start with [installation](../install.md), then
[your first app](first-app.md). Guides are named by topic and their headings are not numbered, so adding one
never renumbers the others; link to a guide by file name. Decisions and their rejected alternatives live in
[`docs/decisions/`](../decisions/README.md), ready-made specs in [`docs/examples/`](../examples/).

## Getting started

| Guide | Covers |
|---|---|
| [First app](first-app.md) | Adding an app, secrets basics, mounted secret owner, images that persist env into config, private registries, switching over from Coolify |
| [Webhooks](webhooks.md) | GitHub and Forgejo webhooks for auto-update, redelivery deduplication |
| [Verification and rollback](verify-and-rollback.md) | Checking a deployment, rolling an app back, downgrading Węglarka |

## Data

| Guide | Covers |
|---|---|
| [Volumes and UID ranges](volumes.md) | Per-app UID ranges, volumes in the spec, removing and detaching |
| [Shared volumes](shared-volumes.md) | One volume for several apps, groups, SQLite with several writers |
| [Importing data](data-import.md) | Importing and exporting volumes, Coolify migration, SQLite lessons |
| [Secrets cleanup](secrets-cleanup.md) | `secrets remove`, `apps remove --purge-secrets`, orphaned secrets |
| [Host config files](host-configs.md) | `config_root`, `configs`, `apps reload` |
| [Read-only host paths](host-mounts.md) | `[runtime] host_mounts`/`group_add` allowlists, `host_mounts` and `group_add` in the spec |

## App behaviour

| Guide | Covers |
|---|---|
| [Stopped apps](stopped-apps.md) | `start = false`, provisioning without a container |
| [App dependencies](dependencies.md) | `depends_on` start order and health gate |
| [Blue-green deploys](blue-green.md) | `strategy = "blue_green"`: deploys without the restart outage for stateless apps |
| [Container command](container-command.md) | `command` (argv) |
| [Generated config](generated-config.md) | Files rendered from `apps.toml` for an app (identity provider): versions, validation, apply and rollback |
| [Container hardening](container-hardening.md) | `security` for apps, the always-hardened ingress container |
| [Image retention](image-retention.md) | Which images stay, `images prune` |
| [One-off commands](one-off-commands.md) | `weglarka run` |
| [Port forward](port-forward.md) | `weglarka forward`, `cli.toml` (`ssh_host`) |
| [Deploying a local image](push-local-images.md) | `weglarka push`: an image archive or another tag of the repository |
| [Static sites](static-sites.md) | `kind = "static"`: a built site (Astro, Hugo…) served by the ingress nginx, releases and `current` |
| [Site environments](site-environments.md) | `[sites]`: a development and a production environment of one static site, `weglarka promote` |
| [apps update](apps-update.md) | What each change does to a running app |

## Networking and ingress

| Guide | Covers |
|---|---|
| [Host ports](host-ports.md) | `host_ports` (non-HTTP services such as SSH) |
| [Shared networks](shared-networks.md) | `shared_networks` between apps |
| [Path routing](path-routing.md) | `paths` and `strip_prefix` on one domain |
| [Streaming](streaming.md) | SSE and long polling |
| [Request body size](max-body-size.md) | `ingress.max_body_size` |
| [Access log](access-log.md) | `ingress.access_log_skip_paths`, `weglarka access`, what `169.254.1.2` means |
| [Edge mode](edge-mode.md) | nginx on 80/443 terminating TLS |
| [Edge behind a CDN](edge-cdn.md) | Visitor address behind Cloudflare (`[ingress.cdn]`) |
| [ACME behind a CDN](acme-behind-cdn.md) | HTTP-01 through the Cloudflare proxy, `acme.cdn` |
| [ACME certificates](acme.md) | HTTP-01 issuance and renewal (`[acme]`) |
| [Wildcard certificates](wildcard-certificates.md) | DNS-01 (`[acme.dns]`) |
| [Forward auth](forward-auth.md) | Login in front of an app via the identity provider (`ingress.auth`) |
| [Admin API tokens](admin-api-tokens.md) | A token listener for the panel and other clients, `read`/`admin` scopes from provider groups (`[admin.http]`) |
| [Admin panel](admin-panel.md) | The read-mostly web UI: app definition, OIDC login, sessions, what viewers and admins see |
| [Remote CLI](remote-cli.md) | `weglarka login` with the device flow, where the tokens are kept, `whoami`, `logout` |
| [Operating with the CLI](agent-cli.md) | The safe way to drive a host (people and coding agents): where commands go, reads first, writes only on a throwaway app, the agent plugin |
| [Identity provider](identity-provider.md) | Authelia as a managed app, OIDC clients per app, external clients, secret rotation (`oidc`, `[identity]`) |

## Operations

| Guide | Covers |
|---|---|
| [Metrics](metrics.md) | The opt-in Prometheus `/metrics` listener on a dedicated network (`[metrics]`), and opting an app in (`metrics_port`) |
| [Notifications](notifications.md) | ntfy notifications, outbox, deduplication |
| [Crash detection](crash-detection.md) | Crash loops and unhealthy apps (`[monitor]`) |
| [Self-update](self-update.md) | Signed image updates, watchdog and automatic fallback |
| [State schema](state-schema.md) | `schema_version` of the state files and rolling back across it |
