# Guides

Operator guides for Węglarka, one topic per file. Start with [installation](../install.md), then
[your first app](first-app.md). Guides are named by topic and their headings are not numbered, so adding one
never renumbers the others; link to a guide by file name. Decisions and their rejected alternatives live in
[`docs/decisions/`](../decisions/README.md), ready-made specs in [`docs/examples/`](../examples/).

## Getting started

| Guide | Covers |
|---|---|
| [First app](first-app.md) | Adding an app, secrets basics, mounted secret owner, private registries, switching over from Coolify |
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
| [Container command](container-command.md) | `command` (argv) |
| [Container hardening](container-hardening.md) | `security` for apps, the always-hardened ingress container |
| [Image retention](image-retention.md) | Which images stay, `images prune` |
| [One-off commands](one-off-commands.md) | `weglarka run` |
| [Port forward](port-forward.md) | `weglarka forward`, `cli.toml` (`ssh_host`) |
| [Deploying a local image](push-local-images.md) | `weglarka push`: an image archive or another tag of the repository |
| [apps update](apps-update.md) | What each change does to a running app |

## Networking and ingress

| Guide | Covers |
|---|---|
| [Host ports](host-ports.md) | `host_ports` (non-HTTP services such as SSH) |
| [Shared networks](shared-networks.md) | `shared_networks` between apps |
| [Path routing](path-routing.md) | `paths` and `strip_prefix` on one domain |
| [Streaming](streaming.md) | SSE and long polling |
| [Request body size](max-body-size.md) | `ingress.max_body_size` |
| [Access log](access-log.md) | `ingress.access_log_skip_paths`, what `169.254.1.2` means |
| [Edge mode](edge-mode.md) | nginx on 80/443 terminating TLS |
| [Edge behind a CDN](edge-cdn.md) | Visitor address behind Cloudflare (`[ingress.cdn]`) |
| [ACME behind a CDN](acme-behind-cdn.md) | HTTP-01 through the Cloudflare proxy, `acme.cdn` |
| [ACME certificates](acme.md) | HTTP-01 issuance and renewal (`[acme]`) |
| [Wildcard certificates](wildcard-certificates.md) | DNS-01 (`[acme.dns]`) |

## Operations

| Guide | Covers |
|---|---|
| [Notifications](notifications.md) | ntfy notifications, outbox, deduplication |
| [Crash detection](crash-detection.md) | Crash loops and unhealthy apps (`[monitor]`) |
| [Self-update](self-update.md) | Signed image updates, watchdog and automatic fallback |
| [State schema](state-schema.md) | `schema_version` of the state files and rolling back across it |
