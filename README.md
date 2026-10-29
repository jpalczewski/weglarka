# Węglarka

A lightweight deploy tool in Rust that manages **rootless Podman 6**: declarative state in TOML,
a reconcile loop, nginx in a container, auto-update on a GitHub webhook (GHCR), a health gate with rollback,
and push notifications (ntfy) for deploys, rollbacks and failures — through a durable outbox, so a
notification survives the notification server being redeployed.
An alternative to Coolify for a small VPS (priorities: security, extensible code, low RAM).

Status: **MVP** — the daemon, CLI, Podman client, ingress and packaging are ready; deployment on the host is in progress.

## Workspace

`weglarka-model` (domain model, state files, traits) · `weglarka-engine` (reconcile, deploy, volumes) · `weglarka-api` (admin API contract) ·
`weglarka-podman` (libpod v6 client) · `weglarka-ingress` (nginx config, `behind`/`edge`) ·
`weglarka-notify` (events → severity → dedup → durable outbox → ntfy) ·
`weglarka-daemon` (daemon) · `weglarka-cli` (the `weglarka` binary).

```sh
cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

Conventions and division of work: [CLAUDE.md](CLAUDE.md). Implementation decisions: [docs/decisions](docs/decisions).
Contributing with agent sessions, issues and the roadmap project: [agent workflow](docs/contributing/agent-workflow.md), [issues and project](docs/contributing/issues-and-project.md).

## Installation

The `ghcr.io/jpalczewski/weglarka` image (a rootless Podman container, systemd quadlet) + the `weglarka` CLI
from GitHub Release assets: host requirements, `weglarka.toml`, startup, the CLI over an SSH tunnel, the first app
(ntfy.zig), the GitHub webhook, signature verification and rollback — [docs/install.md](docs/install.md), then the topic [guides](docs/guides/README.md).

## License

`MIT OR Apache-2.0` — [LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE).
