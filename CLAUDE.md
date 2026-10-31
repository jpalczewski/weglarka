# Węglarka — agent guide

A home-grown deploy tool in Rust (a Coolify replacement): the daemon manages rootless Podman 6 (libpod API v6 over a unix
socket), declarative reconcile from TOML state, nginx in a container behind Traefik (`behind` mode), auto-update on a
GitHub webhook (GHCR). MVP: `ntfy.zig` updates itself.

Tasks and roadmap: [GitHub Issues](https://github.com/jpalczewski/weglarka/issues) (label `roadmap` = planned features,
`bug` = defects); the roadmap view (board/timeline, field `Area`) is the
[GitHub project "Węglarka roadmap"](https://github.com/users/jpalczewski/projects/12) — a view only, issues are the
source of truth. Implementation decisions with rationale: `docs/decisions/` (index generated from ADR titles:
[`docs/decisions/README.md`](docs/decisions/README.md)). Installation: `docs/install.md`; topic guides (migrations,
ingress, ACME, rollback…): [`docs/guides/`](docs/guides/README.md). The repo is **public** — never write references to
private notes or details of private infrastructure (account names, private organizations, tokens) here, in PRs, issues
or commits.

Priorities for every decision: **security → elegant, extensible code (traits/adapters) → RAM economy.**

## Never break (holds even if no rule file is loaded)

- A new `AppSpec`/`ContainerSpec` field is optional and does not change `spec_hash` when unset — [state-and-schema](.claude/rules/state-and-schema.md).
- A new `apps.toml`/`state.toml` field bumps `state::SCHEMA_VERSION` and adds a `SCHEMA_STEPS` entry (ADR 0023) — [state-and-schema](.claude/rules/state-and-schema.md).
- Secrets never appear in logs, `Debug` or app TOML (only name references) — [engine-and-deploy](.claude/rules/engine-and-deploy.md).
- Leaf crates never depend on `engine`; nothing depends on `panel` — [crate-map](.claude/rules/crate-map.md).
- Views for the `read` scope are allowlist projections (destructure without `..`), never blocklists — [api-and-cli](.claude/rules/api-and-cli.md).
- `unsafe_code = forbid` (workspace lints).
- Public repo: no private names, hosts or domains in docs (use `example.com`/`example.org`, host `myhost`) — [operator-docs](.claude/rules/operator-docs.md).
- Conventional Commits in English, `Closes #NN`, squash merge after green CI — [commits-and-prs](.claude/rules/commits-and-prs.md).

## Conventions (binding, not up for discussion in PRs)

- Rust: toolchain pinned in `rust-toolchain.toml` (1.99.1), edition 2024.
- Errors: `thiserror` in libraries, `anyhow` **only** in binaries (`weglarka-daemon`, `weglarka-cli`).
- Runtime: `tokio`. Logs: `tracing` (JSON in the daemon). Dependencies only in `[workspace.dependencies]`.
- Serde: our TOML files (`weglarka.toml`, `apps.toml`, `secrets.toml`, state) → `#[serde(deny_unknown_fields)]`; *external*
  models (Podman, GitHub) → `#[serde(default)]`, unknown fields ignored, only the used fields.
- Async in traits: native `async fn`/`impl Future + Send` + generics, no `async-trait` (`docs/decisions/0001-async-traits.md`).
  Traits that need `dyn` (`WebhookSource`, `SecretStore`) are synchronous.
- Tests: `insta` snapshots (commit `.snap`; update with `INSTA_UPDATE=always cargo test`, then review the diff).
- Before a commit: `cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`.
- **Language: README, code comments and ADRs in English** (Jacek's decision, 2026-10-23; ADRs: 2026-10-24) — all
  `README.md` files, `//`, `///`/`//!` comments, comments in scripts and workflows, and `docs/decisions/`. `docs/install.md`
  and `docs/guides/` are in English (2026-10-25); runtime/CLI messages are being translated (issue #32). Write new and
  changed code in English right away; do not mix translation of untouched files into unrelated PRs.
- Git: PR to `main`, squash merge after green CI; reference issues (`#NN`), never private notes.

## Build and test pitfalls (details in [testing](.claude/rules/testing.md) and [worktrees](.claude/rules/worktrees.md))

- Every checkout builds in its **own** `target/` (`export CARGO_TARGET_DIR="$(scripts/worktree.sh target)"`); a shared
  build directory can link another worktree's code without recompiling.
- Do not hide the exit code in a pipe: `cargo test … > log 2>&1; echo "EXIT: $?"`.
- Daemon integration tests are one binary (`crates/weglarka-daemon/tests/it/`); a new area = a new `mod`.

## Rules (`.claude/rules/`) — path-scoped ones load when you read or edit a matching file; open by hand if unsure

- [commits-and-prs](.claude/rules/commits-and-prs.md) — Conventional Commits, releases, pre-PR checklist, ADR numbering.
- [worktrees](.claude/rules/worktrees.md) — one task = one checkout, private `target/`, Agent Teams.
- [testing](.claude/rules/testing.md) — insta, test binaries, real-Podman tests, CI behaviour.
- [operator-docs](.claude/rules/operator-docs.md) — `docs/install.md`, `docs/guides/`, language and public-repo rules.
- [state-and-schema](.claude/rules/state-and-schema.md) — `spec_hash`, `SCHEMA_VERSION`, rollback, serde policy.
- [engine-and-deploy](.claude/rules/engine-and-deploy.md) — reconcile, deploy, volumes, secrets, configs, sites, run/forward/push.
- [ingress-and-tls](.claude/rules/ingress-and-tls.md) — nginx/Traefik, edge mode, ACME, probe socket.
- [api-and-cli](.claude/rules/api-and-cli.md) — endpoints, read views, logs, CLI.
- [identity-and-admin-tokens](.claude/rules/identity-and-admin-tokens.md) — identity provider, generated configs, token listener.
- [panel](.claude/rules/panel.md) — admin panel (BFF) and `weglarka-unix-http`.
- [notify-and-selfupdate](.claude/rules/notify-and-selfupdate.md) — notifications, self-update, watchdog, webhook dedup.
- [crate-map](.claude/rules/crate-map.md) — dependency graph and the crate table.

Contributor docs: [`docs/contributing/agent-workflow.md`](docs/contributing/agent-workflow.md) (parallel sessions, briefs,
reviews), [`docs/contributing/issues-and-project.md`](docs/contributing/issues-and-project.md) (labels, project) and
[`docs/contributing/releasing.md`](docs/contributing/releasing.md) (manual release steps).
Verify this setup with `bash scripts/claude-md-lint.sh`.
