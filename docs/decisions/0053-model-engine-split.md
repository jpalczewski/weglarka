# 0053 — Splitting `weglarka-core` into `weglarka-model` and `weglarka-engine`

Status: accepted (2026-10-27, issue #222)

## Problem

`weglarka-core` held the domain model and the reconcile/deploy engine, and every crate depended on it. An edit to an
engine file rebuilt the API contract, ingress generators, notifications, ACME, DNS and registry crates, none of which
use the engine. The planned crates (identity renderer, shared HTTP client, privilege-separated vault and webhook
roles) are model-only consumers: they must not rebuild on engine edits, and a role that is meant to be small should
not be able to reach reconcile or deploy internals at all.

## Decision

Two crates, a **pure move** (no change to `spec_hash`, TOML files, `schema_version`, API or behaviour):

- `weglarka-model`: `app`, `environments`, `config`, `events`, `state` (file types, schema gate, validation),
  `fsutil` (`write_atomic`), `hash`, `labels`, `uid_range`, `limits`, `podman` (the `PodmanClient` trait and its types),
  `secret_store`, `secrets` (`FileSecretStore`, `rfc3339_utc`), `identity`, `host_ports`, `delivery`, `self_update`,
  `webhook`, and the pure parts of `depends`, `shared_networks`, `shared_volumes`. No Podman calls, no `tokio`.
- `weglarka-engine`: `reconcile`, `deploy`, `volumes`, `crash`, `images`, `sites`, `run`, `push`, `promote`,
  `forward`, `waiting`, `config_mounts`, `host_mounts`, `platform`, the run-time halves of `depends`,
  `shared_networks` and `secrets`, `FakePodman` (feature `testing`) and the engine tests.

The dependency direction decides ambiguous modules: anything that `state`/`config` validation calls is in the model.
That moved three modules against the issue's sketch: `self_update` (its `FallbackPolicy` bounds are validated by
`config`), `delivery` (a state file, named by `state::Paths`) and `shared_volumes` (validated on every `apps.toml`
load). Modules that mixed both halves were split by file under the same name in both crates: `depends`
(`validate`/`order` in the model; the start gate and removal guard in the engine), `shared_networks` and `secrets`
(`FileSecretStore` in the model; the `Arc<dyn SecretStore>` helpers that return `EngineError` in the engine).
`state::write_atomic` moved to `fsutil` so the file types no longer carry I/O helpers.

Leaf crates (api, ingress, notify, acme, podman, dns, registry) depend on the model only; `cli` and `daemon` also
depend on the engine. The libpod integration tests that drive the engine (`volumes`, `image_save`,
`ingress_identity`) moved from `weglarka-podman` to `weglarka-engine/tests`, which dev-depends on `weglarka-podman`;
otherwise the adapter crate would depend on the engine.

No `weglarka-core` facade is kept: the workspace is the only consumer, the rename was mechanical, and a facade would
keep every re-exporting crate rebuilding on engine edits.

## Consequences

- `weglarka-model` and `weglarka-engine` are versioned and changelogged per crate (ADR 0015); `weglarka-core`'s
  history stays in git. Both start at the old core version, with `version = "0.0"` in `[workspace.dependencies]`.
- New model-only crates add `weglarka-model` and nothing else; the `SecretOps` trait (#213) belongs next to
  `secret_store` in the model.
- Operators see no change: the state schema, TOML files and the binaries are untouched, so rollback is the ordinary
  one.

## Rejected alternatives

- **A thin `weglarka-core` re-export facade for one release.** Nothing outside the workspace imports core, and
  the facade would depend on the engine, defeating the point.
- **Keeping `self_update`, `delivery` and `shared_volumes` in the engine.** The model would have to call upward into
  the engine for validation, or duplicate the constants.
- **Keeping the integration tests in `weglarka-podman`.** It would need the engine as a dev-dependency and
  `cargo tree -p weglarka-podman` would list the engine.
