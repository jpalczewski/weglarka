---
paths:
  - "crates/weglarka-api/**"
  - "crates/weglarka-cli/**"
  - "crates/weglarka-daemon/src/{admin,app,app_view,config_view,certificates,events,logs,stream,doctor,lib,main}.rs"
  - "crates/weglarka-daemon/tests/**"
  - "docs/guides/{apps-update,first-app}.md"
---

# Admin API and CLI

## Invariants

- **Adding an endpoint:** start in `crates/weglarka-api/src/endpoints.rs` (one table for both listeners); each `Endpoint`
  declares its required scope and its `Body` (`NoAppData`, `AppView`, `Credential`). A `read` endpoint cannot be
  `Credential`.
- **Read-scope views are allowlist projections, never blocklists (ADR 0057):** the constructor behind `GET /v1/apps/{name}`
  rebuilds the spec and the state by destructuring every field of `AppSpec`, `AppState` and the nested structs
  **without `..`**, so a new field does not compile until someone decides what a `read` caller sees of it. Policy: `env`
  values blank (keys kept), every `command` element replaced by a placeholder (arity kept), `health.http.path` cut to its first
  segment, `state.failed.reason` a fixed marker; `ShowAppResponse` carries `redacted: true` whenever this applies, and
  the CLI refuses to write such a spec back.
- **A stream ends with its token:** streaming handlers stop at the verified principal's `exp` (`StreamDeadline`).
- Contract changes (`app.rs`, `podman.rs`, `weglarka-api`) are additive only and always update `FakePodman`.

## Entry points

| Area | Files |
|---|---|
| contract and API routes | `crates/weglarka-api/src/types.rs` + `crates/weglarka-api/src/endpoints.rs` → `crates/weglarka-daemon/src/admin.rs` (new endpoint: `endpoints.rs` first) |
| app logs (`GET /v1/apps/{name}/logs`, `admin`) | `LogOptions` + `PodmanClient::container_logs` in `crates/weglarka-model/src/podman.rs` (+ `crates/weglarka-podman/src/{client,wire}.rs`, `FakePodman::script_logs`), `LogsQuery::parse` (strict, protects the libpod query) in `crates/weglarka-api/src/types.rs`, frames `crates/weglarka-api/src/logs.rs` + codec `crates/weglarka-api/src/frame.rs`, `APPS_LOGS` (`Body::Credential`) in `crates/weglarka-api/src/endpoints.rs`, handler and pump (ends at the token's `exp`, an audit line at the end) in `crates/weglarka-daemon/src/logs.rs`, `StreamDeadline`/`stream_response` in `crates/weglarka-daemon/src/stream.rs`, tests `crates/weglarka-daemon/tests/it/logs.rs`, `docs/guides/admin-api-tokens.md` (ADR 0057) |
| CLI | `crates/weglarka-cli/src/update.rs` (read-modify-write of the spec: `apps update/start/stop`, `--dry-run`), `crates/weglarka-cli/src/commands.rs` |
| daemon/API tests | `crates/weglarka-daemon/tests/it/*.rs` — see [testing.md](testing.md) |
