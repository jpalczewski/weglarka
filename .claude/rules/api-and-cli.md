---
paths:
  - "crates/weglarka-api/**"
  - "crates/weglarka-cli/**"
  - "crates/weglarka-daemon/src/metrics/**"
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
  segment, `state.failed.reason` a fixed marker. Below the first level (#281): data-less enums go through a `read_*`
  function with an exhaustive `match` and no wildcard arm; validated newtypes (`MemoryLimit`, `CpuLimit`, `Digest`,
  `InstanceName`) pass through whole; pass-through structs bind every field (`field: _`, no `..`); path and name lists
  the model validates to identifier shapes (`domains`, `paths`, `streaming_paths`, `auth_exempt_paths`,
  `access_log_skip_paths`, `auth_groups`, `security.tmpfs`, `cap_add/cap_drop`, `group_add`, `aliases`, `scopes`,
  `metrics_path` — the `paths` shape, no query or fragment, #364) are shown, as is `metrics_port`; `oidc.redirect_uris`
  and `oidc.audience` lose their query (their path stays visible on purpose: public registration data, a credential there is unsupported). A new free-text field needs an explicit decision
  there, not a pass-through. `ShowAppResponse` carries `redacted: true` whenever this applies, and
  the CLI refuses to write such a spec back.
- **Doctor free-form text (#272/#276):** `doctor::run` takes the caller's `Access`; a check interpolates any error text it
  does not author itself (engine, Podman, I/O, the first-deploy reason) through `doctor::detail(..)`, and `apply_access`
  keeps it for `Full` callers and replaces it with a marker for `Redacted` ones. A new check follows the same rule.
- **A stream ends with its token:** streaming handlers stop at the verified principal's `exp` (`StreamDeadline`).
- Contract changes (`app.rs`, `podman.rs`, `weglarka-api`) are additive only and always update `FakePodman`.

## Entry points

| Area | Files |
|---|---|
| contract and API routes | `crates/weglarka-api/src/types.rs` + `crates/weglarka-api/src/endpoints.rs` → `crates/weglarka-daemon/src/admin.rs` (new endpoint: `endpoints.rs` first) |
| app logs (`GET /v1/apps/{name}/logs`, `admin`) | `LogOptions` + `PodmanClient::container_logs` in `crates/weglarka-model/src/podman.rs` (+ `crates/weglarka-podman/src/{client,wire}.rs`, `FakePodman::script_logs`), `LogsQuery::parse` (strict, protects the libpod query) in `crates/weglarka-api/src/types.rs`, frames `crates/weglarka-api/src/logs.rs` + codec `crates/weglarka-api/src/frame.rs`, `APPS_LOGS` (`Body::Credential`) in `crates/weglarka-api/src/endpoints.rs`, handler and pump (ends at the token's `exp`, an audit line at the end) in `crates/weglarka-daemon/src/logs.rs`, `StreamDeadline`/`stream_response` in `crates/weglarka-daemon/src/stream.rs`, tests `crates/weglarka-daemon/tests/it/logs.rs`, `docs/guides/admin-api-tokens.md` (ADR 0057) |
| app access log (`GET /v1/apps/{name}/access`, `admin`) | `APPS_ACCESS` (`Body::Credential`) in `crates/weglarka-api/src/endpoints.rs`, `AccessEntry`/`AccessFrame` in `crates/weglarka-api/src/access.rs`, `AccessQuery::parse` (strict) in `crates/weglarka-api/src/types.rs`, handler, line parser/filter (pure) and pump in `crates/weglarka-daemon/src/access.rs` (the daemon filters the shared nginx log by `app`; its format comes from `weglarka_ingress::nginx::LOG_FORMAT`, a test holds the two together), CLI `crates/weglarka-cli/src/access.rs`, tests `crates/weglarka-daemon/tests/it/access.rs`, `docs/guides/access-log.md` (ADR 0063) |
| metrics listener (`[metrics]`, #350) | `MetricsConfig` in `crates/weglarka-model/src/config.rs`, `labels::METRICS_NETWORK`, `crates/weglarka-daemon/src/metrics/{mod,encode}.rs` (own router with only `GET /metrics`, `MetricsSource` trait, hand-written encoder; add metrics as sources, keep the label contract of ADR 0061), per-app resources in `crates/weglarka-daemon/src/metrics/resources.rs` (#351: one list and one stats call per cache window), daemon counters, certificate expiry and self-update state in `crates/weglarka-daemon/src/metrics/daemon.rs` (#352: `EventCounters` is one more sink in the event fan-out, only with `[metrics]`), host metrics in `crates/weglarka-daemon/src/metrics/host.rs` (#353: `HostSource` trait, default `ProcSource` reads `/proc` from `Paths::proc_root` — tests use `tests/fixtures/proc` — with `node_*` names, no network counters; container storage from `PodmanClient::storage_info`, cached 60 s), startup beside the webhook in `crates/weglarka-daemon/src/lib.rs` (a failure is logged, never fatal), doctor `metrics.listener`, `MetricsView` in the config view, tests `crates/weglarka-daemon/tests/it/metrics.rs`, `docs/guides/metrics.md` (ADR 0061); per-app opt-in (#364): `metrics_port`/`metrics_path` in `crates/weglarka-model/src/app.rs` (validated in `state.rs`, only the port in `hash.rs`), `labels::metrics_network_name`/`METRICS_FOR`, network created in `prepare_instance` and joined after the gate in `launch_blue_green` (`crates/weglarka-engine/src/deploy.rs`), pruned by label in `prune_networks` (`reconcile.rs`), tests `engine_tests.rs` (mods `metrics_network`, `blue_green`); scraper membership (#365): `[metrics] scraper` → `ReconcilerOptions::metrics_scraper`, `crates/weglarka-engine/src/scraper.rs` (pure `plan_membership`, synced first in `prune_networks`, created-on in `launch`/`launch_blue_green`, live join in `prepare_instance`), doctor `metrics.scraper`, tests `engine_tests.rs` (mod `scraper`) and `tests/it/metrics.rs` (mod `scraper`) |
| CLI | `crates/weglarka-cli/src/update.rs` (read-modify-write of the spec: `apps update/start/stop`, `--dry-run`), `crates/weglarka-cli/src/commands.rs` |
| daemon/API tests | `crates/weglarka-daemon/tests/it/*.rs` — see [testing.md](testing.md) |
