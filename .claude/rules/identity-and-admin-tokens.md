---
paths:
  - "crates/weglarka-identity/**"
  - "crates/weglarka-model/src/{identity,admin_auth,generated,generated_state}.rs"
  - "crates/weglarka-model/src/identity/**"
  - "crates/weglarka-engine/src/{identity,oidc_credentials,generated,admin_token}.rs"
  - "crates/weglarka-daemon/src/{identity,admin_token,generated}.rs"
  - "crates/weglarka-daemon/tests/it/{identity,generated,token_api,oidc_credentials}.rs"
  - "crates/weglarka-cli/src/oidc.rs"
  - ".github/authelia/**"
  - "docs/guides/{identity-provider,admin-api-tokens,generated-config,forward-auth}.md"
---

# Identity provider, generated configs and admin API tokens

## Invariants

- **Generated configs (ADR 0055):** `apply_generated` renders → versions in `v-<fp12>/` →
  validates in a one-off container → swaps the `current` symlink → reload + health gate → rollback. The generator
  registry is `daemon/src/generated.rs::registered`; it registers the Authelia generator when `[identity]` is present and the Prometheus targets
  generator when `[metrics] scraper` is set. A generator whose consumer re-reads its files returns
  `ApplyMode::ConsumerWatches` and is never reloaded or rolled back (ADR 0064).
  `prune_generated` (each reconcile pass) removes `generated/<app>/` and its records only once the app is out of
  `apps.toml` and has no container, never because a generator is unregistered (ADR 0055, addendum).
- **`effective_spec`** (`crates/weglarka-model/src/identity.rs`) is the only overlay of injected env/secrets/`depends_on`
  (hash, materialize, container, `weglarka run`).
- Identity config renderers are pure, deterministic and snapshot-tested; the access-control file always has
  `default_policy: deny` plus the fixed `bypass` rule for the issuer host (#90); client secrets appear only as a digest
  (#91). Schema 14 (`identity_v14`), ADR 0051/0052.
- Admin API tokens (ADR 0056): JWT RS256/ES256 validation is pure (`admin_auth.rs`); the token listener and the unix
  socket serve one route table (`admin::api_routes`).

## Entry points

| Area | Files |
|---|---|
| admin API token (`[admin.http]`, #43/#92) | `crates/weglarka-model/src/admin_auth.rs` (pure JWT RS256/ES256 validation, `JwkSet`, `Scope`/`Principal`, group mapping; `testing::TestIssuer` under feature `testing`), `AdminHttpConfig` in `crates/weglarka-model/src/config.rs`, `Endpoint.scope`/`lookup` in `crates/weglarka-api/src/endpoints.rs`, `crates/weglarka-daemon/src/admin_token.rs` (`JwksVerifier` + JWKS fetch through the probe socket, the `authenticate` layer, `token_router`), `admin::api_routes` (one route table for both listeners), `bind_unix`/`spawn_server` in `crates/weglarka-daemon/src/lib.rs`, mount of the socket directory only for `clients`: `crates/weglarka-engine/src/admin_token.rs` + `spec_hash_with_admin_token`, check `admin.http` in `crates/weglarka-daemon/src/doctor.rs`, tests `crates/weglarka-daemon/tests/it/token_api.rs`, `docs/guides/admin-api-tokens.md` (ADR 0056) |
| identity provider (#42, #88, #91) | `crates/weglarka-model/src/identity.rs` (`OidcClientSpec`, `ExternalClientSpec`, `IngressAuth`, lexical validation, **`effective_spec`** — the only overlay of injected env/secrets/`depends_on` (hash, materialize, container, `weglarka run`), the `--config` parser (`config_sources`), `validate_host_app`/`validate_provider`, `issuer_host`; `ingress.auth_policy`/`auth_groups` is rendered by `weglarka-identity` into `access-control.yml` (#90), `crates/weglarka-daemon/tests/it/identity.rs`), `crates/weglarka-engine/src/identity.rs` (external clients, rotation), `crates/weglarka-engine/src/oidc_credentials.rs`, `crates/weglarka-daemon/src/identity.rs` (routes `/v1/oidc-clients`, `/v1/apps/{name}/oidc/rotate`), CLI `crates/weglarka-cli/src/oidc.rs`, doctor `identity.provider`/`oidc.credentials`, `docs/guides/identity-provider.md`, `IdentityConfig` in `crates/weglarka-model/src/config.rs`, fields `oidc`/`ingress.auth*`/`[oidc_clients]` in `crates/weglarka-model/src/app.rs`, schema 14 (`identity_v14`), `device_flow` schema 15 (`oidc_device_flow_v15`, ADR 0060), ADR 0051/0052 |
| generated configs (`apply_generated`, #212) | `crates/weglarka-model/src/generated.rs` (trait `ConfigGenerator`, `FileName`, `Fingerprint`), `crates/weglarka-model/src/generated_state.rs` (`generated.toml`: result of the last pass per generator, tolerant, 0600), events `GeneratedConfig*` in `crates/weglarka-model/src/events.rs`, `crates/weglarka-engine/src/generated.rs` (`Reconciler::apply_generated`: render → version `v-<fp12>/` → validation with a one-off container → swap of the `current` symlink → reload + health gate → rollback; `bootstrap_generated` before the first start; mount `/weglarka/generated` in `prepare_instance`; `spec_hash_with_generated` only for the consumer), the typed lock `EngineGuard` (`Reconciler::acquire`) in `crates/weglarka-engine/src/reconcile.rs`, worker with a 2 s debounce in `crates/weglarka-daemon/src/generated.rs` (+ `Daemon::changed()`), check `generated.<id>` in `crates/weglarka-daemon/src/doctor.rs`, `docs/guides/generated-config.md` (ADR 0055); the generator registry is empty until the identity renderer is wired in (#42) |
| identity config renderers | the `weglarka-identity` row of [crate-map.md](crate-map.md) |
