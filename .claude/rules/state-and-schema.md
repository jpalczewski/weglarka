---
paths:
  - "crates/weglarka-model/src/{app,state,hash,config,generated_state}.rs"
  - "crates/weglarka-model/src/snapshots/**"
  - "docs/guides/state-schema.md"
  - "docs/guides/verify-and-rollback.md"
---

# State files, `spec_hash` and schema versions

## Invariants

- **New `AppSpec` / `ContainerSpec` fields are optional and do not change `spec_hash` when unset**
  (`skip_serializing_if` in `HashInput`) — otherwise updating Węglarka recreates every running app.
- **State schema versioning (ADR 0023):** `apps.toml`/`state.toml` may carry `schema_version`; a file without the marker
  is v1 (today's shape — the daemon deliberately does not write it, so as not to break the nearest rollback), and every
  new field requires bumping `state::SCHEMA_VERSION` and an entry in `SCHEMA_STEPS` (a const-assert enforces it). An
  older daemon refuses to start with a readable message instead of a parse error; a rollback across a schema-version
  boundary requires copies of the files from before the update. `secrets.toml` is not (yet) versioned, and `[notify]` in
  `weglarka.toml` still has to be removed by hand before a downgrade. Guide: `docs/guides/state-schema.md`.
- **Serde:** our TOML files (`weglarka.toml`, `apps.toml`, `secrets.toml`, state) use `#[serde(deny_unknown_fields)]`;
  *external* models (Podman, GitHub) use `#[serde(default)]`, ignore unknown fields and declare only the fields used.
  That is why a new field in our files breaks a downgrade (describe it in the PR and under `## Rollback` of the guide,
  and add the field to the table in `docs/guides/verify-and-rollback.md`).
- **Rollback restores the digest, not the spec:** a failed deploy resumes the previous image *with the new spec*, so a
  spec change that breaks startup (`command`, `env`, a mount) fails the deploy **and** the rollback — the app stays
  down until the spec is fixed. Do not describe a new `AppSpec` field as "rollback-safe" (example: `command`,
  ADR 0019).
- Per-feature schema bumps recorded elsewhere: configs (ADR 0028) → `apps.toml` `schema_version = 2` (no-op step), mounted
  secret owner (ADR 0037) → `schema_version = 7` (no-op step), identity (ADR 0051/0052) → schema 14, OIDC `device_flow` (ADR 0060) → schema 15; see the
  matching rules ([engine-and-deploy.md](engine-and-deploy.md), [identity-and-admin-tokens.md](identity-and-admin-tokens.md)).

## Entry points

| Area | Files |
|---|---|
| app model and validation | `crates/weglarka-model/src/app.rs`, `crates/weglarka-model/src/state.rs` (`AppSpec`, `AppsFile`, `validate_app`, `SCHEMA_VERSION` + the schema gate) |
| spec-hash | `crates/weglarka-model/src/hash.rs` — what recreates the container (`HashInput`) |
| host config | `crates/weglarka-model/src/config.rs` (`HostConfig`, its `validate`) |
| generated-config state | `crates/weglarka-model/src/generated_state.rs` (`generated.toml`) |
