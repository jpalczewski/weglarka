# 0026 — Per-app registry credentials for private image pulls (issue #44, option (b))

Status: accepted (2026-10-24, issue #44).

## Problem

`images/pull` sent no `X-Registry-Auth`, so a private image (GHCR, a self-hosted registry) could only be
pulled if the rootless podman user happened to have a matching `auth.json`. That is ambient, per-host and
invisible to Węglarka: credentials are not scoped to an app, not rotated through the tool's own secret
workflow, and a missing or expired login surfaced as a raw libpod error in the middle of a deploy.

Constraints: credentials never reach logs, `Debug`, events, API errors or `apps.toml`; no new on-disk format
(the schema rules of ADR 0023); `PodmanClient` stays additive for callers and implementors' call sites;
the pull happens before anything is created, so a refused pull must leave the running app untouched.
House order: security → extensible code → RAM.

ADR 0025 chose option (a) for the Forgejo webhook (pulls via `auth.json`); this ADR is the follow-up, option (b).
It keeps the `auth.json` fallback and the `PodmanError::is_registry_auth_failure` / `EngineError::RegistryAuth`
reporting introduced there.

## Decision

**The credentials are an ordinary per-instance secret under a reserved name, and the engine sends them on
every pull of that app.**

1. **Reserved secret `<instance>.registry-auth`**, value `<username>:<password>` (split at the first colon,
   so the password may contain colons; both parts non-empty). It is set like any other secret:
   `weglarka secrets set <app> registry-auth < creds.txt`, removed by `secrets remove` and by
   `apps remove --purge-secrets` (ADR 0024) — nothing new in the API or the TOML files.
2. **Never bound to the container.** `validate_app` rejects a spec that binds `registry-auth` (`secrets =
   [...]`): the credential is for the engine, not for the workload, and binding it would publish it to the
   app. (`webhook-hmac` is deliberately not rejected — it predates this rule and the daemon reads it too.)
3. **`PodmanClient::image_pull_with(reference, Option<&RegistryAuth>)`** is the new required method;
   `image_pull(reference)` becomes a provided method calling it with `None`, so every existing caller
   (ingress' nginx pull, tests) is unchanged and `FakePodman` / `LibpodClient` just implement the new one.
   `RegistryAuth` has private fields, a `Debug` that redacts the password and no `Serialize`.
4. **Wire format:** `X-Registry-Auth` = base64url of `{"username","password","serveraddress"}`, with
   `serveraddress` the registry host of the reference (first path component containing `.`/`:` or
   `localhost`, else `docker.io`). The header value is marked sensitive in hyper, so no `Debug` of the
   request shows it. Base64url is a dozen lines in `weglarka-podman`, tested against the RFC 4648 vectors —
   not worth a new dependency.
5. **Engine:** `Reconciler::pull(instance, reference)` reads the secret on every pull (deploy, provision,
   digest-pinned re-pull in `ensure_image`), so a rotated value applies to the next deploy without a restart.
   - Absent secret → anonymous pull, as before (public images and `auth.json` keep working).
   - Malformed value → `SecretError::Malformed` (never contains the value). It does **not** fall back to
     anonymous: a typo must not silently become a different identity.
   - `PodmanError::is_registry_auth_failure()` (HTTP 401/403, or libpod's 500 / mid-stream error carrying
     `unauthorized`, `authentication required`, `denied:` …) is mapped to `EngineError::RegistryAuth
     { instance, reference, sent_credentials }`. The message names the secret to fix, whether credentials
     were sent (rejected) or absent (required), and never the credentials. The admin API answers `409`, and
     the deploy emits the usual `DeployFailed` event with that text.

`spec_hash`, `apps.toml` and `state.toml` are untouched (the secret is not part of the hash and has no
binding), so there is no schema bump and nothing to roll back across versions: an older daemon simply never
reads the secret and pulls anonymously.

## Consequences

- Operators of private images: `weglarka secrets set <app> registry-auth` (see `docs/install.md`), one
  credential per app, scoped to that app's registry host. Two apps on one registry set it twice — the cost of
  never sharing a credential implicitly.
- A rollback that needs the registry (image no longer local) uses the same secret.
- Only username/password (or a registry token as the password) is supported; identity tokens and per-registry
  maps are not.
- Tests: `RegistryAuth` parsing/`Debug`, `is_registry_auth_failure`, base64url + header sensitivity, the mock
  socket asserts the header on `image_pull_with` and its absence on `image_pull`, engine scenarios on
  `FakePodman::require_pull_auth` (missing → rejected → accepted, malformed, reserved name).

## Rejected alternatives

- **A field in `apps.toml` (`registry_user`, …).** Credentials in the spec file, `spec_hash` impact, schema
  bump — the opposite of "secrets are only referenced by name".
- **A host-wide credential in `weglarka.toml`.** One identity for every app; no per-app revocation; more
  blast radius per leak.
- **Keeping `auth.json` only (option (a)).** Ambient and per-host; still works as the fallback.
- **Changing `image_pull`'s signature.** Would touch every caller for an optional argument; the provided
  method keeps the change additive.
- **A `base64` crate dependency.** One encoder of a dozen lines does not justify a new supply-chain edge.
