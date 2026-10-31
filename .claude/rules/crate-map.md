---
paths:
  - "Cargo.toml"
  - "crates/*/Cargo.toml"
  - ".github/scripts/check-deps.sh"
---

# Crate map and dependency rules

Dependencies: `api → model`; `podman → model`; `ingress → model`; `notify → model, http`; `registry → model, http`;
`dns → model, http`; `acme → model, http`; `identity → model`; `http → (nothing from Węglarka)`; `unix-http → (nothing from
Węglarka)`; `engine → model`; `acme → dns`; `cli → api, model, engine, unix-http`; `panel → api, model, http,
unix-http`; `daemon → everything` (except `panel`). Leaves (api, ingress, notify, acme, podman, dns, registry, panel)
do not depend on `engine` — do not add it to them (most depend **only on the model**); no crate depends on `panel`
(ADR 0057).

A new external dependency: add it to `[workspace.dependencies]` in the root `Cargo.toml` and reference it with
`.workspace = true`. With several agents in parallel: one crate/area per agent, and contract changes (`app.rs`,
`podman.rs`, `weglarka-api`) only additive and always with an update of `FakePodman`.

| Crate | Contents |
|---|---|
| `weglarka-model` | domain model without the engine: types (`AppSpec`, `HostConfig`, state and the schema gate), validation of `apps.toml`/`state.toml` (including the pure parts of `depends`, `shared_networks`, `shared_volumes`), `fsutil::write_atomic`, `hash`/`labels`/`uid_range`/`limits`, `identity`, `events`, self-update state (`self_update.rs`: state file + pure `decide()`/`supervise()`), the webhook dedup file (`delivery.rs`), `FileSecretStore`, traits (`PodmanClient` + types, `WebhookSource`, `SecretStore`); no Podman calls and no `tokio` (ADR 0053) |
| `weglarka-engine` | the engine: reconcile, deploy (health gate, rollback), volumes and UID ranges (including shared), host configs (`config_mounts.rs`), host mounts, crash detection (`crash.rs`), sites/promote/push/run/forward, the `depends_on` gate, secret delivery, the `Platform` trait + `FakePodman` (feature `testing`), engine tests and integration tests with real Podman (`tests/`) |
| `weglarka-podman` | libpod v6 client (hyper, unix socket) + integration tests |
| `weglarka-ingress` | pure generators of `nginx.conf` (`behind` and `edge`) and of Traefik's dynamic file (snapshots) |
| `weglarka-http` | shared HTTP client (#219): `client(Purpose)` builds a `reqwest::Client` (http1, `rustls` + `ring` explicitly, `webpki-roots`, no aws-lc/OpenSSL; `rustls-platform-verifier` is in the graph but unused) with timeouts and a redirect policy per purpose; **depends only on external crates** (nothing from Węglarka), so `reqwest` reaches only network crates (not cli/api/ingress); guard `.github/scripts/check-deps.sh` in the `check` job |
| `weglarka-panel` | admin panel (ADR 0057), see [panel.md](panel.md): server-side rendered (BFF), lib + bin `weglarka-panel`; the guard `check-deps.sh` enforces no `engine` and no C crypto |
| `weglarka-unix-http` | HTTP/1 client over a unix socket (hyper, one connection per request): `UnixClient` — `buffered`, `open` (`StreamingResponse`), `connect`; `bearer()`; `buffered_over`/`open_over` for a stream the caller connected (the CLI's TLS relay connection); feature `testing`: `testing::mock`; **a leaf with no Węglarka dependency and no `reqwest`** (guard in `check-deps.sh`); used by `cli` and `panel`; `health_probe` in the daemon is deliberately separate (raw bytes, HTTP/1.0, injection guards); `podman/src/transport.rs` is the same hyper-over-unix-socket code and a **planned migration** under #77 (not done yet) |
| `weglarka-oidc` | Transport-agnostic OIDC client logic (ADR 0060): `discover` (scheme/host policy, optional device and revocation endpoints), `authorization_url`/`pkce_challenge`, `token_request`/`refresh`/`revoke` with `ClientAuth::{Secret, Public}`, the device grant (`device_authorization`, `poll_device_token`), `Secret`; generic over `Transport`; **no HTTP client, TLS stack or `weglarka-*` dependency** (guard in `check-deps.sh`); used by `panel` (reqwest transport) and `cli` (hyper transport) |
| `weglarka-notify` | notifications: `Event` → `Severity` → messages → dedup → durable queue (outbox) → channels (`ntfy`; mail = #113), HTTP client from `weglarka-http`, `endpoint.rs` (URL parsing); see [notify-and-selfupdate.md](notify-and-selfupdate.md) |
| `weglarka-registry` | cosign signatures from OCI (tag `.sig` + GHCR token) and verification with a static ECDSA P-256 key (`ring`); HTTP client from `weglarka-http` (`Purpose::Registry`: ≤5 redirects, https/loopback only, no token to a foreign host), `FakeRegistry`/`TestSigner` (feature `testing`) |
| `weglarka-acme` | ACME engine for `edge` mode (#96, ADR 0038): `CertSpec`/`CertId` (a certificate = a list of names, the file carries the id), trait `ChallengeSolver` (`Http01Solver`, `DnsSolver` over `weglarka-dns` = #97), `AcmeClient`/`CertInspector`, `CertStore` (key 0600 before cert 0644, atomically), pure `renewal::decide`, `Manager::pass`; `InstantAcme` (client on `instant-acme`, `ring`; HTTP via `weglarka-http` `Purpose::Acme` in `http.rs`; `not_after.rs` = the fail-closed `notAfter` reader, no x509 crate), `FakeAcme` (feature `testing`); the test against Let's Encrypt staging is opt-in (`WEGLARKA_ACME_STAGING_DOMAIN`/`_WEBROOT`); worker in the daemon (`daemon/src/acme.rs`, `[acme]`, events, `doctor acme.*`) |
| `weglarka-dns` | DNS adapters for ACME DNS-01: trait `DnsProvider` (`set_txt`/`remove_txt`, the handle removes exactly its own record), Cloudflare adapter (API v4, HTTP client from `weglarka-http` (`Purpose::Api`, no redirects), token as `SecretValue`), `FakeDns` (feature `testing`); ADR 0039 |
| `weglarka-identity` | pure renderers of the identity provider config (Authelia, #42 P3): `render_oidc_clients` → `oidc-clients.yml` (OIDC clients of apps and external ones + `claims_policies`, secret only as a digest, #91) and `render_access_control` → `access-control.yml` (always `default_policy: deny` + a fixed `bypass` rule for the issuer host, #90); JSON in a `.yml` file, deterministic output, snapshots; no I/O; `AutheliaGenerator` (an impl of `ConfigGenerator` from `model`) plugs both renderers into the pipeline, registered by `daemon/src/generated.rs::registered` when `[identity]` exists; the CI job `identity-config` validates the fixtures with `authelia config validate` on a pinned image |
| `weglarka-api` | admin API contract (types, endpoints, error codes) |
| `weglarka-daemon` | the daemon: admin API (unix socket, including `GET /v1/health`), webhooks, ingress writing, systemd `Platform` (quadlet + self-update and watchdog timers), notification worker, host-side `self-update` and `supervise` |
| `weglarka-cli` | CLI `weglarka`, `doctor --preflight` |
