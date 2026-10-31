---
paths:
  - "crates/weglarka-panel/**"
  - "crates/weglarka-unix-http/**"
  - ".github/scripts/check-deps.sh"
---

# Admin panel and the unix-socket HTTP client

## Invariants

- **Dependencies (ADR 0057):** nothing depends on `weglarka-panel`; it has no `weglarka-engine` and no C crypto (the guard
  `.github/scripts/check-deps.sh` enforces it). `weglarka-unix-http` and `weglarka-http` are leaves; `reqwest` stays out
  of the CLI.
- **Server-side rendered BFF.** Everything except `/healthz`, `/static/*`, `/auth/login`, `/auth/callback` and `/_weglarka/api/*`
  sits behind `auth::require_session` (default-deny). `/_weglarka/api/*` is the bearer-only relay to the daemon (ADR 0060,
  `relay.rs`): endpoint allowlist from `weglarka_api::endpoints`, no cookie ever read, only four headers forwarded, rate
  limit and in-flight cap, the daemon authorizes. The user's access token is only ever sent in `Authorization`; cookies carry
  the session id (`__Host-` prefix). Non-GET requests need a CSRF token and a same-origin `Sec-Fetch-Site`. Every
  response carries the CSP and the other security headers (`headers.rs`).
- **Configuration** is env-only (`config.rs`): `OIDC_*` (including `OIDC_CLIENT_SECRET_FILE`), `PANEL_PUBLIC_URL`,
  `PANEL_API_AUDIENCE`, `PANEL_SESSION_IDLE_SECS`/`_MAX_SECS`, `PANEL_TRUSTED_PROXIES`, `PANEL_LISTEN`, `WEGLARKA_PANEL_SOCKET`; secrets are
  `Secret` with a redacted `Debug`; an `http://` issuer is allowed only on loopback.
- Vendored htmx/SSE/Alpine CSP builds live in `crates/weglarka-panel/assets/vendor/` (versions and SHA-256 in
  `VENDORED.md`; a test pins them).
- `health_probe` in the daemon is deliberately separate from `weglarka-unix-http` (raw bytes, HTTP/1.0, injection
  guards); `crates/weglarka-podman/src/transport.rs` is the same hyper-over-unix-socket code and a **planned migration**
  under #77 (not done yet).

## Entry points

| Area | Files |
|---|---|
| panel (ADR 0057) | `config.rs` (env), `daemon.rs` (`DaemonClient` over `weglarka-unix-http`: `Call` = `Endpoint` + parameters, token only in `Authorization`, mapping 401/403/404/5xx to `DaemonError`, explicit deadline), `app.rs` (axum routes), `oidc.rs` (OIDC client: discovery, PKCE S256, code exchange and refresh with `client_secret_basic`, JWKS + `admin_auth::verify` for the id token), `limit.rs` (callback rate limit per client address, trusted-proxy `X-Forwarded-For`), `relay.rs` (the `/api` relay, tests `tests/it/relay.rs`), `session.rs` (`SessionStore`, `PendingLogins`, `Session::ended()`, `Clock`), `auth.rs` (login/callback/logout, `__Host-` cookies, token refresh), `csrf.rs`, `secure.rs`, `headers.rs`, `assets.rs` (`include_bytes!`), `pages.rs` + `templates/` (askama), `server.rs` (graceful shutdown); read-only pages: `routes.rs` (`app_stats` is the polled "Resources" fragment `GET /apps/{name}/stats`: 404/auth errors are the usual pages, any other daemon failure a muted line inside the fragment so polling keeps the page; the apps list fetches `STATS` once and ignores its failure; fetch with the user's token, mapping daemon errors 401/403/404/5xx to pages), `views.rs` (view models); SSE streams: `live.rs` (events by polling `/v1/events?since=`; daemon streams through one resumable `Driver` — reconnect after `TokenExpired`/a dropped connection with `since` = last data, `MAX_RECONNECTS`, end with the session — over an `UpstreamFeed` per stream (`LogsFeed`, `AccessFeed` — the browser's access filter goes through `weglarka_api::AccessQuery::parse` and only the parsed value is forwarded, fields are cut with `clean_text`; the app page opens no stream on load, the `Start` buttons `hx-get` the `/apps/{name}/logs` and `/apps/{name}/access` fragments that carry the `sse-connect`; a new daemon stream is a new feed, not a new state machine) and `weglarka_api::ControlFrame`; a per-session stream limit) — all under `crates/weglarka-panel/src/`; tests `crates/weglarka-panel/tests/it/main.rs` |
| unix-socket HTTP client | `crates/weglarka-unix-http/src/`: `UnixClient` — `buffered` (whole response), `open` (`StreamingResponse`, body in frames), `connect`; `bearer()` builds a sensitive `Authorization` header; feature `testing`: `testing::mock` (server mock on a short socket, records method, path, query, headers, body); used by `cli` and `panel` |
