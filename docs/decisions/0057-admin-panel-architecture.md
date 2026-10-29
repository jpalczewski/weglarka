# 0057 — Admin panel: a server-rendered BFF with htmx and Alpine

Status: proposed (2026-10-29). Builds on ADR 0056 (token listener, the panel as a confidential BFF client) and ADR 0052
(forward auth). Scope of the first release: read-mostly (decision 7).

## Problem

ADR 0056 gives the panel a way to reach the admin API with a scoped token and fixes that it is a backend-for-frontend
(tokens never reach the browser). It leaves the panel itself open: what it is built with, how its session and requests
are protected, what it may do first, and what the daemon must expose for it.

Threats, in priority order:

- **Token or session theft in the browser.** Anything the page's scripts can read, an injected script can read.
- **A cross-site request riding the session cookie.** The panel authenticates browsers with a cookie, which is
  exactly what CSRF abuses.
- **A panel bug that turns a viewer into an admin.** The panel is the most exposed component that holds a token.
- **Weight on the host.** The panel is one more container on a small box; a Node toolchain and a second dependency
  ecosystem in a Rust workspace are a cost in RAM, build time and supply chain.

## Decision

1. **Server-rendered HTML, no SPA.** The panel is one Rust binary (a new crate, `weglarka-panel`) that renders pages
   and fragments on the server. The browser receives HTML and never sees a bearer token or the raw admin API.
2. **Interactivity: htmx for fragment swaps and refresh, Alpine.js for local widgets** (menus, modals, confirmations).
   Both, and htmx's `sse` extension, are vendored as static files and served by the panel itself: no CDN, no bundler, no
   Node in the build. htmx runs with `includeIndicatorStyles: false` (it would otherwise inject an inline `<style>`) and
   the indicator CSS ships as a static file, so `style-src` never needs `unsafe-inline`. Alpine is
   the CSP build (`@alpinejs/csp`), so the panel can send a Content-Security-Policy without `unsafe-eval`; there is no
   inline script and no inline event handler. The policy also sets `frame-ancestors 'none'`, `form-action 'self'` and
   `base-uri 'none'`, and htmx is configured with `allowEval: false` (a `htmx-config` meta tag), so `hx-on:*` attributes
   are forbidden; the tests fail a page that uses one.
3. **Live data over SSE.** Logs and events reach the page as server-sent events through htmx's SSE support; the panel
   subscribes to the daemon on the page's behalf. No WebSocket and no polling loop in the browser.
4. **Session.** The panel is the OIDC confidential client of ADR 0056 (authorization code with PKCE) and keeps the
   tokens in server memory keyed by an opaque session id. The browser holds only that id in a cookie that is `HttpOnly`,
   `Secure`, `SameSite=Lax` and `__Host-` prefixed. The panel refreshes the access token itself; the daemon still
   verifies every request it forwards (ADR 0056, decision 4), so the panel can never hold more than the user's scope.
   The session id is regenerated at login, a session has an absolute lifetime and an idle timeout, and logout is a `POST`.
   The panel reaches the provider at the public `OIDC_ISSUER` URL over ordinary outbound HTTPS (discovery, token
   endpoint, refresh); unlike the daemon it has no probe socket and needs none. The panel validates the login exchange
   itself (`state`, PKCE and, for any claim it reads from the id token, signature, `iss`, `aud` and `nonce`), but it never
   authorizes an API call: the daemon checks every access token it is given. The host must let the panel's container
   resolve and reach that URL.
5. **CSRF.** Every state-changing request needs a per-session token (a header htmx sets on all requests, or a hidden
   form field) checked by the panel, in addition to `SameSite`. A state-changing route never answers `GET`.
6. **Authorization stays in the daemon.** The panel hides what a viewer cannot do, but never decides it: it forwards
   the user's own token, and a `403` from the daemon is the answer. The panel has no credential of its own with more
   scope than the logged-in user.
7. **Release 1 is read-mostly.** A viewer (`read`) sees app list and detail, status, `doctor`, volumes, sites, networks,
   notification state, certificates and recent events. Live app logs need the `admin` scope: logs can hold secrets and
   user data, which ADR 0056 decision 7 already puts behind `admin` (as with volume export). Deploys, secrets, `run`,
   `forward`, `push` and volume export/import are later releases and each gets its own review of the confirmation and
   audit story.
8. **The daemon grows the missing endpoints first**, in `weglarka-api` and routed on both listeners (ADR 0056,
   decision 1), each additive: app logs as a stream (`admin`, audited), recent events (`read`; a flat record with a
   monotonic sequence number, not the engine's `Event`), per-container runtime detail (restarts, health, start time),
   an allowlisted view of host config, and certificate expiry. Two things must hold before any page uses them:
   - **No credential at `read`.** `GET /v1/apps/{name}` returns the whole app spec today, including `env` values; for a
     `read` principal those values are blanked, from one constructor shared by every code path that builds the response.
   - **A stream ends with its token.** The token layer verifies once at the start of a request, so the verified
     principal carries the token's `exp` and a streaming handler stops when it passes; the panel reconnects with a
     refreshed token, resuming by sequence number. The panel's own stream to the browser ends when the session does
     (logout, idle timeout, absolute lifetime or a failed refresh), so a logged-out browser stops receiving logs.
9. **Deployment.** The panel is an ordinary app: an image from the same release, an entry in `[admin.http] clients`, an
   OIDC registration and `ingress.auth_policy` per ADR 0056/0052 (its `health.http` path in `auth_exempt_paths`). It runs
   under the container hardening profile (ADR 0014) with no host mounts besides the token socket.

Invariants for implementers: the browser never receives a bearer token; no inline script or `eval` (the CSP is part of
the contract, tested); every mutation is CSRF-checked; the panel adds no route to the daemon API and holds no host
credential; new endpoints are additive and updated in `FakePodman`-backed tests; nothing in the panel is a required
dependency of the daemon (the unix socket works with the panel gone).

## Consequences

- **Code:** a new leaf crate `weglarka-panel` depending on `weglarka-api`, `weglarka-model`, `weglarka-http` and a shared
  unix-socket HTTP client crate extracted from the CLI (never `engine`, and the daemon never depends on the panel), with
  `askama`/`maud`-style compile-time templates and static assets embedded in the binary. Its dependencies go in
  `[workspace.dependencies]`; the CI dependency guard gains the new crate.
- **API contract:** new read endpoints and stream frames in `weglarka-api` (see decision 8); `ENDPOINTS` tests already
  fail closed on an undeclared route.
- **Operators:** a new guide in `docs/guides/` (enabling the panel, the groups it needs, what release 1 shows). It
  changes no state file, so it adds no `schema_version` step; the `[admin.http]` rollback note of ADR 0056 still applies.
- **Tests:** CSP header and absence of inline script on every page, CSRF rejection on each mutation route, a viewer token
  never reaching an `admin` route, session cookie attributes, and an end-to-end render against a fake daemon.
- **Provider token format:** `typ: at+jwt` was confirmed on Authelia 4.39.22 (ADR 0056 decision 5); a CI check that
  issues a token and asserts the header keeps a provider upgrade from silently locking the panel out.

## Rejected alternatives

- **A single-page application.** It moves rendering and authorization-aware logic into the browser, adds a Node
  toolchain and a second dependency tree, and still needs the BFF for tokens. Nothing in release 1 (tables, forms,
  statuses, logs) needs client-side state. A heavy view added later can be an isolated island without rewriting the rest.
- **A public OIDC client with tokens in the browser.** Already rejected in ADR 0056; repeated here because it is the
  default shape of an SPA.
- **Polling or WebSockets for live data.** Polling wastes the daemon's time per open tab; WebSockets need an upgrade path
  through the ingress and their own authentication. SSE rides plain HTTP and the existing session.
- **Alpine's standard build.** It evaluates expressions with `new Function`, which needs `unsafe-eval` in the CSP and
  removes the main defence against injected script.
- **Letting the panel hold its own admin credential.** It would make a compromised panel equal to the break-glass socket.
  The user's token is forwarded instead, so the panel is never more powerful than its current user.
