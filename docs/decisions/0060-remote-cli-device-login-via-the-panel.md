# 0060 — Remote CLI: `weglarka login` (device authorization grant) through the panel

Status: proposed (2026-10-30, issues #43 and #93). Builds on ADR 0056 (token listener) and ADR 0057 (admin panel);
amends the "listening on the ingress" rejection in ADR 0056.

## Problem

The CLI only talks to the admin API over the unix socket, so a remote operator needs an SSH tunnel and, once there, holds
full root of trust with no identity. ADR 0056 added a token listener and ADR 0057 a public panel that already
authenticates people against the identity provider and reaches that listener. The CLI should do the same: sign in with the
provider (which applies its 2FA policy), hold a short-lived token, and call a remote host. Two things are missing: a
public, bearer-authenticated path to the daemon's token socket, and a way for the CLI to obtain and keep tokens.

ADR 0056 rejected exposing the API on a routed domain: it puts the admin surface on the public ingress. That reasoning
still holds for a *new* surface, but the panel is already public, already holds the socket mount and already carries every
protection a public admin front needs (TLS, rate limiting, security headers). The marginal exposure of relaying the same
API through it is small, provided the relay adds no authority of its own.

## Decision

1. **A bearer-only relay in the panel.** `/_weglarka/api/v1/*` forwards a request to the daemon's token socket. The prefix is
   deliberately one no ordinary app serves (`weglarka_model::admin_auth::RELAY_PREFIX`). It is an allowlist:
   `weglarka_api::endpoints::lookup(method, path)` must match, otherwise `404`; the endpoint table is the only route
   list, as on both daemon listeners. The relay
   - forwards `Authorization: Bearer …` unchanged and **decides nothing**: the daemon verifies signature, audience and
     groups and applies the scope, so a compromised panel cannot widen what a token may do;
   - never reads or forwards `Cookie`, ignores the session store, and carries no CSRF token: a browser session cannot
     authenticate on the relay, and a bearer token is not CSRF-able;
   - is rate-limited per client address by the existing `AddressLimiter`, and caps header and body sizes;
   - passes bodies through unbuffered in both directions, and a streaming answer ends with its token exactly as on the
     socket (the daemon's `TokenExpired` frame arrives unchanged).
   The ingress in front of the panel is Węglarka's own nginx, in `edge` mode terminating TLS itself (there is no Traefik
   to account for). **The operator configures nothing for the relay:** the ingress plan knows `[admin.http] clients`
   and, for such an app served at `/`, carves `RELAY_PREFIX` out of the catch-all itself, without `auth_request`
   (forward auth cannot work for a client that sends a token, and the daemon authenticates), with buffering off
   (ADR 0047), the one-hour idle timeout of a streaming path and an 8 GiB body limit. A separate, otherwise unused
   prefix is what makes this safe: exempting a common path such as `/api` for every admin client would silently
   unprotect an unrelated app that serves its own `/api`. Overlapping `streaming_paths` or `auth_exempt_paths` entries
   are refused. `run`, `push` and `forward` need a request body that streams while the response does; they are enabled
   in v1 only if the relay is shown to carry them through nginx in a test, otherwise they stay on the socket (SSH)
   path and the CLI says so instead of failing obscurely. The rate limit's client address is the connection peer;
   behind nginx on the same host that is nginx itself, so the relay must read the forwarded address the way
   `PANEL_TRUSTED_PROXIES` does (ADR 0059), and the guide states how to set it for `edge`.
2. **The CLI is a public OIDC client using the device authorization grant (RFC 8628).**
   `weglarka login --host https://panel.example.com` discovers the provider from the panel (not from user input),
   requests a device code at the provider's `device_authorization_endpoint`, prints the `verification_uri` and the
   `user_code`, and polls the token endpoint at the advertised `interval` (honouring `slow_down`, giving up at
   `expires_in`) until the person approves on any device, where the provider applies its 2FA policy. No browser, no local
   listener and no redirect URI are needed, so it works over SSH and on headless machines. The client sends no secret
   (`public = true`, `token_endpoint_auth_method = "none"`) and the access token is verified exactly as the panel
   verifies its own (`admin_auth`). The client needs the same `audience`, `access_token = "jwt"` and groups in the access
   token as the panel's, plus `offline_access`.
   The identity renderer currently emits only `authorization_code` and `refresh_token` grants
   (`crates/weglarka-identity/src/oidc.rs`), so the OIDC client spec gains an **optional** `device_flow` flag that adds
   `urn:ietf:params:oauth:grant-type:device_code`; unset it changes neither the rendered file nor `spec_hash`.
   Authelia supports the grant (its OIDC support chart lists RFC 8628 as complete); the provider's discovery must list
   `device_authorization_endpoint`, and `login` says so plainly when it does not.
3. **Tokens are kept by the CLI and refreshed on use.** File `credentials.toml` next to `cli.toml`, mode `0600`, keyed by
   host; the access token is refreshed shortly before `exp` with the refresh token, under a file lock so two CLI processes
   do not race a rotating refresh token. No token is printed, logged or put in an error. `weglarka logout` deletes the
   host's entry and revokes the refresh token at the provider's `revocation_endpoint` when discovery lists one.
4. **A transport seam in the CLI.** `ApiClient` gains a second transport (HTTPS with a bearer) next to the unix socket;
   the host comes from `--host`, `WEGLARKA_HOST` or `cli.toml`. `--socket` and the default socket stay as they are and
   remain the break-glass path. `weglarka-unix-http` exposes `buffered_over`/`open_over` for a stream the caller connected,
   so the remote path reuses the same request/response code over a hyper + rustls connection.
5. **Shared OIDC logic without `reqwest` in the CLI.** The transport-independent half of the panel's client lives in a
   new crate, `weglarka-oidc`: discovery with the scheme and host policy, PKCE and the authorization URL, token requests
   for a confidential (`client_secret_basic`) or public client, refresh, revocation and the device grant. It is generic
   over a small `Transport` trait (`get`, `post_form`, native `async fn`, ADR 0001). The panel implements the transport
   with `weglarka-http` (reqwest) and keeps its caches, JWKS and id-token verification (it is the only client that
   verifies id tokens; the CLI treats the access token as opaque, the daemon decides). The CLI implements the transport
   with `hyper` + `tokio-rustls` + the bundled roots (`ring`, no C crypto). The guard that keeps `reqwest` out of the
   CLI stays; `check-deps.sh` additionally checks that `weglarka-oidc` has no HTTP client or TLS stack of its own.
6. **Authorization code flow later.** `weglarka login --browser` (code flow with PKCE and an RFC 8252 loopback redirect,
   for people who prefer a single click on a workstation) shares everything but the login step and is a follow-up. The
   OIDC core keeps PKCE and authorization-URL building for it and for the panel.

## Consequences

- No `apps.toml`/`state.toml` field and no `spec_hash` change: the relay is part of the panel binary and its env
  configuration, the CLI client is registered with existing identity features plus the optional `device_flow` flag above (a new optional `[apps.*.oidc]` field is a schema-visible addition: it bumps `SCHEMA_VERSION` with a `SCHEMA_STEPS` entry, ADR 0023). `cli.toml` gains `host` (its
  `deny_unknown_fields` hint is updated); `credentials.toml` is a new CLI-only file, outside the schema-versioned state.
- Threat model: the **refresh token on the workstation's disk** is the long-lived credential (guarded by `0600` and the
  provider's refresh-token lifetime and revocation); access tokens stay short (15 minutes at most, ADR 0056). The public
  relay path is reachable by anyone, so it must authenticate before it costs anything: unauthenticated requests are
  cheap to refuse and rate-limited. A panel compromise now exposes bearer tokens in flight for API calls, as it already
  does for its own sessions, but never gives a token more power than the daemon grants it.
- Operators who do not run the panel have no remote path (the unix socket and SSH remain); the panel is a documented
  prerequisite of `weglarka login`.
- Tests that must exist: relay allowlist and `404` for unknown routes, cookie never accepted, bearer forwarded byte for
  byte, daemon `401`/`403` passed through, streaming answers and `TokenExpired` relayed unbuffered, rate limit; the OIDC
  core against the existing panel provider mock; CLI login against that mock (state/nonce mismatch, timeout, port
  in use, refresh, refresh failure, logout and revocation); `check-deps.sh` guards.
- Docs: `docs/guides/admin-api-tokens.md` (the relay), `docs/guides/admin-panel.md` (the relay), a new
  `docs/guides/remote-cli.md`; issues #43/#93 keep the device flow wording.

## Rejected alternatives

- **A new listener on the ingress for the CLI** (ADR 0056's rejection stands): a second public admin surface with its own
  TLS, routing and rate limiting to maintain, for no extra capability over the panel.
- **The CLI as a confidential client sharing the panel's secret:** a secret on every workstation is not a secret.
- **Authorization code flow first (loopback redirect):** one click on a workstation, but it needs a local browser and a
  redirect URI the provider must match for an ephemeral port (unverified against Authelia, #294), and it fails over SSH.
  Kept as `--browser`.
- **`reqwest` in the CLI:** simplest code, but it turns a small static client into a network-facing binary with the whole
  `reqwest` tree; the transport trait keeps the guard in place at the cost of a small hyper client.
- **Panel mints its own CLI tokens:** a second token system next to the provider's, with its own revocation and 2FA story.
- **Relay terminates auth and talks to the socket as the panel's identity:** it would make the panel the authority; the
  daemon must keep verifying the end user's token.
