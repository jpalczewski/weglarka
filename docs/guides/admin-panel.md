# Admin panel

The admin panel is a small web UI for looking at a Węglarka host: apps and their health, `doctor` results, volumes,
sites, networks, notification state, certificates and recent events, and (for admins) live app logs. It is an ordinary
app that Węglarka runs for you, one container from the `ghcr.io/jpalczewski/weglarka-panel` image
([ADR 0057](../decisions/0057-admin-panel-architecture.md)).

## What it is, and what it is not

- **Read-mostly.** Release 1 only shows things. There is no deploy button, no secret editor, no `run`, `forward`, `push`
  or volume export/import: those come later, each with its own review. Everything you can change, you still change with
  the CLI or by editing `apps.toml`.
- **A backend-for-frontend.** The panel renders HTML on the server. The browser never receives a bearer token and never
  talks to the admin API; it holds only an opaque session cookie. There is no single-page app and no Node toolchain.
- **Not an authority.** The panel logs the user in at your identity provider and forwards the *user's own* access token
  to the daemon's token listener ([admin API tokens](admin-api-tokens.md)). The daemon verifies every request and decides
  what the token may see. The panel hides what a viewer cannot do, but it holds no credential of its own, so a
  compromised panel is never more powerful than the user who is currently logged in.
- **Optional.** Nothing in the daemon depends on the panel. The unix socket and the CLI work with the panel gone.

## Prerequisites

1. An [identity provider](identity-provider.md): `[identity]` in `weglarka.toml` and the provider app running.
2. The [token listener](admin-api-tokens.md): `[admin.http]` with the panel's instance name in `clients`, an `audience`
   and the groups that map to `read` and `admin`:

   ```toml
   [admin.http]
   clients = ["panel"]
   audience = "https://admin.example.com/api/"
   read_groups = ["viewers"]
   admin_groups = ["admins"]
   ```

   Restart the daemon after editing `weglarka.toml`. The panel container gets the token socket directory mounted
   read-only at `/run/weglarka-admin/` (the socket is `/run/weglarka-admin/api.sock`); that mount is the only host path
   the panel needs, and it is added because the instance is listed in `clients`.
3. The user groups `viewers` and `admins` (or whatever you named them) exist in the provider's user database. A user in
   neither group can sign in but sees nothing: every page answers "No access" and the session is ended.
4. A public domain for the panel (`panel.example.com` below) pointing at the host, and the panel container being able to
   resolve and reach the issuer URL outbound (see [Operations](#operations)).

## The app definition

```toml
[apps.panel]
image = "ghcr.io/jpalczewski/weglarka-panel:0.1.0"   # same version as the daemon, see below
domains = ["panel.example.com"]
port = 8080
auto_update = false
security = { read_only = true, cap_drop = ["ALL"], no_new_privileges = true }
health = { http = { path = "/healthz" } }

[apps.panel.env]
PANEL_PUBLIC_URL = "https://panel.example.com"
PANEL_API_AUDIENCE = "https://admin.example.com/api/"   # byte for byte [admin.http] audience

[apps.panel.ingress]
auth = "forward"
auth_policy = "two_factor"
auth_groups = ["viewers", "admins"]
auth_exempt_paths = ["/healthz"]

[apps.panel.oidc]
redirect_uris = ["https://panel.example.com/auth/callback"]
scopes = ["openid", "profile", "groups", "offline_access"]
audience = ["https://admin.example.com/api/"]
access_token = "jwt"
groups_in_access_token = true
client_secret = { kind = "env", var = "OIDC_CLIENT_SECRET" }
```

Notes on each part:

- **Image and tag.** The panel is released together with the daemon: a `vX.Y.Z` tag publishes
  `ghcr.io/jpalczewski/weglarka:X.Y.Z` and `ghcr.io/jpalczewski/weglarka-panel:X.Y.Z` (no `v` in the image tag). Run the
  panel at the same version as the daemon, because both speak the admin API contract. The panel image is public
  and has no `latest` before the first release. Both images are signed like the daemon's
  ([self-update](self-update.md) explains the signatures). Keep `auto_update = false` so the panel is upgraded together
  with the daemon, on purpose.
- **Image contents.** A single static binary on `scratch`, running as the numeric user `65532:65532`, listening on `8080`.
  It writes nothing to disk, so the hardening above works (the CI smoke test starts it with exactly these flags).
  [Container hardening](container-hardening.md) describes the block.
- **No volumes, no host mounts.** Sessions are in memory and the configuration is environment-only. Do not add
  `host_mounts`; the token socket is mounted by Węglarka itself.
- **Health.** `GET /healthz` answers `200 ok` without a session. The daemon's probe reaches it through the ingress probe
  socket, which forward auth lets through, so `auth_exempt_paths` is not needed for Węglarka's own health gate. List it
  only if an *external* monitor must reach it ([forward auth](forward-auth.md)). Paths other than `/healthz`,
  `/static/*`, `/auth/login`, `/auth/callback` and `/_weglarka/api/*` (bearer only, [see below](#the-api-relay-for-weglarka-login)) need a session, so exempting `/healthz` exposes nothing else.
- **Forward auth in front.** The panel does its own OpenID Connect login, so forward auth is a second gate: it keeps the
  login page, the assets and the callback away from anyone who is not in `auth_groups`. The provider session cookie domain
  must cover `panel.example.com`. You can leave `ingress.auth` out and rely on the panel's own login and the daemon's
  scopes; the guide above keeps both on purpose.
- **OIDC client.** The client id is the instance name (`panel`). The daemon injects `OIDC_CLIENT_ID`, `OIDC_ISSUER`
  and the client secret ([identity provider](identity-provider.md)); the redirect URI is `PANEL_PUBLIC_URL` plus
  `/auth/callback`. `audience` must equal `[admin.http] audience` and `access_token = "jwt"` with
  `groups_in_access_token = true` is what lets the daemon map groups to scopes. The panel always requests the scopes
  `openid profile groups offline_access`, so list all four: without `offline_access` the provider issues no refresh token
  and a session ends when its first access token expires.
- **Secret as a file.** To keep the secret out of the environment use
  `client_secret = { kind = "mount", path = "/run/secrets/oidc", uid = 65532, gid = 65532, mode = 0o400 }` and add `OIDC_CLIENT_SECRET_FILE = "/run/secrets/oidc"` to `[apps.panel.env]`. The owner must be the
  panel's user, or the process cannot read the file and refuses to start.

First start: `weglarka apps show panel`, then open `https://panel.example.com/`.

## Environment

All configuration is environment-only. The daemon injects the three `OIDC_*` values for an app with `oidc`; set the rest
in `[apps.panel.env]`. A bad value stops the process at start with a message that names the variable and never prints the
value (look in `podman logs` for the panel container). Empty values count as unset.

| Variable | Default | Meaning |
|---|---|---|
| `OIDC_CLIENT_ID` | required | Client id at the provider (the instance name; injected). |
| `OIDC_ISSUER` | required | Issuer URL, compared byte for byte with the token's `iss` (injected). Must be `https://`. Plain `http://` is accepted only for a loopback IP address (`127.0.0.1`, `[::1]`, not `localhost`), meant for a test provider; the same rule applies to every endpoint the discovery document names. |
| `OIDC_CLIENT_SECRET` | required unless the file variable is set | Client secret (injected for `kind = "env"`). |
| `OIDC_CLIENT_SECRET_FILE` | none | Path of a mounted secret file (first line, at most 4 KiB). Set it **or** `OIDC_CLIENT_SECRET`, not both. |
| `PANEL_API_AUDIENCE` | required | The `aud` the daemon expects (`[admin.http] audience`); sent in the authorization request so tokens carry it. |
| `PANEL_PUBLIC_URL` | required | The panel's public origin; the redirect URI is `<url>/auth/callback`. |
| `PANEL_SESSION_IDLE_SECS` | `1800` | A session ends after this long without a request (60 to 86400); must not exceed the maximum. |
| `PANEL_SESSION_MAX_SECS` | `28800` | A session ends this long after login, however active (300 to 604800). |
| `OIDC_ENDPOINT_HOSTS` | none | Comma-separated host names, besides the issuer's, that the discovery document may name for `token_endpoint` and `jwks_uri`. By default both must be on the issuer's host and port, so a poisoned discovery document cannot redirect the client secret. |
| `PANEL_TRUSTED_PROXIES` | none | Comma-separated IP addresses or CIDR ranges (for example the Traefik network) whose `X-Forwarded-For` the panel believes. Sign-in callbacks are limited to 20 per minute per client address ([ADR 0059](../decisions/0059-panel-login-callback-rate-limit.md)); the client is the connection's peer, or, for a trusted peer, the right-most forwarded address that is not itself trusted. Behind a proxy set this, otherwise all clients share the proxy's address and one budget: Traefik's network in `behind` mode, Węglarka's own nginx in `edge` mode (it sets `X-Forwarded-For` from the client address). The same address also keys the `/api` relay's rate limit. **It is required for per-client limits:** without it the sign-in limit and the `/api` relay's limit (300 requests a minute) are each one counter shared by every client, so a single busy or hostile client can exhaust it for everybody. If a request from a peer outside this list carries `X-Forwarded-For`, `Forwarded` or `X-Real-IP`, the panel logs one warning naming the peer (it never trusts those headers from it). Leave it empty only when the panel's port is reachable without a proxy. |
| `PANEL_LISTEN` | `0.0.0.0:8080` | Listen address inside the container. Leave it unless you also change `port`. |
| `WEGLARKA_PANEL_SOCKET` | `/run/weglarka-admin/api.sock` | The daemon's token socket (also `--socket`). |
| `PANEL_REQUEST_TIMEOUT_SECS` | `10` | How long the daemon may take to answer a request (1 to 120). |

## What each user sees

| Scope (from the token's groups) | Pages |
|---|---|
| none | Signed in, but every page says "No access" and the session ends. |
| `read` (viewers) | Dashboard, apps and app detail, `doctor`, volumes, networks, sites, notifications, certificates, recent events (with a live feed), and the allowlisted host config view. |
| `admin` | Everything a viewer sees, plus live logs on each app page. |

- App detail is the daemon's *redacted* view for viewers: environment **values are never shown, only the keys** (and not
  to admins either: the panel renders keys only), every element of the command is replaced by a placeholder (the page then shows `<redacted>` where it names the
  program) and the health probe path is cut. A page built from a redacted view carries a badge. Details: [admin API tokens](admin-api-tokens.md).
- Logs need `admin` because they can hold secrets and user data. The log view relays the daemon's stream, with control
  characters stripped and long lines cut. A viewer's request is answered `403` by the daemon; the page offers the log
  section only when the view is not redacted.
- Events are polled from the daemon every few seconds and pushed to the page as server-sent events; a reconnect resumes
  where it stopped. A session may hold at most four live streams.
- The panel never decides access itself: a `403` from the daemon is the answer.

## Login and sessions

1. `GET /auth/login` starts an authorization code flow with PKCE (S256) at the provider and sets a short-lived
   `__Host-weglarka-login` cookie. That cookie is sealed (ChaCha20-Poly1305) under a key that exists only in the panel
   process, and each login can be answered once, so nothing is stored for anonymous visitors.
2. `GET /auth/callback` exchanges the code with the client secret, verifies the id token (signature, `iss`, `aud`,
   `nonce`) and creates a session with a fresh id. The browser receives only that id in `__Host-weglarka-session`:
   `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, no `Domain`.
3. The access and refresh tokens stay in the panel's memory. The panel refreshes the access token when less than a minute
   is left; if the provider refuses the refresh, the session ends. Keep the provider's access token lifetime short (15
   minutes at most, see [admin API tokens](admin-api-tokens.md)); a stream ends with its token and reconnects with a
   fresh one.
4. A session ends after `PANEL_SESSION_IDLE_SECS` without a request or `PANEL_SESSION_MAX_SECS` after login, whichever
   comes first. Streams do not count as activity. At most 1024 sessions exist at once and 5 per identity (a further login
   evicts that identity's oldest).
5. Logout is `POST /auth/logout` (CSRF-checked). It ends the panel session only, not the provider's.

**Sessions live in memory, so run exactly one replica.** A restart of the panel (including an upgrade and a daemon
restart that recreates it) signs everybody out, and users just log in again. There is no shared session store.

A request whose lowest-scope (`read`) call is refused by the daemon (`401`, or `403` because the groups map to no scope)
ends the session immediately and shows the sign-in page. A `403` on a higher-scope call (the logs) keeps the session.

## The API relay for `weglarka login`

`/_weglarka/api/v1/*` is a second, non-browser face of the panel ([ADR 0060](../decisions/0060-remote-cli-device-login-via-the-panel.md)):
it forwards a request, byte for byte, to the daemon's token socket, so the CLI can work with a remote host after
[`weglarka login`](remote-cli.md). `GET https://panel.example.com/_weglarka/api/v1/apps` reaches `GET /v1/apps` on the daemon.

- **It decides nothing.** The caller's own `Authorization: Bearer …` goes through unchanged and the daemon verifies the
  signature, audience and groups and applies the scope, exactly as for the panel's own calls. A compromised panel
  cannot make a token more powerful than the daemon says it is.
- **Bearer only.** No cookie is read or forwarded, and the session gate does not apply to the relay, so a browser session
  cannot authenticate there. A request without a `Bearer` credential is refused (`401`) before the daemon is asked,
  except `GET /v1/health`.
- **Only declared endpoints.** A method and path must match an entry of the admin API's endpoint table, with a path
  parameter being a single segment of `[A-Za-z0-9_.-]`; anything else is `404`. Only `Authorization`, `Content-Type`,
  `Accept` and `Content-Length` are forwarded.
- **Limits.** 300 requests per minute per client address, and 64 relayed requests in flight at once (a stream holds a
  slot until it ends); beyond that the answer is `429` with `Retry-After` and the `busy` error code, which makes the CLI
  back off and retry. A JSON request body may be 1 MiB; image archives (`push`) and volume imports 8 GiB.
- **Streams** (logs, events) pass through unbuffered and end where the daemon ends them, including its `TokenExpired`
  frame when the token expires.

**Nothing to configure.** The instance listed in `[admin.http] clients` is the panel, and Węglarka carves the relay
prefix `/_weglarka/api` out of that app's `location /` by itself (the same mechanism as
[forward auth](forward-auth.md) exemptions and [streaming](streaming.md) paths, rendered with the rest of `nginx.conf`):
no forward-auth login on it (the CLI sends a token, not a cookie; the daemon checks the token), buffering off for bodies
and answers, an idle timeout of an hour (a deploy through the relay is silent until the health gate ends), and a body
limit of 8 GiB. The rest of the panel keeps its forward auth and its defaults. Nothing is written to `apps.toml`.

- The prefix exists on every `clients` instance that is served at `/` (not under `paths`), so only list the panel
  there, or an app that serves nothing at `/_weglarka/` of its own. A `streaming_paths` or `auth_exempt_paths` entry
  that overlaps the prefix is refused, because the carve-out owns it.
- `weglarka run`, `push` and `forward` are not claimed to work through the relay yet; they need a request body that
  streams while the answer does, and stay on the socket (SSH) path until that is tested end to end.
- Set `PANEL_TRUSTED_PROXIES` too (required for per-client limits): the panel sits behind Węglarka's nginx, so without it every client shares nginx's address and one rate-limit budget.

## Security properties

- Default-deny: only `/healthz`, `/static/*`, `/auth/login` and `/auth/callback` answer without a session.
- Cookies are `__Host-` prefixed, so a sibling subdomain cannot set or shadow them. The session id is minted at the
  callback, so a planted id gains nothing.
- Every non-`GET` request needs a CSRF token and a same-origin `Sec-Fetch-Site`; a state-changing route never answers `GET`.
- Every response carries a strict Content-Security-Policy (no inline script, no `eval`, `frame-ancestors 'none'`) and the
  other security headers. htmx and Alpine are vendored and served by the panel; no CDN is involved.
- The access token is only ever sent in an `Authorization` header to the daemon's socket. Error pages never quote a daemon
  body or a token, and the log never contains the code, the state, a token or the secret.
- The container runs read-only, without capabilities, as a non-root numeric user, with no host mounts besides the token socket.

Deliberately not there yet:

- **No mutating actions** in release 1 (see the top of this page).
- **No TLS on the token socket.** It is a unix socket in a directory only the listed clients can reach; the bearer token
  still has to verify.
- **No high availability.** One replica, sessions in memory.
- **No panel-side audit trail** beyond the daemon's own log: the daemon logs every `admin`-scope call with the token's `sub`.

## Operations

`weglarka doctor` reports `admin.http` (the token socket exists, every `clients` entry is in `apps.toml`, the provider's
keys can be fetched) and `identity.provider`. `weglarka apps show panel` shows the container state and
`GET /healthz` answers `200 ok` while the process is up.

What the pages mean:

| What you see | Meaning |
|---|---|
| `401` "Sign-in required" | No or expired session, or the daemon refused the token. Sign in again. A loop right after a successful login usually means the daemon rejects the token (see below). |
| `403` "No access" | The token is valid, but its groups map to no scope, or the page needs `admin` (logs). Check `read_groups`/`admin_groups` against the user's groups. |
| `502` "Sign-in unavailable" | The panel could not reach the identity provider's discovery or token endpoint. |
| `502` "The daemon had a problem" / "refused the request" | The daemon answered with a server error or a 4xx the page cannot use. See the daemon log. |
| `503` "The daemon is unreachable" | The token socket is missing or refuses connections: the daemon is down, `[admin.http]` is off, or the panel is not in `clients`. |
| `504` "The daemon did not answer in time" | Longer than `PANEL_REQUEST_TIMEOUT_SECS`. |

Common failures:

- **Audience mismatch.** The daemon log says `audience`. `PANEL_API_AUDIENCE`, `[apps.panel.oidc] audience` and
  `[admin.http] audience` must be byte for byte the same.
- **Issuer not reachable from the container.** The panel dials `OIDC_ISSUER` over ordinary outbound HTTPS from inside its
  own container (discovery, token and refresh). If the name resolves only on the host, or the host's firewall blocks the
  container, login fails with "Sign-in unavailable". The panel's CA roots are bundled in the binary, so a provider with a
  private CA is not supported.
- **`typ is not at+jwt`** in the daemon log, for every token after a provider upgrade: the provider no longer issues RFC
  9068 JWT access tokens. Check `access_token = "jwt"` and the provider version, and see
  [admin API tokens](admin-api-tokens.md).
- **Clock skew.** The daemon allows 60 seconds. A host clock that is minutes off makes fresh tokens look expired or not
  yet valid and sends users in a login loop; fix NTP on the host.
- **Login works, sessions end after minutes.** `offline_access` is missing from `scopes`, so there is no refresh token.
- **The panel refuses to start.** Read the log for the variable name (for example an `http://` issuer that is not a
  loopback IP, both secret variables set, or an unreadable secret file).

Known limitation: one OIDC client without a digest blocks the whole generated provider config render, so a broken
credential of any app delays new clients and access rules, including the panel's
([#240](https://github.com/jpalczewski/weglarka/issues/240)). `weglarka doctor` reports `oidc.credentials` and
`generated.identity`.

### Keeping it private

The panel is an app like any other, so any domain you route to it is public, protected by forward auth, the panel login
and the daemon's scopes. If you would rather not expose it to the internet at all, a VPN-only listener is planned
([#216](https://github.com/jpalczewski/weglarka/issues/216)); until then you can leave `domains` empty and reach the
container through [`weglarka forward`](port-forward.md), but the OIDC redirect URI needs a stable HTTPS origin, so this
needs care.

## Rollback

The panel itself changes no state file and adds no `schema_version` step, but the fields it relies on do:
`[admin.http]`, `[identity]`, `oidc` and `ingress.auth*` are unknown to an older Węglarka (`deny_unknown_fields`), and
the daemon refuses to start with `oidc` apps or `[admin.http]` but no `[identity]`. Remove things in this order, so the
admin API stays reachable until the end (the unix socket always works):

1. Remove the panel: `weglarka apps remove panel --purge-secrets`. This takes its `oidc` section and `ingress.auth*`
   fields with it.
2. Remove `[admin.http]` from `weglarka.toml` (its `clients` entry goes with it) and restart the daemon.
3. Remove every other `oidc` section and `[oidc_clients]`, as described in [identity provider](identity-provider.md).
4. Last, remove `[identity]`, after giving the provider a hand-written configuration again.

Then downgrade ([verification and rollback](verify-and-rollback.md)). Removing `[identity]` first would make the daemon
refuse to start while `oidc` apps remain
([#243](https://github.com/jpalczewski/weglarka/issues/243)). The recreated clients lose the token socket mount again; the
unused `run/admin-token/` directory can be deleted.
