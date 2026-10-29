# weglarka-panel

The admin panel: a server-rendered backend-for-frontend (docs/decisions/0057). One Rust binary renders HTML
on the server; the browser never sees a bearer token or the raw admin API. A leaf crate: it depends on
`weglarka-api` and `weglarka-unix-http` (the OIDC login adds `weglarka-http`), never on `weglarka-engine`, and no
crate depends on it.

This is the skeleton the login and the pages plug into:

- `config`: environment configuration, validated once at start-up (a bad value stops the process with a message
  that never contains the value). The daemon injects `OIDC_CLIENT_ID`, `OIDC_ISSUER` and the client secret for
  an app with `oidc`; the rest are panel settings.

  | Variable | Default | Meaning |
  |---|---|---|
  | `OIDC_CLIENT_ID` | required | The panel's client id at the identity provider. |
  | `OIDC_ISSUER` | required | The provider's issuer URL, compared byte for byte with the id token's `iss`. Must be `https://`; plain `http://` is accepted only for a loopback IP address (`127.0.0.1`, `[::1]`; not `localhost`), meant for a test provider. The same rule applies to every endpoint the discovery document names. |
  | `OIDC_CLIENT_SECRET` | required unless the file variable is set | The client secret. |
  | `OIDC_CLIENT_SECRET_FILE` | none | Path of a mounted secret file (first line, at most 4 KiB). Set it **or** `OIDC_CLIENT_SECRET`, not both. |
  | `PANEL_API_AUDIENCE` | required | The `aud` the daemon expects of an access token (`[admin.http] audience`). Sent in the authorization request so the provider mints tokens the daemon accepts. |
  | `PANEL_PUBLIC_URL` | required | The panel's own public origin; the login redirect URI is `<url>/auth/callback`. |
  | `PANEL_SESSION_IDLE_SECS` | `1800` | A session ends after this long without a request (60 to 86400); must not exceed the maximum below. |
  | `PANEL_SESSION_MAX_SECS` | `28800` | A session ends this long after login, however active (300 to 604800). |
  | `OIDC_ENDPOINT_HOSTS` | none | Comma-separated host names, besides the issuer's own, that the discovery document may name for `token_endpoint` and `jwks_uri`. By default both must be on the issuer's host and port, so a poisoned discovery document cannot redirect the client secret. Needed for providers whose token endpoint lives elsewhere (for example a separate API host). |
  | `PANEL_LISTEN` | `0.0.0.0:8080` | Listen address. |
  | `WEGLARKA_PANEL_SOCKET` | `/run/weglarka-admin/api.sock` | The daemon's token socket (also `--socket`). |
  | `PANEL_REQUEST_TIMEOUT_SECS` | `10` | How long the daemon may take to answer a request (1 to 120). |

  Empty values count as unset. Secrets are `Secret`, whose `Debug` is redacted.
- `session`: sessions live in memory (a restart signs everybody out): at most 1024 in total and 5 per identity (a
  further login evicts that identity's oldest). A login in progress is not stored on the server at all: it travels
  in a short-lived `__Host-weglarka-login` cookie sealed with ChaCha20-Poly1305 under a key that exists only in the
  process, and each login can be answered once.
- `auth`: a session whose lowest-scope (`read`) call is refused (`401`, or `403` because the identity maps to no scope) is ended immediately; a `403` on a higher-scope call (the logs) shows the polite page and keeps the session.
- `daemon`: `DaemonClient` calls the daemon's token socket (ADR 0056) over `weglarka-unix-http`. A `Call` is a
  `weglarka_api::Endpoint` plus path parameters (restricted to `[A-Za-z0-9._-]`) and query; the token goes in
  `Authorization: Bearer` only; `401`/`403`/`404`/`5xx` map to `DaemonError`; every exchange has a deadline (`Call::timeout` overrides it, `None` = no limit, for long operations). `send_empty` is for `204` endpoints.
- `app`: `GET /healthz` and `/static/*` are public. Everything else sits behind `require_session`, which
  refuses every request until sessions exist: that function is the single place login plugs in. Add routes
  to the protected router before its `.layer(..)`.
- `headers`: the Content-Security-Policy and the other security headers, on every response (one layer).
- `assets`: files embedded with `include_bytes!`, served from a fixed table.
- `pages`: askama templates (`templates/`; `layout.html` adds the navigation to `base.html`). Templates carry no
  inline script, style or event handler; a test scans them, and the page tests scan every route's output.
- `routes`, `views`: the read-only pages. Every handler forwards the signed-in user's own token and the daemon
  decides: a `403` renders a polite "no access" page, a `401` ends the session, `5xx`/timeouts/unreachable render a
  retryable page; daemon bodies are never quoted. `views` turns API types into plain strings (statuses are words as
  well as styles; env values are never shown, only keys; a redacted app view carries a badge).
- `live`: server-sent events for htmx's `sse` extension. `/events/stream` polls `GET /v1/events?since=` server-side
  every few seconds and pushes new rows (`id: <boot_id>:<seq>`, so a reconnect resumes through `Last-Event-ID`);
  `/apps/{name}/logs/stream` relays the daemon's admin-only log stream, decoded with `weglarka_api::LogFrameDecoder`,
  every line cut, stripped of control characters and escaped, reconnecting with `since` after `TokenExpired`. A stream
  ends with its session and with the browser connection; each session may hold four. Stream activity does not count as session activity, so a tab that only watches a stream is signed out when the idle timeout passes. The daemon's refusal of a stream is answered as an HTTP status before any event is sent; terminal log conditions send a `done` event (`sse-close`), so the browser does not reconnect.
- Vendored front end: `assets/vendor/` holds htmx, its `sse` extension and Alpine's CSP build (versions and SHA-256
  in `VENDORED.md`, verified by a test); `assets/app.css` and `assets/app.js` are the panel's own.

Routes (all behind the session except `/healthz`, `/static/*` and the login): `/` (dashboard), `/apps`,
`/apps/{name}`, `/doctor`, `/volumes`, `/networks`, `/sites`, `/certificates`, `/events`, `/notifications`,
`/config`, plus the two streams above and `POST /auth/logout`. The app page offers the log section when the view is not
`redacted` (the token has `admin`); the daemon still enforces it on the stream.

Run it with `weglarka-panel` (flags and variables above); it logs JSON and shuts down gracefully on SIGTERM
and SIGINT. Tests use `weglarka_unix_http::testing::mock` as a fake daemon.
