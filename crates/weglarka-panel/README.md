# weglarka-panel

The admin panel: a server-rendered backend-for-frontend (docs/decisions/0057). One Rust binary renders HTML
on the server; the browser never sees a bearer token or the raw admin API. A leaf crate: it depends on
`weglarka-api`, `weglarka-model`, `weglarka-http` and `weglarka-unix-http`, never on `weglarka-engine`, and no
crate depends on it.

This is the skeleton the login and the pages plug into:

- `config`: environment configuration. `OIDC_CLIENT_ID`, `OIDC_ISSUER` and `OIDC_CLIENT_SECRET` are injected by
  the daemon for an app with `oidc`; `PANEL_PUBLIC_URL` is required; `PANEL_LISTEN` (default `0.0.0.0:8080`),
  `WEGLARKA_PANEL_SOCKET` (default `/run/weglarka-admin/api.sock`, also `--socket`) and
  `PANEL_REQUEST_TIMEOUT_SECS` (default 10) are optional. Secrets are `Secret`, whose `Debug` is redacted.
- `daemon`: `DaemonClient` calls the daemon's token socket (ADR 0056) over `weglarka-unix-http`. A `Call` is a
  `weglarka_api::Endpoint` plus path parameters (restricted to `[A-Za-z0-9._-]`) and query; the token goes in
  `Authorization: Bearer` only; `401`/`403`/`404`/`5xx` map to `DaemonError`; every exchange has a deadline.
- `app`: `GET /healthz` and `/static/*` are public. Everything else sits behind `require_session`, which
  refuses every request until sessions exist: that function is the single place login plugs in. Add routes
  to the protected router before its `.layer(..)`.
- `headers`: the Content-Security-Policy and the other security headers, on every response (one layer).
- `assets`: files embedded with `include_bytes!`, served from a fixed table.
- `pages`: askama templates (`templates/`). Templates carry no inline script, style or event handler; a test
  scans them.

Run it with `weglarka-panel` (flags and variables above); it logs JSON and shuts down gracefully on SIGTERM
and SIGINT. Tests use `weglarka_unix_http::testing::mock` as a fake daemon.
