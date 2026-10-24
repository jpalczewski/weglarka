# 0018 — Per-app streaming through the ingress (no response buffering, long idle timeout)

Status: accepted (2026-10-24, issue #64).

## Problem

The generated nginx config uses nginx's defaults: `proxy_buffering on` and `proxy_read_timeout 60s`. For an
ordinary request/response app that is exactly right — the buffer decouples a slow client from the upstream and
frees the upstream connection early. For an app that holds a response open it is a defect: an SSE stream
(`/<topic>/sse` in ntfy), a chunked JSON feed or a long-poll request has its events parked in nginx's proxy
buffers — a close-delimited body is held until a buffer fills or the response ends, and even a chunked one is
forwarded only as far as nginx's buffering happens to allow — while an idle stream is cut after 60 seconds with
a 504 upstream timeout. Measured on `nginx:1-alpine` (the test below): with `proxy_buffering on` a 6-byte first
line of a close-delimited body never reaches the client before the response ends, and a stream that idles for
66 s dies at exactly 60 s. WebSocket is **not** affected — the `http {}` block already sends `proxy_http_version 1.1`
and the `Upgrade`/`Connection` headers — so the regression is exactly the non-WebSocket streaming clients: the
same app can have working WebSocket notifications and a broken SSE endpoint.

An upstream cannot be relied on to fix this. nginx honours `X-Accel-Buffering: no` on the response and some
upstreams send it, but ntfy — the app that motivated the issue — does not, and a proxy setting that requires
cooperation from every future upstream is a setting that fails silently when the next app forgets it.

## Decision

**Opt-in per app, as an optional nested table on `AppSpec`** (in `apps.toml`; a `--spec` file describes one app,
so there it is the plain `[ingress]` table):

```toml
[apps.ntfy.ingress]
streaming = true                 # opt-in; false is the default
# stream_timeout_secs = 180      # optional, default 180, allowed 1..=3600
```

`AppIngress { streaming: bool, stream_timeout_secs: u64 }` is serialized only when it is not the default
(`skip_serializing_if`), so an app that does not use it keeps its file shape and its generated nginx config
byte-for-byte.

**Four directives, inside that app's `location /` only** — the block `Backend::write_location` emits in
`weglarka-ingress/src/nginx.rs`:

```nginx
proxy_buffering off;
proxy_request_buffering off;
proxy_read_timeout <stream_timeout_secs>s;
proxy_send_timeout <stream_timeout_secs>s;
```

`proxy_buffering off` forwards each response chunk as it arrives instead of filling `proxy_buffers`;
`proxy_request_buffering off` stops nginx from reading the whole request body before contacting the upstream,
so an upload in a long-lived request streams too. Both timeouts are raised together: a stream is idle in both
directions between events, and raising only `proxy_read_timeout` would still truncate a slow request body at
60 s. The scope is `location /` deliberately — the webhook and static locations, other apps' servers and the
default server are untouched.

**Defaults and bounds.** `streaming` defaults to `false`. `stream_timeout_secs` defaults to **180**
(`AppIngress::DEFAULT_STREAM_TIMEOUT_SECS`): three minutes covers SSE with 45 s keepalives with a wide margin
and still turns a dead stream into an error. The allowed range is **1..=3600**
(`AppIngress::MAX_STREAM_TIMEOUT_SECS`); the upper bound is the practical tolerance for a worker connection,
not a licence for an unbounded stream. Validation rejects a `stream_timeout_secs` set while `streaming = false`
with "requires ingress.streaming = true" — a timeout that never reaches the config is a typo, not a knob.
Setting only `streaming = true` is a complete spec: the default timeout is omitted from the serialized form.

**Not part of `spec_hash`.** `HashInput` (`core/src/hash.rs`) does not include `AppIngress`, exactly like
`domains`: changing it re-renders the config and reloads nginx (`nginx -t` + SIGHUP) and never recreates the
app container. The setting is ingress-only by construction, not by a special case in reconcile.

**No global default in `[ingress]`.** Buffering is the right default for an ordinary HTTP app, and one app's
need must not change every other app's proxy behaviour; the per-app table is the smallest unit that matches
reality. If the requirement turns out to be host-wide, a default there can be added additively later.

**CLI surface.** `weglarka apps add --streaming`, `weglarka apps update --streaming` / `--no-streaming`.
`--no-streaming` clears the whole `ingress` block, including a custom timeout (a timeout on a non-streaming app
is invalid by the rule above), and is a no-op — nothing is sent — when the app is not streaming. There is
deliberately **no flag for the timeout in v1**: it is set in `apps.toml` or via `apps update --spec`. Like the
other spec flags, `--streaming`/`--no-streaming` conflicts with `--spec`.

**nginx only; Traefik stays as it is.** In `behind` mode Traefik forwards a response as it arrives and does not
buffer it; its `idleTimeout` bounds idle time between keep-alive requests, not an in-flight streaming response,
so an SSE stream over an established connection is not cut by it. The `edge` mode (not implemented, 0005/0014)
terminates TLS itself and adds its own timeouts — it must re-check this before it is enabled, as an explicit
task rather than a silent assumption.

## Consequences

- **A reload, not a deploy.** Flipping `--streaming` re-renders `nginx.conf`, validates it with `nginx -t` and
  applies it with SIGHUP; the app container, its digest, `spec_hash` and its state are untouched and no deploy
  runs. The change affects new connections; nginx drains old workers, so a stream already open finishes on the
  old one.
- **A slow client now holds a worker connection.** That is the point, but it is a trade: the generated config
  has `worker_processes 1` and `worker_connections 1024`, so every open stream is one connection from that
  budget, and `proxy_request_buffering off` extends the same trade to slow uploads (the body is forwarded as
  it arrives, holding an upstream connection too). Opt-in is also a statement about that app's traffic, not a
  free performance switch.
- **WebSocket apps that opt in also get the longer idle timeout.** A WebSocket connection is idle between
  messages; 180 s instead of 60 s prolongs a connection that used to be reaped — usually what such apps want,
  but a behaviour change to state, not a side effect to discover.
- **A rejected config keeps the existing rollback path.** The daemon validates with `nginx -t` and restores the
  previous config when nginx refuses it (`daemon/src/ingress.rs`), so a bad generated directive cannot take the
  ingress down; the failure is reported and the running config stays valid.
- **Rollback caveat (`deny_unknown_fields`).** `apps.toml` rejects unknown fields, so an older daemon cannot
  parse an `ingress` table. Downgrading Węglarka requires removing the `[apps.X.ingress]` blocks first
  (`apps update --no-streaming` or editing the file); documented in `docs/install.md` (6d and section 7).
- **Verification that must exist** (the issue's list): unit and snapshot tests of the generated `nginx.conf`
  (the four directives in the streaming app's `location /`, every other app and the default server unchanged);
  `.github/scripts/test-streaming.sh` in Docker CI with one upstream answering on both hostnames of the sample
  config, asserting that (a) the first line of a close-delimited body reaches the client in ~1 s through
  `streaming = true` and is held back for the buffered app (a chunked body is forwarded chunk by chunk even with
  buffering on, so it cannot show the difference), and (b) a chunked SSE stream idle for 66 s survives the
  default 60 s `proxy_read_timeout`; and a `scripts/acceptance.sh` step that flips `--streaming` on the canary
  and checks the generated `nginx.conf` **and** that the container was not recreated.

## Rejected alternatives

- **A global default in `[ingress]`.** A host-wide `streaming = true` makes every install pay for the streaming
  case and lets one app's need change every other app's proxy behaviour. Buffering is a feature for the
  ordinary app, so the switch belongs where the need is.
- **Relying on `X-Accel-Buffering: no` from apps.** A fine escape hatch for an app that controls its own
  headers, but it requires cooperation from every upstream and fails silently when one is added — ntfy, the
  motivating case, does not send it. The ingress has to be able to declare the requirement for the app.
- **Raising the global 60 s for every app.** It fixes the idle cut but neither buffering (events would still be
  held until a buffer fills) nor request buffering, and it leaves every ordinary app with a long window to leak
  a dead upstream connection. Two of the four directives would still be missing, and the timeout is only the
  smaller half of the problem.
- **A boolean `streaming` directly on `AppSpec` instead of a nested table.** It makes the timeout a second
  top-level field and every future ingress knob (`proxy_buffers`, a per-app body limit) another one; the table
  groups them, is self-documenting in TOML (`[apps.ntfy.ingress]`) and grows additively without touching
  `AppSpec` — the same argument as for `resources` and `security`.
- **An unlimited or very long timeout.** A stream without a bound turns a dead upstream into an immortal
  connection that counts against `worker_connections` until nginx is reloaded. The 3600 s ceiling makes "no
  data for an hour" an error; an app that genuinely needs a longer idle stream needs a keepalive, not a longer
  timeout.
