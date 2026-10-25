# 0033 — Per-app request body limit: `ingress.max_body_size`

Status: accepted (2026-10-24)

## Problem

The generated `nginx.conf` sets `client_max_body_size 67108864;` (64 MiB) once per app `server`, and nothing
can change it per app. That is the right default for an ordinary web app, but it makes two kinds of services
impossible to host: a git server (a push can be hundreds of MB) and a container registry (one layer of an
image is a single `PATCH`/`PUT` of several GB). nginx answers `413` before the app sees a byte.

Raising the number is not enough, because of how the ingress container runs (ADR 0014): a read-only root with
a small writable tmpfs on `/tmp`. nginx's default is to read the **whole** request body before contacting the
upstream and, past `client_body_buffer_size` (16 KiB here), to spool it to `client_body_temp_path`
(`/tmp/client_body`). A multi-GB upload would either fail with a `500` when the tmpfs is full, or — if the
tmpfs were large — sit in RAM, the resource this project optimises for. Buffering a registry blob in the
proxy is also pure latency: the app can only start verifying the layer after the last byte arrived.

A second concern is timeouts. A multi-GB push over a slow link lasts minutes, longer than any of nginx's 60 s
defaults.

## Decision

**A per-app, optional `ingress.max_body_size`**, next to `streaming` in the nested `AppIngress` table:

```toml
[apps.git.ingress]
streaming = true
max_body_size = "4g"        # "0" = no limit; unset = the generator default, 64 MiB
```

- **Syntax and validation.** Same as `resources.memory`: an integer (bytes) or a string `<n>[k|m|g]`
  (binary multiples, case-insensitive), parsed by the shared `parse_binary_size`. Unlike a memory limit, `0`
  is valid and means *no limit* (nginx's own meaning of `client_max_body_size 0`). The type is
  `BodySizeLimit`; it is serialized in the largest exact unit (`"4g"`), `0` as `"0"`. Anything else, an
  overflow, or a value above `i64::MAX` is a parse error (so `apps.toml` and `--spec` fail loudly at load).
- **Rendering.** `client_max_body_size <bytes>;` is emitted inside that app's `location`(s), not in the
  `server`. Several apps can share a `server` under different path prefixes (ADR 0031), and `location` is a
  valid context for the directive, so `/upload` can take 4 GiB while `/` on the same domain stays at 64 MiB.
  The server-level 64 MiB stays as the default; an app without the field renders **byte-for-byte as before**.
- **A limit implies unbuffered requests.** When `max_body_size` is set the location also gets
  `proxy_request_buffering off;` (once — `streaming = true` already emits it). nginx then forwards the body
  to the app as it arrives and never spools it. This holds below the default too (`"8m"`): the reason is not
  the size but that the ingress container has no place to put a body. `proxy_buffering` (the *response*) and
  the timeouts stay untouched unless `streaming = true` is also set.
- **Timeouts need no new knob.** `client_body_timeout`, `proxy_send_timeout` and `proxy_read_timeout` are
  **idle** timeouts — the time between two successive reads or writes, not a deadline for the request. A
  steady upload of any length is therefore never cut by them; `test-body-size.sh` proves it with a 96 MiB
  upload throttled to run ~76 s, past all of the 60 s defaults. The one real exposure is the opposite
  direction: after the last byte a registry may think for a while (verify the digest, move the blob into
  place) before it answers, and `proxy_read_timeout` is 60 s by default. For such an app set
  `streaming = true` as well, which raises both proxy timeouts to `stream_timeout_secs` (default 180,
  ADR 0018) — the recommended pairing for git and registry services, and what the example uses.
- **Not part of `spec_hash`.** `AppIngress` is outside `HashInput` (ADR 0018), so changing the limit renders
  `nginx.conf`, runs `nginx -t` and sends `SIGHUP`; the container is never recreated.
- **State schema.** `apps.toml` gains a field, so `state::SCHEMA_VERSION` becomes 6 with a no-op step
  (ADR 0023) and the image label `io.weglarka.state-schema` follows. The field is omitted when unset.
- **CLI.** `apps add --max-body-size <SIZE>`, `apps update --max-body-size <SIZE>` and
  `--unset-max-body-size`. They conflict with `--spec`, like the other spec flags. `--no-streaming` resets the
  streaming knobs but keeps the body limit (they are independent settings).
- **Traefik (`behind`) is unchanged.** It has no request-size middleware in our generated file, so the nginx
  limit is the only one on the path. An `edge` mode must revisit this (ADR 0005).

## Consequences

Operators can host a git/registry service behind the ingress (`docs/examples/max-body-size.toml`,
[the max body size guide](../guides/max-body-size.md)). A host-wide default is still the 64 MiB constant in `NginxOptions`; making that
configurable is possible later without touching specs.

`apps.toml` with `ingress.max_body_size` is refused by an older daemon (`deny_unknown_fields` plus the schema
gate): before a downgrade run `apps update <app> --unset-max-body-size` or restore the pre-upgrade files.
A downgraded daemon that cannot read the field would otherwise not start.

Tests: parser forms and round-trip (`app.rs`), hash stability (`hash.rs`), CLI flags (`update.rs`,
`tests.rs`), a snapshot plus assertions that the directive is per-location, once, and absent for apps
without the field (`weglarka-ingress/tests`), the existing daemon reload-without-recreate test pattern, and
`.github/scripts/test-body-size.sh` against real nginx on a read-only root: 413 above the limit, success
above 64 MiB, nothing spooled in `/tmp/client_body`, and a slow upload surviving the 60 s defaults.

## Rejected alternatives

- **Raise the global limit.** Every app would accept multi-GB bodies; the point of the default is that most
  apps should not.
- **A server-level directive per app.** Wrong with path routing: two apps sharing a `server` would fight over
  one value.
- **Require `streaming = true` for a large limit.** It couples a size to response unbuffering, which a git
  server does not need for correctness, and makes the pairing rule fragile (`--no-streaming` would invalidate
  a spec). Request buffering is the only part that matters, so the limit switches exactly that off.
- **Let nginx spool large bodies and size the tmpfs.** Spends RAM proportional to the largest upload and
  delays the first byte to the app by the whole transfer.
- **A separate timeout setting for uploads.** The idle timeouts already allow arbitrarily long steady
  uploads; the only long wait is the app's post-upload think time, covered by `stream_timeout_secs`.
