# Request body size limit (ingress.max_body_size)

By default nginx accepts a request body of up to **64 MiB** (`client_max_body_size`) and answers `413` to larger
ones. That is a good default for an ordinary app, but it rules out a git server (a push of hundreds of MB) and a
container registry (one image layer is a single request of several GB). The `ingress.max_body_size` field changes
the limit for **one app**. Decision and rejected alternatives:
[ADR 0033](../decisions/0033-ingress-max-body-size.md).

```toml
# apps.toml
[apps.git.ingress]
streaming = true        # recommended together with the limit, see below
max_body_size = "4g"
```

Via the CLI: `weglarka apps add git --max-body-size 4g ...`, `weglarka apps update git --max-body-size 4g` and
`--unset-max-body-size` (back to 64 MiB). Ready-made file:
[`docs/examples/max-body-size.toml`](../examples/max-body-size.toml) (a git server: HTTP through ingress + SSH on
`host_ports` 2222:22).

- **Syntax** as for `resources.memory`: a number of bytes or `<n>[k|m|g]` (binary multiples, case-insensitive).
  **`0` means no limit** (unlike memory, where `0` is an error). An invalid value (`"1.5g"`, `"1t"`, overflow)
  makes loading `apps.toml`/`--spec` fail.
- **Where it goes:** `client_max_body_size` in the app's `location`, not in `server` — apps sharing a domain under
  different `paths` ([path routing](path-routing.md)) have separate limits. An app without the field gets the same
  `nginx.conf` as before (64 MiB in `server`).
- **A configured limit also turns off `proxy_request_buffering`** in the app's locations. The ingress container
  has a read-only root and a small tmpfs in `/tmp`, so the default request body buffering (nginx writes the body
  to `/tmp/client_body` before it calls the app) would mean writing many GB to RAM or a `500` error. This applies
  to limits below 64 MiB too. *Response* buffering and timeouts stay unchanged unless you set `streaming`.
- **Timeouts:** `client_body_timeout`, `proxy_send_timeout` and `proxy_read_timeout` count **idle time** between
  consecutive reads/writes, not the duration of the whole request, so a steady upload lasting minutes is not cut
  off (CI test: 96 MiB in ~76 s passes despite the default 60 s). The risk is the response *after* the last
  byte — a registry verifies the layer digest and may stay silent for longer than 60 s — so set
  `streaming = true` together with the limit (180 s timeouts, see [streaming](streaming.md)) and raise
  `stream_timeout_secs` if needed.
- **Ingress only:** the change renders `nginx.conf`, checks it with `nginx -t` and sends SIGHUP — the container is
  not recreated and `spec-hash` does not change. `--no-streaming` resets streaming but keeps the limit.
- **Traefik (`behind`) does not change** — the generated file has no size limit; the only limit on the path is the
  nginx one.

## Rollback

This is a state-file schema change (version 6) — `apps.toml` and `state.toml` get `schema_version = 6` on the
first write after the update. Before a downgrade, remove `ingress.max_body_size` from the apps
(`weglarka apps update <app> --unset-max-body-size`) or restore the files **from a backup taken before the
update** (see [state schema](state-schema.md)).
