# Streaming: SSE and long polling

Applications that hold a response open (SSE such as `/<topic>/sse` in ntfy, a chunked stream, or long polling) must get around two nginx defaults: `proxy_buffering on` (events wait in the proxy buffer instead of reaching the client) and `proxy_read_timeout 60s` (silence for longer ends the stream with a 504). WebSocket already works (the `Upgrade`/`Connection` headers), so this is about clients that stream over plain HTTP. Decision and rejected alternatives: [ADR 0018](../decisions/0018-ingress-streaming.md).

```toml
# apps.toml: streaming enabled for this app only
[apps.ntfy.ingress]
streaming = true
# stream_timeout_secs = 180   # optional: default 180, allowed 1..=3600
```

Apply it with `weglarka apps update ntfy --streaming` for an existing app, or `weglarka apps add ntfy --streaming` when adding. In a `--spec` file (one app, not the whole `apps.toml`) the same block is a plain `[ingress]` table:

```toml
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
domains = ["ntfy.example.com"]
port = 8080
[ingress]
streaming = true
```

A ready-made file: [`docs/examples/streaming.toml`](../examples/streaming.toml).

- `streaming = true` adds four directives to `location /` of **that one app**: `proxy_buffering off;`, `proxy_request_buffering off;`, `proxy_read_timeout <n>s;` and `proxy_send_timeout <n>s;`. Other apps, webhook blocks and the default server stay unchanged: an app without `ingress` gets exactly the `nginx.conf` it gets today.
- `stream_timeout_secs` is idle time in both directions: **default 180**, allowed **1-3600**. `streaming = true` alone is enough (the default timeout is not written out). Setting a timeout with `streaming = false` is rejected by validation with the message "requires ingress.streaming = true": a timeout that never reaches the config is a typo, not an option. In v1 there is **no CLI flag** for the timeout: set it in `apps.toml` or through `apps update --spec`.
- **Ingress only:** the change renders `nginx.conf`, checks it with `nginx -t` and sends SIGHUP, the same as `--domain`. The app's container, its digest and its `spec-hash` stay untouched: no deploy and no interruption of traffic to the app. The change applies to new connections; nginx closes the old workers gracefully, so an open stream ends on the old configuration.
- `--no-streaming` resets the streaming settings (together with a custom timeout; `strip_prefix` stays) and sends nothing when the app does not stream anyway. The flags, like `--domain`, are mutually exclusive with `--spec`.
- **Operational note:** `proxy_buffering off` is the point, but it has a cost: a slow client holds an nginx worker connection for the whole duration of the stream (`worker_processes 1`, `worker_connections 1024`), and `proxy_request_buffering off` extends the same to a slowly uploaded request body. Enable streaming for apps that really stream, not for everything "just in case".
- An app that has WebSocket and enables streaming also gets a longer idle timeout (180 s instead of 60 s). That is usually exactly what you want, but it is a behaviour change, not a side effect.
- **Traefik (`behind`) does not change:** it forwards the response as it arrives and does not buffer it, and its `idleTimeout` concerns idleness between keep-alive requests, not an ongoing stream. (In `edge` mode traffic goes straight to Węglarka's nginx, which terminates TLS; buffering and timeouts work identically, see [edge mode](edge-mode.md).)
- **Config safety:** when nginx rejects the generated config, `nginx -t` in the daemon fails and the previous, working config is restored, so a bad entry does not leave the ingress without traffic.

## Rollback

`apps.toml` has `deny_unknown_fields`, so an **older daemon** cannot read an `[apps.X.ingress]` block. Remove it before a downgrade (`apps update --no-streaming` or by hand); see [verify and rollback](verify-and-rollback.md).
