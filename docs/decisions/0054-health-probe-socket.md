# 0054 — Health probe over the ingress probe socket

Status: accepted (2026-10-27, issue #221). Amends ADR 0010 (what the probe is) and ADR 0036 (the plain-HTTP listener). The nginx behaviours the design inferred from the docs are measured in CI (`test-edge.sh`, `nginx-e2e`); see the PR.

## Problem

The deploy health gate's `health.http` probe sends plain HTTP to `weglarka-nginx:8080` with the app's first
domain as `Host` (ADR 0010). In `edge` that port only redirects: every routed domain answers
`301 https://…` (ADR 0036), so a probe expecting anything but 301 fails the gate and rolls back every deploy.
ADR 0036 said both "the daemon's health probe keeps working on 8080" and "the plain-HTTP listener only
redirects, except ACME"; those were never true together, and ADR 0043 only inherited the first sentence. The same
`http_probe` runs in the health gate, after the blue-green switch and in the dependency gate.

The probe was always a privileged anonymous client that tests **routing and the upstream** (nginx → app network
alias → port → container), never TLS termination or authentication: in `behind`, Traefik terminated TLS before
nginx. `edge` broke that parity by moving TLS into nginx, and forward auth (ADR 0052) would break it again.

Constraints: security first (the probe path must not become a second, unauthenticated route to apps for anyone
but the daemon), then no duplicated server/location tree, then RAM.

## Decision

nginx gets a **probe socket**: a plain-HTTP `listen unix:/run/weglarka-probe/probe.sock;` (no `ssl`, no
`proxy_protocol`) on **every app server in both modes** and on the default server (as `default_server`, so a
foreign `Host` still gets `444`). The daemon's `NginxProber` dials it with a `tokio::net::UnixStream`; the request
shape is unchanged (`GET path`, `Host` = first domain, no `X-Forwarded-*`).

* **Isolation is by mounts**, like the forwarder's sockets (ADR 0043). `<nginx_conf_dir>/probe/` is `0700`
  (re-applied on every pass), mounted writable into **nginx only**, in both modes. It is not part of `run/`:
  the internet-facing forwarder mounts `run/` writable and must not be able to reach a socket that skips TLS and
  authentication. The daemon already mounts `<nginx_conf_dir>` and dials the host path. The generator rejects a
  probe socket inside `proxy_socket_dir`. Stale socket files are removed before every nginx start.
* **Same route as real traffic.** The probe reaches the same `server`, `location` and `$upstream` as a client
  would, minus the client-facing layers (TLS, the HTTPS redirect, and later forward auth).
* **`edge`:** each routed domain is **one** app server that always has the probe listener and has the TLS
  listeners (`8443 ssl`, the forwarder's `https.sock`, `http2 on`, the certificate) only when the domain has a
  certificate. This replaces the pair "plain redirect server + optional TLS server" by "redirect server + app
  server"; the plain `8080` redirect/ACME server is unchanged. A domain without a certificate therefore still
  fails closed for every client and is probe-able, which also makes the first deploy before ACME work.
* **`behind`:** only the extra `listen` line.
* **Header discipline.** On the probe socket `$remote_addr` is the literal `unix:` (there is no PROXY header and
  `realip` only replaces the address of connections that carry one). Upstreams see `X-Real-IP: unix:` and
  `X-Forwarded-For: unix:` for probes — documented, and deliberately **not** mapped to `127.0.0.1`, which would
  look like loopback to apps that trust loopback. In `edge`, `X-Forwarded-Proto` is `http` for a probe (the
  scheme of the listener); `behind` always did this. The access log's `$weglarka_peer` map keeps `unix:` for such
  connections instead of the empty `$proxy_protocol_addr`.
* **`INGRESS_HASH_FORMAT` goes to v5 for both modes.** The probe directory is a new mount, and a mount cannot be
  added to a live container; without the bump an existing nginx would keep running without the directory and
  `nginx -t` on the new config would fail forever. The upgrade recreates nginx once per host (in `edge` the
  forwarder holds connections meanwhile, ADR 0043). No `apps.toml`/`state.toml`/`weglarka.toml` change, no
  schema bump.
* Forward auth (#89) will exempt exactly this listener structurally
  (`map $remote_addr $weglarka_probe { "unix:" 1; default 0; }`), so the P0 rule that `health.http` must be in
  `auth_exempt_paths` can be dropped then. The identity provider's doctor and JWKS traffic (#88) can use the same
  socket with the provider's `Host`. Both are out of scope here.

## Consequences

* The probe no longer depends on the HTTP port, TLS state or the mode; `health.http` works in `edge`.
* The probe tests nginx routing and the upstream only. TLS and authentication are not exercised by the gate.
* All ingress snapshots change (one more `listen`; in `edge` the server layout). Operators: one nginx recreate on
  upgrade in both modes; see [verify and rollback](../guides/verify-and-rollback.md). A downgrade makes the old
  daemon recreate nginx with its old mounts; the `probe/` directory lingers, harmlessly.
* `weglarka-notify`'s internal route `http://weglarka-nginx:8080` + `host` still goes through the TCP port and
  therefore does not work in `edge` (it gets the 301). Moving notify onto the socket is a follow-up.
* The socket path must fit in 107 bytes (`sun_path`): `<nginx_conf_dir>/probe/probe.sock` on the host.
* Tests: generator snapshots and listener/isolation assertions; a prober unit test over a unix socket; the
  daemon integration tests pin the mount (nginx only, writable) and the `0700` mode; `test-edge.sh` requests a
  certless domain over the socket (upstream status, not 301) and a foreign `Host` (444); `nginx -t` runs with the
  directory mounted; the acceptance canary sets `health.http`.

## Rejected alternatives

| Option | Why not |
|---|---|
| Internal `:8079` server with all app routes | `listen 8079` binds every interface and nginx is on every app network, so any app container could dial it with another app's `Host` and bypass TLS and forward auth; it also duplicates the server/location tree |
| The same without an allowlist | the bypass above |
| TLS probe to `:8443` with SNI | ties the gate to certificate state (first deploy before ACME, renewals, wildcards), needs a TLS client and mode switch in the prober, and keeps the forward-auth exemption rule |
| Container-level check (exec, `HEALTHCHECK`) | reverses ADR 0010; distroless images have no client; that is what `health.command` already is |
| The daemon joins the app networks | breaks the network invariant of ADRs 0007/0010/0032 |
| Exempt the probe by `User-Agent` | forgeable by any client |
| Map the probe's address to `127.0.0.1` | would look like loopback to apps that trust loopback |
