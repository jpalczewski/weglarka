# 0007 — Trusted proxies behind rootless Podman, reload instead of recreate

Status: accepted (2026-10-23). Section 1's default trust (the `net-weglarka` subnet) is superseded by 0032.

## 1. Who nginx sees as the peer

In `behind` mode Traefik (Docker, network `coolify`) proxies to `172.17.0.1:8088`, a port published by rootless
Podman. Rootless port publishing goes through the forwarder (rootlessport), which opens a **new** connection
from *inside the container network*. Measured on the host (`niechybnie`, acceptance report, Podman 6.1.3):
nginx sees every client as `10.89.1.2`, an address of the Podman network — never Traefik's `172.18.x.x`.
So a `set_real_ip_from` limited to Docker's ranges never matched: no `X-Forwarded-Proto`, no real IPs in the log.

**Decision.**
- Default trust = the **subnet(s) of `net-weglarka` only**, read from `network_inspect` on every `apply`. nginx's
  primary (first) network is `net-weglarka`, and that is where the forwarder's connections originate (observed
  `10.89.1.2`). App networks (`net-<app>`) are **not** trusted, so an app container that reaches nginx over its own
  network cannot forge `X-Forwarded-*`. Only Węglarka's own container shares `net-weglarka` with nginx.
  Docker's `172.16.0.0/12` is not in the default: with rootlessport Traefik's address is never the source.
- `[ingress] trusted_proxies = ["10.89.1.2", …]` (CIDRs or bare addresses) overrides the default entirely, e.g. to
  pin the single forwarder address. The generator itself has no default and refuses an empty list.
- If the forwarder's source turned out *not* to be in `net-weglarka`, the symptom is exactly the old one (no
  `X-Forwarded-Proto` upstream); `scripts/acceptance.sh` fails on it with a pointer to `trusted_proxies`.
- nginx: `set_real_ip_from` for each entry, `real_ip_header X-Forwarded-For`, `real_ip_recursive on`; the access log
  and `X-Real-IP` carry the real client.
- Upstream headers: when the original peer (`$realip_remote_addr`) is trusted, `X-Forwarded-Proto/For/Host` are passed
  on from the request (fallbacks: `$scheme`, `$remote_addr`, `$host`); otherwise they are **overwritten** with our own
  values, so a client outside the list cannot forge them. No `$proxy_add_x_forwarded_for` (it would duplicate the client).

**Security reasoning.** In `behind` the published port is reachable only from Traefik (UFW: only the `coolify`
network → 8088), so trusting the forwarder = trusting Traefik. Because only `net-weglarka` is trusted, apps cannot
impersonate it. In `edge` mode (future) direct clients must never be trusted.

**Alternative considered: pasta for the nginx container** (`--network pasta` preserves the source address) — it
cannot be combined with user networks (aardvark DNS, per-app networks `proxy_pass` relies on). Rejected.

## 2. Reload instead of recreate

Before, every ingress change that altered the set of app networks recreated `weglarka-nginx` (a gap for all apps
and webhooks). Now:
- Config change → atomic write → `nginx -t` (container exec, new `PodmanClient::container_exec`) → `SIGHUP`.
  A rejected config is **not** reloaded: the previous `nginx.conf` is restored, the Traefik file is not written, the
  error is returned (`last_error`, `doctor`) and logged; the next `apply` retries. The exit code is reported, the
  output is not captured (detached exec + polling) — run `podman exec weglarka-nginx nginx -t` for the message.
- New app network → `network_connect` on the running container (before the reload); removed app → `network_disconnect`
  (after the reload). Current attachment comes from `ContainerInfo.networks` (inspect).
- `weglarka.ingress-hash` = image + bind + listen port only — things a live container cannot change. The **network
  list is deliberately not in the hash**, otherwise every added app would look like a spec change and recreate it.
  The upgrade to this version recreates nginx once (the hash changed).
- Resolvers are written from all networks' gateways; a network connected later gets its aardvark address via the
  regenerated config + reload.
