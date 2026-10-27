# 0043 — Edge mode: the client address is lost behind rootlessport

Status: accepted (2026-10-25, issue #162). Measured on a real host (comments on #162); the end-to-end path through the new containers is covered by the measurements and by `acceptance.sh --expect-client-ip`, not by CI.

## Problem

In `edge` (ADR 0036) nginx has no trusted upstream and rebuilds `X-Forwarded-For` / `X-Real-IP` from
`$remote_addr`. With the ingress container on a netavark bridge and its ports published by `rootlessport`,
the forwarder opens a new connection from inside the container's netns, so `$remote_addr` is nginx's own
interface address (the same mechanism ADR 0032 describes for `behind`, where the real address survives only
through Traefik's trusted `X-Forwarded-For`). In `edge` every client therefore looks like one internal
address: access logs, per-IP limits and anything an app derives from `X-Forwarded-For` lose their meaning.

Measured 2026-10-25 (Ubuntu 24.04, rootless Podman 6.1.3, netavark 2.1, pasta 0+20261002), `traefik/whoami`
queried from the host's own public address:

| container network | `RemoteAddr` seen by the app |
|---|---|
| user-defined netavark bridge + `rootlessport` (the ingress setup) | `10.89.21.2` (the container itself) |
| default rootless network (pasta) | `169.254.1.2` (pasta gateway; inconclusive, local source) |

The pasta row was an artefact of curling from the host itself. Measured again from a remote client
(2026-10-25, comment on #162; podman 6.1.3, netavark 2.1.0, pasta 0+20261002, nginx 1.31.8, systemd 255):

| variant | address the app sees | verdict |
|---|---|---|
| A: default rootless network (pasta) + `-p` | real client | preserved |
| B: bridge + `rootlessport` (today's ingress) | `10.89.21.2` (container) | **bug confirmed** |
| C: `--network pasta --network <bridge>` | — | impossible (`cannot set multiple networks without bridge network mode`) |
| D: `--network host` | real client | preserved, but cannot reach bridge containers (the bridge lives in the rootless netns); only published loopback ports are reachable |
| E: `systemd-socket-activate … podman run -e 'NGINX=3;' nginx`, `listen <port>;` | real client | works: nginx accepts the inherited fd |
| E2: same, container on a bridge, `proxy_pass` to a bridge upstream | `X-Forwarded-For`/`X-Real-IP` = real client | works: upstream addressing is unchanged |

Not measured: ports < 1024 handed over by a system-level `.socket`, and the quadlet `.socket` + `.container` form.

## Decision

**A forwarder container publishes the public sockets and relays to nginx over unix sockets with PROXY protocol v2.**

* `weglarka-forwarder` is created by the daemon from its **own image** (`weglarka-daemon forward --route
  <addr:port>=<socket>`, `crates/weglarka-daemon/src/forwarder.rs`) on libpod's default rootless network
  (pasta, which keeps the remote client address, measurement A). It publishes `bind` / `https_bind`
  (container ports 8080/8443), opens `<nginx_conf_dir>/run/{http,https}.sock` per connection and writes the
  client's address in a PROXY v2 header before copying bytes both ways. It does no TLS and parses nothing.
  Hardening: read-only root, `cap_drop: ALL` (no `NET_BIND_SERVICE`: the host sysctl decides about
  privileged ports, as before), `no-new-privileges`, libpod's default uid map (container root = runtime user,
  so it can open the `0700` directory), only the socket directory mounted.
* nginx in `edge` publishes nothing. Its generator (`NginxOptions::proxy_socket_dir`) adds
  `listen unix:/run/weglarka-ingress/{http,https}.sock [ssl] proxy_protocol;` next to the TCP listeners
  (8080 stays for the daemon's health probe; superseded by 0054) and, in the `http` block, `set_real_ip_from unix:;
  real_ip_header proxy_protocol;`. Only the unix peer is trusted to announce a client; TCP peers keep their
  own `$remote_addr`, so `X-Forwarded-*` are still rebuilt from the connection and never from the client
  (ADR 0007). `behind` is untouched (the option is rejected there).
* **The socket directory is the security boundary.** `<nginx_conf_dir>/run` is `0700`, owned by the runtime
  user and re-applied on every pass. Measurement G2: a loopback TCP port accepted a forged PROXY header from
  any local user, a unix socket in a `0700` directory did not. It is a subdirectory of the one directory nginx
  already mounts (ADR 0036's "only `<nginx_conf_dir>`" rule holds), mounted a second time writable at
  `/run/weglarka-ingress`; the nginx master has the runtime user's identity there (edge uid map), the worker
  inherits the listening sockets and never needs the directory. nginx does not unlink a stale socket file
  after a kill, so the daemon removes both files before every start of the nginx container.
* **Identity.** `weglarka.ingress-hash` is `v4` in `edge` only (`behind` keeps `v3` and is not recreated);
  the forwarder carries its own hash (own image id, both publishes, hardening). A daemon self-update changes
  the image id and recreates the forwarder once (a short gap on the public ports). A switch to `behind`
  removes the forwarder.
* **`doctor`:** `ingress.client_ip` is ok when the forwarder runs and fails when it is missing or stopped
  (nothing is published then).
* Not independent of the init system: nothing here uses systemd, so it works under OpenRC (Alpine) where
  socket activation does not exist. Not measured yet: Alpine itself (G4) and ports below 1024 on the forwarder.

## Consequences

* No `apps.toml` / `state.toml` / `weglarka.toml` change, no schema bump; `behind` is byte-for-byte unchanged.
  Upgrading an `edge` host recreates nginx once (`v4`) and creates the forwarder; a downgrade to an older daemon
  leaves a `weglarka-forwarder` container behind (remove it with `podman rm -f weglarka-forwarder`) and the
  older daemon recreates nginx with the old publishes.
* One more small process and hop (no TLS work in it). Connections are capped at 4096 per route.
* #159 (`edge` behind a CDN) can now rely on a real peer address: after `real_ip_header proxy_protocol`,
  `$remote_addr` is the address that connected to the forwarder (a CDN edge address, measurement F) while
  `$realip_remote_addr` is only the unix peer. nginx's realip module takes one `real_ip_header` per context,
  so #159 cannot chain a second `set_real_ip_from <CDN ranges>` + `CF-Connecting-IP` on top of it: it has to
  test `$remote_addr` against the CDN ranges (`geo`) and pick the client address with a `map`, the way `behind`
  does with `$weglarka_xff`.
* Tests: generator snapshot, forwarder unit/relay tests, daemon tests on `FakePodman` (no publishes on nginx,
  forwarder spec, directory mode, hash), `smoke-image.sh edge` checks the bindings, and `scripts/acceptance.sh
  --expect-client-ip <ip>` run from **another host** asserts the address the app sees. CI cannot do the latter.

## Rejected alternatives

* **Trusting the forwarder's address with `set_real_ip_from`.** It would trust a value that is the same for
  every client, hiding the problem instead of fixing it.
* **Silently leaving `edge` as is.** The loss of client addresses is a security-relevant surprise.
* **systemd socket activation** (measurements E, E2). Works and needs no extra process, but is systemd-only
  and moves the start of nginx out of the daemon's libpod logic; the target host runs OpenRC.
* **nginx on pasta / host network** (C, D). Keeps the address, but cannot reach the per-app bridge networks.
* **PROXY protocol over loopback TCP** (G2). Any local user can connect and forge the client address.
