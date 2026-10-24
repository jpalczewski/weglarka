# 0005 — Ingress in the daemon: nginx reload, Traefik file, quadlet

Status: accepted (daemon session, 2026-10-23). **Update: the reload without `exec`/recreating nginx is superseded
by 0007** (`nginx -t` + HUP, live networks).

**nginx.**
- The `weglarka-nginx` container is managed by the daemon (`IngressManager::apply`, idempotent). The directory with
  `nginx.conf` (`[ingress] nginx_conf_dir`, default `<state dir>/nginx`) is mounted **as a directory** at
  `/etc/nginx` (ro) — a `rename` of the file is then visible in the container (a bind-mount of a single file would
  keep the old inode). The generated config is self-contained (no `mime.types`).
- Reload: `SIGHUP` via `container_kill` (libpod `POST /containers/{n}/kill`), not `exec`. The daemon does not run
  `nginx -t` itself (no `exec`); the correctness of the generator is guarded by CI (`nginx -t` on a sample config),
  and after a bad HUP nginx stays on the old config and logs the error.
- The `weglarka.ingress-hash` label (image + bind + port + set of networks). A change in the set of networks (an app
  with a domain was added/removed) = **recreating** the container, because there is no `network_disconnect` and
  `ContainerInfo` does not carry the list of networks; a change of the config alone = HUP. Consequence: adding the
  first app with a domain means a brief ingress gap (seconds). The container does not carry the
  `weglarka.instance` label, so reconcile will not treat it as an orphan.
- The `net-weglarka` and `net-<app>` networks are created by the ingress itself (idempotently), regardless of the
  order relative to deploy. nginx's resolvers = the gateways (aardvark-dns) of all attached networks, from
  `network_inspect`.
- `apply` runs on start-up, after every change (add/remove/deploy/secret — coalesced) and every reconcile period
  (self-repair: a dead nginx container is started).

**Traefik.** The dynamic file is overwritten **in place** (opened without `rename`, truncate + write + `fsync`),
because the ACL only grants traversal through the directory; the file is created up front. With identical content
it is not touched (Traefik throttles reloads).

**systemd platform.** The user quadlet `~/.config/containers/systemd/weglarka.container` + `net-weglarka.network`
(`NetworkName=net-weglarka`, so the network name matches `ContainerName=weglarka` = the host in `proxy_pass`). We
mount all paths (the Podman socket, the state directory, the admin socket directory, `weglarka.toml`, the Traefik
file) under **the same name as on the host**, so that one `weglarka.toml` is correct inside the container and for
the CLI on the host. Installation: `weglarka-daemon platform install [--dry-run]` as the runtime user. OpenRC:
enum variant only.

**Admin API.** Unix socket only (0600, the old socket is removed only if it is a socket). Reads do not take the
engine mutex; mutations wait for it at most 30 s, then 409 (`conflict`) — a deploy with a health gate does not
block the API. `POST …/deploy` first tries a normal deploy and, on a known bad digest, retries with `force` (a
manual call = the operator's will); `image_ref` in the request → 400 (outside the MVP); `Failed` → 500 with the
reason.

**Update: Podman socket and quadlet hardening (quadlet-fix session).**
- The image is on `scratch` — no `/etc/passwd`. `weglarka-daemon run` **never** reads user files: it takes the
  Podman socket from `[runtime] socket`, and when that is absent, from the `WEGLARKA_PODMAN_SOCKET` variable; with
  neither it ends with a readable error. `platform install` (on the host, where `/etc/passwd` exists) computes the
  socket and writes it into the quadlet as `Environment=WEGLARKA_PODMAN_SOCKET=…` — the socket is mounted under the
  same path, so the same `weglarka.toml` works for the daemon in the container and for the CLI on the host,
  without `runtime.socket`. The variant with a fixed path in the container was rejected: it would require a
  separate config for the CLI.
- Quadlet: `ReadOnly=true` + `Tmpfs=/tmp`, `DropCapability=ALL`, `NoNewPrivileges=true`,
  `PodmanArgs=--memory=<M> --memory-swap=<M>` (swap = limit, the host swaps), `PidsLimit=<N>`.
  The daemon writes only to mounted directories (state, admin socket, nginx.conf, the Traefik file), so it does not
  need to write to the root FS. `[platform] memory` (default `128M`) and `pids_limit` (256) are configurable; 128M
  is an estimate (a static daemon on tokio, current_thread, a few to a dozen or so MB RSS) with a large margin, not
  a measurement.
- `weglarka-daemon platform run-args` prints the same options as `podman run` arguments; the smoke test in CI
  (`.github/scripts/smoke-quadlet.sh`) starts the image with exactly those, with a config without `runtime.socket`.
- Out of scope at the time (follow-up): hardening of the `weglarka-nginx` container created by the daemon (cap drop,
  memory limit) — it requires extending `ContainerSpec` and the libpod wire. The security part is now done in
  [0014](0014-ingress-nginx-hardening.md); a memory limit is still open.

## HTTP → HTTPS (`behind` mode)

The Traefik file contains, for every router, a twin `weglarka-http-*` on the `http` entrypoint (no `tls`, the same
service); without it Traefik answered 404 for `http://domain/`. The twin has the **prefix** `weglarka-http-`, not the
suffix `-http`: an instance `foo-http` would collide with the twin of `foo`. The `redirectScheme` middleware is out
(the publication validator rejects middlewares), so the redirect is done by nginx:
`return 301 https://$host$request_uri;` in the `server` of apps and webhooks, when `$weglarka_redirect_https` (a
map: trusted peer **and** a non-empty `X-Forwarded-Proto` other than `https`/`wss` — fail closed, e.g. `ws` from
Traefik for a WebSocket over HTTP). `$weglarka_proto = http` is not enough: a trusted peer without the header (the
daemon's health probe, `health.http`, docs/decisions/0010) gets the `$scheme` fallback = `http` and must not get a
301. An untrusted peer is never redirected. `edge` mode was implemented in [0035](0035-edge-mode.md) with a different
mechanism than planned here: the redirect lives in the plain-HTTP `server` (`location /`), the ACME prefix is an
`^~` location served from `<nginx_conf_dir>/acme`, and the `behind` map is not rendered at all. Entrypoint name:
`TraefikOptions::http_entrypoint` (default `http`). Tests: snapshots, a test of compliance with the validator
policy, `.github/scripts/test-forwarded-headers.sh`, the `http_redirect` step in `scripts/acceptance.sh`.
