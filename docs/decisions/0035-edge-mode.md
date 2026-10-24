# 0035 — Edge mode: nginx owns 80/443 (TLS, ACME webroot, certificate reload)

Status: proposed (2026-10-24, issue #95). The uid-map half (below, “Ingress container identity”) is
accepted only once `integration-podman` runs `crates/weglarka-podman/tests/ingress_identity.rs` green —
there was no rootless Podman 6 on the development machine, so it is measured in CI, not locally. The
nginx half was measured locally (see “Verification”).

## Problem

`behind` mode (ADR 0005) publishes one port on the host and leaves TLS, certificates and the HTTP→HTTPS
redirect to Traefik. The target installation (issue #45) is a host where no Traefik runs any more:
Węglarka's nginx has to own ports 80 and 443, terminate TLS itself, and keep serving while certificates
are issued and renewed. Issue #95 is that first step; ACME issuance (#96) and DNS-01 (#97) build on it.

Constraints from the existing code:

* the ingress container is hardened (ADR 0014): read-only root, `cap_drop: ALL` with only
  `CHOWN`/`SETGID`/`SETUID`, `no-new-privileges`. It listens on 8080, so it never needed
  `NET_BIND_SERVICE` — and that must not change (the smoke tests pin the exact capability set);
* the container runs in a private user namespace with an explicit uid range (ADR 0009): its root is
  the first subuid of the runtime user, its worker is uid 101 inside the namespace. The daemon cannot
  `chown` a host file into that range (no privilege), and ACME keys are supposed to be `0600`;
* the generated config is pure and snapshot-tested; `nginx -t` and `SIGHUP` are the only ways a config
  change is applied (ADR 0005/0007), and a change must never recreate the container;
* an operator configures the public address in `[ingress] bind`; the mode is `behind` or `edge`
  (`weglarka-core/src/config.rs`).

## Decision

**Two publishes, high ports inside.** `edge` publishes a plain-HTTP and a TLS socket on the host
(`[ingress] bind` and the new `[ingress] https_bind`) while nginx keeps listening on 8080/8443 inside
the container. Host port 80/443 → container 8080/8443, so the hardened profile stays unchanged and the
daemon's health probe (`weglarka-nginx:8080`) keeps working.

The configuration is explicit per mode and validated at startup
(`HostConfig::validate` → `StartError::Ingress`; `doctor --preflight` check `ingress.config`):

| key | `behind` | `edge` |
|---|---|---|
| `bind` | required, the only publish | required, the **plain-HTTP** publish |
| `https_bind` | forbidden | required, the **TLS** publish (must be a different socket) |
| `traefik_dynamic_file` | optional | forbidden |
| `trusted_proxies` | optional | forbidden (no client is trusted, ADR 0007) |
| port < 1024 | not used by the ingress | requires `[runtime] allow_privileged_host_ports = true` (same opt-in as `host_ports`, ADR 0013; the sysctl itself is check `ingress.privileged_ports`) |

`https_bind` is a new `weglarka.toml` key, so `deny_unknown_fields` makes an older daemon refuse an
`edge` config — documented in `docs/install.md` (downgrade: remove `https_bind`, switch to `behind`).
`apps.toml`/`state.toml` are untouched: no schema bump (ADR 0023).

**The plain-HTTP listener only redirects, except ACME.** Every routed domain (apps and the webhook
domain) gets a `server` on 8080 with

```nginx
location ^~ /.well-known/acme-challenge/ {   # served from <nginx_conf_dir>/acme, never redirected
    alias /etc/nginx/acme/;
    default_type text/plain;
    limit_except GET { deny all; }
}
location / { return 301 https://$host$request_uri; }
```

The `^~` prefix wins over `location /`, so no server-level `if`/map is needed and no request can slip
past the exception. The unknown-`Host` default server returns 444. App paths on port 443 never conflict
with the reserved ACME prefix because apps are not proxied on the plain port at all.

**One TLS `server` per domain, only when a certificate exists.** nginx selects the server — and
therefore the certificate — by SNI, so `edge` emits one server per domain (unlike `behind`, which groups
domains that share the same set of apps). A routed domain without a certificate pair gets no TLS server;
its handshake is answered by the default server with `ssl_reject_handshake on;` (no certificate needed,
nginx ≥ 1.19.4). This is fail-closed: a domain without a certificate redirects to HTTPS but does not
serve the app over plaintext. The TLS server sets `http2 on;` (nginx ≥ 1.25.1) and the `http` block
carries `ssl_protocols TLSv1.2 TLSv1.3`, a session cache/timeout, `ssl_session_tickets off` and
`ssl_prefer_server_ciphers off`. HSTS is left to the app for now (it is a policy the operator may not
want to commit to from a deploy tool).

**TLS material lives in the state directory.** `<nginx_conf_dir>/tls/<domain>.crt` (PEM chain, leaf
first) and `<domain>.key` (PEM, `0600`) inside a `0700` directory; `<nginx_conf_dir>/acme/` (`0755`) is
the HTTP-01 webroot (a token file `<token>` is served at `/.well-known/acme-challenge/<token>`; files
`0644` — they are public by design, and served by the worker). Both directories are inside the directory
already mounted read-only at `/etc/nginx`, so `edge` needs no extra mount and no change to the ingress
container's mounts.

The daemon rescans `tls/` on every `apply`: only regular `<domain>.crt` files with a matching `.key` and
a name that parses as a `Domain` count; everything else is ignored (the domain keeps its redirect, the
doctor reports it). The set of certified domains and a fingerprint of the material (name, size, mtime —
the daemon never reads the private keys) are rendered into `nginx.conf` as data and as a comment. A
renewal therefore changes the config, goes through the usual `nginx -t` + `SIGHUP` path and never
recreates the container; a rejected config is rolled back on disk as before. This is the hook issue #96
needs: write the certificate and the reload happens.

**Ingress container identity (amends ADR 0009).** The nginx master — the process that reads
`ssl_certificate_key` at start and at every reload — is container uid 0. `edge` gives the ingress
container a two-line map (`volumes::ingress_id_mapping`): container uid 0 → the rootless namespace's
uid 0 (the daemon's host user), container uid 1.. → the reserved ingress range as before. The master
can read the daemon's `0600` keys; the worker (uid 101) still lands in the ingress range and cannot.
This is not the pool-spanning default map: only uid 0 is shared, the range stays disjoint from every
app range. The security consequence is recorded honestly: if something is ever mounted into the nginx
container, the master sees the daemon's filesystem identity inside that mount, and the mounts are
read-only. **Nothing but `<nginx_conf_dir>` may ever be mounted into the ingress container** (no state
directory, no `config_root`, no Traefik file) — the certificate directory becomes a trust boundary.

**Container identity bumps to `weglarka.ingress-hash/v3`.** The mode, both publishes and both listen
ports are part of the hash, so the upgrade recreates `weglarka-nginx` once (the same one-time recreation
contract as ADR 0014) and a change of `https_bind` can never reuse a container with the old port
mapping. The hash still excludes networks and certificates (both are synced/rendered live).

**No trusted peers in `edge`.** nginx terminates TLS itself, so `X-Forwarded-For/Proto/Host` are
rebuilt from `$remote_addr`/`$scheme`/`$host` for every request; a client that sends its own values is
overwritten (ADR 0007: direct clients are never trusted). There is no `real_ip` and no trust map.
`[ingress] trusted_proxies` is rejected by validation rather than silently ignored.

**host_ports reserves both ingress sockets.** `core/src/host_ports.rs` iterates
`IngressConfig::publish_sockets()`, so an app cannot publish over the HTTP or the TLS socket.

## Verification

Measured locally (2026-10-24; Docker 29 on macOS, image `nginx:1.31.8-alpine@sha256:a3554c0d…`, generated
config from `cargo run -p weglarka-ingress --example dump -- nginx-edge blog.example.eu`, TLS material
mounted at `/etc/nginx/tls`, webroot at `/etc/nginx/acme`):

* `nginx -t` accepts the generated config (including the TLS default server without a certificate);
* plain HTTP for a routed domain → `301` with exactly `https://<domain>/` (path and query preserved);
* `/.well-known/acme-challenge/<token>` over plain HTTP → `200` with the file body, not redirected; a
  missing token → `404`; `POST` → `403`; an unknown `Host` closes the connection (`444`);
* TLS with SNI for a domain with a certificate → the app route is taken (`502` from the unresolvable
  test upstream, i.e. TLS + routing work); HTTP/2 is negotiated;
* a routed domain without a certificate → redirect over HTTP, TLS handshake rejected with
  `unrecognized_name`; unknown SNI rejected the same way.

CI: `check` runs `nginx -t` on an `edge` config with a mounted certificate and
`.github/scripts/test-edge.sh` (Docker: redirect, ACME, TLS, fail-closed paths, forwarded headers,
unknown SNI); `integration-podman` runs `smoke-image.sh … edge` (two publishes, hardened profile,
acceptance in `edge`, certificate change → reload without recreate) and
`crates/weglarka-podman/tests/ingress_identity.rs` (the uid map: master reads a `0600` file, an
app-style container on the plain map cannot, `/proc/self/uid_map` matches the two lines). Snapshots:
`crates/weglarka-ingress/tests/snapshots/generators__nginx_edge_*.snap`, with the `behind` snapshots
unchanged. Daemon tests cover the two publishes, the map, directory modes, certificate scan/reload and
the doctor check; CLI preflight tests cover `ingress.config`, `ingress.tls` and
`ingress.privileged_ports`.

## Consequences

- **`behind` is untouched.** Same config, same generated `nginx.conf` byte for byte, same snapshots;
  the daemon does not even read the TLS directories there.
- **Custom `ingress.nginx_image`**: `ssl_reject_handshake` needs nginx ≥ 1.19.4 and `http2 on` needs
  ≥ 1.25.1; the official `nginx:1-alpine` (and the digest pinned in `docs/install.md`) is newer. An
  older image fails `nginx -t` loudly.
- **Host preparation**: ports 80/443 on the host need `net.ipv4.ip_unprivileged_port_start=0` (rootless
  Podman), the explicit `[runtime] allow_privileged_host_ports = true` opt-in (validation refuses the
  config without it) and firewall rules; the preflight check reads the sysctl. High ports (e.g.
  18080/18443) need none of that — which is how CI and local acceptance run `edge`.
- **One-time recreation** on upgrade from a build without `v3`; a downgrade recreates nginx again with
  the old map (harmless before #96 writes keys, which is why this lands before it), and the config must
  drop `https_bind` to parse on an older daemon.
- **Emergency access**: with no certificate for a domain there is no TLS server for it at all — ACME
  (issue #96) fills the gap; until then the operator places a certificate (self-signed for tests is
  enough) or serves `behind`.
- The daemon never logs, renders or copies private keys: the generator only receives domain names and
  paths, and the fingerprint is metadata.

## Rejected alternatives

- **`listen 80/443` inside the container** (with `NET_BIND_SERVICE` added back). It would change the
  mandatory hardening profile and the exact-capability assertions of ADR 0014 for a cosmetic reason;
  publishing host 80/443 onto 8080/8443 is equivalent from outside.
- **World-readable keys (`0644`)** to avoid touching the uid map. It contradicts #96's “key files
  `0600`” and makes every private key readable by any host user; the ingress container is exactly the
  case where the map should adapt, not the key permissions.
- **Podman secrets for the TLS material.** libpod copies a secret at container creation and rotation
  does not reach the running container: every renewal (or new domain) would recreate the ingress, the
  one thing ADR 0005/0007/0014 promise never to do for a config change. It also stores a second copy of
  the key.
- **POSIX ACLs on the key files.** The daemon runs on `scratch` without `setfacl`, would need a crate
  that writes the `system.posix_acl_access` xattr (and re-apply it on every atomic write), and the
  display mode still becomes `0640` — cost and fragility without a benefit over the uid map.
- **Hard-coded 80/443.** Acceptance and CI could not exercise `edge` without changing a host sysctl;
  the two configurable publishes keep tests honest and still default to 80/443 in the documentation.
- **A self-signed default certificate** for the unknown-SNI server. `ssl_reject_handshake` needs none
  and leaks nothing; a self-signed pair would add key generation (and another key to protect) to the
  daemon.
- **ACME issuance in this change.** #96 owns the account key, staging tests and renewal policy; #95
  delivers the webroot contract, the per-domain TLS servers and the reload-on-change that #96 needs.
- **Trusted peers in `edge`** (for a CDN/LB in front). It would reopen exactly the forgery hole ADR
  0007 closes; a future “behind an edge load balancer” mode can add it explicitly.

## Follow-ups

- **#96** ACME HTTP-01: `instant-acme`, account key `0600` outside the webroot, write
  `<nginx_conf_dir>/tls/<domain>.crt|key` atomically, then rely on the fingerprint-triggered reload;
  renewal ~30 days before expiry, Let's Encrypt staging in tests.
- **#97** ACME DNS-01 through a provider adapter (Cloudflare first).
- **#89** forward auth per app: nginx `auth_request` in `edge` (fail-closed) — the per-domain TLS servers
  are the place for it.
- Consider HSTS, OCSP stapling and a per-app `security_headers` option as separate decisions.
