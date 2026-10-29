# Installing Węglarka

Węglarka runs as a **rootless Podman container** (a quadlet in the user's systemd) next to its own nginx container.
The `weglarka` CLI stays outside the container: on the host, or on a laptop through an SSH tunnel to the admin socket.
Examples assume the host `myhost` (Ubuntu 24.04, `behind` mode, Traefik from Coolify). Decisions:
[ADR 0005](decisions/0005-ingress-i-platforma.md), [ADR 0006](decisions/0006-pakowanie-obrazy-i-release.md).

This page covers installation only: host requirements, host configuration, binaries, the quadlet, image
verification, the CLI from a laptop and the acceptance test. Everything else (your first app, volumes, webhooks,
ports, TLS, self-update, rollback, ...) lives in task-oriented guides in [`docs/guides/`](guides/README.md).
Ready-made app specs and `apps.toml` snippets (copy-paste): [`docs/examples/`](examples/).

## Host requirements

Prepare these with your host provisioning (e.g. an Ansible role); Węglarka installs none of it by itself:

- **Podman 6.x** from the OBS repo `home:alvistack` (apt pinning for the Podman stack only), netavark 2 (nftables), pasta;
- a runtime user (default `weglarka`) with `subuid`/`subgid` ranges ≥ 65536 and **linger**
  (`loginctl enable-linger weglarka`);
- `systemctl --user enable --now podman.socket` for that user (socket: `/run/user/<uid>/podman/podman.sock`);
- directories (owner `weglarka`): state `/var/lib/weglarka` (0755) and **`/var/lib/weglarka/run` (0700)**.
  The admin socket lives in a persistent directory because `/run/user/<uid>` disappears on reboot, and Podman
  does not start a container if a mounted directory does not exist;
- `/etc/weglarka/weglarka.toml` readable by `weglarka` ([Host configuration](#host-configuration));
- (`behind` mode) a Traefik file **on Węglarka's side**: `/var/lib/weglarka/traefik/weglarka.yml` created up front
  (owner `weglarka`, 0644, the content may be a comment — the quadlet mounts this single file, so it must exist
  before start). Węglarka overwrites it in place. It **gets no access to Traefik's directory** (`/data` and
  `/data/coolify` are 0700, an ACL on `/data` would expose other services) — publishing is done by root, see below;
- (`behind` mode) **publishing to Traefik through a root-owned path unit with a validator**:
  `weglarka-traefik-sync.path` (watches `/var/lib/weglarka/traefik`) → `weglarka-traefik-sync.service` →
  `/usr/local/sbin/weglarka-traefik-sync`. The validator (policy in `/etc/weglarka/traefik-policy.json`) only lets
  through `http.routers`/`http.services` named `weglarka` or `weglarka-*`, `Host()` rules (optionally
  `&& PathPrefix()`) for domains on the allowlist, a single backend `http://host.docker.internal:<port from bind>`,
  and `tls.certResolver: letsencrypt` (routers on the `http` entrypoint without `tls`); no middlewares, no tcp/udp.
  For every domain Węglarka generates a second router `weglarka-http-*` on the `http` entrypoint — the 301 redirect
  to HTTPS is done by Węglarka's nginx (not Traefik), so the validator policy must allow the `http` entrypoint
  without `tls`. The validated YAML is copied atomically to `/data/coolify/proxy/dynamic/weglarka.yml`; on an error
  the previous version stays, and the reason is in `journalctl -t weglarka-traefik-sync`. A new app domain means
  adding it to the domain allowlist in your publish-validator policy first (`allowed_domains` in
  `/etc/weglarka/traefik-policy.json`);
- (`behind` mode) Węglarka's nginx port on the `docker0` address **other than 8080** (8080 on `0.0.0.0` is held by
  the docker-proxy of Coolify's Traefik) — on `myhost` that is `172.17.0.1:8088`, and UFW lets only the `coolify`
  network (`172.18.0.0/16`) reach it;
- AppArmor (Ubuntu 24.04, `apparmor_restrict_unprivileged_userns=1`): the system `podman` profile from the package
  is enough, rootless works without sysctl changes;
- **ports published on the host** (`host_ports`, [Host ports](guides/host-ports.md)): traffic to them is forwarded
  by rootless Podman's port forwarder, so nothing needs to be installed on the host, but **UFW must allow them** —
  add the rules in your host provisioning, Węglarka does not change the firewall. Ports < 1024 need
  `net.ipv4.ip_unprivileged_port_start=0` on the host **and** `[runtime] allow_privileged_host_ports = true` in
  `weglarka.toml`; without the sysctl the container itself fails to start;
- (`edge` mode) **ports 80/443 on the host**: Węglarka's nginx publishes them directly (inside the container it
  still listens on 8080/8443), so rootless Podman needs `net.ipv4.ip_unprivileged_port_start=0` **and**
  `[runtime] allow_privileged_host_ports = true` in `weglarka.toml` (the same flag as for `host_ports`,
  [Host ports](guides/host-ports.md)); without the flag validation refuses to start, and without the sysctl
  publishing the port fails. UFW must allow 80 and 443. TLS and certificates live in the state directory
  (`<state>/nginx/tls`, directory `0700`, key `0600`), the ACME webroot in `<state>/nginx/acme` (`0755`, files
  `0644`) — [Edge mode](guides/edge-mode.md). Ports other than 80/443 (e.g. 18080/18443) let you run `edge`
  without the sysctl — that is what CI does;
- DNS: the record for the webhook domain (`[webhook] domain`) and for app domains points at the host (in `behind`
  TLS is terminated by Traefik, in `edge` by Węglarka's nginx).

Check (as the runtime user, after writing `weglarka.toml`):

```sh
sudo -iu weglarka env XDG_RUNTIME_DIR=/run/user/$(id -u weglarka) \
  weglarka doctor --preflight --config /etc/weglarka/weglarka.toml
```

Every `warn`/`fail` comes with a fix hint (`runtime.subuid`, `runtime.linger`, `runtime.podman_source`,
`ingress.traefik_file`, `state.secrets_file`, ...). Selected host checks:
`runtime.subuid`/`subgid` (warn < 1 000 000 ids, fail < 65 536), `runtime.apparmor_userns` (Ubuntu 24.04:
the `podman` profile is loaded when `apparmor_restrict_unprivileged_userns=1`; full result only as root),
`ingress.config` (the `[ingress]` keys match the mode: `edge` requires `https_bind` and rejects
`traefik_dynamic_file`/`trusted_proxies` as well as ports < 1024 without `allow_privileged_host_ports`),
`ingress.bind`/`ingress.bind_free` (the publishing addresses and ports — in `edge` **both**, HTTP and TLS — are not
taken by a foreign process, e.g. Traefik), `ingress.tls` (`edge` only: every routed domain has a
`<domain>.crt`/`<domain>.key` pair in `<nginx_conf_dir>/tls`; a missing pair is a `warn`; `[acme]` —
[ACME certificates](guides/acme.md) — issues them automatically),
`ingress.privileged_ports` (`edge` with a port < 1024 only: whether `net.ipv4.ip_unprivileged_port_start` allows
it), `ingress.traefik_sync` (`behind` mode: `weglarka-traefik-sync.path` is active when
`/etc/weglarka/traefik-policy.json` exists; the domains from `apps.toml` are on the policy allowlist, key
`allowed_domains`), `apps.host_ports_free` (ports from `apps.toml` are not taken by a foreign process —
`/proc/net/tcp*`, like `ingress.bind_free` — and no ports < 1024 without `allow_privileged_host_ports`).
Firewall rules (including those for `host_ports`) are not checked. Exit codes: 0 ok, 1 warn, 2 fail.

## Host configuration

`/etc/weglarka/weglarka.toml` (the UID comes from `id -u weglarka`; paths are mounted into the container under the
same name, so the same file works for the daemon and for the CLI on the host):

```toml
[runtime]
user = "weglarka"
# Ports published on the host < 1024 (`host_ports`, see the host-ports guide): the host must have
# net.ipv4.ip_unprivileged_port_start=0. Default false — such ports are rejected during validation.
# allow_privileged_host_ports = true

[ingress]
mode = "behind"
bind = "172.17.0.1:8088"                                   # docker0; 8080 is taken by Coolify's Traefik
traefik_dynamic_file = "/var/lib/weglarka/traefik/weglarka.yml"  # a root-owned path unit validates and publishes to dynamic/
# nginx pinned by digest (ADR 0006); bump it deliberately — a change recreates the nginx container:
nginx_image = "docker.io/library/nginx:1.31.8-alpine@sha256:1ef7ca94d7879df82421428ce13bd1eaa412404953859cf7a5b6512c25e67a60"
# The nginx container is always hardened (ADR 0014): read-only root, cap_drop ALL (+ CHOWN/SETGID/SETUID),
# no-new-privileges. A custom image must tolerate that (it must not write to its rootfs at startup).
# Optional: peers nginx trusts for X-Forwarded-* (ADR 0007, ADR 0032). By default the nginx container's *own
# addresses* in all its networks (that is where rootless Podman's port forwarder connects from); the list REPLACES
# the default and is static (container addresses may change). Usually leave it unset.
# trusted_proxies = ["10.89.1.2"]
# `edge` mode (#95, ADR 0036): nginx terminates TLS itself and publishes TWO ports — `bind` (HTTP: only the
# redirect to HTTPS and ACME) and `https_bind` (TLS). `traefik_dynamic_file` and `trusted_proxies` are then
# rejected by validation, and you put certificates in <state>/nginx/tls (see the edge-mode guide).
# mode = "edge"
# bind = "0.0.0.0:80"
# https_bind = "0.0.0.0:443"

[admin]
socket = "/var/lib/weglarka/run/admin.sock"

[webhook]
listen = "0.0.0.0:9180"                                    # inside the container, on the net-weglarka network
domain = "weglarka.example.com"                            # only /webhook/ paths are exposed

[state]
dir = "/var/lib/weglarka"                                  # apps.toml, state.toml, secrets.toml, nginx/

# Directory with the apps' configuration files (see the host-configs guide). Mounted read-only into Węglarka's container.
# Absolute, or relative to the directory of weglarka.toml. Unset = feature disabled.
# config_root = "/var/lib/weglarka/config"

[platform]
kind = "systemd"
memory = "128M"                                            # memory limit of Węglarka's container (with swap); default 128M
pids_limit = 256                                           # process/thread limit; default 256
```

The guides for the optional parts of this file: [Host ports](guides/host-ports.md) (`allow_privileged_host_ports`),
[Edge mode](guides/edge-mode.md) (`mode = "edge"`), [Host configs](guides/host-configs.md) (`config_root`).

`[runtime] socket` is **not needed**: `platform install` works out the socket on the host
(`/run/user/<uid>/podman/podman.sock`) and passes it to the container in the `WEGLARKA_PODMAN_SOCKET` variable in
the quadlet. An explicit `socket` takes precedence over the variable. The daemon in the container does not read
`/etc/passwd` (the image is `scratch`); with no socket in the config and no variable it exits with a clear error.

**nginx trust in `X-Forwarded-*` (ADR 0032).** Without `trusted_proxies`, on every `apply` the daemon reads the
*own addresses* of the `weglarka-nginx` container (in all its networks: `net-weglarka` and `net-<app>`) and trusts
exactly those (`/32` entries). Rootless Podman's port forwarder opens the connection from inside the nginx netns, so
its source address is one of those addresses — not necessarily one from `net-weglarka`. App containers connecting
over `net-<app>` have different addresses and cannot forge the headers. The nginx address in a newly joined network
(or after the container is recreated) is only known once it appears, so the same `apply` pass reads the addresses
again and, if they changed, regenerates the config and reloads nginx. A container restart by Podman that changes
the addresses is noticed only on the next periodic `apply`. Symptom of a mismatch: an app that checks the scheme
(e.g. OIDC requiring https) answers 400; compare `remote_addr` from the nginx log with `podman inspect weglarka-nginx`
(the `IPAddress` field of each network).

## Host binaries

`platform install` uses `systemctl --user` and `/etc/passwd`, so it **does not work inside the container** — you need
`weglarka-daemon` on the host (CLI and daemon, `x86_64-unknown-linux-musl`).

**Before the first `v*` tag** there is no release — extract the binaries from the signed `:main` image
(first `cosign verify` as in [Verifying the image and binaries](#verifying-the-image-and-binaries)):

```sh
IMG=ghcr.io/jpalczewski/weglarka:main
podman pull "$IMG"
podman create --name wg-extract "$IMG"
podman cp wg-extract:/usr/local/bin/weglarka-daemon .
podman cp wg-extract:/usr/local/bin/weglarka .
podman rm wg-extract
sudo install -m 0755 weglarka weglarka-daemon /usr/local/bin/
```

**From the first tag on** — from the release tarball:

```sh
VER=0.1.0
base=https://github.com/jpalczewski/weglarka/releases/download/v$VER
cd "$(mktemp -d)"
curl -fsSLO "$base/weglarka-$VER-x86_64-unknown-linux-musl.tar.gz" -O "$base/SHA256SUMS"
sha256sum -c --ignore-missing SHA256SUMS
tar xzf weglarka-$VER-x86_64-unknown-linux-musl.tar.gz
sudo install -m 0755 weglarka-$VER-x86_64-unknown-linux-musl/{weglarka,weglarka-daemon} /usr/local/bin/
```

## Quadlet and start

The `ghcr.io/jpalczewski/weglarka` image is public (pulling needs no `podman login`).
The `:latest` tag only exists from the first `v*` tag; before that use `--image ghcr.io/jpalczewski/weglarka:main`.

```sh
sudo -iu weglarka
export XDG_RUNTIME_DIR=/run/user/$(id -u) DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u)/bus

weglarka-daemon --config /etc/weglarka/weglarka.toml platform install --dry-run   # preview the files
weglarka-daemon --config /etc/weglarka/weglarka.toml platform install \
  --image ghcr.io/jpalczewski/weglarka:latest                                     # write + daemon-reload
systemctl --user start weglarka.service
systemctl --user status weglarka.service
podman logs weglarka                                                              # JSON, no secrets
```

The generated quadlet (example for `weglarka`, UID 1004) is hardened: read-only root FS (`ReadOnly=true`,
`Tmpfs=/tmp`), `DropCapability=ALL`, `NoNewPrivileges=true`, a memory limit (`PodmanArgs=--memory=128M --memory-swap=128M`)
and `PidsLimit=256`:

```ini
[Container]
Image=ghcr.io/jpalczewski/weglarka:latest
ContainerName=weglarka
Network=net-weglarka.network
Volume=/run/user/1004/podman/podman.sock:/run/user/1004/podman/podman.sock
Volume=/var/lib/weglarka:/var/lib/weglarka
Volume=/etc/weglarka/weglarka.toml:/etc/weglarka/weglarka.toml:ro
Environment=RUST_LOG=info
Environment=WEGLARKA_PODMAN_SOCKET=/run/user/1004/podman/podman.sock
ReadOnly=true
Tmpfs=/tmp
DropCapability=ALL
NoNewPrivileges=true
PodmanArgs=--memory=128M --memory-swap=128M
PidsLimit=256
Exec=run --config /etc/weglarka/weglarka.toml
```

(The full file: `platform install --dry-run`; the same options as `podman run` arguments: `platform run-args`.)

The quadlet has `WantedBy=default.target` — with linger the service comes up after a host reboot. On startup the
daemon creates the `net-weglarka` network, pulls and starts the `weglarka-nginx` container on `bind`, and writes the
Traefik file. Updating Węglarka itself: automatic through the `weglarka-self-update.timer` timer, and a failed swap
is rolled back by the `weglarka-watchdog.timer` watchdog — see [Self-update](guides/self-update.md); manually:
`platform install --image <image>@<digest>` + `systemctl --user restart weglarka.service`.

### Verifying the image and binaries

```sh
cosign verify \
  --certificate-identity-regexp '^https://github.com/jpalczewski/weglarka/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/jpalczewski/weglarka:latest

# the same image, static key (exactly what Węglarka checks before a self-update, see the self-update guide):
cosign verify --key cosign.pub ghcr.io/jpalczewski/weglarka:latest

# SBOM (SPDX) – a cosign attestation:
cosign verify-attestation --type spdxjson <as above> ghcr.io/jpalczewski/weglarka:latest | jq -r .payload | base64 -d | jq .predicate | head

# SHA256SUMS from the release:
cosign verify-blob --bundle SHA256SUMS.sigstore.json <identity flags as above> SHA256SUMS
```

Each `v*` release also publishes the admin panel image, `ghcr.io/jpalczewski/weglarka-panel`, at the same version
tag (and `:latest`). It is an ordinary app image, not part of the daemon install: nothing above needs it, and it is
signed and attested the same way, so the commands above verify it with the image name swapped.

## CLI from a laptop

The admin socket is 0600 and owned by `weglarka`, so the tunnel is set up as that user (or root). Example for macOS:

```sh
# CLI (aarch64-apple-darwin) from the same release page, check the sum against SHA256SUMS
mkdir -p ~/.weglarka
ssh -N -o StreamLocalBindUnlink=yes \
  -L ~/.weglarka/admin.sock:/var/lib/weglarka/run/admin.sock weglarka@myhost &

export WEGLARKA_SOCKET=~/.weglarka/admin.sock
weglarka status
weglarka doctor            # self-diagnosis through the API (--json for machines)
```

## Acceptance test

`scripts/acceptance.sh` tests the whole chain on a real host: preflight and `doctor`, a `traefik/whoami` canary on a
test domain (Traefik → nginx → container, TLS), the GitHub webhook (202/401/204) and cleanup. **In `edge` mode** the
script detects the mode from `weglarka.toml` (or `--edge`), builds a test certificate for the canary domain in
`<nginx_conf_dir>/tls` itself, waits for the nginx reload, and checks traffic over `https` on the port from
`[ingress] https_bind`, the redirect on the HTTP port and the ACME webroot (`/.well-known/acme-challenge/`);
`--direct` is rejected then. Run it **after installation** and **after every Węglarka update** (before you touch a
real app), as the runtime user:

```sh
sudo -iu weglarka env XDG_RUNTIME_DIR=/run/user/$(id -u weglarka) \
  scripts/acceptance.sh --canary-domain wg-test.example.com
```

Requirement: the canary domain is in DNS (points at the host) **and on the validator allowlist** (the publish-validator
policy) — without that Traefik gets no router and the "traffic" step ends in a timeout.
The script only touches the `wg-canary` instance (by default), `wg-webhook`/`wg-rollback` (with
`--with-local-registry`), `wg-volume`/`wg-nostart` (with `--with-volume`) and the `wg-accept-registry` container —
never `ntfy`. Options: `--canary-image`, `--webhook-base`, `--keep` (the canary stays), `--skip-preflight`,
`--strict` (a `doctor` warn is an error), `--cert-timeout`, `--json` (machine report on stdout),
`--direct http://127.0.0.1:8088` (traffic straight to nginx, no Traefik/TLS — used by CI). Exit code ≠ 0 on any FAIL;
`ACCEPTANCE_VERBOSE=1` shows the log of successful steps too. Requires `weglarka`, `curl`, `openssl`, `jq`, `podman`.
The optional `--with-volume` (also in CI; needs `tar`) adds two volume steps: on the `wg-volume` instance, import of
a foreign tar, data and the UID range surviving `apps remove` + `apps add`, export with the owner `uid_range.start`,
`--purge-volumes`; on the `wg-nostart` instance, an app added with `start = false` (no container), import before the
first `apps start`, export with a content check.

**The webhook on the host** checks the protocol (a valid signature → 202 for the canary image — the deploy ends
`Unchanged`, a bad signature → 401, `ping` → 204, a foreign tag → 204). The **full rollback test** (exit code 6, return
to the previous digest) and the webhook with a real deploy and a duplicate delivery run in CI (`smoke-behind`);
on the host they are optional (`--with-local-registry`) — they need a temporary registry on `127.0.0.1:15099` and a
`[[registry]] location = "127.0.0.1:15099" insecure = true` entry in the user's `registries.conf` **before** the
Podman service starts (it reads the file at startup). The script configures nothing itself; without the entry the
deploy ends in a FAIL with a hint. Not recommended in production.

Note: `apps remove` **keeps** the canary's secrets in `secrets.toml` by default (`webhook-hmac`); the script cleans
them up in its "cleanup" step with `--purge-secrets`, so no orphaned entries are left after a run (and `doctor` does
not report them in `state.orphan_secrets`). Cleaning up after the fact: [Secrets cleanup](guides/secrets-cleanup.md).

## Next steps

- [Your first app: ntfy.zig](guides/first-app.md) — add an app, set its secret, switch over from Coolify.
- [Guide index](guides/README.md) — all guides: volumes, webhooks, host ports, edge mode and ACME, self-update,
  notifications, verification and rollback, ...
