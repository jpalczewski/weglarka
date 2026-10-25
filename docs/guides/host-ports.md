# Host ports (host_ports)

Some services must be reachable on a **fixed TCP port of the host**, alongside their HTTPS page behind the ingress. A typical case is a git server whose SSH has to stay on a well-known number (e.g. `2222` → port `22` in the container), because that number lives in `git remote` and in the router's port forwarding, while the UI still goes through the ingress by domain. Decision and rejected alternatives: [ADR 0013](../decisions/0013-host-ports.md).

```toml
# apps.toml / --spec: git.example.com over HTTPS via the ingress + SSH on a host port
image = "ghcr.io/example/git-server:latest"
domains = ["git.example.com"]
port = 3000
# 127.0.0.1:2222 → 22 in the container (without `ip` = loopback only):
host_ports = [{ host = 2222, container = 22 }]
# public, only after a UFW rule:
# host_ports = [{ host = 2222, container = 22, ip = "0.0.0.0" }]
```

Apply it with `weglarka apps add git --spec git.toml` (or `apps update git --spec git.toml`); a ready-made file: [`docs/examples/host-ports.toml`](../examples/host-ports.toml). The same through `apps add` / `apps update` flags: `--host-port 2222:22` (no IP = loopback), `--host-port 0.0.0.0:2222:22`, `--host-port none` clears the list. The flag, like `--volume`, is mutually exclusive with `--spec`; the rest of the spec (image, domains, limits) stays on the usual flags or in the file.

- `host` is the port on the host, `container` the port in the container, `ip` an optional listen address. **Without `ip` the port listens on `127.0.0.1` only**: from the host, through an SSH tunnel or a local proxy. Exposing it to the world requires an explicit `ip = "0.0.0.0"` (or `::`, or the address of a specific interface). This is deliberate, so that the new field never exposes a service by accident.
- **TCP only.** No UDP, TLS or PROXY protocol: this is a plain Podman port mapping (`ContainerSpec.publish`), not a proxy.
- **The ingress is bypassed entirely:** no nginx/Traefik router, certificate, access log or routing by domain. The only "door" is the host firewall. The UFW rule is added by your host provisioning (e.g. an Ansible role); **Węglarka does not change the firewall** (it runs rootless). A port without a rule is unreachable from outside even though it works locally: do not assume that "`curl` works from the host" means it works from the internet.
- `host_ports` **is part of the `spec-hash`**: changing `host`, `container` or the exposed address recreates the container (a short interruption; health gate and rollback as with any recreate). An empty/unset list hashes as before, so upgrading Węglarka recreates nothing. Writing `ip = "127.0.0.1"` instead of omitting `ip` gives the same hash (entry order does not matter either), so an explicit loopback does not recreate the container.
- `apps update --spec` replaces the **whole** spec, so a file without `host_ports` silently removes the entries, like any other field.
- An app with `start = false` ([stopped apps](stopped-apps.md)) publishes nothing (there is no container, so nobody listens), but the entries stay in the spec and in conflict validation, reserved like domains.
- **Validation:** `host` and `container` must be non-zero, `ip` must be an IP literal, and no two entries of the same app may use the same socket; there must also be no collision between apps or with `[ingress] bind` (an address of `0.0.0.0`/`::` collides with every other address on that port). The daemon rejects such a spec on `apps add`/`apps update` (HTTP 400, `invalid_request`), and an `apps.toml` with a collision does not load at startup; the message names the app and the port.
- **Ports < 1024** (e.g. `22` itself): rootless Podman binds them only if the host has `net.ipv4.ip_unprivileged_port_start=0`, and Węglarka additionally requires `[runtime] allow_privileged_host_ports = true` (see [host configuration](../install.md#host-configuration); default `false`). Without it the spec is rejected immediately instead of failing when the container starts.
- Check before adding: `weglarka doctor --preflight`. `apps.host_ports_free` reads the local `apps.toml`, validates the declaration (collisions, ports < 1024 without the opt-in) and shows ports taken by a foreign process. After the deploy: `podman port <instance>` or `ss -lnt | grep 2222`.

**Security note:** a published port bypasses the whole ingress: there is no TLS, access log, routing by domain or any Węglarka layer. Authorization (SSH keys, application tokens) is done by the service itself, and access is limited only by the host firewall. Expose only what really has to be public, and start with loopback until you have a UFW rule.

## Rollback

`host_ports` is a new field in `apps.toml`, and `[runtime] allow_privileged_host_ports` is a new field in `weglarka.toml`; both files have `deny_unknown_fields`, so an **older daemon** cannot read them. Before going back to an earlier Węglarka version, remove the `host_ports` entries from the apps and that flag from the config, otherwise the daemon refuses to start with a parse error.
