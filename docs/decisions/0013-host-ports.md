# 0013 — `host_ports`: publishing app container ports directly on the host

Status: accepted (2026-10-24, issue #34).

## Problem

Everything Węglarka exposes today goes through the ingress: nginx (behind Traefik in the default `behind`
mode) proxies HTTP by domain to the app's `port`, and the only host TCP socket Węglarka opens is
`[ingress] bind` (0005, 0007). Some services also need a **raw TCP port on the host, at a fixed number**, next
to their HTTPS site. The motivating case is a self-hosted git server (Forgejo-style): SSH has to stay on a known
host port (e.g. `2222`, forwarded to container port `22`) because that number is baked into `git remote` URLs and
into the router's port forwarding, while the web UI stays behind the ingress on a normal domain. SSH is not HTTP:
it cannot be routed by `Host()`, must not be terminated by nginx and needs no certificate.

Without a first-class field there are two bad paths: opening a TCP route through Traefik, which means
extending the root-owned validator policy (0005) with `tcp.routers` — a far larger and riskier surface than a
container port mapping — or running such services outside Węglarka, losing reconcile, auto-update and state.
A naive port mapping has its own trap: Podman publishes on `0.0.0.0` by default, so a careless spec would
expose a database or an admin panel to the internet (priority: security first).

## Decision

**A per-app `host_ports` list, as an array of tables** (the same shape as `volumes` and `resources`):

```toml
# Loopback by default: 127.0.0.1:2222 → container port 22. Add `ip = "0.0.0.0"` to expose it publicly.
host_ports = [{ host = 2222, container = 22 }]
```

`host` is the port on the host, `container` the port inside the app container, `ip` the optional bind
address. The field lives in `AppSpec` next to `port` and `volumes`, so it is available in `apps.toml` and in
`--spec` like every other spec field; `ip` is omitted (`skip_serializing_if`) when unset, like other optional
fields.

**The same publish path as the ingress nginx port.** `host_ports` entries become `ContainerSpec.publish`
(`PortMapping`: host address, host port, container port), which libpod receives as `portmappings` — exactly
the mechanism that publishes nginx's `[ingress] bind`. Deploy and recreate just map additional ports on the app
container: no new deployment path, no extra process, no second source of bindings. The ingress keeps routing
`domains`/`port` independently, so one container can be reachable through HTTPS and on a published port at the
same time.

**TCP only in v1.** The libpod wire (`weglarka-podman`) serializes `protocol: "tcp"` for every port mapping
(the nginx bind included). UDP would have to be carried end to end as a new field in the spec, the API and the
wire — an additive change for later, not a hidden `udp = true` flag now.

**Loopback by default: publishing is opt-in.** An omitted `ip` binds `127.0.0.1` (`HostPort::DEFAULT_IP`,
`HostPort::bind_ip()`), so a published port is reachable only from the host — through an SSH tunnel, a local
reverse proxy or a local client. Public exposure requires an explicit address (`ip = "0.0.0.0"`, `::` or a
specific interface address). The default is part of the decision, not a convenience: adding a field to a spec
must never open a service to the network by itself, and Podman's own default (`0.0.0.0`) is precisely the
failure mode to avoid.

**The ingress is bypassed entirely.** A published port has no TLS, no certificate, no nginx/Traefik router, no
routing by domain and no access log; `docs/install.md` says so next to the example. The host firewall is the
only gate, and it is owned **outside** Węglarka: the Ansible role `weglarka_host` manages UFW, while Węglarka
runs rootless (and `DropCapability=ALL` in the quadlet) and never edits firewall rules — an app spec must not
be able to open the host's firewall as a side effect. Closing the port is therefore an operator action in
Ansible, not `apps update`.

**Privileged ports (< 1024) are an explicit host opt-in.** Rootless Podman can only bind them when the host
has `net.ipv4.ip_unprivileged_port_start=0`; the precondition is host policy, not app intent. The host
declares it with `[runtime] allow_privileged_host_ports = true` in `weglarka.toml` (default `false`); without
it, validation rejects the spec with a message naming the app and the port, instead of letting the container
fail at start. The sysctl is still required — the flag only says "this host is prepared", it does not change
the kernel setting.

**Validation: structural per app, cross-app against the host.** The per-app rules (non-zero `host` and
`container`, a parseable IP literal, no two entries of the same app on the same socket) sit with the other
spec rules in `validate_app`. The rules that need the host live in `core::host_ports` and are checked when the
daemon writes a spec (`apps add` / `apps update`) and when it loads `apps.toml` at startup: privileged ports
without the opt-in, two apps on the same host port/bind address, and a collision with `[ingress] bind`. Two
bind addresses overlap when they are equal or when either is a wildcard (`0.0.0.0`/`::`): on Linux a wildcard
IPv4 bind also blocks a specific IPv6 one, and being conservative here costs only a clearer error. A bad spec is
rejected at the write (`apps add` / `apps update` → HTTP 400 `invalid_request`) and a conflicting `apps.toml`
refuses to load at daemon startup, naming the app and the port.

**`spec_hash`: part of the container, skipped while empty.** The list is appended to `HashInput` like
`volumes` and `security` (`HASH_FORMAT` stays v1): skipped while empty, so an app that does not use
`host_ports` hashes exactly as before and upgrading Węglarka recreates nothing. The hash stores the
**effective** address (loopback when `ip` is unset) and sorts the entries — spelling out `ip = "127.0.0.1"` or
reordering the list does not recreate the container, while changing `host`, `container` or the exposed
address does (a short interruption, with the health gate and rollback of a normal recreate).

**CLI: a repeatable flag next to `--volume`.** `--host-port [IP:]HOST:CONTAINER` on `apps add` and
`apps update` (e.g. `--host-port 2222:22`, `--host-port 0.0.0.0:2222:22`), omitted `IP` = loopback, `none`
clears the list — the same conventions as `--tmpfs`/`--cap-drop`. Like the other spec flags it conflicts with
`--spec`: either the flags or a complete `--spec` file, never both.

**`doctor --preflight`: `apps.host_ports_free`.** The check reads `apps.toml` locally (as
`ingress.traefik_sync` already reads the domains) and re-runs the same cross-app validation on it — privileged
ports without the opt-in, two apps on one socket, the ingress bind — then parses `/proc/net/tcp*` the way
`ingress.bind_free` does and reports published ports already held by another process (a socket of the runtime
user is Węglarka's own port forwarder, not a collision). Preflight runs in the CLI process, so this adds no admin
API surface.

## Consequences

- A published port is a host-level contract: DNS and the firewall rule (Ansible role `weglarka_host`) have to
  be prepared by the operator, and exposure is visible in `podman port <instance>` / `ss -lnt`. `doctor
  --preflight` catches a port that is already taken before the container fails to start.
- The field is optional and serialized only when set, so existing `apps.toml` files keep their shape and
  existing instances are not recreated by the upgrade. The first `apps add`/`apps update` that sets
  `host_ports` recreates that app's container once.
- An app with `start = false` (0011) publishes nothing — there is no container, hence no listener — but its
  `host_ports` stay in the spec and in the cross-app validation, like reserved domains: a stopped app cannot
  be silently duplicated by another one.
- Rollback: `apps.toml` and `weglarka.toml` use `deny_unknown_fields`, so an older daemon cannot read a file
  containing `host_ports` or `[runtime] allow_privileged_host_ports`. A downgrade requires removing those
  entries first; `apps update --spec` replaces the whole spec, so a file without `host_ports` drops them like
  any other field. Documented in `docs/install.md` (6c and the rollback section).
- Tests: unit tests for the structural rules (zero ports, invalid IP, a duplicate socket within one app), the
  cross-app module (two apps, wildcard overlap, the ingress bind, privileged ports with and without the
  opt-in), the hash (`host_ports_are_container_settings`: empty list unchanged, explicit loopback equal to the
  omitted `ip`, order irrelevant, a different exposed address recreates), deploy (a `FakePodman` scenario
  asserting the publish list), the CLI parser (`[IP:]HOST:CONTAINER`, `none`) and preflight on a fake
  `/proc/net/tcp`.

## Rejected alternatives

- **The string form proposed in the issue** (`"2222:22"`): it has no room for a bind address without
  inventing a third syntax, it would be parsed in several layers (CLI, API, TOML, libpod wire) instead of by
  serde, it is inconsistent with `volumes` (`{ name, target, read_only }`) and `resources`, and it cannot grow
  a field (protocol, future options) without a breaking syntax change. An array of tables is self-documenting,
  type-checked at parse time and extends additively.
- **A TCP route through Traefik** (`tcp.routers`): would require extending the root-owned validator policy
  (0005) with a protocol Węglarka does not need, and in `behind` mode the Traefik and its entrypoints belong to
  the host/Coolify — the port would still have to be opened on a Traefik entrypoint Węglarka does not control.
  A container port mapping is exactly the primitive this use case needs, with no extra component to run or
  supervise.
- **A host-global `publish` list in `weglarka.toml`**: detaches port mappings from the app lifecycle — reconcile
  and the spec hash would have to diff a global list, and `apps remove` would have to guess which entries
  belonged to the app. Ports belong to the container, so they belong to the spec.
- **Defaulting to `0.0.0.0`** (Podman's default): convenient in a quick test, but a spec written carelessly
  would expose an internal service to the internet. Exposure has to be a deliberate line in the file.
- **A per-app opt-in for privileged ports** instead of `[runtime]`: the blocker is a host sysctl, so an app
  flag would invite enabling it per app on an unprepared host — the flag would be accepted and then fail at
  container start, the failure mode validation exists to prevent.
- **Opening UFW rules automatically**: needs root, and it would let anyone who can write a spec change host
  firewall state. The firewall stays in the Ansible role; Węglarka reports, it does not manage it.
