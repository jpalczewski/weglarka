# 0071 — Apps reach their own domains through Podman's host-gateway (internal_hosts)

Status: proposed (2026-11-05, issue #303)

## Problem

In `edge` mode an app cannot reach a domain this host serves by resolving it normally: the host's
public IPv4 is not reachable from inside a rootless container (pasta gives the container its own
address, so connecting to the host's public IP is refused). The real cases are OIDC discovery and
token exchange (Forgejo → the identity provider) and API calls to a domain of another app on the
same host.

Operators work around it from outside Węglarka: a `base_hosts_file` in the runtime user's
`containers.conf` mapping the domains to `172.17.0.1` — the address of Docker's `docker0` bridge.
That works only while Docker is installed. Removing Docker deletes the address, the apps lose OIDC
and webhooks, and nothing in Węglarka reports it. The address is borrowed from another tool; the
feature needs one Węglarka owns and explains.

Measured on rootless Podman 6.1.3 (netavark 2.1.0, pasta, aardvark-dns):

| Target from inside an app | user bridge | default pasta |
|---|---|---|
| host's public IP | refused | refused |
| `<domain>` → `host-gateway` (`169.254.1.2`) | works | works |

`hostadd: ["<domain>:host-gateway"]` on `POST /libpod/containers/create` behaves like
`podman run --add-host`: Podman writes `169.254.1.2 <domain>` into the container's `/etc/hosts`,
and the connection reaches the ports the edge forwarder publishes on the host. The entry is fixed at
create and resolved at every **start** (Podman rewrites `/etc/hosts` from the running process's
`containers.conf`).

## Decision

A new optional `AppSpec` field `internal_hosts: Vec<String>`: domains this host serves that the app
needs to resolve, turned into `ContainerSpec::host_aliases` → `CreateContainer.hostadd` as
`<domain>:host-gateway`.

Invariants:

- **Only domains this host serves.** Every entry must be a `domains` entry of some app in the same
  `apps.toml`, the `[webhook] domain`, or the `[identity]` issuer host. It is not a general
  hosts-file override: a typo, a duplicate, or an arbitrary third-party domain is refused with an
  error, not silently honoured.
- **Part of `spec_hash` only when set.** The entry is fixed at container create, so a change must
  recreate the app; an app that does not use the field hashes exactly as before, so upgrading
  recreates nothing.
- **`schema_version` bump** (`state::SCHEMA_VERSION` + a no-op `SCHEMA_STEPS` entry, ADR 0023) and
  the matching guide entry: `apps.toml` has `deny_unknown_fields`, so a rollback to an older daemon
  needs the field removed (or the files restored from a backup).
- **The field is mode-agnostic.** It works in `behind` too (Traefik publishes on the host as well);
  only `edge` is tested.

## Consequences

- **The route is IPv4 only.** Podman passes pasta `--map-guest-addr 169.254.1.2` (v4); a dual-stack
  bridge gets no v6 host-gateway. It works only when the listener publishes on `0.0.0.0` or the
  host's public IPv4 — anything bound to `127.0.0.1` or an IPv6-only socket is refused.
- **`host_containers_internal_ip` in `containers.conf` decides the address.** Unset is the measured
  `169.254.1.2`; a custom value is written in unchecked (a wrong one breaks the connection), and
  `none` makes the container **fail to start** (`unable to replace "host-gateway" of host entry …`).
  Because the entry is resolved at every start, changing the setting later breaks apps at their next
  restart, not at `apply`.
- **In `edge` internal calls arrive from `169.254.1.2`.** All of them share that peer address: a
  per-IP limit or an address-based `allow`/`deny` in front of the ingress applies to all apps at
  once. Today no generator emits such rules, and the address is never trusted for `X-Forwarded-*`.
- **`doctor` warns statically** (`ingress.internal_hosts`): no warning when the field is unused, a
  warning when `https_bind` is loopback or IPv6-only, and for a listed domain without a certificate
  pair in `edge`. Nothing is spawned; an active probe is a separate task.
- Operators migrate off a `base_hosts_file` workaround by removing its entries and setting
  `internal_hosts`, which recreates exactly those apps once.
- Tests: the create-body snapshot and a unit test for the wire shape, an engine test that the field
  reaches `ContainerSpec` and only set values change the hash, validation tests, and a real-Podman
  test that `/etc/hosts` contains `169.254.1.2 <domain>`.

## Rejected alternatives

- **Network aliases on the nginx container.** nginx would have to listen on 443 inside its
  container: it runs with `cap_drop: ALL`, so that needs `--sysctl net.ipv4.ip_unprivileged_port_start=0`,
  an ingress-hash bump and one nginx recreate. Aliases are fixed when a network is connected, so
  changing them means disconnecting and reconnecting nginx — a short outage for that app. It also
  bypasses the forwarder, so internal calls would not take the same path as visitors (no PROXY
  protocol, different client address, different TLS termination).
- **A host-side `base_hosts_file` shipped by Węglarka.** It is invisible in `apps.toml`, applies to
  every container on the host (including ones Węglarka does not manage), needs the containers
  recreated after a change, and still hard-codes an address Węglarka does not own.
- **A `172.17.0.1`-style bridge address.** Borrowed from another tool's bridge: it exists only while
  that tool is installed, which is exactly the invisible dependency this issue reports.
- **Mapping the domain to the ingress container's address.** That would require the app to share a
  network with the ingress (every app on one network, or a network pair per app), and it skips TLS
  and the forwarder.
