# 0032 — Trust nginx's own addresses as the port forwarder's source

Status: proposed (2026-10-24)

## Problem

ADR 0007 (section 1) trusts the subnet(s) of `net-weglarka` for `X-Forwarded-*` and `real_ip`, assuming the rootless
port forwarder connects from there (observed once: nginx saw `10.89.1.2`). That held while nginx had a single
network. The forwarder opens a **new** connection from inside the nginx container's network namespace, so the
source address is whichever **nginx interface** the connection was routed through. Measured later on a host
where nginx also joined app networks: `$realip_remote_addr` was nginx's own address on an app network
(`10.89.2.6`, `net-<app>`), outside the trusted `net-weglarka` subnet. The mappings then overwrote
`X-Forwarded-Proto/Host/For` with nginx's own values (`$scheme` = `http`), and an app that validates the
scheme (OIDC issuer must be https) answered 400. Apps that never look at the scheme did not notice.

Trusting the whole Podman range (`10.89.0.0/16`) would fix it and is rejected: any app container could then
forge `X-Forwarded-*`, which is exactly what 0007 prevents.

## Decision

- Default trust = **the nginx container's own addresses** on all of its networks, as single-host entries
  (`a.b.c.d/32`, or `/128`). A connection whose source is one of nginx's own addresses can only come from a
  process inside nginx's netns — the forwarder. App containers connecting over `net-<app>` have other
  addresses and stay untrusted.
- The addresses come from `container_inspect` (`NetworkSettings.Networks.*.IPAddress` / `GlobalIPv6Address`,
  `ContainerInfo::addresses`), read on every `apply` (twice: before and after the container is brought in line); the generator is unchanged (it already accepts bare
  addresses) and still has no default of its own.
- They are not known before the container exists or joins a network, so the first rendering of a pass can be
  stale: on the first `apply` the `net-weglarka` subnet bootstraps the list (as in 0007, only the daemon and
  nginx live there). After `ensure_nginx` the addresses are read again and, if they moved, the same pass
  regenerates the config and reloads once more, so a config that trusts addresses nginx no longer owns (or
  lacks the new ones) is not left in place. If the re-read fails, `retry_soon` schedules another pass.
  Steady state is `Unchanged`.
- Addresses are **not** in `ingress_hash` (same reasoning as the network list in 0007: they change without
  the container's identity changing).
- `[ingress] trusted_proxies` still overrides the default entirely and stays static.
- The daemon's own address on `net-weglarka` is no longer trusted by default. Its health probe sends no
  `X-Forwarded-*` and is not redirected either way, so nothing changes for it.

## Consequences

- `ContainerInfo` gains `addresses` (additive; the libpod client fills it from inspect, `FakePodman`
  synthesizes `10.89.N.x` from network membership). No state file or `spec_hash` changes; rollback to an
  older daemon returns to the `net-weglarka` subnet default.
- A restart of the nginx container (Podman's restart policy) that changes its addresses is not seen until
  the next periodic `apply`; until then the old addresses stay trusted and the new ones are not. That
  window needs another container to take over a freed address *and* send forged headers, and ends at the
  next pass.
- Tests: daemon (`tests/ingress.rs`) — nginx on an app network, the app container's address and the
  networks themselves absent from the config, convergence to `Unchanged`; `libpod` inspect parsing;
  `.github/scripts/test-forwarded-headers.sh` — with real nginx, a `/32` entry trusts exactly that peer and
  not its neighbour in the same subnet. `scripts/acceptance.sh` already fails when `X-Forwarded-Proto: https`
  does not reach the canary through the forwarder; its message now points here.

## Rejected alternatives

- **Trust `10.89.0.0/16` or every app network**: lets app containers forge `X-Forwarded-*` (see Problem).
- **Detect the forwarder in nginx** (`$realip_remote_addr` equal to `$server_addr` via a regex `map`): needs no
  inspect and no second pass, but rests on the forwarder dialling nginx's own address, which was not
  verified against rootlesskit's dialer; `set_real_ip_from` would still need static entries for the real
  client address in logs. Left as a possible follow-up.
- **Pin the address by hand** in `trusted_proxies`: still supported, but breaks when nginx is recreated or
  joins a network.
