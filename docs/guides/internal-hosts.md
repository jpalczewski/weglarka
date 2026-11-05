# Reaching your own domains from apps

An app often calls another service this host serves: OIDC discovery and token exchange from an app to the identity
provider, an API call to a domain of another app, a package webhook back to Węglarka. Resolving such a domain the
normal way does not work from inside a rootless container: the host's public IPv4 is not reachable from the
container's own network namespace, so the connection is refused.

`internal_hosts` gives an app a supported way to reach these domains. Węglarka maps each one through Podman's
**`host-gateway`**: the container's `/etc/hosts` gets `169.254.1.2 <domain>`, and a connection to it reaches the
ports the ingress publishes on the host. Internal calls then take the same path as visitors: the port forwarder,
the ingress, TLS with the domain's real certificate. Decision and rejected alternatives:
[ADR 0071](../decisions/0071-internal-hosts-host-gateway.md).

## Configuration

```toml
[apps.git]
image = "codeberg.org/forgejo/forgejo:14"
domains = ["git.example.org"]
port = 3000
# Domains this host serves that the app must resolve anyway.
internal_hosts = ["auth.example.org", "hooks.example.org"]

[apps.auth]
image = "authelia/authelia:4"
domains = ["auth.example.org"]
port = 9091
```

`apps apply` (or the next reconcile pass) recreates exactly the apps whose list changed — the entry is written when
the container is created. Add or remove a domain with `apps update` through the admin API, or edit `apps.toml` and
run `weglarka apply`.

## Rules

- **Only domains this host serves.** Each entry must be a `domains` value of some app in the same `apps.toml`, the
  `[webhook] domain` from `weglarka.toml`, or the host of the `[identity]` issuer. It is not a hosts-file override: a
  typo, a duplicate, or a third-party domain is refused, at startup and on every write, with a message naming the
  offending app and domain.
- **Syntax:** a DNS name (`[a-z0-9-]` labels, at least two labels, no numeric last label), the same check the ingress
  applies to `domains`.
- **The list is part of the container's identity.** Changing it recreates the app once (a short restart, like any
  spec change); an app that does not set the field is untouched by an upgrade.

## Requirements

- **IPv4 only.** Podman hands pasta a `--map-guest-addr 169.254.1.2` and no IPv6 equivalent, so a dual-stack bridge
  still resolves only the IPv4 address. Domains are reached over IPv4.
- **The listener must publish on every address or the host's public IPv4.** In `edge`, `[ingress] https_bind` must be
  `0.0.0.0:443` (or the host's public IPv4). A `127.0.0.1` publish and an IPv6-only one are not the host from inside a
  container, and the connection is refused. In `behind`, Traefik must publish the same way.
- **Certificates as usual.** In `edge` the internal call is terminated by nginx with the domain's certificate pair, so
  the domain needs `<domain>.crt|key` (or a wildcard covering it, or `[acme]`) exactly like a visitor's request.
- **`host_containers_internal_ip` in the Podman user's `containers.conf`.** Unset is the measured default
  (`169.254.1.2`). A custom value is written into `/etc/hosts` unchecked, and `"none"` makes the container **fail to
  start** (`unable to replace "host-gateway" of host entry …`). The entry is resolved at every container **start**
  using the configuration of the process that starts it, so a later change breaks the app at its next restart, not at
  `apply`. Leave the setting alone or set it to an address the host really has.

## Client address in `edge`

All internal calls arrive at nginx from `169.254.1.2`, the same address for every app (see
[access log](access-log.md)). Consequences:

- The address is never trusted for `X-Forwarded-*` and no generator emits a per-address `allow`/`deny` or
  `limit_req`, so nothing breaks today.
- If you add such a rule yourself, remember that it applies to every app's internal calls at once and cannot tell
  them apart.
- In `behind` the internal call arrives from whatever address Traefik publishes on, not from `169.254.1.2`.

## Migrating from a `base_hosts_file` workaround

A common workaround maps the domains to `172.17.0.1` (Docker's `docker0` bridge) through a host-side file in the
Podman user's `containers.conf`. It works only while Docker is installed and nothing reports when it stops working.
To replace it:

1. Remove the entries (or the whole `base_hosts_file` setting) from the Podman user's `containers.conf`.
2. Set `internal_hosts` on the app that makes the calls, as above.
3. Run `weglarka apply`. The app is recreated once with the `host-gateway` entries; nothing else changes.
4. Run `weglarka doctor` and look at `ingress.internal_hosts`.

## Doctor

`ingress.internal_hosts` is a **static** check — it spawns no container and makes no connection:

- nothing is listed when no app uses the field;
- a warning when `https_bind` is loopback or IPv6-only (the route is IPv4 and the host publishes elsewhere);
- a warning in `edge` for a listed domain without a certificate pair, with the same lookup as `ingress.tls`;
- `ok` otherwise, naming which apps resolve which domains and, in `edge`, that the calls arrive from `169.254.1.2`.

An active probe (a throwaway container that connects through the route) is not implemented yet; until then a broken
route shows up as a refused connection in the app's own logs.

## Rollback

`internal_hosts` is a state-file schema change (version 19): `apps.toml` and `state.toml` get
`schema_version = 19` on the first write after the update. Before a downgrade remove `internal_hosts` from every app
or restore the files **from a backup taken before the update** (see [state schema](state-schema.md)). After removing
the field, run `weglarka apply`: the apps are recreated once more without the `/etc/hosts` entries. See
[verification and rollback](verify-and-rollback.md).
