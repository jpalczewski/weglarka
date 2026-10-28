# 0056 — Admin API beyond the unix socket: a token listener

Status: accepted (2026-10-29, issues #43 and #92). Builds on ADR 0051 (identity provider) and ADR 0054 (the probe
socket). `GET /v1/health` and the full-trust socket keep the behaviour ADR 0034 relies on.

## Problem

The admin API is a unix socket reached over an SSH tunnel: whoever can open it is root of trust, with no identity, no
scopes and no audit trail. The next clients (the admin panel, `weglarka login` in #93, a restricted client for AI agents
in #94) are people and programs that must authenticate with the identity provider, hold less than full power, and in
the panel's case run inside a container on the same host.

Threats the design has to answer, in priority order:

- **A stolen or replayed token.** It must be short-lived, bound to one audience, and scoped; nothing in it may be
  trusted before its signature is checked against the provider's keys.
- **A compromised front end.** The component that accepts the network connection (a panel today, a gateway in #200
  later) must not be able to promote itself to `admin`.
- **A second, unauthenticated route to the API.** The break-glass socket must stay exactly as powerful and exactly as
  hard to reach as it is; the new listener must never offer more than it does.
- **A client that grants itself access.** Reaching the API must be a host decision, not an app's.
- **A provider outage that locks the operator out.** The socket must keep working with no provider at all.

Constraints: security first, then one implementation for both listeners (traits and adapters, not copies), then RAM.

## Decision

1. **Two listeners, never merged.** The **full-trust** unix socket (`admin.socket`, `0700`/`0600`, no token) is
   unchanged and stays the break-glass path. The **token listener** is a second unix socket that answers every request
   except `GET /v1/health` only with a valid bearer token. Both serve the same route table (`admin::api_routes`); the
   token listener wraps it in an authentication layer, so it can never have an endpoint the socket lacks.
2. **Where it listens: a unix socket in its own directory**, `<state dir>/run/admin-token/api.sock`, bind-mounted
   read-only into the instances named by `[admin.http] clients` at `/run/weglarka-admin/` and into nothing else. The
   opt-in is host config (`weglarka.toml`), not an `AppSpec` field, so an app cannot grant itself the API. The public
   ingress never routes it. This is isolation by mounts (ADR 0043, ADR 0054), with no new Podman network and no TCP
   surface for whatever else joins one.
   - The directory is `0711` and the socket `0666`: the clients are containers whose uids map into other host uids, so a
     `0700`/`0600` socket would be unreachable for them. This is safe only because the socket is not the access control:
     every request carries a token the daemon verifies. The mount decides who is *given a path*, the token decides who
     is *let in*. A local host user who finds the socket gets a `401` like anyone else.
   - A read-only bind is enough: `connect(2)` on a unix socket writes nothing to its filesystem.
3. **TLS: none.** It is a local socket. Exposing the API beyond the host (a TCP listener, routing through the ingress)
   is a later ADR; the verification below does not depend on the transport.
4. **The daemon verifies every token itself; the transport is replaceable.** Authentication and authorization live in
   the daemon core (`weglarka_model::admin_auth` plus the layer in `weglarka-daemon`), never in whatever accepts the
   connection. A future gateway process (#200) may take the network-facing HTTP and forward the request **with its bearer
   token unchanged** to the token socket; the daemon still verifies, so a compromised gateway cannot promote itself. The
   gateway only ever gets a path to the token socket, never the full-trust one.
5. **Token format: JWT access tokens (RFC 9068), verified statelessly.**
   - Header: `alg` is `RS256` or `ES256` and must match the type of the key the `kid` selects (never `none`, never
     HMAC, never a key-type confusion); `typ` is `at+jwt`; `kid` is required.
   - Claims: `iss` equals `[identity] issuer`, `aud` contains `[admin.http] audience` byte for byte, `exp` is required,
     `nbf` is honoured, with 60 s of leeway; `sub` is required and is what the audit log records.
   - Keys come from the provider's `jwks.json`. The daemon shares no network with the provider, so it fetches the JWKS
     over the **ingress probe socket** (ADR 0054) with the issuer's host as `Host`, the way nginx would route a client
     minus TLS and forward auth. The set is cached (a few keys); an unknown `kid` triggers a refetch, rate limited to
     one attempt per 30 s (failures count), and a set older than an hour is refetched even for a known `kid`, so a
     withdrawn key stops verifying. A failed fetch keeps the old keys: a provider that blips does not lock operators out.
   - Lifetime: tokens are short (Authelia `lifespans.access_token`, at most 15 minutes), because a JWT cannot be revoked
     mid-life. **Introspection** (`/api/oidc/introspection`) would give real revocation at the price of a provider call
     per request and a daemon client; it is the documented fallback if revocation ever matters more than that dependency.
   - **Not yet verified against a real provider:** that Authelia stamps `typ: at+jwt` on its JWT access tokens. The check
     follows RFC 9068, and a mismatch would show as every token refused with `typ is not at+jwt` in the daemon log. The
     first real deployment must confirm it, and this line comes out when it has.
6. **Groups become scopes.** There are two scopes, `read` and `admin` (`admin` includes `read`). The client's claims
   policy puts the `groups` claim into the access token (`groups_in_access_token`, ADR 0051); `[admin.http] read_groups`
   and `admin_groups` map groups to scopes. A token whose groups map to nothing is refused. There are no custom provider
   scopes to keep in sync.
7. **Every endpoint declares its scope.** `weglarka_api::Endpoint` carries `scope: Option<Scope>` (`None` only for
   `GET /v1/health`, the readiness probe the host watchdog uses). Reads are `read`; every mutation is `admin`, as is
   everything that exports data, returns a credential or runs code (`volumes export`/`import`, `run`, `forward`, `push`, and the OIDC client list, whose entries carry secret digests). The layer looks the
   endpoint up by method and matched route template and **fails closed**: a route that is not in `ENDPOINTS` is refused
   even to an admin. Tests assert that every declared endpoint is routed, that only health is open, and that mutations
   need `admin`.
8. **Audit.** Every mutation made through the token listener logs `sub`, method, route template and the response
   status at `info`; every refusal logs at `warn` with the reason. No token, no part of one, and no claim other than `sub`
   is ever logged.
9. **The panel is a confidential client with a backend (BFF).** Tokens stay server-side and the browser gets an
   httpOnly session cookie; a public SPA client would keep bearer tokens in the browser. The panel's `client_secret` is
   the one minted by #213 (ADR 0051).
10. **The panel is behind forward auth *and* OIDC, deliberately.** What it buys: the UI is unreachable without a
    provider session even if the panel's own login has a bug. What it costs: two redirects on the first visit, and the
    panel's `health.http` path in `auth_exempt_paths` (ADR 0052).

Invariants for implementers: the full-trust socket is never given a token check and never loses an endpoint; the token
listener never has a route the socket lacks; `[admin.http]` is host policy and never an `AppSpec` field; the mount enters
`spec_hash` **only** for the listed clients (`spec_hash_with_admin_token`), so an upgrade recreates nothing else.

## Consequences

- **`weglarka.toml`** gains `[admin.http]` (`clients`, `audience`, `read_groups`, `admin_groups`); it needs `[identity]`.
  It is outside the schema-versioned files, so it needs no `schema_version` bump, but `deny_unknown_fields` means an
  older daemon refuses to start while it is present: remove it before downgrading
  ([admin API tokens](../guides/admin-api-tokens.md), [verify and rollback](../guides/verify-and-rollback.md)).
- **API contract:** `Endpoint` gains `scope`, `ErrorCode` gains `unauthorized` (401) and `forbidden` (403); both are
  additive, and the unix socket never returns them.
- **Clients:** each instance in `clients` is recreated once when `[admin.http]` is first enabled, to gain the mount.
  `doctor` reports `admin.http` (the socket, the clients, the provider's keys).
- **Refactors this needed:** one route table for both listeners; one raw-HTTP exchange over the probe socket instead of
  three hand-rolled reads (`health_probe::probe_get`); one socket binder and one server spawner.
- **Tests:** `weglarka_model::admin_auth` (signature, algorithm confusion, claims, leeway, groups, JWKS parsing),
  `daemon/tests/it/token_api.rs` (401/403/404, every declared endpoint, the socket staying open, doctor), the engine's
  mount and hash tests.
- **Out of scope:** `weglarka login` (#93), the restricted agent client (#94), exposing the API beyond the host.

## Rejected alternatives

- **Listening on the ingress (a routed domain).** It puts the admin surface on the public ingress, needs TLS and a
  protected route, and makes the provider a hard dependency for reaching the API at all. A unix socket reached through a
  mount keeps the attack surface off the network.
- **A TCP listener on a Podman network.** It exposes the API to every container that joins the network and needs a
  daemon-side network join the daemon does not have.
- **Opaque tokens with introspection.** Real revocation, but a provider round trip per request and a client in the
  daemon; kept as the fallback in decision 5.
- **A bearer check in the connection acceptor (or in the gateway) only.** The acceptor is the component most exposed to
  the network; trusting it to authorize would make its compromise equal to an admin token. The daemon verifies.
- **Custom provider scopes for `read`/`admin`.** They would have to be kept in sync with the provider's config; groups
  already exist and already feed forward auth.
- **One router with a "trusted" flag on the socket.** A single flag read per request is a single bug away from
  authenticating nothing; two listeners over one route table make "the socket has no check" a property of the listener.
- **A public SPA client for the panel.** Bearer tokens would live in the browser.
