# 0059 — Per-address rate limit on panel login callbacks

Status: accepted (2026-10-30, issue #308).

## Problem

`PendingLogins::open` (ADR 0057, #292) records the `state` of every genuine login cookie that reaches
`/auth/callback` in a bounded "used" set, before the identity provider has accepted anything. An anonymous client can
start logins for free (`GET /auth/login` stores nothing) and send fake callbacks, filling the set (4096 entries,
10-minute TTL). Every entry has the same TTL, so the entry nearest expiry is the oldest cookie, which may be a real
user's still-pending login: it is evicted and could then be replayed. Refusing when the set is full would recreate the
lockout that #292 removed.

## Decision

- The callback handler applies a **sliding-window limit per client address** (20 callbacks per 60 s) *before* calling
  `PendingLogins::open`. A refused request gets `429`, records nothing, and does not extend its own lockout (only
  admitted attempts are counted). One address can therefore write at most 20 entries a minute, not enough to push out
  other users' entries.
- The limiter keeps at most 4096 addresses; idle ones are swept when the table is full, and the least recently active
  one is dropped if all are live. IPv6 addresses share a bucket per /64.
- **Client address:** the connection's peer, except when the peer is in `PANEL_TRUSTED_PROXIES` (comma-separated
  addresses or CIDR ranges, default empty). Then `X-Forwarded-For` is read from the right, skipping trusted hops; the
  first other entry is the client. The left-most entry is never used, because a client can write it. An unparsable
  entry makes the panel fall back to the peer. With no trusted proxy configured the header is ignored. That includes
  `edge` mode, where Węglarka's nginx does sit in front of the panel (and sets `X-Forwarded-For` from the real client
  address) but the panel only sees nginx's address until nginx is listed in `PANEL_TRUSTED_PROXIES`.
- The panel serves with `into_make_service_with_connect_info` to see the peer address.

## Consequences

- The panel's configuration is env-only, so there is **no** `apps.toml`/`state.toml` field, no `SCHEMA_VERSION` bump and
  no `spec_hash` change. `PANEL_TRUSTED_PROXIES` is an ordinary entry in the panel app's `env`.
- Operators running the panel behind a proxy (Traefik in `behind` mode, Węglarka's nginx in `edge` mode) should set
  `PANEL_TRUSTED_PROXIES` to the proxy's network; otherwise every client shares the proxy's address and therefore one
  bucket (safe, but 20 sign-ins a minute for everybody together). Documented in `docs/guides/admin-panel.md`.
- A user behind a shared address (NAT, office) shares the budget; a person needs one callback per sign-in.

## Rejected alternatives

- **Refuse new entries when the set is full:** an attacker locks everybody out of signing in (#292 again).
- **Open the cookie only after the provider accepted the code:** the code exchange needs the PKCE verifier from the
  cookie, and single use has to be decided before the exchange, or a replay reaches the provider.
- **Trust the left-most `X-Forwarded-For` value or any peer's header:** the client controls it, so the limit could be
  dodged by rotating the value or aimed at an innocent address.
- **A global (not per-address) limit:** the attacker would exhaust it and lock out logins, same as refusing when full.
