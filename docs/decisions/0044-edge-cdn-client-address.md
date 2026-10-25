# 0044 — Edge mode behind a CDN: trusting the visitor header of a CDN peer

Status: accepted (2026-10-25, issue #159). The generated config is covered by snapshots; the combination with a real Cloudflare zone is to be confirmed on a host (see the issue's measurements).

## Problem

`edge` (ADR 0036) trusts nobody for `X-Forwarded-*` and, since ADR 0043, `$remote_addr` is the real peer of the
port forwarder. For a hostname that sits behind a CDN's proxy that peer is a CDN edge address, so apps see the
CDN as every client: per-IP rate limits and visitor statistics lose their meaning. The visitor is in a provider
header (`CF-Connecting-IP` for Cloudflare). Trusting that header from anyone would let any client forge its
address, so the trust has to be tied to the peer.

## Decision

**A peer inside the CDN's published ranges speaks for its visitor; every other peer is its own client.**

* `[ingress.cdn]` (`edge` only; `behind` rejects it): `provider = "cloudflare"` (the only provider for now; it
  names the header and the bundled range list) and an optional `ranges = [...]` pin that replaces the list.
* nginx's realip module takes one `real_ip_header` per context (it is already used for `proxy_protocol`), so the
  CDN step is a `geo $remote_addr $weglarka_cdn` plus a `map "$weglarka_cdn:$http_cf_connecting_ip"
  $weglarka_client`, the shape `behind` uses for `$weglarka_trusted`. `$weglarka_client` is the header value for
  a CDN peer **whose header is a plausible IP literal**, else `$remote_addr`; it never is empty.
* `X-Forwarded-For` of the peer is never read (a CDN appends to it, so its prefix is client-controlled). The
  client address goes to `X-Forwarded-For`, `X-Real-IP` and the access log (`remote_addr`); the CDN edge address
  stays in the log as `peer`. `X-Forwarded-Proto` stays `$scheme`.
* No per-domain switch: trust is a property of the peer. A non-proxied domain reached through somebody else's
  zone is still routed by `Host` and still sees that visitor's honest address.
* The range list is data rendered into `nginx.conf` with its source as a comment (`bundled etag …` /
  `pinned`), so a change takes the `nginx -t` + SIGHUP path and never recreates the container; it is not part of
  `weglarka.ingress-hash`. A stale list fails closed: an unlisted new edge address is untrusted and appears as
  the client itself.
* The option needs the forwarder path (`proxy_socket_dir`): without a real peer address the ranges would be
  compared with nginx's own address, so the generator rejects the combination (an invariant, `edge` always sets it).
* **Range source.** The binary bundles a snapshot of Cloudflare's prefixes (`GET /client/v4/ips`, 15 IPv4 + 7
  IPv6, with its `etag`). Unless `ranges` pins a list, the daemon refreshes it daily (with jitter) from that API:
  no token, HTTPS with the bundled webpki roots, host pinned, response capped at 64 KiB, at most 256 entries, every
  entry a valid CIDR. Because the list's authority rests on that TLS channel alone, it must also still cover every
  bundled prefix; an empty list, or one that drops a prefix, is rejected. A good list is saved in
  `<state dir>/cdn-ranges.toml` (tolerant serde, `0644`: public data) and rendered into `nginx.conf` with its
  `etag` in a comment, so a change takes the `nginx -t` + SIGHUP path. A failed or rejected refresh keeps the last
  good list (saved, else bundled) and is reported by `doctor`; a corrupted file falls back to the bundled list with
  a warning. `ranges = [...]` disables the refresh and the bundled list.

## Consequences

* `weglarka.toml` gets a new table: an older daemon refuses it (`deny_unknown_fields`), so remove `[ingress.cdn]`
  before a downgrade. `apps.toml` / `state.toml` are unchanged: no schema bump, no hash change, no recreation
  (nginx reloads). Every existing snapshot is unchanged.
* The Cloudflare zone must use **Full (strict)**; with Flexible, Cloudflare reaches the plain listener and loops
  on the 301.
* `doctor`: `ingress.cdn` reports the range source in use (`bundled etag …` / `refreshed <age> ago, etag …` /
  `pinned, N ranges`) and warns when the last refresh failed or the last success is older than 7 days.
* `cdn-ranges.toml` is a new file in the state directory; an older daemon never reads it, so it needs no cleanup.
* Tests: generator snapshot `nginx_edge_cdn`, header/trust assertions, rejection in `behind` and without the
  forwarder, config validation; the refresh on a fake fetcher (a new etag re-renders and reloads and never
  recreates, a failed or implausible fetch keeps the list, a corrupted file falls back to bundled) and the
  anonymous, size-capped `GET /ips` against a loopback mock.

## Rejected alternatives

* **`set_real_ip_from <CDN ranges>` + `real_ip_header CF-Connecting-IP`.** A context takes one header and it is
  `proxy_protocol` already.
* **`real_ip_header X-Forwarded-For` + `real_ip_recursive`.** Relies on the client-controlled prefix.
* **A per-domain switch.** Adds state without closing a hole: the peer, not the hostname, decides.
* **Trusting the header from every peer.** Any client could forge its address.
