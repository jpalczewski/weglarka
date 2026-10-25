# Edge mode behind a CDN (Cloudflare)

When the public hostnames of an [edge](edge-mode.md) host sit behind Cloudflare's proxy, the peer that connects
to Węglarka is a Cloudflare edge address and the visitor is in `CF-Connecting-IP`. Without configuration the
apps see Cloudflare as every client. Decision and rejected alternatives:
[ADR 0044](../decisions/0044-edge-cdn-client-address.md).

```toml
[ingress]
mode = "edge"
bind = "0.0.0.0:80"
https_bind = "0.0.0.0:443"

[ingress.cdn]
provider = "cloudflare"            # the only provider for now
# ranges = ["203.0.113.0/24"]      # optional pin: replaces the bundled list
```

- **Who is trusted.** Only a peer inside the CDN ranges; for it the client address is `CF-Connecting-IP`. Any other
  peer is its own client and the header is ignored. `X-Forwarded-For` sent by the peer is never used.
- **Fail closed.** A CDN peer without `CF-Connecting-IP`, or with a value that is not an IP literal, shows up as
  the CDN edge address. A stale range list makes a new edge address look like a client, never the other way round.
- **Where it shows.** `X-Forwarded-For` and `X-Real-IP` carry the visitor; the access log has `remote_addr` (the
  visitor) and `peer` (the connecting address). `X-Forwarded-Proto` is still the scheme of the connection.
- **No per-domain switch:** non-proxied domains keep working, they simply never receive a CDN peer.
- **Ranges.** The binary bundles Cloudflare's published prefixes. Unless you pin `ranges`, the daemon refreshes
  them once a day from `https://api.cloudflare.com/client/v4/ips` (no token) and keeps the last good list in
  `<state dir>/cdn-ranges.toml`. A list that is empty, malformed, too long, or that no longer covers the bundled
  prefixes is rejected and the previous list stays in use; a changed list is applied with `nginx -t` and a reload
  and never recreates the container. `ranges = [...]` disables the refresh and the bundled list entirely.
- **Check it:** `doctor` shows `ingress.cdn` with the source (`bundled etag …`, `refreshed <age> ago, etag …` or
  `pinned, N ranges`) and warns when a refresh failed or the last success is older than 7 days. If the daemon
  cannot reach `api.cloudflare.com`, the list simply stays as it is; an edge address that is not on it is treated
  as a plain client, never trusted.
- **Certificates:** see [ACME behind a CDN](acme-behind-cdn.md) (wildcards preferred, zone rule for HTTP-01).
- **Zone setting:** use SSL/TLS mode **Full (strict)**. With Flexible, Cloudflare connects to the plain listener
  and loops on the redirect to HTTPS.

## Rollback

`[ingress.cdn]` is a new table in `weglarka.toml`, so an older daemon refuses the file (`deny_unknown_fields`):
remove the table before downgrading. `apps.toml` and `state.toml` are unchanged, and `cdn-ranges.toml` is ignored
by an older daemon.
