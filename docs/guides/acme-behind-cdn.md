# ACME certificates behind the Cloudflare proxy

For a hostname proxied by Cloudflare (see [edge behind a CDN](edge-cdn.md)) the CA's validator does not reach
Węglarka directly: HTTP-01 goes through the proxy, and DNS-01 does not care about it. Two ways to get a certificate
for such a domain.

## Preferred: a wildcard over DNS-01

Cover the domains with a wildcard certificate: `[acme.dns]` with `wildcards = ["example.com"]` serves the apex and
every name one label below it ([wildcard certificates](wildcard-certificates.md)). The TXT record is published in
the zone through the DNS API, so the proxy, "Always Use HTTPS" and the WAF are irrelevant, and a domain a wildcard
covers does not order an HTTP-01 certificate at all. Per-domain DNS-01 is not available yet.

## HTTP-01 through the proxy

This works for renewals once a domain is set up, and fails in predictable ways for a new one:

- **First issuance of a new proxied domain** fails when the zone has **Always Use HTTPS** (or Automatic HTTPS
  Rewrites) on and the SSL/TLS mode is **Full (strict)**: Cloudflare redirects the validator to HTTPS and the origin
  has no certificate yet. Węglarka's nginx already exempts `/.well-known/acme-challenge/` from its own redirect;
  the zone has to do the same. Add a configuration rule for `/.well-known/acme-challenge/*` that
  - turns off Always Use HTTPS and Automatic HTTPS Rewrites,
  - bypasses the cache,
  - skips the WAF and security checks for that path.
- **Bot Fight Mode** (and similar challenges) blocks the validators. Keep it off during issuance, or skip it for
  the path above.
- Alternatively, set the record to **DNS only** (grey cloud) until the first certificate exists, then proxy it.
- Renewals reuse the same path, so the rule has to stay in place.

## Check

With `[ingress.cdn]` and `[acme]` both configured, `doctor` reports `acme.cdn`: a warning naming every routed
domain that resolves into the CDN ranges and has no wildcard coverage, i.e. whose HTTP-01 depends on the zone
settings above. A domain that does not resolve from the host is not reported here (see `acme.certs`).

## Rollback

Documentation and a `doctor` check only: nothing to roll back.
