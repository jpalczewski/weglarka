# Wildcard certificates (DNS-01, [acme.dns])

Besides per-domain certificates ([ACME certificates](acme.md)) the daemon can issue a **wildcard**
(`*.example.com` together with `example.com`) via DNS-01: it orders it from the CA and proves control of the
domain with a `_acme-challenge.<domain>` TXT record, which it creates and removes itself through the DNS
provider's API. A wildcard needs no port 80 and does not expose individual subdomains in CT logs. First
provider: Cloudflare. Decision: [ADR 0039](../decisions/0039-acme-dns01.md).

```toml
[acme]
accept_terms = true

[acme.dns]
provider = "cloudflare"
token_file = "/var/lib/weglarka/cloudflare-token"   # a 0600 file, absolute path
wildcards = ["example.com"]                          # apexes: creates *.example.com + example.com
propagation_secs = 30                                # optional (default 30): wait after publishing the TXT records
```

- **Cloudflare token:** create an API token with `Zone → Zone → Read` and `Zone → DNS → Edit` permissions
  **scoped to the zones in `wildcards`** (not the global API key, not an account-wide token). Such a token can
  rewrite any record in the zone, so a leak is serious: keep it only in this file
  (`umask 077 && printf '%s\n' '…' | sudo -u weglarka tee /var/lib/weglarka/cloudflare-token >/dev/null`) and use
  a separate token per installation. The daemon reads the file once at startup and refuses to start when it is
  readable by group/others (`chmod 600`), empty or contains non-ASCII characters; the value never reaches
  `weglarka.toml`, logs, events or errors.
- **Flow:** the same pass as in [ACME certificates](acme.md): after the per-domain certificates the worker orders
  the wildcard (if it is missing or `renew_before_days` days or fewer are left), creates the TXT record, waits
  for the CA's validation and **removes the record also after a failure**. A wildcard failure does not hold up
  per-domain certificates. For `*.example.com` and `example.com` in one order, two TXT records exist at once on
  `_acme-challenge.example.com` — that is normal.
- **Files:** `tls/_wildcard.<apex>.key` (`0600`) and `tls/_wildcard.<apex>.crt` (`0644`), atomic writes, key
  before certificate. The name contains no `*`.
- **Which domains a wildcard serves:** the apex and domains **one label below** (`example.com`,
  `app.example.com`, `pr-42.example.com`; not `a.b.example.com`). nginx picks the certificate by domain name: **an
  own `<domain>.crt|key` pair always wins**, otherwise it takes the wildcard of the longest matching apex
  (`tls/_wildcard.<apex>.crt|key`), and a domain without any pair still has no TLS server (handshake rejected, as
  in [edge mode](edge-mode.md)). A wildcard reaches `nginx.conf` like any certificate: through `nginx -t` +
  SIGHUP, without recreating the container. A wildcard pair put there by hand (without `[acme.dns]`) works the
  same way, but you are responsible for the certificate really covering `*.<apex>` and `<apex>`.
- **What about per-domain certificates:** the worker does not order an HTTP-01 certificate for a domain that
  (1) has no certificate of its own and (2) is covered by a valid (existing, unexpired) wildcard from
  `wildcards`. The wildcard goes first in a pass, so a new domain (e.g. a PR preview, #105) is served right away
  without a separate order. A domain that **already has** its own certificate keeps being renewed (nginx prefers
  the own one, so an expired one must not remain); to move it to the wildcard, remove its `tls/<domain>.crt|key`
  and wait for the next pass. A failed or expired wildcard = domains fall back to their own HTTP-01 certificates.
- **`doctor`:** `acme.dns` (provider, token file mode) and `acme.wildcards` (missing/expired/due for renewal).
  A missing wildcard before the first pass is a `warn`. `acme.certs` and `ingress.tls` (and `doctor --preflight`)
  treat a domain covered by a wildcard as served.
- **DNS requirements:** the token must see the zone; the zone's CAA record (if any) must allow the CA (Let's
  Encrypt: `letsencrypt.org`). The CA queries the authoritative servers once, and a record it cannot see yet fails the
  whole order (`NXDOMAIN looking up TXT`). The daemon therefore publishes every TXT record first and waits
  `propagation_secs` (default 30) before asking the CA to validate; raise it if a provider is slow, `0` disables the wait.
- **Live test (opt-in):** on a separate development zone; skipped in CI, and the adapter and solver logic is
  tested against a Cloudflare API fake.

## Rollback

`[acme.dns]` is a new sub-block of the `[acme]` section with `deny_unknown_fields`, so **an older daemon refuses
to start** until you remove it (the same as `[acme]` in [ACME certificates](acme.md)). Remove `[acme.dns]` and
restart (this includes `propagation_secs`, which an older daemon does not know); issued wildcards in `tls/` stay but will not be renewed. You can also revoke the Cloudflare token in the
dashboard. `apps.toml`/`state.toml` did not change (no schema version bump).
