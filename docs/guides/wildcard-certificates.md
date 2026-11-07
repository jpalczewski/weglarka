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
token_secret = "cloudflare-token"                    # recommended: a host secret (see below)
# token_file = "/var/lib/weglarka/cloudflare-token" # the older form, a 0600 file — exactly one of the two
wildcards = ["example.com"]                          # apexes: creates *.example.com + example.com
propagation_secs = 30                                # optional (default 30): wait after publishing the TXT records
prefer_wildcard = false                              # optional (default false): the wildcard outranks an own pair
```

- **Cloudflare token:** create an API token with `Zone → Zone → Read` and `Zone → DNS → Edit` permissions
  **scoped to the zones in `wildcards`** (not the global API key, not an account-wide token). Such a token can
  rewrite any record in the zone, so a leak is serious: keep it out of `weglarka.toml` and use a separate token
  per installation. `[acme.dns]` needs **exactly one** of the two forms:
    - **A host secret (recommended).** A bare name in `host-secrets.toml` (0600, next to `secrets.toml`), set
      with `weglarka secrets host set cloudflare-token < cloudflare-token.txt` and referenced as
      `token_secret = "cloudflare-token"`. See [host secrets](host-secrets.md).
    - **A file (the older form, still supported).** `umask 077 && printf '%s\n' '…' | sudo -u weglarka tee
      /var/lib/weglarka/cloudflare-token >/dev/null` with `chmod 600` and `token_file = "…"` (absolute path).
  Setting both keys is a startup error (`[acme.dns] set exactly one of token_file / token_secret`); omitting
  both is one too. In either form the value is validated as a header token — non-empty, printable ASCII, no CR/LF
  — and never reaches `weglarka.toml`, logs, events or errors.
- **Rotation without a restart:** the token is read on **every DNS API request**, so replacing the host secret or
  rewriting the token file takes effect on the next order or renewal, in either form. No restart, no `SIGHUP`.
- **Startup:** a broken source — a missing or unreadable file, permissions looser than 0600, a value that cannot go
  into an HTTP header — **stops the daemon** (wildcards are opt-in, but once configured a silent skip would hide a
  broken deployment). A host secret that is **not set yet** only warns, because it can be set only through the
  running daemon; `doctor` reports it as a failure.
- **Flow:** the same pass as in [ACME certificates](acme.md): after the per-domain certificates the worker orders
  the wildcard (if it is missing or `renew_before_days` days or fewer are left), creates the TXT record, waits
  for the CA's validation and **removes the record also after a failure**. A wildcard failure does not hold up
  per-domain certificates. For `*.example.com` and `example.com` in one order, two TXT records exist at once on
  `_acme-challenge.example.com` — that is normal.
- **Files:** `tls/_wildcard.<apex>.key` (`0600`) and `tls/_wildcard.<apex>.crt` (`0644`), atomic writes, key
  before certificate. The name contains no `*`.
- **Which domains a wildcard serves:** the apex and domains **one label below** (`example.com`,
  `app.example.com`, `pr-42.example.com`; not `a.b.example.com`). nginx picks the certificate by domain name: **an
  own `<domain>.crt|key` pair wins** unless `prefer_wildcard` says otherwise, otherwise it takes the wildcard of
  the longest matching apex (`tls/_wildcard.<apex>.crt|key`), and a domain without any pair still has no TLS server
  (handshake rejected, as in [edge mode](edge-mode.md)). A wildcard reaches `nginx.conf` like any certificate:
  through `nginx -t` + SIGHUP, without recreating the container. A wildcard pair put there by hand (without
  `[acme.dns]`) works the same way, but you are responsible for the certificate really covering `*.<apex>` and
  `<apex>`.
- **What about per-domain certificates:** the worker does not order an HTTP-01 certificate for a domain that
  (1) has no certificate of its own and (2) is covered by a valid (existing, unexpired) wildcard from
  `wildcards`. The wildcard goes first in a pass, so a new domain (e.g. a PR preview, #105) is served right away
  without a separate order. A domain that **already has** its own certificate keeps being renewed (nginx prefers
  the own one, so an expired one must not remain); to move it to the wildcard, remove its `tls/<domain>.crt|key`
  and wait for the next pass, or set `[acme.dns] prefer_wildcard` (see below), which leaves the pair on disk. A
  failed or expired wildcard = domains fall back to their own HTTP-01 certificates.
- **`doctor`:** `acme.dns` (provider and apexes), `host.credentials` (the token source — file or host secret —
  read and validated now) and `acme.wildcards` (missing/expired/due for renewal). A missing wildcard before the
  first pass is a `warn`. `acme.certs` and `ingress.tls` (and `doctor --preflight`) treat a domain covered by a
  wildcard as served.
- **DNS requirements:** the token must see the zone; the zone's CAA record (if any) must allow the CA (Let's
  Encrypt: `letsencrypt.org`). The CA queries the authoritative servers once, and a record it cannot see yet fails the
  whole order (`NXDOMAIN looking up TXT`). The daemon therefore publishes every TXT record first and waits
  `propagation_secs` (default 30) before asking the CA to validate; raise it if a provider is slow, `0` disables the wait.
- **Live test (opt-in):** on a separate development zone; skipped in CI, and the adapter and solver logic is
  tested against a Cloudflare API fake.

## Precedence: the wildcard or the domain's own pair

A routed domain is served with its own pair (`tls/<domain>.crt|key`) when one exists, and with the wildcard of the
longest covering apex only otherwise. That is right for a pair you placed deliberately, but it means every covered
domain keeps its own renewal over HTTP-01 — also the pairs a host carried over from another proxy, or the ones
issued before `[acme.dns]` existed.

`prefer_wildcard` flips that precedence for covered domains:

```toml
[acme.dns]
provider = "cloudflare"
token_secret = "cloudflare-token"
wildcards = ["example.com"]
prefer_wildcard = true
```

- **What it does:** a domain covered by a valid (existing, unexpired) wildcard is served with the wildcard even
  when it has a pair of its own, and the worker stops renewing that pair. One selection rule decides this for the
  generator, the worker and `GET /v1/certificates` (`docs/decisions/0077`), so they cannot disagree.
- **Your pairs are never touched:** the daemon does not delete, move or rewrite anything in `tls/`. A pair that is
  no longer served simply stops being renewed and stays as a fallback; delete it whenever you like.
- **Fallback:** a wildcard that failed to renew or has expired does not count as covering any more (in this mode
  the daemon reads only its `.crt`), so the worker orders the domain's own certificate over HTTP-01 again. That
  path needs what HTTP-01 always needs — port 80 reachable, or the [CDN](acme-behind-cdn.md) / zone rule — and a
  pair that was not renewed for months may itself be expired by then, which is the one renewal the fallback
  cannot avoid.
- **When to use it:** a host migrated from another proxy (its old per-domain pairs sit in `tls/`), or per-domain
  certificates issued before `[acme.dns]` was configured, with a wildcard that covers them reliably.
- **`doctor`:** without the setting, `acme.shadowed` lists the domains whose own pair shadows a valid wildcard and
  suggests either remedy — deleting `tls/<domain>.crt|key` or setting `prefer_wildcard`. With the setting the
  check stays silent, and such a domain is reported as `covered` by `GET /v1/certificates`.
- **Default:** `false` — nothing changes in what is served or renewed, byte for byte.

## Rollback

`[acme.dns]` is a new sub-block of the `[acme]` section with `deny_unknown_fields`, so **an older daemon refuses
to start** until you remove it (the same as `[acme]` in [ACME certificates](acme.md)). Remove `[acme.dns]` and
restart (this includes `propagation_secs` and `prefer_wildcard`, which an older daemon does not know); issued
wildcards in `tls/` stay but will not be renewed. You can also revoke the Cloudflare token in the
dashboard. `apps.toml`/`state.toml` did not change (no schema version bump).

A `token_secret` in `[acme.dns]` does not parse on a daemon older than ADR 0080 either: switch back to
`token_file` before downgrading, and keep the token in the file while the older daemon runs. `host-secrets.toml`
itself is ignored by an older daemon. The field is in the table in
[verification and rollback](verify-and-rollback.md).
