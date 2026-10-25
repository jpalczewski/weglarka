# ACME certificates (HTTP-01, [acme])

In [`edge` mode](edge-mode.md) the daemon issues and renews certificates itself: for every routed domain (apps and
webhook) it orders a separate certificate via HTTP-01 and writes it to `tls/`; nginx reloads without recreating
the container. Decision: [ADR 0038](../decisions/0038-acme-engine-seams.md).

```toml
[acme]
accept_terms = true                  # required: agreement to the CA's terms; without it no account is created
email = "ops@example.com"            # optional: CA contact address (expiry notices)
# directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory"   # staging, for trials
# renew_before_days = 30             # renew when this many days or fewer are left (1..=60)
# check_interval_secs = 21600        # a pass every 6 h (minimum 600)
# enabled = false                    # pause without removing the section
```

- **Requirements:** `mode = "edge"`, the HTTP port (`bind`) reachable from the internet as **port 80**, and the
  domain's DNS pointing at this host — the CA fetches `http://<domain>/.well-known/acme-challenge/<token>`.
  Validation rejects `[acme]` in `behind` mode (unless `enabled = false`).
- **Flow:** the first pass starts 30 s after the daemon (nginx must already be listening). A domain without a
  certificate gets one right away; an existing one is renewed when `renew_before_days` days or fewer are left.
  After an error the next pass is in 30 minutes (the CA limit is 5 failed validations per hour for one name),
  and the previous certificate is still served.
- **Files:** the CA account is `<state dir>/acme/account.key` (`0600`, JSON with the account private key; outside
  the webroot and `tls/`; the daemon refuses a file readable by group/others), the domain key is
  `tls/<domain>.key` (`0600`), the chain `tls/<domain>.crt` (`0644`). Writes are atomic, **key before
  certificate**. Keys never reach logs, events or error messages.
- **Notifications:** `CertificateIssued` (info) after issuance/renewal; `CertificateRenewalFailed` (warning,
  critical when fewer than 7 days are left or there is no certificate) — through the regular `[notify]` channel
  (see [notifications](notifications.md)).
- **`doctor`:** `acme.config` (warns on staging), `acme.account` (account file mode), `acme.certs`
  (missing/expired/due for renewal and the last error). A domain without a certificate still gives
  `ingress.tls` = warn, with a hint that the worker will order it in the next pass.
- **Staging:** for trials set `directory_url` to Let's Encrypt staging; browsers do not trust its certificates.
  Switching to production: remove `directory_url` and the `tls/<domain>.*` files and
  `<state dir>/acme/account.key` (the staging account does not exist in production), then restart the daemon.
- **Staging test (opt-in):** `WEGLARKA_ACME_STAGING_DOMAIN=<domain> WEGLARKA_ACME_STAGING_WEBROOT=<dir>
  cargo test -p weglarka-acme --test staging -- --nocapture` — requires a public port 80 that serves `<dir>`
  under `/.well-known/acme-challenge/` (skipped in CI).
- **Behind a CDN:** domains proxied by Cloudflare validate through the proxy, see [ACME behind a CDN](acme-behind-cdn.md).
- **Not supported (yet):** several names in one per-domain certificate, a custom CA other than `directory_url`.
  Wildcard certificates via DNS-01: [wildcard certificates](wildcard-certificates.md).

## Rollback

`[acme]` is a new `weglarka.toml` section with `deny_unknown_fields`, so **an older daemon refuses to start**
until you remove it. Remove the section (or set `enabled = false` before rolling back to a release that knows it)
and restart; the issued certificates in `tls/` stay and are still served, they just will not be renewed.
`apps.toml`/`state.toml` did not change (no schema version bump).
