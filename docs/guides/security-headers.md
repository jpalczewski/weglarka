# Security headers for a container app (ingress.security_headers)

A browser-facing app should send a few hardening headers even when its framework does not: nosniff, a frame
policy, a referrer policy, HSTS on an HTTPS domain, and a content security policy. `ingress.security_headers`
adds them through the ingress nginx for one app, using the same validated table as a static site's
[`ingress.static.security_headers`](static-sites.md) ([ADR 0069](../decisions/0069-static-site-ingress-options.md),
[ADR 0076](../decisions/0076-security-headers-for-container-apps.md)).

```toml
# apps.toml — an ordinary container app
[apps.api]
image = "ghcr.io/me/api:latest"
domains = ["api.example.com"]
port = 3000

[apps.api.ingress.security_headers]
preset = "baseline"          # X-Content-Type-Options: nosniff, X-Frame-Options: DENY,
                             # Referrer-Policy: strict-origin-when-cross-origin
hsts_max_age_secs = 31536000 # Strict-Transport-Security: max-age=31536000
csp = "default-src 'self'"   # Content-Security-Policy
```

Apply it with `weglarka apps update api --spec api.toml` (the table is part of the app's spec, like `ingress`
itself); there is no dedicated CLI flag for it yet, and the panel does not edit it.

- **`preset`** is the only enum today (`baseline`, the default of the table). The three headers it names are
  constants the generator chooses, not operator input.
- **`hsts_max_age_secs`** sends `Strict-Transport-Security: max-age=<n>`. Unset sends no HSTS header; there is no
  `includeSubDomains`/`preload` in v1, because those extend the policy beyond this one domain. It works in both
  ingress modes — in `behind` mode Traefik terminates TLS, but the header reaches the browser through it all the
  same.
- **`csp`** is the one free-form value: printable ASCII, no `"`/`\`/`$`, at most 2048 bytes. There is deliberately
  no way to name an arbitrary header or value — the table is not a channel for injecting `nginx.conf` directives
  ([ADR 0069](../decisions/0069-static-site-ingress-options.md)'s rejected alternatives).

## The app wins on a conflict

A proxied app may already send one of these headers, and only the app knows what its pages need: a CSP with a
per-request nonce, `X-Frame-Options: SAMEORIGIN` for an embed, a stricter referrer policy. The ingress therefore
adds a header **only when the app's response does not carry it**. When both would set it, the app's value is the
only one sent — never two, and never the ingress value replacing the app's.

This is why a `csp` set here is a default for the app's plain responses, not an override: an app that answers with
its own `Content-Security-Policy` keeps it. If you want the ingress policy to be final regardless of what the app
sends, set it in the app itself — or in Traefik/nginx in front, which is outside Węglarka's route model.

The mechanism is an `http`-level `map` from nginx's `$upstream_http_<header>` to either the configured value (the
app sent nothing) or the empty string (nginx omits an `add_header` with an empty value), plus a per-app
`add_header … always;` in every proxy `location` of that app. The variable name carries the instance name, so two
apps on one host never share a `map`.

## Effects

- The headers are added with `always`, so they are on error answers (`4xx`/`5xx`) too, not only on `200`.
- Ingress only: a change re-renders `nginx.conf`, checks it with `nginx -t` and sends SIGHUP. The container is not
  recreated and `spec-hash` does not change — the same applies to `weglarka apps update`.
- The table is **not** part of `spec_hash`: adding or removing it never recreates anything.
- A `kind = "static"` app uses [`ingress.static.security_headers`](static-sites.md); setting
  `ingress.security_headers` on a static site is refused with a message that names the right key, and setting
  `ingress.static` on a container app is refused too.

### Behind Traefik

In `behind` mode **Traefik** terminates TLS. If Traefik (or a CDN in front of it) already sets
`Strict-Transport-Security` for the domain, do not set `hsts_max_age_secs` here as well: two `Strict-Transport-Security`
headers are a configuration error for a browser, and which one wins is not something to rely on. Pick one layer — the
Traefik middleware or this table — and leave the other unset.

## Rollback

This is a state-file schema change (version 21, [state schema](state-schema.md)): the first write after the upgrade
stamps `schema_version = 21` in `apps.toml`/`state.toml`. `apps.toml` uses `deny_unknown_fields`, so an older daemon
cannot read the table. Before a downgrade, remove every `[apps.X.ingress.security_headers]` table (or restore
`apps.toml` and `state.toml` from the backup taken before the upgrade). Nothing else changed: no container was
recreated and no state entry was transformed.
