# Identity provider and OIDC clients

Węglarka can run an OpenID Connect provider (Authelia) as an ordinary app and keep its client list in step with
`apps.toml` ([ADR 0051](../decisions/0051-identity-provider-integration.md)). An app that declares `oidc` gets a client
registered in the provider, and its credentials arrive in the container as environment variables or a mounted secret.
Removing the app removes the client at the next apply, so a dead client cannot outlive its app.

Forward auth in front of an app without a login of its own is a separate switch: [forward auth](forward-auth.md). A worked
OIDC client is the [admin panel](admin-panel.md).

## The provider

The provider is an app instance you declare yourself; `weglarka.toml` says which one it is (operator-owned, like `[acme]`;
changing it needs a host edit and a daemon restart):

```toml
[identity]
provider = "authelia"
instance = "authelia"
issuer = "https://auth.example.com"   # public URL, the OIDC issuer; no path
# upstream = "authelia:9091"          # how nginx reaches it; default <instance>:<port>
```

```toml
[apps.authelia]
image = "ghcr.io/authelia/authelia:4.39"
port = 9091
domains = ["auth.example.com"]
auto_update = false                    # required: the provider is updated deliberately
command = [
  "authelia",
  "--config=/config/configuration.yml",
  "--config=/weglarka/generated/current",   # must be the LAST config source
]
```

Węglarka refuses a write of the provider whose `command` does not load `/weglarka/generated/current` last, whose
`domains` do not include the issuer host, or that keeps `auto_update = true`. The order matters for security: Authelia
merges config sources in order, the last one wins for scalars and **replaces lists wholesale**. Anything loaded after the
generated directory could re-open `access_control.default_policy`.

### What Węglarka owns

Two sections of Authelia's configuration are generated as whole files in `/weglarka/generated/current`:
`identity_providers.oidc.clients` (with `claims_policies`) and `access_control`. Delete both from your base
configuration; a copy left there is silently replaced. The access control file always has `default_policy: deny`, a
constant `bypass` rule for the portal host and one rule per forward-auth app, so the provider can start before any app
exists.

Generated files hold only digests, never client secrets. They are validated by `authelia config validate` in a one-off
container before they go live; a bad render never replaces a working one ([generated config](generated-config.md)).

### Enabling it

Setting `[identity]` makes the provider the consumer of generated config, so its container gets a read-only mount of the
generated directory. That mount is part of its spec hash: **the first reconcile after enabling `[identity]` recreates a
running provider once.** Sessions are lost on every apply of a changed client list or rule set (Authelia keeps sessions in
memory unless you configure Redis), so batch changes where you can; the pipeline already coalesces a burst into one
restart.

## An app with an OIDC client

```toml
[apps.panel]
image = "ghcr.io/example/panel:1"
port = 8080
domains = ["app.example.com"]

[apps.panel.oidc]
redirect_uris = ["https://app.example.com/auth/callback"]   # https, on the app's own domains
scopes = ["openid", "profile", "email"]                      # default
audience = ["https://app.example.com/mcp/"]                  # RFC 8707, matched byte for byte
client_secret = { kind = "env", var = "OIDC_CLIENT_SECRET" } # or { kind = "mount", path = "/run/secrets/oidc" }
```

The client id is the instance name. The container receives `OIDC_CLIENT_ID`, `OIDC_ISSUER` (override the names with
`client_id_env` / `issuer_env`) and the client secret at the target you chose. Węglarka mints a 72-character secret, stores
it under the app's scope (`panel.oidc-client-secret`) and gives the provider only its PBKDF2 digest. These values are added
at launch and never written back to `apps.toml`; they take part in the spec hash, so adding `oidc` recreates the app once.
`weglarka run panel -- …` sees the same environment.

Other fields (`authorization_policy`, `token_endpoint_auth_method`, `groups_in_id_token`, `groups_in_access_token`,
`access_token = "jwt"`, `pkce`, `public`) are render-only: changing them restarts the provider, never the app. Authelia
issues opaque access tokens by default; a resource server must introspect them, or set `access_token = "jwt"`.

Apps with `oidc` (or `ingress.auth = "forward"`) start after the provider: Węglarka adds the provider to their
`depends_on` for ordering only, without touching `apps.toml` or the spec hash.

### Rotating the secret

```bash
weglarka oidc rotate panel
```

The new secret and digest are staged next to the live pair (`<app>.oidc-client-secret-pending` and its `-digest`), the
provider's files are re-rendered with the staged digest, validated and applied, and only a successful apply promotes the
staged pair to the live one; then the app is recreated. Between the provider restart and the recreate, logins fail. A
provider that rejects the new files (or is unhealthy on them) leaves the old secret and digest in place and answers 409
with "nothing was rotated": fix the provider and run the command again. The whole sequence runs under the daemon's
desired-state and engine locks. No state-file field is involved, so there is nothing to do before a downgrade; a pending
pair left by a crash is overwritten by the next rotation (and removed with the app by `--purge-secrets`).

`weglarka secrets set` and `secrets remove` refuse the two reserved names, so the pair cannot be split by hand.

## Clients of apps Węglarka does not run

Authelia replaces the client list wholesale, so clients for a forge or a dashboard deployed elsewhere are declared here too:

```toml
[oidc_clients.forge]
name = "Forge"
redirect_uris = ["https://git.example.com/user/oauth2/authelia/callback"]
secret_digest = "$pbkdf2-sha512$310000$…"   # operator-supplied; plain secrets are rejected
```

```bash
weglarka oidc clients set forge --spec forge.toml
weglarka oidc clients list
weglarka oidc clients remove forge
```

Generate a digest with `authelia crypto hash generate pbkdf2 --variant sha512 --iterations 310000 --password <secret>`.
A client id must not equal any app name.

### Device authorization grant

`device_flow = true` (on `[apps.<name>.oidc]` and on `[oidc_clients.<id>]`) adds the OAuth 2.0 device authorization
grant (RFC 8628, `urn:ietf:params:oauth:grant-type:device_code`) to the client, so a program with no browser can sign a
person in: it shows a short code, the person approves it on another device, and the provider applies its authorization
policy (two factors by default). The provider must advertise a `device_authorization_endpoint` in its discovery document;
Authelia does. It is how `weglarka login` is meant to authenticate ([ADR 0060](../decisions/0060-remote-cli-device-login-via-the-panel.md)),
as a public client:

```toml
[oidc_clients.cli]
name = "weglarka CLI"
public = true
device_flow = true
scopes = ["openid", "profile", "groups", "offline_access"]
audience = ["https://admin.example.com/api/"]   # byte for byte equal to [admin.http] audience
access_token = "jwt"
groups_in_access_token = true
```

A client with `device_flow` may leave `redirect_uris` out; it then has no authorization code grant, only the device grant
(and `refresh_token` when `offline_access` is in its scopes). With redirect URIs it has both. The flag is render-only,
like the other client fields: changing it restarts the provider, never an app. Left unset, the rendered file is byte for
byte what it was before.

## Migrating a hand-written configuration

1. Delete `access_control` (including `default_policy`) and `identity_providers.oidc.clients` from the base file.
2. Move each client of an app Węglarka runs into that app's `oidc` section; the secret is minted, so update the relying
   party only if it keeps its own copy.
3. Move clients of other apps into `[oidc_clients.<id>]`; hash a plaintext secret as above, or rotate it in the relying
   party.
4. Replace hand-written claims policies that only put `groups` into a token with `groups_in_id_token`.
5. Add `--config=/weglarka/generated/current` as the last config source and set `auto_update = false`.
6. Under `--hardened`, Authelia needs `server.disable_healthcheck: true` (read-only root filesystem).

## Checks

`weglarka doctor` reports:

- `identity.provider`: the instance exists, follows the provider rules, runs and answers `/api/health` over the ingress probe
  socket. A missing or wrong provider does not stop the daemon (the admin API must stay up to repair it); forward-auth apps
  are refused until it is fixed, which is fail closed.
- `oidc.credentials`: an app with a confidential client has both its secret and its digest.
- `generated.identity`: the last result of the pipeline.
- `state.orphan_secrets`: secrets left by removed apps (`apps remove --purge-secrets` clears them).

Removing the provider while `[identity]` names it returns `409`.

## Access rules

The pipeline also writes `access-control.yml` from `ingress.auth_policy` and `ingress.auth_groups` of the forward apps
(always `default_policy: deny`); [forward auth](forward-auth.md) describes the rules and their pitfalls.

## Rollback

`oidc`, `[oidc_clients]` (in `apps.toml`) and `[identity]` (in `weglarka.toml`) are new fields, and both files use
`deny_unknown_fields`: an older Węglarka refuses to start while they are present. Before downgrading, remove `[identity]`,
every `oidc` section and `[oidc_clients]`, or restore the state files from a copy ([state schema](state-schema.md)).
Removing them stops generation; the provider keeps the last files it was given, so give it a hand-written configuration
again first, then downgrade. The minted secrets stay in `secrets.toml` until you remove them
(`apps remove --purge-secrets`).

`device_flow` was added at schema version 15: a file that carries it is refused by an older Węglarka the same way, so remove
the key (and any client left with no `redirect_uris`) before downgrading.
