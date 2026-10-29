# Admin API tokens

The admin API normally lives on a unix socket (`admin.socket`) that only the host's user can open: whoever reaches it is
root of trust. Containers and people that should hold *less* than that — the admin panel, `weglarka login`, an AI agent —
use a second listener where every request carries a bearer token issued by your identity provider
([ADR 0056](../decisions/0056-admin-api-token-listener.md)). The unix socket is unchanged and stays the break-glass path:
it has no token check, full access, and works with no provider at all.

## Enabling it

`[admin.http]` needs [`[identity]`](identity-provider.md) (its tokens come from that provider):

```toml
[admin.http]
clients = ["panel"]                             # instances that get the socket mounted
audience = "https://admin.example.com/api/"     # the exact `aud` a token must carry
read_groups = ["viewers"]                       # may use every GET
admin_groups = ["admins"]                       # may do everything; includes `read`
```

Restart the daemon. It creates `<state dir>/run/admin-token/api.sock`; each instance in `clients` gets that directory
read-only at `/run/weglarka-admin/`, so the socket is `/run/weglarka-admin/api.sock` inside it. **Each client is
recreated once** when you first enable this, to gain the mount. The opt-in is this host file only: an app cannot put
itself in `clients`.

The client's OIDC registration must request that audience and put the user's groups into the access token, with a JWT
access token (RFC 9068):

```toml
[apps.panel.oidc]
redirect_uris = ["https://panel.example.com/auth/callback"]
scopes = ["openid", "profile", "groups"]
audience = ["https://admin.example.com/api/"]   # byte for byte equal to [admin.http] audience
access_token = "jwt"
groups_in_access_token = true
```

Keep the provider's access token lifetime short (Authelia `lifespans.access_token`, 15 minutes at most): a JWT cannot be
revoked before it expires.

## What a token may do

| Scope | Allowed |
|---|---|
| none (no token) | `GET /v1/health` only; everything else is `401` |
| a valid token whose groups map to no scope | nothing: `403` |
| `read` | every `GET` except those that carry credentials or data: status, apps, doctor, volumes, sites, secrets *names*, notifications (not volume exports and not the OIDC client list, which holds secret digests) |
| `admin` | everything, including deploys, secrets, volume export/import, `run`, `forward`, `push` and OIDC clients |

`GET /v1/apps/{name}` is open to `read` but redacted: for a token without `admin` the values of `env` are blank (the keys
stay), in every response that carries an app spec. Put connection strings and other credentials in secrets, not in `env`,
and do not put them in `command` or `health.command` either, which are shown as written. The same answer also reports the
container's `restarts`, its raw `health` (`starting`, `healthy` or `unhealthy`) and `started_at` (RFC 3339). The unix socket
and `admin` tokens see the real values. The notification status (`GET /v1/notifications`) is safe at `read`: its
`last_error` holds the daemon's own wording of the failure, never the server URL or the access token.

A token whose scopes are too small, or whose groups map to no scope, gets `403`; an invalid, expired, foreign or missing token gets `401`. A route that is
not declared with a scope is refused even to an admin.

A request is checked by the daemon itself, never by whoever accepted the connection:

- the signature must verify against the provider's published keys (`RS256` or `ES256`; `none` and HMAC are refused),
  and the header `typ` must be `at+jwt`;
- `iss` must equal `[identity] issuer`, `aud` must include `[admin.http] audience`, and `exp` is required (60 s of clock
  leeway);
- the token's `groups` are mapped through `read_groups` and `admin_groups`.

The daemon reaches the provider's `jwks.json` over the ingress probe socket (it shares no network with the provider), keeps
the keys cached, refetches when it sees an unknown key id (at most every 30 s) and at least hourly, and keeps using the old
keys while the provider is down.

Every call that needs `admin` (all changes, plus exports and the OIDC client list) is logged with the token's `sub`, the route and the result; refusals are
logged with their reason. Tokens themselves are never logged.

## Checks

`weglarka doctor` reports `admin.http`: whether the token socket exists, whether every `clients` entry is in `apps.toml`,
and whether the provider's signing keys can be fetched. A `401` for a token you believe is valid usually shows up there or
in the daemon log (`typ is not at+jwt`, `audience`, `issuer`, `unknown key`).

> The `typ: at+jwt` header is what RFC 9068 requires and what the daemon insists on. Authelia 4.39.22 issues it for JWT
> access tokens; if every token is refused with `typ is not at+jwt` after a provider upgrade, that is the reason, so
> please report it.

## Rollback

`[admin.http]` is a new section of `weglarka.toml`, and the file uses `deny_unknown_fields`: an older Węglarka refuses to
start while it is present. Before downgrading, remove `[admin.http]` (the unix socket keeps working throughout). No
`apps.toml` or `state.toml` field is involved, so [`schema_version`](state-schema.md) does not change. The recreated
clients lose the mount again when the older daemon next recreates them; the unused `run/admin-token/` directory stays in
the state directory and can be deleted.
