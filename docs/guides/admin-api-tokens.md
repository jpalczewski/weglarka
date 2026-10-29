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
| `read` | every `GET` except those that carry credentials or data: status, apps, doctor, volumes, sites, recent events, certificates, the host config view, secrets *names*, notifications (not volume exports and not the OIDC client list, which holds secret digests) |
| `admin` | everything, including deploys, secrets, volume export/import, `run`, `forward`, `push`, app logs and OIDC clients |

App logs (`GET /v1/apps/{name}/logs`) need `admin`, although they only read: logs can hold anything the app printed,
secrets included, and unlike a spec they cannot be redacted. The answer is a stream that ends with the token: when it
expires the daemon sends a final `TokenExpired` frame and closes, and the client reconnects with a fresh token and
`since=` (unix seconds) set to where it stopped. `forward` streams end at the token's expiry the same way; `run` does not,
because cutting a command off halfway can be destructive (it has its own `timeout_secs`). On the unix socket there is
no token, so no deadline.

`GET /v1/apps/{name}` is open to `read` but redacted, in every response that carries an app spec or state. The `read`
view is an allowlist projection: the daemon rebuilds it field by field, so a field added in a later release does not
compile until someone decides what `read` sees of it. The free-form `detail` and the content `fingerprint` of the
config and host mount views are withheld too. For a token without `admin`: the values of `env` are blank (the keys stay);
`command` and `health.command` keep only their first element and show `<redacted>` for every other argument (the count
stays); `health.http.path` keeps its first path segment and shows `<redacted>` for the rest (`/hooks/<token>/ready` is
shown as `/hooks/<redacted>`; the query string is always dropped, and a credential in the *first* segment would still be
visible, so keep credentials out of the probe path); and the engine's failure text in `state.failed.reason` is replaced
by a fixed marker (the failed `digest` stays); `state.spec_hash` is omitted, because it is a hash of the spec including the blanked `env` values. The response then carries `"redacted": true`; an `admin` token and the unix
socket get no such key. A redacted spec is a view, not the stored spec: do not send it back in `PUT /v1/apps/{name}`
(a full replacement), and `weglarka apps update/start/stop` refuses to when it receives one. Put
connection strings and other credentials in secrets, not in `env` or command arguments. The same answer also reports the
container's `restarts`, its raw `health` (`starting`, `healthy` or `unhealthy`) and `started_at` (RFC 3339). The unix socket
and `admin` tokens see the real values. The notification status (`GET /v1/notifications`) is safe at `read`: its
`last_error` holds the daemon's own wording of the failure, never the server URL or the access token.

`GET /v1/events?since=<seq>&boot=<boot_id>` (`read`) returns the daemon's recent domain events (deploys, rollbacks,
crash loops, certificate and self-update events) from a bounded in-memory history of the last 256 events of severity
`info` and above. Each record has a `seq`, a UTC timestamp, a severity, a stable `kind`, the app and a short capped
message built from structured fields only: the engine's free-form failure text (podman and validator output) is never
included, it stays in the daemon log. Pass the answer's `next_seq` as `since` and its `boot_id` as `boot` to get only
newer events. `dropped` is `true` when events after `since` were evicted. The history is not persisted: a restart begins
again at `seq` 1 with a new `boot_id`, and a request carrying the old one gets everything retained with `reset: true`.

`GET /v1/certificates` (`read`) lists the certificates the ACME worker looks after, one row per routed domain and per
wildcard: the names covered, `not_after` (UTC), whole `days_left` (negative once expired), a `status` (`valid`,
`renewal_due`, `expired`, `missing`, or `covered` by a wildcard) and whether the last pass `failed` on it, plus
`renew_before_days`, the worker's `last_pass` and its failure count. Only `notAfter` is read from the chains: no key
material, no file paths and no failure text (that stays in `doctor` and the log). Without an enabled `[acme]` section
the list is empty and `acme_enabled` is `false`.

`GET /v1/config` (`read`) is an allow-list view of `weglarka.toml`: ingress mode and binds, the runtime allowlists
and limits, which optional sections are on (`notify`, `acme`, `identity`, `self_update`, `[admin.http]`) with their
non-secret settings (intervals, thresholds, issuer URL, audience, client instances). Everything that reveals the host
layout (socket, state and config paths, the runtime account, the identity upstream address) or is a credential or personal data is left out; where it
matters a flag says it is set (`authenticated`, `has_contact`, `custom_public_key`). The ntfy URL, host and topic are
not shown, and the operator-chosen `host_mounts` allowlist is shown as configured, and the groups behind `read`/`admin` appear only as counts. The daemon builds it field by field, so a new
config field stays hidden until it is added on purpose.

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

Every call that needs `admin` (all changes, plus exports, the OIDC client list and app logs) is logged with the token's `sub`, the route and the result; a logs stream adds a line when it ends (`sub`, app, `follow`, `tail`, `since`, frames, bytes, duration and why it ended — never the content); refusals are
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
