# Forward auth

An app with no login of its own (or one you do not trust) can sit behind the identity provider's login. With
`ingress.auth = "forward"` Węglarka's nginx asks the provider about every request before proxying it
([ADR 0052](../decisions/0052-forward-auth.md)). It works the same in `behind` and `edge` mode; the Traefik file is not
involved.

**Prerequisites:** an `[identity]` section in `weglarka.toml` (`issuer`, the provider's `instance`, optional
`upstream` as `host:port`; it defaults to `<instance>:<port>`), the provider app routed by ingress, and the app's
domains under one of the provider's `session.cookies[].domain`.

```toml
[apps.panel.ingress]
auth = "forward"
auth_policy = "one_factor"                       # optional, default "two_factor"
auth_groups = ["panel-admins"]                   # optional, any one group is enough
auth_exempt_paths = ["/mcp/", "/.well-known/"]   # optional
```

## What happens to a request

- **No session:** `302` to the provider's login (its `Location`; the issuer's portal if it sent none).
- **Session:** the request goes through with `Remote-User`, `Remote-Groups`, `Remote-Name` and `Remote-Email` taken from the
  provider's answer.
- **Access denied:** `403`. **Provider down or rejecting the URL:** `500`; the app is never contacted (fail closed).
- **Any other location** (apps without forward auth, static sites, the webhook) never sees those four headers: nginx
  clears whatever a client sends, so an identity cannot be injected.

The daemon's `health.http` probe arrives on the ingress probe socket ([ADR 0054](../decisions/0054-health-probe-socket.md)),
which the authorization location lets through, so `/` can stay protected while it is probed. No exemption is needed.

## Unusual paths are refused

The provider matches its rules against the URL as the client wrote it, while nginx routes on the normalized path. So every
protected location answers `400` when the path contains `;`, a backslash, a dot segment (`/./`, `/../`), an empty segment (`//`) or an encoded dot,
slash, backslash, semicolon or percent sign (`%2e`, `%2f`, `%5c`, `%3b`, `%25`), before any request reaches the provider. The
query string is not checked. A path such as `/files/a%2fb` therefore does not work behind forward auth.

## Exempt paths

Paths for non-browser clients with their own tokens (OAuth-protected APIs, MCP endpoints, discovery documents) cannot
follow a login redirect. List them in `auth_exempt_paths`:

- `/mcp/` exempts `/mcp` **and** everything below `/mcp/`; `/mcp` exempts only that exact path.
- An exempt path is a full copy of the app's location (same upstream, body limit, streaming and timeouts) without the
  login check. It is structural, not an access rule: the path is simply not guarded.
- Requests to an exempt path whose URI contains `;`, `\` (raw or percent-encoded) or an encoded `%` (`%25`) get `400`: nginx matches the normalized
  path but the upstream receives the raw URI, and some servers read those characters as path syntax (`/mcp/..;/admin`). Only the path is checked, not the query string.
- The guard is a denylist of the common ways a path is read differently by nginx and an upstream. It assumes the upstream
  does not resolve dot-segments from overlong or non-ASCII input and does not Unicode-normalize paths; exempt only paths
  that the app protects by itself (tokens), never ones that rely on the path layout.
- `kind = "static"` apps cannot use forward auth. Exempt paths must not overlap `streaming_paths`, and cannot be combined with `paths` (prefix routing).

## Access rules

nginx only learns *who is logged in*. Who may open the app is decided by the provider's access rules, which Węglarka
generates for you from `auth_policy` and `auth_groups` (`access-control.yml`, the same generated directory as the OIDC
clients; see [identity provider](identity-provider.md) and [generated config](generated-config.md)):

- The default is **deny**. A constant first rule lets the provider's own portal host through; every forward app adds one
  rule for its domains. A request no rule matches is denied, so a forward app without a rule is closed to everyone until the
  rules are applied, and nothing changes the default when apps come and go.
- `auth_policy` is `one_factor` or `two_factor` (the default).
- `auth_groups` lists group names (`[A-Za-z0-9._-]`); membership of **any one** is enough. Without it every user the
  provider authenticates may enter. Only groups are supported, not individual users: manage membership in the provider's
  user database.
- Apps routed by `paths` get a rule per prefix, anchored so `/p` does not match `/pp`.
- A rule that names groups is followed by a `deny` for the same domain and paths. The provider skips a group rule for a
  user outside the groups and tries the next one, so without that `deny` another app on the same domain could admit them.
- Exempt paths need no rule: nginx never asks the provider about them.
- Węglarka owns the whole `access_control` section. The provider replaces lists as a whole, so `rules` and
  `default_policy` from your own base configuration are dropped; keep them out of it.
- **A group that does not exist in the provider's user database locks everyone out**, so a typo fails closed.
- Every change to the rules restarts the provider (it has no config reload) and logs everyone out; changes are coalesced.
- **Tightening is applied after the render passes validation.** Until then the previous rules stay in force. If the
  provider's validator rejects the new files, `weglarka doctor` shows `generated.identity` as a warning and the old
  (laxer) rules keep serving; fix the cause and the render is retried.

## Check

`weglarka doctor` runs `identity.forward`: for each protected domain it asks the provider the question nginx asks, over
the probe socket. A `401` with a `Location` is healthy; a `400` means the domain is not under any of the provider's
`session.cookies[].domain` (every request would fail with `500`).

## Rollback

The nginx change is output only: removing `auth`/`auth_exempt_paths` from an app and reconciling restores the previous
config. A Węglarka from before this stage **refuses to start** while `apps.toml` still holds `ingress.auth` or
`ingress.auth_exempt_paths` (the P0 gate, and `deny_unknown_fields` on older ones); it never serves such an app unenforced.
The same goes for `ingress.auth_policy` and `ingress.auth_groups` on a release from before access rules. Remove those
fields from `apps.toml` (the apps are then public, or open to every logged-in user), or restore the files from before the
upgrade, before downgrading. See [the state schema](state-schema.md) and [verify and rollback](verify-and-rollback.md).
