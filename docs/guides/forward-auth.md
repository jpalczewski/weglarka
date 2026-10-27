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

## Not enabled yet

`auth_policy` and `auth_groups` are still refused ("not enabled in this release"): nginx only knows who is logged in;
the policy and group rules become the provider's access rules in a later stage, and accepting them earlier would
silently let every logged-in user in.

## Check

`weglarka doctor` runs `identity.forward`: for each protected domain it asks the provider the question nginx asks, over
the probe socket. A `401` with a `Location` is healthy; a `400` means the domain is not under any of the provider's
`session.cookies[].domain` (every request would fail with `500`).

## Rollback

The nginx change is output only: removing `auth`/`auth_exempt_paths` from an app and reconciling restores the previous
config. A Węglarka from before this stage **refuses to start** while `apps.toml` still holds `ingress.auth` or
`ingress.auth_exempt_paths` (the P0 gate, and `deny_unknown_fields` on older ones); it never serves such an app unenforced.
Remove both fields from `apps.toml` (the apps are then public again), or restore the files from before the upgrade, before
downgrading. See [the state schema](state-schema.md) and [verify and rollback](verify-and-rollback.md).
