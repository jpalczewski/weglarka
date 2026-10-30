# Signing in to a remote host (`weglarka login`)

`weglarka login` lets the CLI authenticate against your identity provider with the OAuth 2.0 device authorization grant
(RFC 8628), so a person can work with a remote host without an SSH tunnel and without holding the full trust of the
admin socket. Design and rejected alternatives: [ADR 0060](../decisions/0060-remote-cli-device-login-via-the-panel.md).

> **Status:** every command that talks to the daemon can go through a remote host: `--host` (or `WEGLARKA_HOST`, or `host` in
> `cli.toml`) sends it to the panel's [relay under `/_weglarka/api`](admin-panel.md) with your token. `run`, `push` and
> `forward` use the same relay but are not yet tested end to end through a real nginx; on a host you can still reach by
> SSH, prefer the local socket for those.

## Register the CLI at the provider

The CLI is a *public* client: it has no secret to leak from a workstation. Declare it once, with the
[device grant](identity-provider.md), the same audience as the panel and groups in the access token:

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

The client id is `cli` here; the CLI asks for `weglarka-cli` unless you pass `--client-id`, so either name the client
`weglarka-cli` or pass `--client-id cli`.

## Sign in

```bash
weglarka login --host https://panel.example.com \
  --issuer https://auth.example.com \
  --audience https://admin.example.com/api/
```

The command prints a short code and an address; approve it in any browser (the provider applies its two-factor policy)
and the command finishes. Nothing needs to run on the machine's own browser, so it works over SSH.

```bash
weglarka whoami        # the session; refreshes the token if it is about to expire
weglarka logout        # forgets the tokens and asks the provider to revoke the session
```

`--host` may be left out of `whoami` and `logout` when you are signed in to exactly one host (or set `WEGLARKA_HOST` or `host` in `cli.toml`); `login` needs it.
`--json` prints the session as JSON (never a token).

## Use it

```bash
weglarka --host https://panel.example.com status
weglarka --host https://panel.example.com apps list
```

To make it the default, put the address in `cli.toml`:

```toml
host = "https://panel.example.com"
```

Where a command goes, first match wins: `--socket` / `WEGLARKA_SOCKET`, then `--host` / `WEGLARKA_HOST`, then `host` in
`cli.toml`, then the local `admin.socket` from `weglarka.toml`. `--host` and `--socket` together are refused. On the host
itself with a `host` default in `cli.toml`, pass `--socket` to use the local daemon.

The relay forwards your token unchanged and the daemon decides: `read` endpoints need the `read` group, mutations the
`admin` group. An expired access token is refreshed before each request; when the session has ended the command says to
run `weglarka login` again (exit code 70/5 with a hint, never a token in the output).

## Where the tokens are

`credentials.toml` next to `cli.toml` (`$XDG_CONFIG_HOME/weglarka/`, else `~/.config/weglarka/`), mode `0600` in a `0700`
directory. It holds the access token and the refresh token: **the refresh token is the long-lived credential**, so treat
the file like an SSH key. Tokens are never printed, logged or put in an error message. The access token lives about 15
minutes (the provider's `lifespans.access_token`, see [admin API tokens](admin-api-tokens.md)); it is refreshed on use under a
file lock, so two commands running at once do not spend the same rotating refresh token. If the provider refuses a
refresh (revoked, expired or rotated elsewhere) the stored session is deleted and the CLI asks you to sign in again; a
provider that is merely unreachable keeps it.

`logout` deletes the local copy first, then tells the provider to revoke the refresh token (when its discovery document
lists a `revocation_endpoint`); a provider that is down never leaves tokens behind.

## When it does not work

- *the identity provider does not offer the device authorization grant*: its discovery document has no
  `device_authorization_endpoint`. Authelia has one; check the version.
- *the identity provider refused the sign-in request*: the client is not registered as a public client with
  `device_flow = true`, or the scopes or audience differ.
- *provider discovery failed*: `--issuer` must equal the provider's issuer byte for byte (no trailing slash).

## Rollback

`device_flow` is a new field of `apps.toml` (schema version 15): remove it, and any client left with no
`redirect_uris`, before downgrading ([identity provider](identity-provider.md), [state schema](state-schema.md)).
The CLI side adds only `credentials.toml`, which an older CLI ignores; delete it with `weglarka logout`.
