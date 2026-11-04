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

To also sign in with `--browser` (below), register the loopback callback on the same client:

```toml
redirect_uris = ["http://127.0.0.1/callback"]
```

Only a `public = true` client may carry a loopback `http://` entry; `localhost` and any other `http://` stay refused.
Authelia ignores the port of a registered `http://127.0.0.1` redirect (RFC 8252 section 7.3), so one entry covers the
port the CLI picks each time ([ADR 0068](../decisions/0068-cli-browser-login-loopback-redirect.md)). A provider that
matches the port exactly is not supported by `--browser`.

## Sign in

```bash
weglarka --host https://panel.example.com login
```

The CLI reads the provider's issuer and the audience from the panel itself (`GET /_weglarka/api/login`, a public
document with just those two values) and prints `Signing in to https://panel.example.com with https://auth.example.com`
before it starts. A panel older than this feature answers `404`; then pass both explicitly, which also skips the request:

```bash
weglarka --host https://panel.example.com login \
  --issuer https://auth.example.com \
  --audience https://admin.example.com/api/
```

Either flag may also be given alone, but it must equal what the panel publishes (byte for byte), otherwise the command
stops. The command prints a short code and an address; approve it in any browser (the provider applies its two-factor policy)
and the command finishes. Nothing needs to run on the machine's own browser, so it works over SSH.

### Signing in with the browser

```bash
weglarka --host https://panel.example.com login --browser
```

On a workstation where you sit at the keyboard, `--browser` opens the provider's sign-in page (`open` on macOS,
`xdg-open` elsewhere; the address is always printed too) and receives the result on `http://127.0.0.1:<port>/callback`,
a listener that lives for the sign-in only, binds the loopback interface only and gives up after five minutes. Use the
device flow over SSH, on a machine without a browser or when the provider does not have the loopback entry above.
Everything after the sign-in (tokens, refresh, `logout`) is identical. A callback that does not carry the expected
`state` is ignored with a note, so a stray request to the port cannot end the sign-in.

### Whom you trust when you sign in

The host already receives your bearer token on every call, so the audience it publishes changes nothing. The issuer is
the sensitive value: a malicious or hijacked host could name its own "identity provider" and ask you for credentials
there. Check the issuer line the command prints before you approve anything. The CLI also remembers the issuer and
audience per host and **refuses to change them** for a host you are signed in to (run `weglarka --host <url> logout`
first). That protects later logins only, not the first one: the first sign-in to a host is trusted on first use, so
type the address yourself rather than following a link.

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
`cli.toml`, then the local `admin.socket` from `weglarka.toml`. `--host` and `--socket` together on the command line are refused, but an explicit flag beats the other one's variable:
`weglarka --host https://panel.example.com status` works on a machine that exports `WEGLARKA_SOCKET`, and `--socket` beats
`WEGLARKA_HOST`. On the host
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
refresh with `400` or `401` (the grant is revoked, expired or rotated elsewhere) the stored session is deleted and the
CLI asks you to sign in again; so is an answer that is not a usable token response. Any other failure keeps it: a
provider that is unreachable, answers `408`, `429` or `503` (rate limiting or a short outage; the command fails with
*the identity provider asked to retry later* and, when the provider sent `Retry-After`, how long to wait), or any other
error status, such as a proxy in front of it answering another 4xx.

`logout` deletes the local copy first, then tells the provider to revoke the refresh token (when its discovery document
lists a `revocation_endpoint`); a provider that is down never leaves tokens behind.

## When it does not work

- *the identity provider does not offer the device authorization grant*: its discovery document has no
  `device_authorization_endpoint`. Authelia has one; check the version.
- *the identity provider refused the sign-in request*: the client is not registered as a public client with
  `device_flow = true`, or the scopes or audience differ.
- `login --browser` timed out or *the identity provider refused the sign-in* (the provider shows its own error page and
  never calls back for a redirect it does not know): the client lacks `http://127.0.0.1/callback` in `redirect_uris`, is
  not `public = true`, or the scopes differ.
- *the host does not publish its sign-in settings*: an older panel; pass `--issuer` and `--audience`.
- *--issuer differs from the issuer the host publishes*: drop the flag, or check you are signing in to the right host.
- *already signed in with a different issuer or audience*: the host's settings changed (or the host is not the one you signed in to before); `logout` first if that is expected.
- *provider discovery failed*: the issuer must equal the provider's issuer byte for byte (no trailing slash).
- *the identity provider asked to retry later*: the provider is rate limiting this client address (Authelia does after
  many rejected requests, for example a `weglarka login` left waiting for a long time). Nothing stored is lost; run the
  command again after the time in the hint.

## Rollback

`device_flow` is a new field of `apps.toml` (schema version 15): remove it, and any client left with no
`redirect_uris`, before downgrading ([identity provider](identity-provider.md), [state schema](state-schema.md)).
The CLI side adds only `credentials.toml`, which an older CLI ignores; delete it with `weglarka logout`.
