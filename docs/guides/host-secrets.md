# Host secrets

Host secrets are the daemon's own credentials, as opposed to an app's secrets: today the ntfy access token
(`[notify.ntfy]`) and the Cloudflare API token of `[acme.dns]`. They live in `host-secrets.toml` — next to
`secrets.toml` in the state directory, mode `0600` — and are referenced from `weglarka.toml` by name
(`token_secret = "<name>"`), never by value. Decision: [ADR 0079](../decisions/0079-host-credentials.md).

The file is separate from `secrets.toml` on purpose: an older daemon validates every key of `secrets.toml` and
would treat a store holding host keys as corrupt after a rollback, taking the app secrets down with it.

- **Keys are bare names** (`[A-Za-z0-9_-]{1,64}`, no dot, so they cannot be mistaken for the app-scoped
  `<app>.<name>` of `secrets.toml`).
- **A host secret is never bound into a container:** no `apps.toml` spec can reference it, so it cannot be mounted
  or exported into an app environment. It is read by the daemon only.
- **Read on use.** Both consumers read the value on every use — each ntfy message, each DNS API request — so
  rotating a token needs no restart and no `SIGHUP`. The value must be a header token (non-empty, printable ASCII,
  no CR/LF); one that is not is reported at use and by `doctor`.
- **At startup** a broken source (missing or unreadable file, permissions looser than `0600`, a value that cannot
  go into an HTTP header) stops the daemon. A host secret that is **not set yet** only warns, because it can only
  be set through the running daemon; `doctor` reports it as a failure.
- **The older form is still supported.** `token_file` keeps pointing at a `0600` file; `token_file` and
  `token_secret` are mutually exclusive and exactly one is required in `[acme.dns]` (in `[notify.ntfy]` at most
  one). See [notifications](notifications.md) and [wildcard certificates](wildcard-certificates.md).

## Commands

```sh
weglarka secrets host set ntfy-token < ntfy-token.txt            # set or overwrite; value from stdin
weglarka secrets host set ntfy-token --from-file token.txt       # the same, from a file the CLI may read
weglarka secrets host set ntfy-token --dry-run < ntfy-token.txt  # validate, show the request, change nothing
weglarka secrets host list                                       # NAME, FINGERPRINT, UPDATED
weglarka secrets host remove ntfy-token
weglarka secrets host remove ntfy-token --dry-run                # no server lookup
```

- **The value never goes into an argument** (`ps`, shell history, logs): it comes from stdin or `--from-file`.
  Prefer the `< file` redirection — it works through `sudo -u weglarka` too, exactly as described in
  [first app](first-app.md).
- **The list never shows values:** name, fingerprint and update date only, like `secrets list`. There is no
  command or endpoint that returns a stored value.
- **Names:** an invalid name is a `400`, `remove` of a name the store does not hold a `404`. `set` overwrites.
- `--host` is the global remote flag, not a subcommand of `secrets`: `weglarka --host https://panel.example.org
  secrets host list` reads the secrets of that host.

## Scope

- `set` and `remove` change credentials: they need the **admin** scope (the local unix socket, or an admin token
  from `[admin.http]`).
- `list` is metadata only: the **read** scope is enough, like app secrets, and its view is an allowlist of three
  fields (name, fingerprint, `updated_at`), never the stored value.

## Doctor

`weglarka doctor` runs three checks around host secrets:

| Check | Status | When |
|---|---|---|
| `host.credentials` | `fail` | a configured source (file or host secret) cannot be read, the store cannot be parsed, or the value fails validation; the line names `notify.ntfy` or `acme.dns`, the source (path or secret name) and the remedy — never the value |
| `host.orphan_secrets` | `warn` | the store holds names no `[notify.ntfy] token_secret` or `[acme.dns] token_secret` references; `weglarka secrets host remove <name>` |
| `state.host_secrets_file` | `fail` | `host-secrets.toml` is unreadable or accessible by group/others (looser than `0600`); a missing file (nothing set yet) is `ok` |

## Rotation

Replace the value — `weglarka secrets host set <name> < new-token.txt` — and the next message or DNS API request
uses it. Nothing is restarted, and no state file changes. `secrets host list` shows a new fingerprint, which is
how you confirm that the daemon reads the new value (the fingerprint is derived from the value, never the value
itself). Revoking the old token at the provider is the operator's step; the daemon holds no other copy.

## Rollback

`host-secrets.toml` is **ignored** by a daemon older than ADR 0079: it does not read the file, does not mind it
staying on disk, and app secrets in `secrets.toml` are unaffected.

What does break is `weglarka.toml`, which has `deny_unknown_fields`: `token_secret` in `[notify.ntfy]` or
`[acme.dns]` makes an older daemon fail at startup. Before downgrading, put the token back into a `0600` file and
switch the key to `token_file`; delete `host-secrets.toml` whenever you like. The row in
[verification and rollback](verify-and-rollback.md) has the same note.
