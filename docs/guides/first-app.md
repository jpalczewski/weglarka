# Your first app: ntfy.zig

This guide walks through adding a first app (ntfy.zig, which updates itself from GHCR), setting its secret, and the
details of secrets: mounted-secret mode and owner, how to pass a value, private-image credentials. It ends with
switching an app over from Coolify with minimal downtime. Prerequisite: a running Węglarka
([installation](../install.md#quadlet-and-start)).

## Add the app and set its secret

Order matters: `secrets set` needs an existing app, and the first deploy needs the `config` secret.
Until the secret exists, the app is in the **"waiting for a secret"** state (`weglarka status` →
`waiting-for-secret`, `apps show` lists the missing names, `doctor` warns) — this is not an error and the daemon
does not attempt a deploy. After `secrets set` the state disappears and the deploy starts by itself; a separate
`weglarka deploy` is not needed.

```sh
weglarka apps add ntfy ghcr.io/jpalczewski/ntfy.zig:latest \
  --domain ntfy.example.com --port 8085 \
  --env CONFIG_FILE=/config.json \
  --secret-mount config=/config.json

weglarka secrets set ntfy config < ./config.json                # the file ends up at /config.json
weglarka apps show ntfy                                         # the deploy starts by itself: pull, health gate
```

`secrets set` only overwrites a value — a secret is removed with `secrets remove`, and an app's whole scope is
cleaned up with `apps remove --purge-secrets` ([Secrets cleanup](secrets-cleanup.md)).

## Many secrets at once: an env file

An app that reads a dozen variables from a `.env` file does not need a dozen calls:

```bash
weglarka secrets set web --env-file - --except DEBUG --plain LOG_LEVEL < prod.env
```

Every `NAME=value` line (comments, blank lines, `export` and quotes as in dotenv; a quoted value ends on its own line) is
stored as a secret and, unless the app already binds a secret of that name, bound as the environment variable `NAME`.
`--only A,B` / `--except A,B` pick names from a mixed file, `--plain A,B` sets those as ordinary `env` of the app
instead. A name that is already a plain `env` key cannot become a secret (and a bound variable cannot become plain):
the command refuses and tells you which `apps update` flag resolves it. Pass the file by redirection and `-`, as above.
Running it again is harmless (same values, same fingerprints, an unchanged spec is not sent). `--dry-run` lists
names only; the output is names and fingerprints, never values. Copying bindings from another instance
(`--from-app`) is not implemented: the API never returns secret values.

## Mounted secret: mode and owner (mode, uid, gid)

`--secret-mount` mounts the file with the default mode `0444` (readable by everyone in the container) and the owner
`0:0` — the container's root. An image that runs as a specific unprivileged user and needs a stricter mode (e.g.
`0400` for that user only) gets both settings through `--spec`/`apps.toml`:

```toml
# apps.toml
[apps.ntfy]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
secrets = [
  { secret = "config", kind = "mount", path = "/config.json", mode = 0o400, uid = 1000, gid = 1000 },
]
```

- **`mode`, `uid`, `gid` are optional.** Without them `0o444` and `0/0` stay (like `podman run --secret`).
- **The ids are numeric and "container" ids** — in the same space the image's `USER` speaks (e.g. `1000`). Podman
  maps them through the instance's UID range ([ADR 0009](../decisions/0009-volume-ownership.md)), so `stat`
  **inside the container** shows `1000`, and on the host the offset `range.start + 1000`. **Do not give host UIDs
  or user names** — a name is a parse error, and a host UID would land on a different owner.
- **Range `0..=65535`** (`0` = root in the container); a larger value makes `apps.toml`/`--spec` be rejected on load.
- **Only through `--spec`:** there is no CLI flag for `uid`/`gid`. `apps update --secret-mount SECRET=PATH` binds
  the secret **anew**, so it resets that entry's `mode`/`uid`/`gid` to the defaults — set them again in the spec.
- **In the `spec-hash`:** unset fields change nothing (a Węglarka update does not recreate the container), while set
  or changed ones recreate the container on the next reconcile — the owner is applied when the container is created.
  Decision and rejected alternatives: [ADR 0037](../decisions/0037-secret-mount-ownership.md).

### Rollback

This is a state-file schema change (version 7) — `apps.toml` and `state.toml` get `schema_version = 7` on the first
write after the update. Before a downgrade remove `uid`/`gid` from mounted secrets (or restore the files **from a
backup taken before the update**; see [State schema](state-schema.md)).

## Secret values: use "< file", not /dev/stdin

Pass the value by **redirection** (`secrets set <app> <name> < file`) or through a pipe
(`pbpaste | weglarka secrets set …`) — the CLI then reads standard input. Do not use
`--from-file /dev/stdin` through `sudo -u`/`ssh` to another user: `/dev/stdin` is a symlink to `/proc/self/fd/0`,
which the CLI opens *anew*, already as the runtime user — and that user has no rights to a file or pipe owned by the
caller, so it ends with `Permission denied`. The `<` redirection opens the file in the caller's shell (with the
caller's permissions) and passes a ready descriptor, so it works with
`sudo -u weglarka weglarka secrets set ntfy config < config.json` too. `--from-file path` is fine only for a file
readable by the user running the CLI. The secret never ends up in arguments (`ps`, shell history).

## Images that write env vars into their own config

Some images turn environment variables into a config file on start. The rootless Forgejo image does: `FORGEJO__section__KEY`
is written into `app.ini` inside the app's volume. A secret bound as `kind = "env"` then ends up **in plaintext in the
volume** (and in every `weglarka volumes export` or backup) even though it never appears in the spec, and removing the
variable from the spec later does not remove it from the file — edit the stale value out by hand.

A file mount does not avoid this. Forgejo's `FORGEJO__SECTION__KEY__FILE=/path` reads the value from a file, but the value
read is written into the ini file too (same behaviour reported for Gitea, go-gitea/gitea#19856): `kind = "mount"` combined
with `…__FILE` changes where the value comes from, not where it ends up. If the application has a setting that stores only
a *path* (Forgejo has `*_URI` keys for some secrets, e.g. `SECRET_KEY_URI = file:/path`; not checked for every key), use
that and mount the secret at the path.

`weglarka run <app> -- …` starts a container with the app's **whole** env, secrets included, so running such an
env-to-config tool (or anything that dumps the config) inside it writes every bound secret into the file or output it
produces.

## Private images (registry-auth)

Credentials for a pull are an ordinary app secret with the reserved name `registry-auth`, in the format
`<user>:<password-or-token>` ([ADR 0026](../decisions/0026-registry-credentials.md)):

```
weglarka secrets set my-app registry-auth < creds.txt   # e.g. "ci-bot:ghp_xxx"
```

The daemon sends them as `X-Registry-Auth` on every pull of that app; without the secret the pull is anonymous (as
before — the Podman user's `auth.json` also works). Rejected credentials give a `409` error naming the secret to
fix; the `registry-auth` secret must not be attached to a container (`secrets = [...]`).

Backward compatibility: no changes to the state files — an older daemon simply ignores this secret.

## Switching an app over from Coolify with minimal downtime

A domain cannot have two routers with the same `Host()` at once — Coolify's and Węglarka's:

1. Add the app **without `--domain`**, set the secret, `deploy` — the container passes the health gate, and
   Coolify keeps serving the traffic.
2. Make sure the domain is on the validator allowlist (`allowed_domains` in `/etc/weglarka/traefik-policy.json`;
   see [Host requirements](../install.md#host-requirements)).
3. Stop the old container in Coolify — its router disappears.
4. Add the domain: `weglarka apps update ntfy --domain ntfy.example.com` (check first with `--dry-run`).
   This only changes the ingress (an nginx reload) — the container is not recreated, so there is no downtime and no
   redeploy. (`apps add` on an existing name returns 409; `remove` + `add` is no longer needed.)
5. Rollback: `weglarka apps remove ntfy` and start the old container in Coolify again (do not delete it right away).

ntfy.zig has no data, so `recreate` is safe.

## Next steps

- [Webhooks: GitHub and Forgejo](webhooks.md) — auto-update when a new image is pushed.
- [Volumes](volumes.md) — apps with data.
