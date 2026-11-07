# Basic auth

`ingress.auth = "basic"` puts one shared password in front of a static site, a container app, or a single environment
of a `[sites]` site. Węglarka's nginx asks for it with the browser's own credential dialog and refuses every request
that does not carry it, in `behind` and `edge` mode alike — no identity provider, no login page. Available from the
release that closes [#169](https://github.com/jpalczewski/weglarka/issues/169); design and rejected alternatives:
[ADR 0081](../decisions/0081-http-basic-auth.md). The fields exist since state schema 25, and that release is the first
one that enforces them.

The intended use is a staging preview or an internal document site that has to be reachable from anywhere without
being public. For real accounts, groups and a login page use [forward auth](forward-auth.md) instead.

## A static site

```toml
[apps.docs]
kind = "static"
image = "registry.example.com/me/docs:latest"
domains = ["docs.example.com"]

[apps.docs.ingress]
auth = "basic"
auth_secret = "basic-auth"           # name of the secret holding the credentials, never the value
auth_exempt_paths = ["/robots.txt"]  # optional
```

A static site's `ingress` accepts these three fields next to its file-serving options
([static sites](static-sites.md)); streaming, body-limit and forward-auth options stay rejected, because a site has no
upstream behind nginx. `auth = "forward"` on a static site is still refused (see below).

## A container app

```toml
[apps.staging]
image = "registry.example.com/me/api:latest"
domains = ["staging.example.com"]
port = 3000

[apps.staging.ingress]
auth = "basic"
auth_secret = "staging-auth"
```

Rules checked when `apps.toml` is read:

- `auth_secret` is **required** with `auth = "basic"` and rejected with any other mode. It is a secret **name**
  (`[A-Za-z0-9_-]`, 1–64 characters), never a value.
- `auth_policy` and `auth_groups` are forward-auth fields and are refused with `basic`.
- `oauth_resources` is refused with `basic`: an OAuth resource checks its own tokens in `Authorization`, exactly where
  the shared password sits, so the two cannot guard the same host.
- `auth_exempt_paths` needs `auth = "forward"` or `auth = "basic"`; with the default (`none`) it is refused.

The credentials themselves never appear in `apps.toml`, only the name of the secret that holds them.

## One environment of a site

Auth belongs to an environment, not to the artifact, so a preview can be protected while production stays open even
though both serve the same digest:

```toml
[sites.blog]
kind = "static"
image = "ghcr.io/me/blog"

[sites.blog.env.dev]
track = "main"
domains = ["dev.example.com"]
auth = "basic"
auth_secret = "dev-auth"
auth_exempt_paths = ["/robots.txt"]

[sites.blog.env.prod]
promote_from = "dev"
domains = ["example.com"]
```

The fields live in `[sites.<site>.env.<env>]`, next to `domains`; `[sites.<site>.ingress]` ([site
environments](site-environments.md)) takes no auth field. The secret is scoped to the instance the environment expands
into, `<site>-<env>` — here `blog-dev`, so `weglarka secrets set blog-dev dev-auth < creds.txt`.

## The credential secret

The value is UTF-8 text, one credential per line (`weglarka_model::basic_auth` parses it before anything is rendered):

```text
alice:Wq3-hZ8tLm2pR5vX
bob:Tb7-kN4sYd9cJ1fG
```

- **User:** 1–64 characters of `[A-Za-z0-9._-]`, no `:`.
- **Password:** 12–128 printable ASCII characters (`0x21..=0x7E`) — no spaces, no control characters. A password may
  contain `:`; the line is split at the first one.
- The last line needs no trailing newline; empty lines are ignored, so a value pasted with a newline at the end is
  fine.
- A user declared twice is an error, and one secret holds at most **32 users**.
- A secret with **no** credential at all (empty, or only empty lines) is an error, not "nobody may log in": the
  instance answers `503` like a missing secret (see below).
- A parse error names the **line number** and nothing else, never the content. Logs and `Debug` output carry the user
  names only.

Set it through the CLI; the value never goes into an argument (`ps`, shell history, logs) but comes from stdin or a
file:

```sh
openssl rand -base64 24                    # one password, 32 printable characters — do this per user
printf 'alice:%s\nbob:%s\n' "$(openssl rand -base64 24)" "$(openssl rand -base64 24)" > creds.txt
chmod 600 creds.txt

weglarka secrets set docs basic-auth < creds.txt             # the value from stdin
weglarka secrets set docs basic-auth --from-file creds.txt    # only for a file the CLI's user may read
weglarka secrets list docs                                    # NAME, FINGERPRINT, UPDATED — never a value
```

The CLI strips one trailing newline by default (`--raw` keeps the bytes); neither matters here, because empty lines
are ignored. Delete `creds.txt` once the secret is set. A `secrets set` of an existing name overwrites the whole value:
the credentials are replaced, not merged.

The secret is read by the daemon only. It is not mounted into the app and does not belong in the spec's `secrets`
list; `auth_secret` is the reference, and the daemon reads it on every ingress apply, so overwriting the secret takes
effect at once (an nginx reload, no container recreate).

## Exempt paths

`auth_exempt_paths` lists paths that carry no auth at all — for non-browser clients with their own tokens. The syntax
and the rules are the ones described in [forward auth](forward-auth.md):

- an entry ending in `/` is a prefix (`/mcp/` exempts `/mcp` and everything below it), anything else matches that exact
  path;
- an exempt path is a full copy of the app's location without the check — structural, not an access rule;
- on an app routed by `paths`, every entry must equal one of the prefixes or lie below one;
- an entry must not overlap `streaming_paths`;
- an `[admin.http] clients` app gets `/_weglarka/api` carved out by Węglarka itself, without auth, as under forward
  auth ([admin panel](admin-panel.md)).

The daemon's `health.http` probe needs no exemption: it arrives on the ingress probe socket and passes
([ADR 0054](../decisions/0054-health-probe-socket.md)).

## The 401 answer

A request whose `Authorization` header is not a key of the rendered map gets:

```text
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="Restricted", charset="UTF-8"
```

- A browser shows its credential dialog; `curl -u alice:<password> https://docs.example.com/` works.
- The body is nginx's own error page.
- **The 401 carries none of the site's security headers** (`ingress.security_headers`,
  [`ingress.static.security_headers`](security-headers.md)): the `add_header` of the auth check replaces the inherited
  ones. Fine for an empty error page, but a monitoring check that expects HSTS or `nosniff` on every response will not
  find them on a 401.
- The comparison is an exact string match, so the client must send the scheme as **`Basic`**, capital `B`, and the
  header exactly as `Basic <base64 of user:password>`. A `basic` written in lower case, or extra whitespace, gets a
  `401` even though RFC 7617 allows either case. Every common client (browsers, `curl`, the usual HTTP libraries)
  sends `Basic`, and the only effect of the mismatch is that such a client cannot get in.

## What the upstream receives

On a protected path of a container app nginx **removes** the `Authorization` header before proxying
(`proxy_set_header Authorization ""`), so the shared password never reaches the app and cannot end up in its logs. An
app that needs its own `Authorization` header (an API with bearer tokens) either gets those paths exempted or is
protected some other way.

On an exempt path the header is passed through unchanged — that is what those paths are for. A static site has no
upstream at all: nginx only compares the header with the map and serves the file.

## A missing, empty or invalid secret

A protected instance whose credentials could not be read renders `return 503;` in **all** of its locations: the app
serves nothing until the secret is fixed, and no content can leak through a half-configured route. Fail closed is the
generator's default, so this never makes `nginx -t` fail for the whole host — the other apps on the host keep serving.

`weglarka doctor` reports `ingress.basic_auth`: for every active instance with `auth = "basic"` it checks that the
secret exists, parses and produced its map file. The daemon logs the instance and the secret **name** only.

The usual causes are a secret that was never set, one set on the wrong instance (a site environment's secret is
`<site>-<env>.<name>`, not the app's), one removed with `secrets remove`, a ten-character or space-containing
password, or the same user twice. Fix it with `weglarka secrets set <instance> <name> < creds.txt` — the next apply
writes the map file and reloads nginx.

## Passwords and rate limiting

There is **no rate limiting** on `401`s: anyone who can reach the domain may guess as fast as they like. Use one long
random password per user; `openssl rand -base64 24` (32 printable characters) is the intended size. Rise above the
12-character minimum, do not reuse a password from anywhere else, and remember that basic auth sends the password on
every request — it is only as private as the TLS in front of it, so serve it over HTTPS only.

Revoking one user means overwriting the whole secret for everybody (`secrets set` replaces the value, not one line);
`secrets list` shows a fingerprint that changes with the value.

## On disk, in reloads and in backups

- The daemon renders `<nginx_conf_dir>/auth/<instance>.map` (directory `0700`, file `0600`, written atomically), one
  line per credential: `"Basic <base64 of user:password>" 1;`.
- The **master** process reads the map at start and at every reload; `nginx.conf` itself never holds the credentials
  (it is `0644`). `<nginx_conf_dir>` is mounted as a whole already, so no new mount appears and the ingress container
  is never recreated.
- A changed credential forces `nginx -t` plus `SIGHUP` even when `nginx.conf` is byte-identical: the credentials are
  deliberately **not** fingerprinted into that readable file (an unkeyed hash of a password can be attacked offline).
  The apply compares the bytes it would write with the file on disk, and any change, addition or removal of a map file
  reloads nginx.
- Map files of instances that are no longer protected are deleted by the next apply.
- **A backup of `<nginx_conf_dir>` now contains the credentials.** The value in the map is base64 of `user:password`,
  not a hash: anyone who reads it can log in. Such a backup already holds the TLS private keys, and it must now be
  treated like `secrets.toml` (`0600`, never in a public artifact store or a ticket).

## Basic auth or forward auth

- `auth` is one field with `none`, `forward` and `basic`, so the two protected modes are mutually exclusive by type:
  there is no way to declare both on one instance.
- Basic auth needs no `[identity]` section, no provider app and no cookie domain, and it works for `kind = "static"`.
- Forward auth on a static site is tracked in [#638](https://github.com/jpalczewski/weglarka/issues/638);
  `auth = "forward"` there stays refused.
- `auth_exempt_paths` works with both modes and means the same in each: the path carries no check.

## Rollback

The new `apps.toml` fields raised the state schema to version 25 ([state schema](state-schema.md), [ADR
0023](../decisions/0023-state-schema-version.md)): the first write after the upgrade stamps `schema_version = 25`.
`apps.toml` uses `deny_unknown_fields`, and an older daemon also refuses a file whose `schema_version` is newer than
it understands, so it will not start while the fields are still there.

Before downgrading to a release with schema 24:

- remove `auth = "basic"` and `auth_secret` from every `[apps.<x>.ingress]`; an `auth_exempt_paths` left behind needs
  `auth = "forward"` on that older release, so remove it too (or keep the app on forward auth);
- remove `auth`, `auth_secret` and `auth_exempt_paths` from every `[sites.<site>.env.<env>]`;
- drop the `schema_version = 25` marker, or restore `apps.toml` and `state.toml` from the backup taken before the
  upgrade;
- delete `<nginx_conf_dir>/auth/`: an older daemon does not know the directory, does not prune it, and it holds the
  credentials.

Without the fields those instances are simply public again — the older release enforces no password. See
[verification and rollback](verify-and-rollback.md).
