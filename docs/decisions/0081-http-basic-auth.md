# 0081 — HTTP Basic auth in the ingress nginx

Status: proposed (2026-11-07, issue #169)

## Problem

Some sites and apps should sit behind a shared password (staging previews, internal docs) without running an identity
provider. Forward auth (ADR 0052) needs `[identity]`; this is the lightweight, self-contained option, enforced by the
ingress nginx in both `behind` and `edge` modes, for `kind = "static"` sites and for container apps.

Constraints, in priority order (CLAUDE.md): security → elegant, extensible code → RAM economy. Specifically:

- **The worker cannot read a daemon-owned `0600` file.** nginx opens `auth_basic_user_file` in the **worker**
  (uid 101 in the ingress range, ADR 0036) on every request; only the master runs as container uid 0 (the runtime
  user) and can read `0600` files, which is how the TLS keys are protected. A `0600` htpasswd file answers 500, a
  `0644` one exposes the hashes to every host user, and chowning into the ingress range needs a user-namespace helper
  (libpod has no chown endpoint).
- **Hashing per request is expensive.** The image (`nginx:1-alpine`, musl) supports bcrypt and sha-crypt, not argon2.
  The ingress runs `worker_processes 1`, so a bcrypt verification at cost 10 blocks the event loop for tens of
  milliseconds on every authenticated request: one client with valid credentials slows down every site.
- **Fail closed.** A protected route with missing, empty or invalid credentials must never serve content.
- **Reload, never recreate**, and the new fields stay outside `spec_hash`.

## Decision

**The credentials live as a named secret of the instance. The daemon renders them into an nginx `map` file `0600`
that the master reads at load and reload, and the protected locations reject a request whose `Authorization` header is
not a key of that map.**

### Model

```toml
[apps.docs]
kind = "static"
image = "ghcr.io/me/docs"

[apps.docs.ingress]
auth = "basic"                      # IngressAuth { None, Forward, Basic }
auth_secret = "basic-auth"          # secret name in the instance scope (ADR 0024), never a value
auth_exempt_paths = ["/robots.txt"] # existing field, now valid for `forward` and `basic`

[sites.blog.env.dev]                # site environments (ADR 0050/0075)
auth = "basic"
auth_secret = "basic-auth"
auth_exempt_paths = ["/robots.txt"]
```

- `IngressAuth` gets a third variant `Basic`. One enum keeps forward and basic auth mutually exclusive by type; no
  cross-field rule is needed.
- `AppIngress::auth_secret: Option<String>` (secret name syntax `[A-Za-z0-9_-]{1,64}`). Required when
  `auth = "basic"` and rejected otherwise.
- `auth_exempt_paths` keeps its syntax and semantics (structural exemption: the location has no auth at all). It is
  accepted with `forward` **or** `basic`, and rejected with `none`.
- `kind = "static"`: the static allowlist (`state.rs`) accepts `auth = "basic"`, `auth_secret` and
  `auth_exempt_paths`. `auth = "forward"` on a static site stays rejected: that is #638, because the
  `RouteBackend::Directory` locations have no forward-auth rendering yet.
- `auth = "basic"` together with `oauth_resources` is rejected in this version: an OAuth resource checks its own
  tokens in `Authorization`, which conflicts with Basic credentials on the same host.
- `EnvSpec` gets `auth`, `auth_secret` and `auth_exempt_paths`, which `environments::expand` copies into the
  instance's `spec.ingress`. The secret is scoped to the expanded instance (`<site>-<env>`), so a preview environment
  can be protected while production is not, even though both serve the same digest. `SiteIngress` gets no auth
  fields: protection is a property of an environment, not of the artifact.
- Every new field is optional and unset by default. `AppIngress` is outside `HashInput`, so nothing changes
  `spec_hash`. The new `apps.toml` fields bump `state::SCHEMA_VERSION` 24 → 25 with a `SCHEMA_STEPS` entry
  (ADR 0023). A downgrade to 24 rejects an `apps.toml` that uses them (`deny_unknown_fields`); remove them first.

### Secret format

The secret value is UTF-8 text, one credential per line: `user:password`. The model owns a single parser
(`weglarka_model::basic_auth`), and the daemon calls it before rendering. The rules:

- user `[A-Za-z0-9._-]{1,64}` (no `:`);
- password: printable ASCII `0x21..=0x7E`, 12–128 bytes (no spaces or control characters, so nothing in the line
  needs escaping in `nginx.conf`, and a value that was pasted with a newline is not silently truncated);
- lines end in `\n`; empty lines are ignored, anything else that does not match is an error; duplicate users are an
  error; at most 32 users;
- the parsed type implements `Debug` without the passwords (`user` only), and parse errors name the line number,
  never its content.

Plaintext at rest is not new: `secrets.toml` already stores every secret as plaintext `0600`. Hashes would not
protect anything here, because the value the map compares against is password-equivalent anyway.

### Rendering

- The daemon writes `<nginx_conf_dir>/auth/<instance>.map` (directory `0700`, file `0600`, atomic write), one line
  per credential: `"~^Basic <base64(user:password)>$" 1;` — an anchored, case-sensitive regex key, with `+` written
  as `[+]` (the only regex metacharacter of the base64 alphabet). Plain `map` keys are compared **ignoring case**,
  which would accept the base64 of a different password whose letters differ only in case; found by the end-to-end
  test before the feature was enabled (#169). `<nginx_conf_dir>` is already mounted whole, so no new
  mount appears and the ingress hash stays the same (no recreate).
- The generator renders, per protected instance, in `http {}`:

  ```nginx
  map $http_authorization $weglarka_basic_<n> {
      default 0;
      include /etc/nginx/auth/<instance>.map;
  }
  ```

  where `<n>` is the instance's index in the plan (nginx variable names cannot contain `-`). When any such map
  exists, `http {}` also sets `map_hash_bucket_size 512;`, because a key can be up to about 270 bytes and the default
  bucket makes `nginx -t` fail. It is the **first** directive of `http {}`: nginx rejects it as a duplicate once any
  `map` block has been parsed (found while implementing the generator, #647).
- Every location of a protected app, except `auth_exempt_paths` and the admin relay carve-out (ADR 0060, unguarded as
  it is under forward auth), answers a request that does not match with:

  ```nginx
  if ($weglarka_basic_ok_<n> = 0) {
      add_header WWW-Authenticate 'Basic realm="Restricted", charset="UTF-8"' always;
      return 401;
  }
  ```

  `$weglarka_basic_ok_<n>` is a second `map` that is `1` when `$weglarka_basic_<n>` is `1` **or** the request came in
  on the probe socket (`$weglarka_probe`, ADR 0054), so the daemon's health probe of a container app works without an
  exemption. The probe map is rendered whenever an active app uses forward **or** basic auth. Only `return` sits
  inside the `if`. The `401` response does not carry the site's security headers (`add_header` inside `if` replaces
  the inherited ones); that is acceptable for an error page with no content.
- A protected container location sends `proxy_set_header Authorization "";`, so the upstream never sees the shared
  password. Exempt locations pass `Authorization` through (that is what they are for: clients with their own tokens).
- The match is an exact, case-sensitive comparison of the whole header (the regex key is anchored at both ends). A
  client that sends the scheme as `basic` instead of `Basic`, or extra whitespace, gets a 401; RFC 7617 allows either case, but every common client sends `Basic`, and the error only ever
  locks a client out.
- `NginxOptions` gets `basic_auth: BTreeMap<InstanceName, String>`: protected instances whose map file was written,
  with the container path of the file. A protected instance **without** an entry renders `return 503;` in all of
  its locations, exactly like an unreleased site (`NginxOptions::unreleased`). Fail closed is therefore the
  generator's default, and a missing, invalid or unreadable secret never makes `nginx -t` fail for the whole host.

### Daemon

- On every ingress `apply`, for each active instance with `auth = "basic"`, the daemon reads the secret from the
  `SecretStore`, parses it, writes the map file and adds the entry to `NginxOptions::basic_auth`. A missing or invalid
  secret leaves the entry out (→ 503), is logged with the instance and secret **name** only, and is reported by a
  new `doctor` check, `ingress.basic_auth`. Map files of instances that are no longer protected are deleted.
- `secrets set`/`secrets remove` already call `Daemon::changed()`, which requests an ingress apply; no new trigger is
  needed.
- A changed credential must reload nginx even when `nginx.conf` itself is unchanged. Unlike the TLS material, the
  credentials are **not** fingerprinted into `nginx.conf` (it is `0644`, and an unkeyed hash of a password can be
  attacked offline). Instead, the apply compares the bytes it writes with the file on disk, and any change, addition
  or removal of a map file forces `nginx -t` + SIGHUP. Never a recreate.

## Consequences

- Operators: `weglarka secrets set <app> basic-auth` with `user:password` lines, then `auth = "basic"` and
  `auth_secret = "basic-auth"` in the spec. A guide `docs/guides/basic-auth.md` explains this, the exempt paths,
  the 503 when the secret is missing, the downgrade caveat, and that a backup of `<nginx_conf_dir>` now contains
  credentials (it already contains TLS keys).
- There is no rate limiting on 401s; the guide recommends long random passwords. Rate limiting is a separate issue.
- Code: `weglarka-model` (enum variant, fields, validation, parser, schema step, environments), `weglarka-ingress`
  (options, maps, locations, snapshots), `weglarka-daemon` (`ingress.rs`, `doctor.rs`, the read view in
  `app_view.rs`).
- Tests: model validation and parser unit tests; nginx snapshots for a static site and a container app in `behind`
  and `edge` (protected, exempt path, missing credentials → 503); daemon integration tests (file modes, deletion,
  reload without recreate, a credential change reloads); an e2e script against a real nginx (401 without
  credentials, 200 with each user, 200 on an exempt path, 503 without the secret, the probe socket passes, the
  upstream does not receive `Authorization`).
- Rollout: the model change first accepts the fields but rejects `auth = "basic"` ("basic auth is not enabled in
  this release"), like P0 of ADR 0052. The gate is lifted only after the generator and the daemon have merged, so no
  intermediate `main` can serve a protected route without enforcement.

## Rejected alternatives

- **htpasswd file with bcrypt hashes (`auth_basic_user_file`), `0644`.** Any host user who can traverse
  `<nginx_conf_dir>` (`0755`) reads the hashes, and bcrypt verification blocks the single worker on every request.
- **htpasswd file chowned into the ingress range.** Fixes the readability problem but needs a user-namespace helper
  (`newuidmap` or a one-shot container) only for this, and still pays bcrypt per request.
- **Argon2 hashes.** Not supported by nginx or musl `crypt(3)`.
- **Credentials or their hashes inline in `nginx.conf`.** The file is `0644` and readable by the worker; even hashes
  can be attacked offline.
- **A separate `basic_auth` table independent of `auth`.** Needs a cross-field rule to keep it exclusive with
  forward auth; the enum variant makes the conflict impossible to write.
- **`auth_request` to a daemon endpoint or a sidecar.** Moves a per-request check into a second process and adds a
  network dependency to every protected request, for no security gain over a map the master loads.
