# Access log

The edge nginx writes one JSON line per request to its stdout (and so to the journal). A single chatty
client can dominate it: a CI runner polling every 2 s is ~43k lines a day, all `200`, all zero information.
`ingress.access_log_skip_paths` lets an app name such paths so that their **successful** requests are left
out of the log.

```toml
# apps.toml
[apps.forgejo.ingress]
access_log_skip_paths = ["/api/actions/runner.v1.RunnerService/", "/healthz"]
```

Via the CLI: `weglarka apps add forgejo ... --access-log-skip-path /healthz`, and
`weglarka apps update forgejo --access-log-skip-path /api/poll/` / `--remove-access-log-skip-path /api/poll/`
(both repeatable).

- **Syntax:** an entry starts with `/`, uses segments of `[A-Za-z0-9_.-]` and is at most 128 bytes. An entry
  that **ends in `/` is a prefix** (`/api/poll/` covers everything below it); any other entry matches that exact
  path. Matching is done on the path without the query string (nginx `$uri`, the same value the log prints
  as `path`), after any `strip_prefix` rewrite. A bare `/` is rejected: it would silence the whole app. The
  app needs at least one domain.
- **Errors are still logged:** a request is skipped only when its status is below 400. A failing poll
  (`401`, `502`, ...) shows up as usual, so a broken runner or a scanner hitting the same path is not hidden.
- **Per app:** an entry applies to the app that lists it, also when it shares a domain with other apps under
  [path routing](path-routing.md). Apps that list nothing log everything.
- **Default:** empty. An app without the field renders the same `nginx.conf` as before, byte for byte; once
  any routed app lists a path the config gains two `map` blocks (`$weglarka_skip_path`, `$weglarka_loggable`)
  and the global `access_log` gets `if=$weglarka_loggable`. Both `edge` and `behind` modes are covered.
- **Ingress only:** the change re-renders `nginx.conf`, checks it with `nginx -t` and sends SIGHUP; the
  container is not recreated and `spec-hash` does not change. `--no-streaming` keeps the list.

## Reading `remote_addr`

In the log, `remote_addr` `169.254.1.2` is **not a client**. It is the gateway address of rootless Podman
networking (pasta): a request that comes from the same host, for example a runner on this machine reaching
the edge through the host's public IP, is seen with that source. Requests from outside carry the real client
address (see [edge CDN](edge-cdn.md) for the address behind Cloudflare). Do not rate-limit or ban on
`169.254.1.2`, and do not read it as one very busy visitor.

## Rollback

This is a state-file schema change (version 9): `apps.toml` and `state.toml` get `schema_version = 9` on the
first write after the update. Before a downgrade, remove `ingress.access_log_skip_paths` from the apps
(`weglarka apps update <app> --remove-access-log-skip-path <path>`) or restore the files **from a backup taken
before the update** (see [state schema](state-schema.md)).
