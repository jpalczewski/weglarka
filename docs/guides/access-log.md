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

## Reading an app's requests: `weglarka access`

`weglarka logs` shows what an app's container printed; `weglarka access` shows the requests that **reached the app
through its domains**, taken from the ingress log above. The log is shared by every app, so the daemon does the
filtering: it keeps only the lines whose `app` is the one you named, and nobody else's traffic leaves it.

```bash
weglarka access web                          # the last 100 requests of the last hour
weglarka access web -f                       # and follow new ones
weglarka access web --since 10m --status 5xx
weglarka access web -n 20 --path /api --method POST --host web.example.com
weglarka --json access web -f | jq -r .remote_addr
```

Each line is `time status method host path request_time remote_addr request_id`; `--json` prints one JSON object per
request (`time`, `host`, `remote_addr`, `peer` behind a CDN, `method`, `path`, `status`, `bytes_sent`, `request_time`,
`upstream_response_time`, `request_id`, `user_agent`). Paths, hosts and user agents are chosen by the visitor, so on a
terminal control characters are replaced and a path can never start a line of its own.

| Flag | Meaning |
|---|---|
| `-f`, `--follow` | keep the stream open |
| `-n N` | the last N **matching** requests (at most 1000); default 100, none with `--since` |
| `--since DUR` | only newer requests (`90`, `10m`, `2h`); default window: the last hour |
| `--status` | one status (`404`) or a class (`5xx`) |
| `--method`, `--host` | exact match |
| `--path` | a prefix of the path (`$uri`: no query string, not percent-decoded) |

- **By app, not by host.** With [path routing](path-routing.md) one domain serves several apps, so the filter is the
  app nginx attributed the request to.
- **Scope.** The endpoint (`GET /v1/apps/{name}/access`) needs the `admin` scope: addresses and paths can identify
  people and cannot be redacted. See [admin API tokens](admin-api-tokens.md). Over a token the stream ends with the
  token and `weglarka access` reopens it itself, so a request near the renewal can appear twice.
- **Limits.** Successful requests on `access_log_skip_paths` are not in the log. Requests nginx could not attribute to
  an app (`app` is `-`, for example a scan of an unknown host) belong to no app and are not shown here. The log lives
  in the nginx container, so its history is gone when that container is recreated.
- **Cost.** `-n` is applied to matching requests, so the daemon reads the whole window to find them (a busy host and
  a window of days takes a while; a quiet app is not slower than a busy one). At most 1 MiB of entries is held in
  memory.

## Reading `remote_addr`

In the log, `remote_addr` `169.254.1.2` is **not a client**. It is the gateway address of rootless Podman
networking (pasta): a request that comes from the same host, for example a runner on this machine reaching
the edge through the host's public IP, is seen with that source. Requests from outside carry the real client
address (see [edge CDN](edge-cdn.md) for the address behind Cloudflare). Do not rate-limit or ban on
`169.254.1.2`, and do not read it as one very busy visitor.

## Rollback

This is a state-file schema change (version 10): `apps.toml` and `state.toml` get `schema_version = 10` on the
first write after the update. Before a downgrade, remove `ingress.access_log_skip_paths` from the apps
(`weglarka apps update <app> --remove-access-log-skip-path <path>`) or restore the files **from a backup taken
before the update** (see [state schema](state-schema.md)).
