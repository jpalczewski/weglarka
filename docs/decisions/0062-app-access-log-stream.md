# 0062 — An app's access log as a filtered stream

Status: proposed (2026-10-31, issue #52). Builds on ADR 0057 (the framed log stream, `admin` scope, streams that end
with their token) and ADR 0056 (token listener).

## Problem

`weglarka logs` shows what an app's container printed. It does not show the requests that reached the app through its
domains: for that the operator reads the ingress nginx. nginx writes one JSON line per request to its stdout, with an
`app` field, in **one log shared by every app** (`docs/guides/access-log.md`). Handing that log to a client, even
an `admin` one scoped to a single app in the CLI, would show it every other app's traffic.

Threats and constraints, in priority order:

- **A client sees another app's traffic.** The boundary between apps has to hold in the daemon, not in a client that
  filters for itself.
- **Request data is sensitive.** Client addresses, paths and user agents identify people and can carry identifiers.
- **A crafted request fakes the boundary.** `$http_user_agent`, `$uri` and `$host` are attacker-controlled text inside
  the log line.
- **RAM.** The shared log can be large; a view of "the last N requests of one app" must not buffer it.

## Decision

1. **The daemon filters.** `GET /v1/apps/{name}/access` reads the nginx container's log, keeps the lines of that app
   and streams them as frames (`AccessFrame`, the framing of ADR 0057). The daemon is the only component that reads the
   shared log for a client.
2. **Filter by `app`, not by `host`.** With path routing (ADR 0031) one domain serves several apps, so the host does not
   identify an app. nginx sets `$app` per `server`/`location`. A request nginx could not attribute (`app: "-"`) belongs
   to no app and is outside this view.
3. **A line is parsed, never searched.** A line is decoded with `serde_json` into a private struct holding `app` and the
   fields of `AccessEntry`; the app comes from that field, and no text search of the raw line decides anything, so
   `"app":"other"` inside a user agent (escaped by `escape=json`) cannot change the match.
4. **`admin` scope, `Body::Credential`.** Addresses, paths and user agents can be sensitive, and unlike a spec they
   cannot be redacted. A later `read` view would be a separate decision with its own projection.
5. **An allowlist of fields.** A parsed line becomes an `AccessEntry` (no `app`; the client knows it) and is serialised
   anew. Unknown fields in the log never leave the daemon, so a future nginx field is a deliberate contract change.
6. **Filters in the query** (`status`, `method`, `path` prefix, `host`) are validated as strictly as the logs query and
   applied in the daemon; they never reach Podman. `tail` counts **matching** lines, not lines of the whole log.
7. **Two-phase read.** libpod does not signal the end of history in follow mode, so the daemon reads history with
   `follow=false` and then, for `follow=true`, opens a second read with `since = T`, where `T` was taken **before** the
   history read. Matching lines are collected in a ring of the last `tail` lines (byte budget `MAX_RING_BYTES`, 1 MiB)
   and sent in order after the history ends; without `tail` they are sent as found. The default window is the last hour;
   there is no upper limit on `since`, since the ring bounds memory and a scan ends when the client hangs up or the token
   expires.
8. **At-least-once between history and follow**, as in ADR 0057: `since` is inclusive and lines carry no sequence
   number, so a request near `T` can appear in both phases. There is no deduplication; a reconnecting client passes
   `since` and accepts overlap.
9. **Only stdout.** nginx's stderr is `error_log`, not the access log.
10. **Bounded lines.** A line longer than 16 KiB is skipped and counted, never buffered whole; an unparseable line is
    skipped and counted. Bytes are converted with `from_utf8_lossy` first, because `$uri` may hold non-UTF-8 bytes.
11. **Audit.** One line when the stream ends: caller, app, shape of the query (`filtered: bool`, never the filter
    values), counts (`scanned`, `frames`, `skipped`), duration and why it ended. When lines were skipped, some were
    scanned and none matched, a content-free `warn` signals that the nginx format may have drifted from `AccessEntry`.
12. **Parsing and filtering are pure functions** without I/O, so shipping the same lines to Loki (#82) can reuse them.

Invariants for implementers: the client never receives a line whose parsed `app` differs from the requested app; the
log format in `weglarka-ingress` stays the single source of truth, and a test substitutes sample values into it for
every client-address shape and parses the result into `AccessEntry`; no `apps.toml`/`state.toml` field and no
`spec_hash` change.

## Consequences

- New endpoint `APPS_ACCESS` (`admin`, `Body::Credential`), new `weglarka access <app>` command, `AccessFrame` /
  `AccessEntry` / `AccessQuery` in `weglarka-api`. Additive; older daemons answer `404` and the CLI says the versions
  may differ.
- Limits an operator should know (documented in `docs/guides/access-log.md`): successful requests on
  `access_log_skip_paths` are not in the log; `app: "-"` traffic is not shown; the log belongs to the nginx container,
  so history disappears when it is recreated; the window is bounded by what the container runtime retains.
- Tests: compatibility of `LOG_FORMAT` with `AccessEntry`, the boundary between apps (including a forged user agent),
  filters, the ring, token expiry during a scan of non-matching lines, hang-up releasing the Podman stream, and the
  call order against `FakePodman`.

## Rejected alternatives

- **Raw access to the nginx log** (a client filtering for itself). There is no boundary between apps: any caller of the
  endpoint would see every app's traffic.
- **Loki as the only source.** Heavy for a small host and optional (#82); this view must work with nothing but the
  daemon and Podman.
- **Filtering by `host`.** Wrong under path routing, where one domain serves several apps.
- **Substring search for `"app":"name"`.** Forgeable through any attacker-controlled field of the line.
- **`tail` as the nginx `tail`.** It would count other apps' lines and return fewer matches than asked.
- **Deduplicating between history and follow.** Needs a stable line identity the log does not have; overlap is cheap and
  the client already tolerates it for `logs`.
