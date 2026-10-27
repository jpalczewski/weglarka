# 0021 — Notifications: engine events → severity → dedup → durable outbox → ntfy

Status: accepted (2026-10-24, issue #38). Crash-loop detection: ADR 0022 (issue #112). Mail fallback: issue #113.

## Problem

A failed deploy, a rollback or a crash-looping app is visible only in the daemon log
(`journalctl --user -u weglarka`). The operator learns about a broken deployment when a user does.

What has to be pushed, and what makes each case hard:

- **Deploys and rollbacks** already exist as domain events (`weglarka_core::events::Event`,
  `EventSink`), but the only sink logs via `tracing`.
- **The notify path goes down exactly when it matters.** The ntfy server is meant to be an app hosted by
  Węglarka itself, so a deploy of ntfy kills the endpoint that would report the deploy.
- **Flapping.** A health gate that keeps failing, a webhook that keeps re-triggering or a container that
  restarts every minute must not produce a notification per attempt.
- **Noise routing.** "deployed" is informational, "deploy failed" is a warning, "rollback failed" is
  critical; a phone should not buzz for container pruning.
- **Constraints.** `EventSink::emit` is synchronous and is called **while the engine mutex is held**
  (`Reconciler::lock`, held through pull and the health gate), so the sink can never block or do I/O.
  The image is `scratch` with no CA store, and a notification may carry an access token, so plaintext
  HTTP to a public host is not acceptable. Secrets never go into TOML files, `Debug` or logs. The
  house order is security → elegant/extensible code → RAM.

## Decision

**A pipeline with one durable seam, in a new crate `weglarka-notify`:**

```
engine (holds the mutex) --Event--> Sink (bounded mpsc, try_send) --> worker
worker: render -> severity filter -> dedup window -> outbox (per channel) -> channel.send -> ntfy
```

1. **`Severity` lives in the domain** (`weglarka_core::events`): `debug | info | warning | critical`,
   with `Event::severity()`. The mapping is part of the domain, not of a channel adapter:
   `RollbackFailed` critical; `DeployFailed`/`RolledBack` warning; `Pruned`, `WaitingForDependency`,
   `WebhookDuplicate` debug; everything else info. `TracingSink` keeps its current log levels (debug
   events stay at `info`, so the daemon log volume does not change).

2. **The sink never does I/O.** `weglarka_notify::Sink` wraps a bounded `mpsc::Sender<Event>` and uses
   `try_send`; a full queue drops the event with a warning (it is still in the log). At human deploy
   rates the queue never fills — the worker's only blocking work is a network call, never a mutex the
   engine waits on.

3. **The outbox is the durable seam, and the single source of truth for pending work.**
   `<state dir>/notifications.toml`, mode 0600, written with
   `weglarka_core::state::write_atomic` after every mutation:
   one item per **(rendered message, channel)**, holding the rendered fields (title, body, priority,
   tags, click), `created`, `attempts`, `next_attempt`. Rendering at enqueue time means an upgrade or a
   config change never rewrites queued history, and a per-channel item means the mail fallback (#113)
   needs no migration. Retries: 30 s doubling to 30 min (`backoff`), give up after 12 attempts
   (≈3.5 h); the queue is capped at 200 items and 7 days, oldest first, every drop counted and
   reported. A corrupt file is renamed to `notifications.toml.corrupt-<unix>` and the queue starts
   empty — notifications are not worth refusing to start the daemon for.
   **Exception to the `deny_unknown_fields` rule:** this file is internal transient state; a field
   added by a newer daemon must not stop an older one when the image is rolled back. The file never
   contains a token.

4. **ntfy via its JSON publish API** — `POST <base>/` with
   `{topic, title, message, priority, tags, click}`, `Authorization: Bearer <token>` when configured.
   Not the header form: `Title:`/`Message:` header values must be ASCII and a UTF-8 title would need
   escaping. `[notify.ntfy]` takes `url`, an optional `host` (= `Host` header **and TLS server name**)
   for the internal route `url = "http://weglarka-nginx:8080"` + `host = "ntfy.example.com"`, `topic`,
   optional `token_file` and `min_severity`. A minimal HTTP/1.1 client (one `POST` per connection,
   `Connection: close`, 10 s timeout, no redirects) speaks to it; status 2xx = delivered,
   401/403/404/413 and redirects are permanent (dropped with `last_error`), 408/429/5xx and network
   errors are retried.

5. **TLS with `rustls` (provider `ring`) and `webpki-roots`.** The `scratch` image has no `/etc/ssl`, so
   system roots are not an option, and bundling Mozilla's roots keeps the daemon self-contained. The
   provider is passed explicitly (`builder_with_provider`) so nothing installs a process-wide default;
   ALPN is pinned to `http/1.1`; hostname verification is on and SNI follows `host` (not the connect
   address). `rustls`/`ring` are pure Rust + C with no OpenSSL; the binary grows by ~1–2 MB.

6. **Severity routing per channel** (`min_severity`, default `info`): messages below it are dropped
   **before** dedup, so the debug events can be opted into but never open windows otherwise. ntfy
   priority maps from severity (2/3/4/5) and tags are emoji shortcodes
   (`white_check_mark`, `warning`, `rewind`, `rotating_light`, …).

7. **Dedup of flapping = per-key windows in memory.** The key is `kind:subject` (`deploy-failed:ntfy`,
   `pruned:<container>`, …). The first event of a key in the window (default 300 s,
   `dedup_window_secs = 0` disables) is delivered; later ones are counted; when the window closes one
   summary is delivered (`<n> more: <last title>`, severity = the worst of the window). Windows are not
   persisted: after a restart the next event opens a fresh window. A success does not reset a failure
   window — an app that alternates ok/fail still produces one failure report per window.

8. **Operator surface.** `GET /v1/notifications` (channels, pending, dropped, last error, last
   delivery), `POST /v1/notifications/test` (a test notification delivered **now**, bypassing the
   outbox and dedup; `409` when notifications are not configured) and `weglarka notify status|test`.
   `notify test` is the install-time verification of URL, DNS, ingress route and token; a refused test
   exits with code 7.

9. **Configuration is opt-in and validated at startup.** `HostConfig.notify: Option<NotifyConfig>` with
   `skip_serializing_if`, so an existing `weglarka.toml` parses and the config snapshot is unchanged.
   A bad URL, topic or token file stops the daemon (`StartError::Notify`) instead of a silent no-op —
   once the operator asked for notifications, a broken section must be loud. The token is read once
   from a 0600 file (loose permissions refused, same rule as `secrets.toml`), must be printable ASCII
   (it becomes a header) and never appears in `Debug`, logs, errors or the outbox.

**Invariants an implementer must preserve:** `emit` never blocks or does I/O; the outbox is persisted
before delivery and is the only source of pending notifications; no secret in the outbox, `Debug` or
logs; `notify test` bypasses the outbox; a new channel goes behind the `Channel` trait and is stored by
name in the outbox; `Severity` ordering is `debug < info < warning < critical`.

## Consequences

- New crate `weglarka-notify` (dependencies: `weglarka-core`, `serde`, `serde_json`, `toml`, `tokio`,
  `thiserror`, `tracing`, `rustls`, `tokio-rustls`, `webpki-roots`; dev: `insta`, `tempfile`), wired in
  `weglarka-daemon` (`start`, `Daemon.notify`, `Running::stop`) and in `weglarka-api` (two endpoints,
  additive). Per-crate versioning picks the crate up automatically (`release-plz.toml` entry).
- **Rollback caveat:** `weglarka.toml` uses `deny_unknown_fields`, so an older daemon refuses to start
  with a `[notify]` section. Remove the section before downgrading (documented in [the notifications guide](../guides/notifications.md)).
- The daemon must be able to reach the ntfy endpoint: `notify test` is the check. For a self-hosted ntfy
  the documented paths are its public HTTPS domain or the internal `weglarka-nginx:8080` + `host` pair.
- Tests: the notify crate covers message rendering (insta snapshots), the severity table, dedup windows
  (fake clock), the outbox (round trip, caps, prune, corrupt file, tolerant parse, backoff), the URL
  parser, the HTTP client against a mock server (2xx/4xx/5xx, timeout, refused) and TLS against a
  local server with the self-signed fixture (`tests/fixtures`, test-only). The daemon integration test
  runs the whole daemon on `FakePodman` against a mock ntfy: status/test endpoints, one publish per
  deploy, an undeliverable deploy kept in the outbox with `last_error`. The CLI tests cover the two
  commands and the status rendering.
- Follow-ups: the SMTP mail fallback (#113). Crash-loop/unhealthy detection shipped separately
  (`docs/decisions/0022-crash-loop-detection.md`) and emits through the same event sink.

## Rejected alternatives

- **`reqwest` / `hyper` + a TLS crate**: a large dependency tree for one `POST`; the repo already
  hand-writes its libpod HTTP and health probe.
- **System CA certificates**: the image is `scratch`; adding a CA bundle means a bigger image and a
  mutable trust store. `webpki-roots` is deterministic and versioned with the binary.
- **Plain HTTP only** (the internal ingress route as the only target): rules out `ntfy.sh`, external
  servers and every SMTP credential path.
- **ntfy header-form publish** (`Title:`, `Priority:`): ASCII-only headers, and a non-ASCII title would
  need ad-hoc escaping.
- **Delivering synchronously from the engine sink**: the sink runs under the engine mutex; one slow
  network call would stall every deploy.
- **A JSONL append log with a separate compaction**: the outbox is tiny; a whole-file atomic replace is
  simpler and crash-safe, and it keeps a rewrite of a single item trivial.
- **Persisting dedup windows**: extra state for a mechanism whose worst case after a restart is one
  extra notification.
- **One topic per app or per severity**: one topic + `min_severity` routing keeps the operator's
  subscription list stable; per-app routing can come later if it is ever needed.
- **`lettre` / SMTP in this PR**: the pipeline and ntfy are the risk; mail gets its own change (#113)
  behind the same `Channel` trait.
- **Reacting to libpod events for crashes**: the action names need verification on a real Podman 6 host
  and `FakePodman` would have to script the stream; polling `RestartCount` is deterministic and testable
  (#112).

## Amendment: shared HTTP client (#219)

The hand-written client was replaced by `reqwest` through the shared `weglarka-http` crate (same
`ring` provider passed explicitly, bundled `webpki-roots`, ALPN `http/1.1`, 10 s timeout, no redirects,
no connection pooling). One behaviour changed: `host` is now accepted only with an `http://` URL.
`reqwest` verifies the certificate against the host in the URL, so the former "SNI follows `host`"
combination over TLS is rejected at configuration time instead of silently verifying a different name.
The documented internal route (`http://weglarka-nginx:8080` + `host`) is plain HTTP and unaffected.
