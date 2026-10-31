# Metrics

Węglarka can serve a Prometheus `/metrics` endpoint ([ADR 0061](../decisions/0061-metrics-listener.md)). It is off by
default: without `[metrics]` there is no listener, no network and no cost. When on, the daemon listens on a TCP address
**inside its own container** and joins a dedicated Podman network; a scraper that joins the same network can read it.
Nothing is published on a host address.

## Enabling it

```toml
[metrics]
listen = "0.0.0.0:9464"   # inside the Węglarka container; not published on the host
network = "metrics"       # optional; this is the default
```

Restart the daemon. It binds the listener at once, then creates the network (if missing; it is `internal`, with no
route out) and connects its own container to it in the background, retrying every few seconds up to a minute until
Podman cooperates, so no `platform install` and no second restart is needed. The network name uses lowercase letters, digits and `-`, and must not start with `net-`
(those names belong to app and ingress networks).

The listener serves `GET /metrics` and nothing else: every other path is `404`, and it has no admin route. There is no
authentication in this version; the network is the boundary, and the text carries no secrets. Put on the `metrics`
network only containers you trust to read it.

## Checking it

Run a one-off container on the network and fetch the page (the daemon's container is called `weglarka`):

```bash
podman run --rm --network metrics docker.io/curlimages/curl:latest -s http://weglarka:9464/metrics
```

Expected: exposition text with a `weglarka_build_info{version="…"} 1` line (families are sorted by name).
`weglarka doctor` shows a `metrics.listener` line when `[metrics]` is set; it is `ok` once the network is joined, `warn`
with the last error while the daemon is still retrying (the page is already served), `fail` when the address could not be
bound (fix `listen` and restart), and absent when `[metrics]` is not set. `GET /v1/config` shows the section.

## What is there

All values are computed when the page is scraped; nothing is sampled in the background and no source calls Podman.
Counters live in memory and start at zero when the daemon starts (Prometheus' `rate()` and `increase()` handle the
reset). A series appears once it has something to say: an app that never failed has no `result="failed"` line.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `weglarka_build_info` | gauge | `version` | Always 1; the running daemon version. |
| `weglarka_deploys_total` | counter | `app`, `result` (`ok`, `failed`) | Deploy attempts since the daemon started; a deploy the reconcile loop retries (a failing pull, for example) counts once per attempt. A deploy rolled back after a failed health gate is counted in `weglarka_rollbacks_total`, not here; a first deploy or a blue-green challenger that fails its gate has nothing to roll back to and counts as `failed`. |
| `weglarka_rollbacks_total` | counter | `app`, `result` (`ok`, `failed`) | Rollbacks to the previous digest after a failed health gate. `failed` means the app needs intervention. |
| `weglarka_app_health_transitions_total` | counter | `app`, `to` (`crash_looping`, `unhealthy`, `recovered`) | Transitions seen by the crash-loop and healthcheck monitor (`[monitor]`). |
| `weglarka_certificate_not_after_seconds` | gauge | `domain` | Expiry of the certificate nginx serves for a routed domain (the webhook domain and every app domain), as a Unix timestamp; a domain served by an `[acme.dns]` wildcard reports the wildcard's expiry. Only with an enabled `[acme]`; a domain without a readable certificate has no line. Re-read at most every 5 minutes. |
| `weglarka_self_update_pending` | gauge | — | 1 while a new daemon image is pinned but the daemon has not confirmed it runs it yet. Only with `[self_update]`. |
| `weglarka_self_update_last_check_timestamp_seconds` | gauge | — | Unix time of the last completed self-update check. |
| `weglarka_self_update_last_error_timestamp_seconds` | gauge | — | Unix time of the last failed or refused self-update attempt; it stays until a later attempt passes the signature check or an update is applied, and is absent when there is none. |

Labels are only ever validated instance names (`app`), routed domains (`domain`) or the fixed values listed above. A
failure reason, an error message, a digest or an image reference never becomes a label: read those with
`weglarka doctor`, `GET /v1/events` or the notifications. Per-app resource use (labelled `app` and `role`) and host
metrics come with #351 and #353; discovery by a Prometheus app comes with #36. An app removed from `apps.toml` keeps its
counter lines until the daemon restarts.

If a file behind a family cannot be read (`apps.toml`, `self-update.toml`), that family is left out of the page and
the page is still served with `200`.

## Suggested alerts

```yaml
groups:
  - name: weglarka
    rules:
      - alert: WeglarkaCertificateExpiresSoon
        # The ACME worker renews well before this; 14 days left means renewals are failing.
        expr: weglarka_certificate_not_after_seconds - time() < 14 * 24 * 3600
        for: 1h
        annotations:
          summary: "Certificate for {{ $labels.domain }} expires in under 14 days"
      - alert: WeglarkaRollback
        expr: increase(weglarka_rollbacks_total{result="ok"}[1h]) > 0
        annotations:
          summary: "{{ $labels.app }} was rolled back after a failed health gate"
      - alert: WeglarkaRollbackFailed
        expr: increase(weglarka_rollbacks_total{result="failed"}[1h]) > 0
        labels:
          severity: critical
        annotations:
          summary: "{{ $labels.app }} failed its health gate and the rollback failed too"
      - alert: WeglarkaSelfUpdatePending
        # A pinned image the daemon still does not run after 30 minutes: the switch did not take effect.
        expr: weglarka_self_update_pending == 1
        for: 30m
        annotations:
          summary: "Self-update on {{ $labels.instance }} is pending for over 30 minutes"
```

`weglarka doctor` on `myhost` explains each of these in detail (`acme.certs`, the app state, `self_update`).

## Rollback

`[metrics]` is a new section of `weglarka.toml`, and the file uses `deny_unknown_fields`: an older Węglarka refuses to
start while it is present. Remove `[metrics]` before downgrading. No `apps.toml` or `state.toml` field is involved, so
[`schema_version`](state-schema.md) does not change. The network and the membership are not removed by the downgrade;
delete the empty network with `podman network rm metrics` if you no longer need it.
