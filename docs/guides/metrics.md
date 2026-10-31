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

Restart the daemon. At start it creates the network (if missing) and connects its own container to it, so no
`platform install` is needed. The network name uses lowercase letters, digits and `-`, and must not start with `net-`
(those names belong to app and ingress networks).

The listener serves `GET /metrics` and nothing else: every other path is `404`, and it has no admin route. There is no
authentication in this version; the network is the boundary, and the text carries no secrets. Put on the `metrics`
network only containers you trust to read it.

## Checking it

Run a one-off container on the network and fetch the page (the daemon's container is called `weglarka`):

```bash
podman run --rm --network metrics docker.io/curlimages/curl:latest -s http://weglarka:9464/metrics
```

Expected: exposition text starting with `# HELP weglarka_build_info …` and a `weglarka_build_info{version="…"} 1` line.
`weglarka doctor` shows a `metrics.listener` line when `[metrics]` is set; it is `fail` when the network could not be
created or joined (the daemon and its other listeners keep running without `/metrics`), and absent when `[metrics]` is not
set. `GET /v1/config` shows the section.

## What is there

Only `weglarka_build_info{version}` so far. Per-app resource use (labelled `app` and `role`), daemon counters and host
metrics come with #351, #352 and #353; discovery by a Prometheus app comes with #36. Label values are always fixed names
or validated instance names, never free text.

## Rollback

`[metrics]` is a new section of `weglarka.toml`, and the file uses `deny_unknown_fields`: an older Węglarka refuses to
start while it is present. Remove `[metrics]` before downgrading. No `apps.toml` or `state.toml` field is involved, so
[`schema_version`](state-schema.md) does not change. The network and the membership are not removed by the downgrade;
delete the empty network with `podman network rm metrics` if you no longer need it.
