# 0041 — Temporary port forward (`weglarka forward`)

Status: accepted (2026-10-25, issue #108)

## Problem

Debugging an app (a database console, an admin UI that is not behind the ingress, a metrics endpoint) needs
a TCP connection to a port that only exists on the app's container network. Without a first-class command
the operator publishes the port with `host_ports` (a spec change, a recreate, and a port that stays open),
or runs `podman` by hand on the host. The failure modes that matter: a forward that outlives its caller, a
port reachable from outside the host, a helper that answers to the app's DNS name or steals its ingress
route, and a container that survives a daemon crash.

## Decision

**`POST /v1/apps/{name}/forward` starts a short-lived relay container on the app's network, published on the
host's loopback, and keeps it for as long as the response stream is open.** The pieces:

- **Same shape as `run` (0040).** Preparation under the engine lock, then a framed stream: errors that can be
  refused up front (unknown app 404, app not running or without a network 409, too many forwards 409,
  invalid port 400) are ordinary JSON `ApiError`s. The lock is never held for the forward itself.
- **The relay is nginx `stream`.** The image is `ingress.nginx_image` (already on the host, has the `stream`
  module) with the ingress hardening profile (0014). The one-server config
  (`listen 8080; proxy_pass <instance DNS name>:<port>;`) is written into the read-only root's `/tmp` by a
  `/bin/sh -c` entrypoint from **positional arguments** (never interpolated into the script), so nothing is
  mounted from the host and the daemon needs no knowledge of host paths. The app's name is resolved once,
  when nginx starts. No new binary or image.
- **It is not the app.** Named `wg-fwd.<instance>.<token>`, labels `weglarka.forward=true` and
  `weglarka.forward-for=<instance>`, **no** `weglarka.instance`, so reconcile, the crash watcher and ingress
  never see it. It joins the app's primary network without extra DNS aliases, has no restart policy and no
  healthcheck.
- **Published on loopback only.** `127.0.0.1:<random>:8080`; the random host port is read back from inspect
  (`host_port = 0` on create) and sent in the first frame. Any local user of the host can connect to it
  while it lives; there is no authentication layer (accepted, documented). Any port 1–65535 of the app may
  be targeted.
- **Lifetime.** Frames: `ready{host_port}`, keepalive, end, error. A client that hangs up, the timeout
  (default and maximum 24 h) and a normal end all take the same path: kill and remove the container.
  A daemon that dies mid-forward leaves a container labelled `weglarka.forward=true`; the engine removes
  every such container at start (`remove_stale_forwards`). At most 4 forwards at once, separate from the
  run limit.
- **CLI.** `weglarka forward <app> <port> [--local-port N] [--ssh <host>] [--timeout 2h]`. After `ready` the
  CLI starts `ssh -N -L 127.0.0.1:<local>:127.0.0.1:<host_port> <host>` as a child (`kill_on_drop`); Ctrl-C
  or ssh exiting ends the request and thereby the forward. When the CLI runs on the host itself (no ssh
  host configured) it prints the loopback address and relays nothing.
- **SSH host is a user-wide CLI setting**, not a flag-only value: a new optional user config file
  (`$XDG_CONFIG_HOME/weglarka/cli.toml`, `deny_unknown_fields`) with `ssh_host`; precedence
  `--ssh` > `WEGLARKA_SSH` > file.

**Invariants:** no `spec_hash` change, no `AppSpec`/`apps.toml`/`state.toml` field, no schema bump — a
forward leaves no state. The app's container, secrets and volumes are never touched.

## Consequences

- New API route, new CLI command, a new `ContainerInfo.published_ports` field (the host port libpod assigned; every literal gained
  `published_ports: vec![]`, `FakePodman` assigns a port when a mapping asks for 0). No `ContainerSpec` field, no
  `PodmanClient` method. `weglarka-api` gets a new version, so the CLI and daemon release with it.
- Rollback to an older daemon needs nothing: no state was written. An older CLI simply has no `forward`.
- The CLI's user config file is new; an older CLI ignores it.
- Tests: engine scenarios on `FakePodman` (no `weglarka.instance`, loopback-only publish, cleanup on
  exit/timeout/hang-up, slot limit, sweep), daemon tests over the real admin socket (frames, JSON errors),
  a snapshot of the generated nginx config, CLI parsing and the pure `ssh` command builder, and an opt-in
  integration test on real Podman.

## Rejected alternatives

- **Tunnelling bytes through the admin API (HTTP upgrade).** Needs a hijacked connection on both hops;
  already rejected for `run` (0040) and unnecessary when SSH can reach a loopback port.
- **A config file mounted from the host.** Needs a host path the daemon (itself in a container) may not
  know, and a per-forward file to clean up; the entrypoint writes it into `/tmp` instead.
- **A relay subcommand in the `scratch` daemon image.** Needs the daemon to know its own image digest; the
  ingress nginx image is already present and already hardened.
- **Daemon picks the host port.** Racy; reading it back from the published mapping is not.
- **Publishing through `host_ports`.** A spec change that recreates the app and leaves the port open.
