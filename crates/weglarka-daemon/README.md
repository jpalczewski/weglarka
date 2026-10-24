# weglarka-daemon

The Węglarka daemon: admin API (unix socket, 0600), GitHub webhook listener (TCP), reconcile loop,
ingress (nginx + Traefik) and the systemd service installer. Decisions: `docs/decisions/0004`, `0005`.

## Running locally

```toml
# weglarka.toml (example; adjust the paths)
[runtime]
user = "weglarka"
# socket = "/run/user/1001/podman/podman.sock"   # defaults from Platform (uid from /etc/passwd)
# reconcile_interval_secs = 60

[ingress]
mode = "behind"
bind = "172.17.0.1:8080"
traefik_dynamic_file = "/data/coolify/proxy/dynamic/weglarka.yml"   # the file must exist
# nginx_image = "docker.io/library/nginx:1-alpine"

[admin]
socket = "/run/user/1001/weglarka/admin.sock"

[webhook]
listen = "0.0.0.0:9180"
domain = "weglarka.example.eu"

[state]
dir = "/var/lib/weglarka"        # apps.toml, state.toml, secrets.toml, nginx/
```

```bash
RUST_LOG=info cargo run -p weglarka-daemon -- --config ./weglarka.toml run
```

Then `weglarka --config ./weglarka.toml status`; app: `weglarka apps add …`, webhook HMAC secret:
`weglarka secrets set <app> webhook-hmac`, GitHub webhook → `https://<domain>/webhook/github/<app>`
(event type: *Packages*).

## systemd service (quadlet)

`weglarka-daemon --config /etc/weglarka/weglarka.toml platform install --dry-run` prints the files;
without `--dry-run` it writes them to the runtime user's `~/.config/containers/systemd/` and runs
`daemon-reload`. Example (`weglarka.container`):

```ini
[Unit]
Description=Węglarka (weglarka)
After=network-online.target
Wants=network-online.target

[Container]
Image=ghcr.io/jpalczewski/weglarka:latest
ContainerName=weglarka
Network=net-weglarka.network
Volume=/run/user/1001/podman/podman.sock:/run/user/1001/podman/podman.sock
Volume=/var/lib/weglarka:/var/lib/weglarka
Volume=/run/user/1001/weglarka:/run/user/1001/weglarka
Volume=/etc/weglarka/weglarka.toml:/etc/weglarka/weglarka.toml:ro
Environment=RUST_LOG=info
Exec=run --config /etc/weglarka/weglarka.toml

[Service]
Restart=always
TimeoutStopSec=70

[Install]
WantedBy=default.target
```

## Self-update (issue #99, decision 0027)

`platform install` also writes and enables `weglarka-self-update.service` and its timer in
`~/.config/systemd/user`: every 10 minutes the oneshot service runs

```sh
weglarka-daemon --config /etc/weglarka/weglarka.toml self-update
```

which does nothing until `[self_update]` is configured, and otherwise pulls `[self_update] image`, verifies its
cosign signature against the key embedded from `cosign.pub`, refuses a state-schema downgrade, pins
`repo@sha256:<digest>` in the quadlet and restarts the service. The switch must run on the host: the container is
`scratch` (no `systemctl`, no `/etc/passwd`, no D-Bus) and must not be able to rewrite its own unit.

- `self-update --check` — pull, verify and check the schema, change nothing (also skips the interval).
- `self-update --force` — ignore the interval and retry a digest that already failed.
- `self-update --rollback` — pin the previous digest recorded in `<state dir>/self-update.toml` and restart.
- `self-update --image <ref>` — follow another reference for this run.

A switch that never becomes healthy is reverted automatically (issue #100, decision 0034): `platform install`
also enables `weglarka-watchdog.timer`, whose oneshot runs

```sh
weglarka-daemon --config /etc/weglarka/weglarka.toml supervise
```

every minute. It probes `GET /v1/health` on the admin socket, and when the switched daemon has not answered within
`[self_update] fallback_timeout_secs` (default 180 s) it restores the digest the switch started from — no registry
access, the image must be in the local store, the state-schema gate still applies — after `systemctl --user
reset-failed`, so a crash-looping unit can restart. One attempt per switch: an exhausted budget is reported, not
looped.

The daemon confirms the outcome on its next start and exposes it as the `doctor` check `self_update`; a switch
that did not take effect is reported there (and as a `SelfUpdatePending` notification) instead of being assumed,
and a confirmed fallback becomes a `SelfUpdateFellBack` notification.
Operator runbook: `docs/install.md` section 6k.

## Known limitations (before deployment)

- Image and release: `Containerfile`, `.github/workflows/release.yml`, decision 0006 (`DEFAULT_IMAGE` = `:latest`, exists after the first `v*` tag).
- No e2e test against a real Podman (daemon tests run on `FakePodman`); ingress on a real
  aardvark-dns (nginx on several networks at once, multiple `resolver`s) needs verification on the host.
- Adding the first app with a domain recreates the nginx container (brief downtime); `net-<app>` networks
  are not removed after `apps remove` (no `network_remove` in the client).
- The GitHub webhook event is unconfirmed on a real push (0004). Fan-out by image is intentional (0004).
- No concurrency limit/rate limit on the webhook listener (nginx with a body-size limit sits in front of it).
- `deploy` with `image_ref` → 400; `Failed` without rollback → 500.
- Changing `[ingress]`/`[webhook]` in `weglarka.toml` requires a daemon restart (config is read once).
