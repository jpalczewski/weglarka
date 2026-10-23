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
