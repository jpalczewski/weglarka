# weglarka-daemon

Demon Węglarki: admin API (unix socket, 0600), listener webhooków GitHub (TCP), pętla reconcile,
ingress (nginx + Traefik) i instalator serwisu systemd. Decyzje: `docs/decisions/0004`, `0005`.

## Uruchomienie lokalne

```toml
# weglarka.toml (przykład; ścieżki dostosuj)
[runtime]
user = "weglarka"
# socket = "/run/user/1001/podman/podman.sock"   # domyślnie z Platform (uid z /etc/passwd)
# reconcile_interval_secs = 60

[ingress]
mode = "behind"
bind = "172.17.0.1:8080"
traefik_dynamic_file = "/data/coolify/proxy/dynamic/weglarka.yml"   # plik musi istnieć
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

Potem `weglarka --config ./weglarka.toml status`; apka: `weglarka apps add …`, sekret HMAC webhooka:
`weglarka secrets set <app> webhook-hmac`, webhook GitHub → `https://<domain>/webhook/github/<app>`
(typ zdarzenia: *Packages*).

## Serwis systemd (quadlet)

`weglarka-daemon --config /etc/weglarka/weglarka.toml platform install --dry-run` wypisuje pliki;
bez `--dry-run` zapisuje je w `~/.config/containers/systemd/` usera runtime'u i robi `daemon-reload`.
Przykład (`weglarka.container`):

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

## Znane ograniczenia (przed wdrożeniem)

- Obraz Węglarki i nginx, release na GHCR — osobna sesja pakowania; `DEFAULT_IMAGE` w `main.rs` to wartość robocza.
- Brak testu e2e na prawdziwym Podmanie (testy demona działają na `FakePodman`); ingress na prawdziwym
  aardvark-dns (nginx w wielu sieciach naraz, kilka `resolver`) wymaga weryfikacji na hoście.
- Dodanie pierwszej apki z domeną odtwarza kontener nginx (krótka przerwa); sieci `net-<app>` nie są
  usuwane po `apps remove` (brak `network_remove` w kliencie).
- Zdarzenie webhooka GitHub niepotwierdzone na prawdziwym pushu (0004). Fan-out po obrazie jest zamierzony (0004).
- Brak limitu współbieżności/rate-limitu na listenerze webhooków (przed nim stoi nginx z limitem ciała).
- `deploy` z `image_ref` → 400; `Failed` bez rollbacku → 500.
- Zmiana `[ingress]`/`[webhook]` w `weglarka.toml` wymaga restartu demona (config czytany raz).
