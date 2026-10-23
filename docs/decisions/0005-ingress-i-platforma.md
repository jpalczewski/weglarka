# 0005 — Ingress w demonie: przeładowanie nginxa, plik Traefika, quadlet

Status: przyjęta (sesja daemon, 2026-10-23). **Aktualizacja: reload bez `exec`/odtwarzania nginxa zastąpiony przez 0007** (`nginx -t` + HUP, sieci w locie).

**nginx.**
- Kontener `weglarka-nginx` zarządza demon (`IngressManager::apply`, idempotentne). Katalog z `nginx.conf`
  (`[ingress] nginx_conf_dir`, domyślnie `<state dir>/nginx`) jest montowany **jako katalog** w `/etc/nginx`
  (ro) — `rename` pliku jest wtedy widoczny w kontenerze (bind-mount pojedynczego pliku trzymałby stary inode).
  Wygenerowany config jest samowystarczalny (bez `mime.types`).
- Przeładowanie: `SIGHUP` przez `container_kill` (libpod `POST /containers/{n}/kill`), nie `exec`.
  Samego `nginx -t` demon nie robi (brak `exec`); poprawność generatora pilnuje CI (`nginx -t` na przykładowym
  configu), a nginx po złym HUP zostaje przy starym configu i loguje błąd.
- Etykieta `weglarka.ingress-hash` (obraz + bind + port + zbiór sieci). Zmiana zbioru sieci (apka z domeną
  doszła/odeszła) = **odtworzenie** kontenera, bo nie ma `network_disconnect`, a `ContainerInfo` nie niesie
  listy sieci; zmiana samego configu = HUP. Konsekwencja: dodanie pierwszej apki z domeną to krótka przerwa
  ingressu (sekundy). Kontener nie nosi etykiety `weglarka.instance`, więc reconcile nie uzna go za sierotę.
- Sieci `net-weglarka` i `net-<app>` tworzy sam ingress (idempotentnie), niezależnie od kolejności z deployem.
  Resolvery nginxa = bramki (aardvark-dns) wszystkich dołączonych sieci, z `network_inspect`.
- `apply` biegnie na starcie, po każdej zmianie (add/remove/deploy/secret — scalane) i co okres reconcile
  (samonaprawa: padły kontener nginx jest startowany).

**Traefik.** Plik dynamiczny jest nadpisywany **w miejscu** (otwarcie bez `rename`, truncate + write + `fsync`),
bo ACL daje tylko przejście przez katalog; plik zakłada się z góry. Przy identycznej treści nie jest dotykany
(Traefik ma throttle przeładowań).

**Platform systemd.** Quadlet usera `~/.config/containers/systemd/weglarka.container` + `net-weglarka.network`
(`NetworkName=net-weglarka`, więc nazwa sieci zgadza się z `ContainerName=weglarka` = host z `proxy_pass`).
Wszystkie ścieżki (socket Podmana, katalog stanu, katalog admin socketu, `weglarka.toml`, plik Traefika)
montujemy pod **tą samą nazwą co na hoście**, żeby jeden `weglarka.toml` był poprawny w kontenerze i dla CLI na hoście.
Instalacja: `weglarka-daemon platform install [--dry-run]` jako user runtime'u. OpenRC: tylko wariant enuma.

**Admin API.** Tylko socket unix (0600, stary socket usuwany wyłącznie gdy jest socketem). Odczyty nie biorą
muteksu silnika; mutacje czekają na niego maks. 30 s, potem 409 (`conflict`) — deploy z bramką zdrowia nie
zawiesza API. `POST …/deploy` próbuje najpierw zwykłego deployu, a przy znanym złym digeście ponawia z `force`
(ręczne wywołanie = wola operatora); `image_ref` w żądaniu → 400 (poza MVP); `Failed` → 500 z powodem.

**Aktualizacja: socket Podmana i utwardzenie quadletu (sesja quadlet-fix).**
- Obraz jest na `scratch` — bez `/etc/passwd`. `weglarka-daemon run` **nigdy** nie czyta plików użytkowników:
  socket Podmana bierze z `[runtime] socket`, a gdy go brak, ze zmiennej `WEGLARKA_PODMAN_SOCKET`; bez obu kończy
  się czytelnym błędem. `platform install` (na hoście, gdzie `/etc/passwd` jest) wylicza socket i wpisuje go
  do quadletu jako `Environment=WEGLARKA_PODMAN_SOCKET=…` — socket jest montowany pod tą samą ścieżką, więc ten sam
  `weglarka.toml` działa dla demona w kontenerze i dla CLI na hoście, bez `runtime.socket`.
  Wariant ze stałą ścieżką w kontenerze odrzucony: wymagałby osobnego configu dla CLI.
- Quadlet: `ReadOnly=true` + `Tmpfs=/tmp`, `DropCapability=ALL`, `NoNewPrivileges=true`,
  `PodmanArgs=--memory=<M> --memory-swap=<M>` (swap = limit, host swapuje), `PidsLimit=<N>`.
  Demon pisze tylko w montowanych katalogach (stan, admin socket, nginx.conf, plik Traefika), więc nie potrzebuje
  zapisu root FS. `[platform] memory` (domyślnie `128M`) i `pids_limit` (256) są konfigurowalne; 128M to szacunek
  (statyczny demon na tokio, current_thread, kilka–kilkanaście MB RSS) z dużym zapasem, nie pomiar.
- `weglarka-daemon platform run-args` drukuje te same opcje jako argumenty `podman run`; smoke test w CI
  (`.github/scripts/smoke-quadlet.sh`) uruchamia obraz dokładnie z nich, z configiem bez `runtime.socket`.
- Poza zakresem (follow-up): utwardzenie kontenera `weglarka-nginx` tworzonego przez demona (cap drop, limit
  pamięci) — wymaga rozszerzenia `ContainerSpec` i wire'u libpod.

## HTTP → HTTPS (tryb `behind`)

Plik Traefika zawiera dla każdego routera bliźniaka `weglarka-http-*` na entrypoincie `http` (bez `tls`, ten sam
service); bez niego Traefik odpowiadał 404 na `http://domena/`. Bliźniak ma **prefiks** `weglarka-http-`, nie sufiks
`-http`: instancja `foo-http` zderzyłaby się z bliźniakiem `foo`. Middleware `redirectScheme` odpada (walidator
publikacji odrzuca middlewares), więc redirect robi nginx: `return 301 https://$host$request_uri;` w `server` apek
i webhooków, gdy `$weglarka_redirect_https` (mapa: zaufany peer **i** jawne `X-Forwarded-Proto: http`).
Nie wystarcza `$weglarka_proto = http`: zaufany peer bez nagłówka (sonda zdrowia demona, `health.http`, docs/decisions/0010)
dostaje fallback `$scheme` = `http` i nie może dostać 301. Niezaufany peer nigdy nie jest przekierowywany.
Tryb `edge` użyje tej samej dyrektywy (`ModeProfile::https_redirect`) z kluczem `$scheme` i wyjątkiem dla
`/.well-known/acme-challenge/`. Nazwa entrypointu: `TraefikOptions::http_entrypoint` (domyślnie `http`).
Testy: snapshoty, test zgodności z polityką walidatora, `.github/scripts/test-forwarded-headers.sh`, krok
`http_redirect` w `scripts/acceptance.sh`.
