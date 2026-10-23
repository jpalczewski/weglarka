# 0005 — Ingress w demonie: przeładowanie nginxa, plik Traefika, quadlet

Status: przyjęta (sesja daemon, 2026-10-23).

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
