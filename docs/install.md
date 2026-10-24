# Instalacja Węglarki

Węglarka działa jako **kontener rootless Podmana** (quadlet w systemd usera) obok własnego kontenera nginx;
CLI `weglarka` zostaje poza kontenerem — na hoście albo na laptopie przez tunel SSH do socketu admina.
Przykłady dotyczą hosta `niechybnie` (Ubuntu 24.04, tryb `behind`, Traefik z Coolify). Decyzje:
[0005](decisions/0005-ingress-i-platforma.md), [0006](decisions/0006-pakowanie-obrazy-i-release.md).

**Spis treści:** [1. Wymagania hosta](#1-wymagania-hosta) · [2. Konfiguracja hosta](#2-konfiguracja-hosta) ·
[3. Binarki na hoście](#3-binarki-na-hoście-platform-install) · [4. Quadlet i start](#4-quadlet-i-start) ·
[5. CLI z laptopa](#5-cli-z-laptopa-macos-przez-tunel-ssh) · [Odbiór](#odbiór-na-hoście-scriptsacceptancesh) ·
[6. Pierwsza apka](#6-pierwsza-apka-ntfyzig) ·
[6a. Wolumeny, UID i import](#6a-wolumeny-zakresy-uid-i-import-z-coolify-iteracja-2)
([wolumeny współdzielone](#wolumeny-współdzielone-grupa-uid-iteracja-2)) ·
[6b. `start = false`](#6b-zatrzymywanie-apek-start--false) ·
[6c. Porty na hoście](#6c-porty-publikowane-na-hoście-host_ports) ·
[6d. Zależności między apkami](#6d-zależności-między-apkami-depends_on) ·
[6e. Streaming](#6e-streaming-sse-long-polling) ·
[6f. Komenda i argumenty](#6f-komenda-i-argumenty-kontenera-command) ·
[6g. Retencja obrazów](#6g-retencja-obrazów-i-jednorazowe-sprzątanie) ·
[6h. Powiadomienia](#6h-powiadomienia-ntfy) ·
[6i. Wykrywanie awarii](#6i-wykrywanie-awarii-apek-crash-loop-unhealthy) ·
[6j. Configi z hosta](#6j-configi-z-hosta-config_root-i-apps-reload) ·
[7. Weryfikacja i rollback](#7-weryfikacja-i-rollback)

Gotowe specy apek i wycinki `apps.toml` (kopiuj-wklej): [`docs/examples/`](examples/).

## 1. Wymagania hosta

Przygotowuje je Ansible (repo `niechybnie`); Węglarka niczego z tego sama nie instaluje:

- **Podman 6.x** z repo OBS `home:alvistack` (apt-pinning tylko dla stosu Podmana), netavark 2 (nftables), pasta;
- użytkownik runtime'u (domyślnie `weglarka`) z zakresami `subuid`/`subgid` ≥ 65536 i **linger**
  (`loginctl enable-linger weglarka`);
- `systemctl --user enable --now podman.socket` dla tego użytkownika (socket: `/run/user/<uid>/podman/podman.sock`);
- katalogi (właściciel `weglarka`): stan `/var/lib/weglarka` (0755) i **`/var/lib/weglarka/run` (0700)**.
  Socket admina leży w trwałym katalogu, bo `/run/user/<uid>` znika po restarcie, a Podman nie startuje
  kontenera, jeśli zamontowany katalog nie istnieje;
- `/etc/weglarka/weglarka.toml` czytelny dla `weglarka` (sekcja 2);
- (tryb `behind`) plik Traefika **po stronie Węglarki**: `/var/lib/weglarka/traefik/weglarka.yml` założony z góry
  (właściciel `weglarka`, 0644, treść może być komentarzem — quadlet montuje ten pojedynczy plik, więc musi istnieć
  przed startem). Węglarka nadpisuje go w miejscu. **Nie dostaje dostępu do katalogu Traefika** (`/data` i
  `/data/coolify` mają 0700, ACL na `/data` odsłoniłby inne usługi) — publikację robi root, patrz niżej;
- (tryb `behind`) **publikacja do Traefika przez root-owy path-unit z walidatorem**: `weglarka-traefik-sync.path`
  (obserwuje `/var/lib/weglarka/traefik`) → `weglarka-traefik-sync.service` → `/usr/local/sbin/weglarka-traefik-sync`.
  Walidator (polityka w `/etc/weglarka/traefik-policy.json`) przepuszcza tylko `http.routers`/`http.services`
  o nazwie `weglarka` lub `weglarka-*`, reguły `Host()` (opcjonalnie `&& PathPrefix()`) dla domen z allowlisty,
  jedyny backend `http://host.docker.internal:<port z bind>`, `tls.certResolver: letsencrypt` (routery na
  entrypoincie `http` bez `tls`); bez middlewares, tcp/udp. Węglarka generuje dla każdej domeny drugi router
  `weglarka-http-*` na entrypoincie `http` — redirect 301 na HTTPS robi nginx Węglarki (nie Traefik), więc polityka
  walidatora musi dopuszczać entrypoint `http` bez `tls`. Zwalidowany YAML jest kopiowany atomowo do `/data/coolify/proxy/dynamic/weglarka.yml`; przy błędzie
  zostaje poprzednia wersja, powód w `journalctl -t weglarka-traefik-sync`. Nowa domena apki = najpierw dopisanie
  jej do allowlisty w Ansible (`weglarka_allowed_domains`);
- (tryb `behind`) port nginx Węglarki na adresie `docker0` **inny niż 8080** (8080 na `0.0.0.0` trzyma docker-proxy
  Traefika z Coolify) — na niechybnie `172.17.0.1:8088`, a UFW wpuszcza na niego tylko sieć `coolify`
  (`172.18.0.0/16`);
- AppArmor (Ubuntu 24.04, `apparmor_restrict_unprivileged_userns=1`): systemowy profil `podman` z pakietu wystarcza,
  rootless działa bez zmian sysctl;
- **porty publikowane na hoście** (`host_ports`, [6c](#6c-porty-publikowane-na-hoście-host_ports)): ruch do nich
  przekazuje forwarder portów rootless Podmana, więc na hoście nie trzeba nic instalować, ale **UFW musi je
  wpuszczać** — reguły dodaje rola `weglarka_host` w Ansible, Węglarka firewalla nie zmienia. Porty < 1024
  wymagają `net.ipv4.ip_unprivileged_port_start=0` na hoście **i** `[runtime] allow_privileged_host_ports = true`
  w `weglarka.toml`; bez sysctla sam start kontenera się nie powiedzie;
- DNS: rekord domeny webhooków (`[webhook] domain`) i domen apek wskazuje na host (Traefik terminuje TLS).

Sprawdzenie (jako użytkownik runtime'u, po zapisaniu `weglarka.toml`):

```sh
sudo -iu weglarka env XDG_RUNTIME_DIR=/run/user/$(id -u weglarka) \
  weglarka doctor --preflight --config /etc/weglarka/weglarka.toml
```

Każde `warn`/`fail` ma podpowiedź naprawy (`runtime.subuid`, `runtime.linger`, `runtime.podman_source`,
`ingress.traefik_file`, `state.secrets_file`, …).
Wybrane sprawdzenia hosta:
`runtime.subuid`/`subgid` (warn < 1 000 000 id, fail < 65 536), `runtime.apparmor_userns` (Ubuntu 24.04:
profil `podman` załadowany, gdy `apparmor_restrict_unprivileged_userns=1`; pełny wynik tylko jako root),
`ingress.bind_free` (port `bind` nie zajęty przez cudzy proces, np. Traefika), `ingress.traefik_sync`
(tryb `behind`: aktywny `weglarka-traefik-sync.path`, gdy istnieje `/etc/weglarka/traefik-policy.json`;
domeny z `apps.toml` na allowliście polityki, klucz `allowed_domains`), `apps.host_ports_free` (porty z
`apps.toml` nie zajęte przez cudzy proces — `/proc/net/tcp*`, jak `ingress.bind_free` — oraz porty < 1024 bez
`allow_privileged_host_ports`). Reguły firewalla (także dla `host_ports`) nie są sprawdzane. Kody wyjścia: 0 ok, 1 warn, 2 fail.

## 2. Konfiguracja hosta

`/etc/weglarka/weglarka.toml` (UID z `id -u weglarka`; ścieżki są montowane do kontenera pod tą samą nazwą,
więc ten sam plik działa dla demona i dla CLI na hoście):

```toml
[runtime]
user = "weglarka"
# Porty publikowane na hoście < 1024 (`host_ports`, sekcja 6c): host musi mieć
# net.ipv4.ip_unprivileged_port_start=0. Domyślnie false — takie porty są odrzucane w walidacji.
# allow_privileged_host_ports = true

[ingress]
mode = "behind"
bind = "172.17.0.1:8088"                                   # docker0; 8080 zajmuje Traefik z Coolify
traefik_dynamic_file = "/var/lib/weglarka/traefik/weglarka.yml"  # root-owy path-unit waliduje i publikuje do dynamic/
# nginx przypięty po digeście (0006); podbijaj świadomie — zmiana odtwarza kontener nginx:
nginx_image = "docker.io/library/nginx:1.31.8-alpine@sha256:1ef7ca94d7879df82421428ce13bd1eaa412404953859cf7a5b6512c25e67a60"
# Kontener nginx jest zawsze osłoniony (0014): read-only root, cap_drop ALL (+ CHOWN/SETGID/SETUID),
# no-new-privileges. Własny obraz musi to tolerować (nie może pisać po swoim rootfs przy starcie).
# Opcjonalnie: peery, którym nginx ufa w sprawie X-Forwarded-* (0007). Domyślnie podsieć `net-weglarka`
# (stąd łączy forwarder portów rootless Podmana); lista ZASTĘPUJE domyślną. Zwykle zostaw nieustawione.
# trusted_proxies = ["10.89.1.2"]

[admin]
socket = "/var/lib/weglarka/run/admin.sock"

[webhook]
listen = "0.0.0.0:9180"                                    # wewnątrz kontenera, w sieci net-weglarka
domain = "weglarka.descriptortable.eu"                     # wystawiane są tylko ścieżki /webhook/

[state]
dir = "/var/lib/weglarka"                                  # apps.toml, state.toml, secrets.toml, nginx/

# Katalog z plikami konfiguracyjnymi apek (sekcja 6i). Montowany read-only do kontenera Węglarki.
# Absolutny albo względny do katalogu weglarka.toml. Nieustawione = funkcja wyłączona.
# config_root = "/var/lib/weglarka/config"

[platform]
kind = "systemd"
memory = "128M"                                            # limit pamięci kontenera Węglarki (z swapem); domyślnie 128M
pids_limit = 256                                           # limit procesów/wątków; domyślnie 256
```

`[runtime] socket` **nie jest potrzebny**: `platform install` wylicza socket na hoście (`/run/user/<uid>/podman/podman.sock`)
i przekazuje go kontenerowi zmienną `WEGLARKA_PODMAN_SOCKET` w quadlecie. Jawne `socket` ma pierwszeństwo przed zmienną.
Demon w kontenerze nie czyta `/etc/passwd` (obraz jest na `scratch`); bez socketu w configu i bez zmiennej kończy się
czytelnym błędem.

## 3. Binarki na hoście (`platform install`)

`platform install` używa `systemctl --user` i `/etc/passwd`, więc **nie działa w kontenerze** — potrzebny jest
`weglarka-daemon` na hoście (CLI i demon, `x86_64-unknown-linux-musl`).

**Przed pierwszym tagiem `v*`** release'u nie ma — wyciągnij binarki z podpisanego obrazu `:main`
(najpierw `cosign verify` jak w sekcji 4, „Weryfikacja”):

```sh
IMG=ghcr.io/jpalczewski/weglarka:main
podman pull "$IMG"
podman create --name wg-extract "$IMG"
podman cp wg-extract:/usr/local/bin/weglarka-daemon .
podman cp wg-extract:/usr/local/bin/weglarka .
podman rm wg-extract
sudo install -m 0755 weglarka weglarka-daemon /usr/local/bin/
```

**Od pierwszego tagu** — z tarballa release'u:

```sh
VER=0.1.0
base=https://github.com/jpalczewski/weglarka/releases/download/v$VER
cd "$(mktemp -d)"
curl -fsSLO "$base/weglarka-$VER-x86_64-unknown-linux-musl.tar.gz" -O "$base/SHA256SUMS"
sha256sum -c --ignore-missing SHA256SUMS
tar xzf weglarka-$VER-x86_64-unknown-linux-musl.tar.gz
sudo install -m 0755 weglarka-$VER-x86_64-unknown-linux-musl/{weglarka,weglarka-daemon} /usr/local/bin/
```

## 4. Quadlet i start

Obraz `ghcr.io/jpalczewski/weglarka` jest publiczny (pobieranie bez `podman login`).
Tag `:latest` powstaje dopiero z pierwszego tagu `v*`; wcześniej użyj `--image ghcr.io/jpalczewski/weglarka:main`.

```sh
sudo -iu weglarka
export XDG_RUNTIME_DIR=/run/user/$(id -u) DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u)/bus

weglarka-daemon --config /etc/weglarka/weglarka.toml platform install --dry-run   # podgląd plików
weglarka-daemon --config /etc/weglarka/weglarka.toml platform install \
  --image ghcr.io/jpalczewski/weglarka:latest                                     # zapis + daemon-reload
systemctl --user start weglarka.service
systemctl --user status weglarka.service
podman logs weglarka                                                              # JSON, bez sekretów
```

Wygenerowany quadlet (przykład dla `weglarka`, UID 1004) jest utwardzony: root FS tylko do odczytu (`ReadOnly=true`,
`Tmpfs=/tmp`), `DropCapability=ALL`, `NoNewPrivileges=true`, limit pamięci (`PodmanArgs=--memory=128M --memory-swap=128M`)
i `PidsLimit=256`:

```ini
[Container]
Image=ghcr.io/jpalczewski/weglarka:latest
ContainerName=weglarka
Network=net-weglarka.network
Volume=/run/user/1004/podman/podman.sock:/run/user/1004/podman/podman.sock
Volume=/var/lib/weglarka:/var/lib/weglarka
Volume=/etc/weglarka/weglarka.toml:/etc/weglarka/weglarka.toml:ro
Environment=RUST_LOG=info
Environment=WEGLARKA_PODMAN_SOCKET=/run/user/1004/podman/podman.sock
ReadOnly=true
Tmpfs=/tmp
DropCapability=ALL
NoNewPrivileges=true
PodmanArgs=--memory=128M --memory-swap=128M
PidsLimit=256
Exec=run --config /etc/weglarka/weglarka.toml
```

(pełny plik: `platform install --dry-run`; te same opcje jako argumenty `podman run`: `platform run-args`).

Quadlet ma `WantedBy=default.target` — z lingerem usługa wstaje po restarcie hosta. Przy starcie demon zakłada
sieć `net-weglarka`, ciągnie i uruchamia kontener `weglarka-nginx` na `bind` i zapisuje plik Traefika.
Aktualizacja samej Węglarki (poza MVP: automat): `podman pull <obraz> && systemctl --user restart weglarka.service`.

### Weryfikacja obrazu i binarek

```sh
cosign verify \
  --certificate-identity-regexp '^https://github.com/jpalczewski/weglarka/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/jpalczewski/weglarka:latest

# SBOM (SPDX) – atestacja cosign:
cosign verify-attestation --type spdxjson <jak wyżej> ghcr.io/jpalczewski/weglarka:latest | jq -r .payload | base64 -d | jq .predicate | head

# SHA256SUMS z release'u:
cosign verify-blob --signature SHA256SUMS.sig --certificate SHA256SUMS.pem <flagi tożsamości jak wyżej> SHA256SUMS
```

## 5. CLI z laptopa (macOS) przez tunel SSH

Socket admina jest 0600 i należy do `weglarka`, więc tunel zestawiamy jako ten użytkownik (albo root):

```sh
# CLI (aarch64-apple-darwin) z tej samej strony release'u, sprawdź sumę z SHA256SUMS
mkdir -p ~/.weglarka
ssh -N -o StreamLocalBindUnlink=yes \
  -L ~/.weglarka/admin.sock:/var/lib/weglarka/run/admin.sock weglarka@niechybnie &

export WEGLARKA_SOCKET=~/.weglarka/admin.sock
weglarka status
weglarka doctor            # autodiagnoza przez API (--json dla maszyn)
```

## Odbiór na hoście (`scripts/acceptance.sh`)

Test łańcucha na prawdziwym hoście: preflight i `doctor`, kanarek `traefik/whoami` na domenie testowej
(Traefik → nginx → kontener, TLS), webhook GitHub (202/401/204) i sprzątanie. Uruchamiaj **po instalacji**
i **po każdej aktualizacji Węglarki** (zanim ruszysz prawdziwą apkę), jako użytkownik runtime'u:

```sh
sudo -iu weglarka env XDG_RUNTIME_DIR=/run/user/$(id -u weglarka) \
  scripts/acceptance.sh --canary-domain wg-test.descriptortable.eu
```

Wymaganie: domena kanarka jest w DNS (wskazuje na host) **i na allowliście walidatora**
(`weglarka_allowed_domains`) — bez tego Traefik nie dostanie routera i krok „ruch” skończy się timeoutem.
Skrypt dotyka tylko instancji `wg-canary` (domyślnie), `wg-webhook`/`wg-rollback` (z `--with-local-registry`),
`wg-volume`/`wg-nostart` (z `--with-volume`) i kontenera `wg-accept-registry` — nigdy `ntfy`. Opcje: `--canary-image`,
`--webhook-base`, `--keep` (kanarek zostaje), `--skip-preflight`, `--strict` (warn z `doctor` = błąd), `--cert-timeout`,
`--json` (raport maszynowy na stdout), `--direct http://127.0.0.1:8088` (ruch prosto do nginx, bez Traefika/TLS — używa
tego CI). Kod wyjścia ≠ 0 przy jakimkolwiek FAIL; `ACCEPTANCE_VERBOSE=1` pokazuje log także udanych kroków.
Wymaga `weglarka`, `curl`, `openssl`, `jq`, `podman`. Opcjonalne `--with-volume` (też w CI; wymaga `tar`) dodaje
dwa kroki wolumenów: na instancji `wg-volume` import obcego tara, dane i zakres UID przeżywają `apps remove` + `apps add`,
eksport z właścicielem `uid_range.start`, `--purge-volumes`; na instancji `wg-nostart` apka dodana z `start = false`
(bez kontenera), import przed pierwszym `apps start`, eksport ze sprawdzeniem zawartości.

**Webhook na hoście** sprawdza protokół (poprawny podpis → 202 dla obrazu kanarka — deploy kończy się `Unchanged`,
zły podpis → 401, `ping` → 204, obcy tag → 204). **Pełny test rollbacku** (kod 6, powrót do poprzedniego digestu)
oraz webhook z realnym deployem i duplikatem dostarczenia biegną w CI (`integration-podman`); na hoście są
opcjonalne (`--with-local-registry`) — wymagają tymczasowego rejestru na `127.0.0.1:15099` i wpisu
`[[registry]] location = "127.0.0.1:15099" insecure = true` w `registries.conf` użytkownika **przed startem**
usługi Podmana (czyta go przy starcie). Skrypt sam niczego nie konfiguruje; bez wpisu deploy kończy się FAIL
z podpowiedzią. Na produkcji nie zalecane.

Uwaga: `secrets.toml` zachowuje sekret `webhook-hmac` kanarka po jego usunięciu (jednorazowa wartość testowa,
nadpisywana przy kolejnym uruchomieniu).

## 6. Pierwsza apka: ntfy.zig

Kolejność ma znaczenie: `secrets set` wymaga istniejącej apki, a pierwszy deploy potrzebuje sekretu `config`.
Dopóki sekretu nie ma, apka jest w stanie **„czeka na sekret”** (`weglarka status` → `waiting-for-secret`,
`apps show` wypisuje brakujące nazwy, `doctor` ostrzega) — to nie błąd i demon nie próbuje deployu. Po
`secrets set` stan znika, a deploy rusza sam; osobne `weglarka deploy` nie jest potrzebne.

```sh
weglarka apps add ntfy ghcr.io/jpalczewski/ntfy.zig:latest \
  --domain nz.descriptortable.eu --port 8085 \
  --env CONFIG_FILE=/config.json \
  --secret-mount config=/config.json

weglarka secrets set ntfy config < ./config.json                # plik trafia pod /config.json
weglarka apps show ntfy                                         # deploy rusza sam: pull, bramka zdrowia
```

### Wartość sekretu: `< plik`, nie `/dev/stdin`

Przekaż wartość **przekierowaniem** (`secrets set <app> <nazwa> < plik`) albo potokiem
(`pbpaste | weglarka secrets set …`) — CLI czyta wtedy standardowe wejście. Nie używaj
`--from-file /dev/stdin` przez `sudo -u`/`ssh` na innego użytkownika: `/dev/stdin` to dowiązanie do
`/proc/self/fd/0`, które CLI otwiera *od nowa*, już jako użytkownik runtime'u — a ten nie ma prawa do pliku
ani potoku, który należy do wywołującego, więc kończy się to `Permission denied`. Przekierowanie `<` otwiera
plik powłoka wywołującego (jego uprawnieniami) i przekazuje gotowy deskryptor, więc działa także w
`sudo -u weglarka weglarka secrets set ntfy config < config.json`. `--from-file ścieżka` jest w porządku
tylko dla pliku czytelnego dla użytkownika, który uruchamia CLI. Sekret nie trafia do argumentów (`ps`,
historia powłoki).

**Przełączenie z Coolify z minimalną przerwą** (domena nie może mieć jednocześnie dwóch routerów z tym samym
`Host()` — Coolify i Węglarki):

1. Dodaj apkę **bez `--domain`**, ustaw sekret, `deploy` — kontener przechodzi bramkę zdrowia, ruch nadal
   obsługuje Coolify.
2. Upewnij się, że domena jest na allowliście walidatora (`weglarka_allowed_domains` w Ansible).
3. Zatrzymaj stary kontener w Coolify (na niechybnie: `coolify-relay`) — znika jego router.
4. Dodaj domenę: `weglarka apps update ntfy --domain nz.descriptortable.eu` (sprawdź najpierw z `--dry-run`).
   To zmienia tylko ingress (przeładowanie nginx) — kontener nie jest odtwarzany, więc bez przerwy i bez
   ponownego deployu. (`apps add` na istniejącą nazwę zwraca 409; `remove` + `add` nie jest już potrzebne.)
5. Rollback: `weglarka apps remove ntfy` i ponowny start starego kontenera w Coolify (nie usuwaj go od razu).

Dane ntfy.zig: brak, więc `recreate` jest bezpieczne.

### Webhook GitHub (auto-update)

HMAC jest per apka (0004). Ten sam ciąg trafia do Węglarki i do GitHuba:

```sh
openssl rand -hex 32 > hmac.txt
weglarka secrets set ntfy webhook-hmac --from-file hmac.txt
cat hmac.txt          # wklej do pola Secret na GitHubie, potem: rm hmac.txt
```

Repozytorium `jpalczewski/ntfy.zig` → Settings → Webhooks → Add webhook:

| Pole | Wartość |
|---|---|
| Payload URL | `https://weglarka.descriptortable.eu/webhook/github/ntfy` (`<webhook.domain>/webhook/github/<instancja>`) |
| Content type | `application/json` |
| Secret | zawartość `hmac.txt` |
| Events | *Let me select individual events* → tylko **Registry packages** (`registry_package`/`package`, akcja `published`) |

Po pierwszym pushu sprawdź *Recent Deliveries*: `latest` → **202**, `sha-…` → 204 (apka śledzi `:latest`); 401 =
zły sekret, 204 dla `latest` = niezgodna nazwa obrazu. Nazwy pól payloadu są jeszcze niepotwierdzone na prawdziwym
pushu (0004) — pierwsza dostawa jest też testem.

## 6a. Wolumeny, zakresy UID i import z Coolify (iteracja 2)

Decyzja i pomiary: [0009](decisions/0009-volume-ownership.md). Import danych przed pierwszym startem apki
(provisioning z `start = false`) i zatrzymywanie apek: [6b](#6b-zatrzymywanie-apek-start--false).

**Każdy kontener Węglarki działa w jawnym zakresie UID** z puli subuid użytkownika runtime'u (`userns: private` +
jawne `UIDMap`/`GIDMap`): zwykła apka ma własny zakres (65 536 UID), **wolumen współdzielony** — jeden zakres na
całą swoją grupę apek ([niżej](#wolumeny-współdzielone-grupa-uid-iteracja-2)), a nginx ingressu ma własny (4 096).
Zakres trafia do `state.toml` (`uid_range`, `shared_volumes.<nazwa>.uid_range`, `ingress_uid_range`) i **nie zmienia
się, dopóki istnieją dane**: apka dostaje go przy pierwszym deployu, wolumen współdzielony — przy pierwszym
deployu/provisioningu pierwszego członka; dzięki temu pliki w wolumenie mają tego samego właściciela po każdym
deployu i rollbacku, a grupa N apek kosztuje **jeden** zakres zamiast N. Pulę Węglarka pyta u Podmana (`GET /info`),
nie czyta `/etc/subuid` (demon w kontenerze go nie widzi). Pula 2 000 000 mieści zakres ingressu i 30 apek lub grup;
brak miejsca = instancja zablokowana z komunikatem w logu reconcile (powiększ `subuid` w Ansible, rozmiar zakresu
się nie zmienia).
Każdy zakres kosztuje też jednorazowo kopię warstw obrazu z przesuniętymi właścicielami (czas i miejsce w
`~/.local/share/containers` przy pierwszym starcie obrazu w nowym zakresie).

### Wolumeny w spec apki

```toml
# apps.toml / --spec
volumes = [{ name = "data", target = "/data" }]   # read_only = true dla montowania tylko do odczytu
resources = { memory = "128m", pids_limit = 256 } # opcjonalnie; domyślnie bez limitów
```

To samo flagami `apps add` / `apps update` (bez pliku spec): `--volume data=/data` (`:ro` na końcu = tylko do
odczytu; ta sama nazwa podmienia wpis), `--memory 128m`, `--pids-limit 256`, `--cpus 0.5`; `none` usuwa limit
(`--memory none`). Literówka w polu pliku spec (np. `memory` zamiast `resources.memory`) daje błąd z listą pól.

Wolumen `<instancja>.<nazwa>` (np. `szklana-pogoda.data`) powstaje przy deployu z etykietą `weglarka.instance`.
`weglarka volumes list <apka>` pokazuje deklarowane wolumeny. `apps remove` **nie usuwa danych** (wolumeny i zakres
UID zostają; ponowne `apps add` tej samej nazwy znajduje je z poprawnym właścicielem). Usunięcie danych:
`weglarka apps remove <apka> --purge-volumes` (kasuje kontener i wolumeny, zwalnia zakres UID — bez odwrotu).
Zakres UID jest też zwalniany, gdy usuniętą apkę zostawiono bez wolumenów. Sieć apki (`net-<instancja>`) demon usuwa
sam przy najbliższym przebiegu reconcile po `apps remove` (gdy nic już z niej nie korzysta).

### Wolumeny współdzielone (grupa UID, iteracja 2)

Kilka apek (kontenerów) może pracować na **jednym** wolumenie — typowy przypadek to SQLite i procesy obok niego
(api, mcp, worker). Decyzja i odrzucone alternatywy: [0014](decisions/0017-shared-volumes.md). Wolumen deklaruje się
**raz**, w sekcji najwyższego poziomu `apps.toml`, a apka montuje go po nazwie:

```toml
[shared_volumes.kajet-data]   # deklaracja: na razie bez pól (miejsce na przyszłe opcje wolumenu)

[apps.kajet-api]
image = "ghcr.io/.../kajet-api:latest"
shared_volumes = [{ name = "kajet-data", target = "/data" }]

[apps.kajet-worker]
image = "ghcr.io/.../kajet-worker:latest"
shared_volumes = [{ name = "kajet-data", target = "/data", read_only = true }]   # tylko do odczytu
```

Gotowy plik (deklaracja + dwie apki): [`docs/examples/sqlite-shared-volume.toml`](examples/sqlite-shared-volume.toml).
Sekcję `[shared_volumes]` dopisuje `weglarka volumes add <nazwa>`; `apps.toml` jest plikiem demona, więc nie edytuj
go równolegle z działającym CLI.

- Kontener Podmana nazywa się `wg-shared-<nazwa>` i ma etykietę `weglarka.shared-volume=<nazwa>`, **bez**
  `weglarka.instance` — dlatego `apps remove --purge-volumes`, sprzątanie osieroconych wolumenów i filtry wolumenów
  per instancja nigdy go nie ruszają.
- **Jeden zakres UID na grupę:** wszyscy członkowie dostają ten sam `UIDMap`/`GIDMap` i tę samą etykietę
  `weglarka.uid-range`, więc ten sam plik ma w każdym kontenerze tego samego właściciela. Członek **nie** dostaje
  własnego `uid_range` w `state.toml`; każdy członek ma nadal swój kontener, sieć i domeny.
- Deklaracja chroni przed literówką: `shared_volumes` z nazwą, której nie ma w `[shared_volumes]`, odrzuca
  walidacja (HTTP 400, podpowiedź `weglarka volumes add <nazwa>`), a `apps.toml` z takim wpisem nie wczyta się przy
  starcie demona.
- **Maks. jeden wolumen współdzielony na apkę** (v1): jeden wolumen = jedna granica zakresu UID. Wolumeny prywatne
  (`volumes`) można łączyć ze współdzielonym — powstają w zakresie grupy, więc pozostali członkowie mogą je czytać
  (celowo słabsza izolacja wewnątrz grupy; wygodny sposób na własny cache jednego procesu).
- `start = false` członka provisionuje zakres i wolumen **bez kontenera** ([6b](#6b-zatrzymywanie-apek-start--false)),
  więc dane można zaimportować przed pierwszym startem.
- **`doctor`:** `state.shared_volumes` raportuje dane bez deklaracji (podpowiedź `weglarka volumes remove <nazwa>
  --purge`), zadeklarowany a jeszcze nieutworzony wolumen, rozjazd etykiety `weglarka.uid-range` i przypomnienie,
  że wszystkie obrazy grupy muszą działać jako ten sam `USER` — porównania użytkowników `doctor` nie robi za Ciebie.
- **Sprzątanie:** `apps remove` (bez `--purge-volumes`) **nie usuwa danych** — wolumen i zakres zostają, a ponowne
  `apps add` znajduje te same pliki. `apps remove --purge-volumes` członka, gdy w grupie są **inni** członkowie,
  kończy się `409` z listą członków i **niczego nie kasuje**: usuń apkę bez `--purge-volumes` (dane zostają dla
  reszty grupy) albo najpierw przenieś dane poza Węglarkę (`volumes export`). Purge **ostatniego** członka usuwa
  wolumen grupy i zwalnia zakres; deklaracja w `apps.toml` **zostaje**, a następny członek dostaje nowy, pusty
  wolumen.

Deklaracja i sprzątanie z CLI (przez API, jak `apps`):

```sh
weglarka volumes add kajet-data                 # deklaracja w apps.toml (idempotentna; PUT /v1/volumes/<nazwa>)
weglarka volumes list                           # bez apki: wszystkie wolumeny współdzielone
                                                # (NAME, PODMAN NAME, MEMBERS, RANGE, EXISTS)
weglarka volumes remove kajet-data              # 409, gdy wolumen montuje jakakolwiek apka; bez danych usuwa
                                                # deklarację (bez --purge nie rusza wolumenu z danymi)
weglarka volumes remove kajet-data --purge      # usuwa wolumen grupy (dane!) i wpis w state.toml; 409, dopóki
                                                # są członkowie (najpierw usuń/odłącz apki)
```

`weglarka volumes list <apka>` działa jak dotąd i pokazuje też wolumeny współdzielone (kolumna `SHARED`).
`apps add` / `apps update` przyjmują `--shared-volume kajet-data=/data` (`:ro` na końcu = tylko do odczytu; ta sama
nazwa podmienia wpis, jak `--volume`; flaga wyklucza się z `--spec`). Usunięcie montowania w v1 zostaje na `--spec`
(pełna podmiana specu).

**Przeniesienie istniejącej apki do grupy (migracja danych).** Dołączenie do grupy zmienia efektywny zakres UID
apki, więc pliki w jej dotychczasowych prywatnych wolumenach stałyby się nieczytelne. Węglarka tego pilnuje: jeśli
stary kontener miał etykietę `weglarka.uid-range` różną od nowej, a instancja ma już wolumeny prywatne (etykieta
`weglarka.instance`), deploy jest odrzucany z błędem o zmianie zakresu z danymi, a `PUT /v1/apps/<apka>` zwraca
`409` — **stary kontener działa dalej**. Kolejność migracji:

1. Zatrzymaj apkę i zrób kopię: `weglarka apps stop <apka>`,
   `weglarka volumes export <apka> <wolumen> --out kopia.tar` dla każdego prywatnego wolumenu (bazę SQLite
   najlepiej przez `.backup`/`VACUUM INTO`).
2. Usuń dane prywatne, żeby strażnik przepuścił zmianę zakresu: `weglarka apps remove <apka> --purge-volumes`
   (albo `podman volume rm <apka>.<wolumen>`) — nieodwracalne, dlatego najpierw kopia.
3. Dodaj apkę z montowaniem wolumenu współdzielonego i `start = false` (provisioning bez kontenera).
4. `weglarka volumes import <apka> kajet-data --from kopia.tar` — tryb domyślny (obcy tar) spłaszcza
   właścicieli do użytkownika kontenera, czyli poprawnie do zakresu grupy.
5. `weglarka apps start <apka>` i weryfikacja danych.

Odejście z grupy (usunięcie montowania) to ta sama zmiana zakresu i ten sam strażnik. Gdy członek ma własne
wolumeny prywatne, `apps remove --purge-volumes` jest zablokowane przez pozostałych członków, więc: eksport →
`apps stop <apka>` → `podman volume rm <apka>.<wolumen>` (ręcznie) → `apps update --spec` bez współdzielonego
wolumenu.

Wymagania dla SQLite z kilkoma pisarzami (wspólny `USER` obrazów, WAL, `busy_timeout`, kopia grupy) i zasady
importu/eksportu wolumenu współdzielonego: [„Import danych z Coolify”](#import-danych-z-coolify-np-szklanapogoda)
niżej.

### Osłonienie kontenera (`security`)

Domyślnie kontener apki ma tylko izolację UID (osobny zakres per instancja, a przy wolumenie współdzielonym —
wspólny zakres grupy, [wyżej](#wolumeny-współdzielone-grupa-uid-iteracja-2)) i ewentualne limity. Dla apek z
sekretami (klucze API, tokeny) i prywatnymi danymi włącz osłonienie — to samo, co Coolify dawał usługom
z `read_only` / `cap_drop` / `no-new-privileges`:

```toml
# apps.toml / --spec
security = { read_only = true, tmpfs = ["/cache"], cap_drop = ["ALL"], no_new_privileges = true }
```

Flagami: `--hardened` (= `read_only`, `cap_drop = ["ALL"]`, `no_new_privileges`), do tego `--tmpfs /ścieżka` dla
zapisywalnych katalogów poza wolumenami i `--cap-add NAZWA`, jeśli apka czegoś potrzebuje (np.
`NET_BIND_SERVICE` dla portu < 1024 w kontenerze). Pojedynczo: `--read-only true|false`,
`--no-new-privileges true|false`, `--cap-drop`, `--cap-add`, `--tmpfs` (`none` czyści listę).

- Przy `read_only` Podman montuje zapisywalne tmpfs na `/tmp`, `/var/tmp` i `/run`; wolumeny i sekrety działają
  jak zwykle. Apka, która pisze gdzie indziej poza wolumenem (cache, pid w katalogu aplikacji), potrzebuje `--tmpfs`.
- Zmiana `security` odtwarza kontener. Apki bez osłonienia hashują się jak wcześniej (aktualizacja Węglarki nic
  nie odtwarza).
- Sprawdź po deployu: `podman inspect <kontener> --format '{{.HostConfig.ReadonlyRootfs}} {{.EffectiveCaps}}'`.

### Kontener ingressu (`weglarka-nginx`)

Kontener nginx jest osłoniony **zawsze** (0014): to jedyny kontener wystawiony na zewnątrz, a jego profil wybiera
Węglarka, nie spec apki. `read_only`, `no_new_privileges`, `cap_drop = ["ALL"]` i tylko trzy capability z powrotem
(`CHOWN`, `SETGID`, `SETUID` — nginx zmienia właściciela swoich katalogów tymczasowych na użytkownika workera z obrazu
i do niego zrzuca uprawnienia; bez nich nie wystartuje). Wszystko, co nginx zapisuje w runtime (pid i katalogi
`*_temp_path`), leży w `/tmp`, który Podman przy `read_only` montuje jako zapisywalny tmpfs (razem z `/var/tmp`
i `/run`) — dlatego profil nie potrzebuje własnego wpisu `tmpfs`.

- Profil jest częścią `weglarka.ingress-hash`, więc **aktualizacja Węglarki odtwarza nginx jednorazowo** (krótka
  przerwa ruchu; obraz jest już na hoście, jeśli `nginx_image` się nie zmienił). Powrót do starszej Węglarki też go
  odtworzy — wtedy bez osłonienia. Żadne pole w TOML-ach się nie zmieniło, więc `deny_unknown_fields` nie
  przeszkadza w rollbacku w żadną stronę.
- Własny `ingress.nginx_image` musi działać z read-only rootem i z dokładnie tymi capability (oficjalny
  `nginx:*-alpine` działa).
- Sprawdź: `podman inspect weglarka-nginx --format '{{.HostConfig.ReadonlyRootfs}} {{.EffectiveCaps}}'` (oczekiwane
  `true` i `[CAP_CHOWN CAP_SETGID CAP_SETUID]`) oraz
  `podman exec weglarka-nginx nginx -t -c /etc/nginx/nginx.conf`.

### Import danych z Coolify (np. szklana.pogoda)

Importuj tar z Coolify trybem domyślnym (**obcy** tar): libpod nadaje wypakowanym plikom właściciela z konfiguracji
kontenera (`USER` obrazu, root gdy brak) — niezależnie od UID-ów w tarze, więc drzewo z wieloma właścicielami zostaje
spłaszczone do jednego (dla SQLite w jednym użytkowniku to właśnie to, o co chodzi).

```sh
# Na hoście Coolify: sam plik z wolumenu, nieskompresowany tar (rozpakuj .tar.gz przez gunzip)
tar -cf szklana-data.tar -C /var/lib/docker/volumes/<wolumen>/_data .
```

Apki nie trzeba najpierw uruchamiać: `start = false` ją **provisionuje** — pull obrazu i przypięcie digestu, sieć,
zakres UID i wolumeny — ale nie tworzy kontenera. Import tego nie wymaga, bo tar wypakowuje pomocniczy, niestartowany
kontener z tego samego obrazu. Cała kolejność: provisioning → import → sekrety → pierwszy start:

```toml
# szklana.toml — apka przygotowana, ale jeszcze nie uruchomiona
image = "ghcr.io/.../szklana-pogoda:latest"
start = false
volumes = [{ name = "data", target = "/data" }]
```

```sh
# Po stronie Węglarki:
weglarka apps add szklana-pogoda --spec szklana.toml                    # obraz, zakres UID, wolumen — bez kontenera
weglarka volumes import szklana-pogoda data --from szklana-data.tar     # lub: < szklana-data.tar
weglarka secrets set szklana-pogoda config < config.json                # jeśli apka ma sekrety
weglarka apps start szklana-pogoda                                      # pull, bramka zdrowia, kontener i router
```

Dopiero `apps start` zdejmuje `start = false`: pull najnowszego tagu, bramka zdrowia (rollback przy porażce), kontener
i router w ingressie. Dane z importu czekają w wolumenie z poprawnym właścicielem (zakres UID), więc apka startuje z nimi
od pierwszego ruchu. Odpowiednik flagowy zamiast pliku: `apps add ... --no-start` (ale wolumeny wymagają `--spec`).

Import zatrzymuje działający kontener apki, wypakowuje tar (robi to Podman w pomocniczym, niestartowanym kontenerze tego
samego obrazu — Węglarka niczego nie rozpakowuje) i uruchamia apkę z powrotem. Dla apki z `start = false` nie ma czego
zatrzymywać ani uruchamiać: import tylko wypakowuje dane. Pliki o tej samej ścieżce są nadpisywane, pozostałe zostają;
przerwany import zostawia część plików. Limit jednego importu: 8 GiB.

**`--replace` — import do pustego wolumenu.** Bez niej pliki spoza tara zostają w wolumenie. Przy SQLite w trybie
**WAL** to pułapka: jeśli apka wystartowała przed importem, w wolumenie leżą jej `*.db-wal`/`*.db-shm`, a po starcie
SQLite odtwarza ten stary WAL na zaimportowaną bazę — dane „znikają”, choć plik `.db` jest poprawny (tak było przy
kartoteka-develop; weryfikacja z `?immutable=1` tego nie widzi, bo ignoruje WAL). `weglarka volumes import <apka>
<wolumen> --from kopia.tar --replace` usuwa i zakłada wolumen od nowa (kontener apki jest przy tym odtwarzany).
Kopię bazy WAL rób przez `.backup` (albo `PRAGMA wal_checkpoint(TRUNCATE)` na kopii), a weryfikuj ją razem z
plikami `-wal`/`-shm`, nie samym `.db`.

**Własne kopie** (`volumes export`) wracają **tylko** z `--own` i tylko do apki o tym samym zakresie UID:

```sh
weglarka volumes export szklana-pogoda data --out backup.tar
weglarka volumes import szklana-pogoda data --from backup.tar --own
```

Nie myl trybów: obcy tar zaimportowany z `--own` ląduje **po cichu** na złych UID-ach; eksport Węglarki
zaimportowany bez `--own` traci właścicieli (wszystko dostaje użytkownika kontenera).

**SQLite w wolumenie współdzielonym (kilku pisarzy).** Wspólny zakres UID wyrównuje właścicieli plików tylko
wtedy, gdy **wszystkie obrazy członków działają jako ten sam użytkownik kontenera** — Węglarka nie nadpisuje
`USER` z obrazu, a uid 1000 w kontenerze to `zakres.start + 1000`, uid 999 to `zakres.start + 999`. Sprawdź przed
dodaniem grupy: `podman inspect <kontener> --format '{{.Config.User}}'` (pusty wynik = root, uid 0 — też musi być
taki sam w całej grupie); `doctor` (`state.shared_volumes`) tylko przypomina o tym i wypisuje członków.

Do tego zwykłe zasady SQLite: `journal_mode=WAL` zapisuje się w pliku bazy i zostaje po restarcie; zapisy i tak
serializuje SQLite (jeden pisarz naraz), więc ustaw `busy_timeout` — bez niego drugi proces dostanie `SQLITE_BUSY`
zamiast poczekać. Wolumen musi leżeć na **lokalnym** dysku (na NFS blokady POSIX są zawodne), a kopię rób przez
`.backup`/`VACUUM INTO` przy zatrzymanej grupie albo z wnętrza kontenera. Litestream zakłada jednego pisarza — to
issue #37; tutaj są tylko wymagania, nie konfiguracja.

**Import/eksport wolumenu współdzielonego.** `volumes export <apka> <wolumen>` działa, ale dla spójnej kopii
SQLite zatrzymaj najpierw **całą grupę** (`apps stop` każdego członka). Import jest odrzucany (`409`, komunikat z
listą działających członków), dopóki którykolwiek członek działa — pisanie do bazy pod żywymi procesami ją psuje.
`--replace` usuwa i zakłada wolumen grupy od nowa (w grupie jest więc jeszcze bardziej ryzykowne), a `--own` jest
poprawne tylko dla eksportu z **tego samego** zakresu, czyli z tej samej grupy; obcy tar importuj trybem domyślnym.
Nazwą wolumenu w tych komendach jest nazwa z deklaracji (`kajet-data`), nie `wg-shared-kajet-data`.

### Migracja apki z SQLite (na przykładzie szklana.pogoda)

Wnioski z migracji szklana.pogoda (2026-10-23, przerwa ≈ 46 s, z czego ~25 s dało się uniknąć):

1. **Próba bez przerwy:** apka w Węglarce **bez domeny**, z wolumenem i `auto_update = false`, jeśli apka migruje
   schemat przy starcie (rollback obrazu nie cofa schematu). Kopia z działającej apki **tylko przez SQLite**
   (`sqlite3 -readonly <baza> ".backup /tmp/kopia.db"` albo `VACUUM INTO`) — nigdy surowy plik bazy, do której
   ktoś właśnie pisze. Import obcym tarem, deploy, porównanie liczności tabel ze starą apką.
2. **Przełączenie:** zatrzymaj starą apkę w Coolify — przez API to `POST /api/v1/applications/{uuid}/stop`
   (`GET` daje 405); samo zatrzymanie trwa do ~30 s. Wyłącz w Coolify jej auto-deploy, żeby push na `main` jej
   nie podniósł. Końcowa kopia `.backup` z **zatrzymanej** bazy → ponowny import → `apps update --domain …`.
3. **Weryfikacja po przełączeniu, nie w oknie przerwy:** `PRAGMA integrity_check` na bazie w wolumenie i
   porównanie liczności rób **po** dodaniu domeny (na kopii końcowej możesz je zrobić równolegle, poza
   oknem). Przy szklanej.pogodzie sprawdzanie w oknie wydłużyło przerwę o ~25 s.
4. **Za proxy:** apka widzi ruch od nginx Węglarki z podsieci swojej sieci (`net-<instancja>`); jeśli apka sama
   ufa nagłówkom proxy, podaj jej tę podsieć (szklana.pogoda: `TRUSTED_PROXIES=10.89.5.0/24`, sprawdź
   `podman network inspect net-<instancja>`). Ustaw publiczny origin, jeśli apka go ma (cookie `Secure`).
5. **Rollback:** `apps update --remove-domain …` + start starej apki. Dane zapisane po przełączeniu przepadają —
   przed powrotem przy realnym ruchu zrób `weglarka volumes export`.

### Aktualizacja Węglarki do wersji z zakresami UID (jednorazowo)

Kontenery stworzone przez starszą Węglarkę (ntfy, nginx) działają na wspólnej domyślnej mapie Podmana (root w
kontenerze = użytkownik `weglarka` na hoście). Po aktualizacji demon przydziela im zakresy i **odtwarza je
jednorazowo**:

1. Zrób `podman ps` i zapisz stan; upewnij się, że masz świeży rollback (poprzedni obraz Węglarki).
2. Zaktualizuj Węglarkę (`podman pull … && systemctl --user restart weglarka.service`).
3. Przy starcie: nginx dostaje zakres (`ingress_uid_range`) i jest odtwarzany — **krótka przerwa ruchu** (kilka
   sekund); pierwszy start obrazu w nowym zakresie jest wolniejszy (kopia warstw).
4. Reconcile przydziela zakres `ntfy`, wykrywa brak etykiety `weglarka.uid-range` na kontenerze i odtwarza go raz
   (bez rollbacku — ten sam digest; ntfy nie ma wolumenów). Kolejne przebiegi nic nie zmieniają.
5. Sprawdź: `podman exec ntfy cat /proc/self/uid_map` (oczekiwane: `0 <start> 65536`, gdzie `<start>` to
   `uid_range.start` z `weglarka apps show ntfy`), `weglarka doctor`, `scripts/acceptance.sh` (obowiązkowo).
6. Gdyby ntfy nie wstał po bramce zdrowia: `journalctl --user -u weglarka` / `weglarka apps show ntfy`; powrót do
   poprzedniej Węglarki zostawia kontenery z zakresami — nginx i ntfy wrócą na domyślną mapę dopiero przy ich
   następnym odtworzeniu przez starą wersję.

Pliki zamontowane z hosta (`nginx.conf` w `/var/lib/weglarka/nginx`) muszą być czytelne dla „obcych” UID-ów
(0644 w katalogu 0755 — tak je zapisuje demon).

### Rollback do Węglarki bez wolumenów współdzielonych

`[shared_volumes]` w `apps.toml` i sekcja `shared_volumes` w `state.toml` to nowe pola, a oba pliki mają
`deny_unknown_fields` — **starszy demon ich nie odczyta**. Przed downgradem:

1. Usuń z apek wszystkie wpisy `shared_volumes` (albo najpierw `apps remove` członków) i sekcję `[shared_volumes.*]`
   z `apps.toml` oraz sekcję `shared_volumes` ze `state.toml` — albo po prostu przywróć oba pliki z kopii zrobionej
   przed wdrożeniem wolumenów współdzielonych.
2. Stara Węglarka nie widzi wolumenów `wg-shared-*` (brak etykiety `weglarka.instance`) i **nie da się jej
   wskazać** takiego wolumenu jako prywatnego wolumenu apki. Jeśli dane nie są potrzebne:
   `podman volume rm wg-shared-<nazwa>`; jeśli są — skopiuj je do prywatnego wolumenu apki przed downgradem
   (pamiętając, że stara Węglarka odtworzy kontener we własnym zakresie UID) albo zostaw wolumen na później.
3. Kontenery członków działają w zakresie grupy, dopóki stary demon ich nie odtworzy — a odtworzy je we własnych
   zakresach i dane w wolumenie staną się nieczytelne. Przed downgradem zrób `volumes export` i zatrzymaj apki
   (`apps stop`).

## 6b. Zatrzymywanie apek: `start = false`

`start` w spec apki (domyślnie `true`, w `apps.toml` zapisywany tylko jako `start = false`) mówi, czy apka ma
**działać**, czy być tylko **przygotowana**. Decyzja i odrzucone alternatywy: [0011](decisions/0011-start-false-provisioning.md).

```sh
weglarka apps add stara-apka ghcr.io/.../stara:latest --domain stara.descriptortable.eu --port 8080 --no-start
weglarka apps start stara-apka               # start = true: pull tagu, bramka zdrowia, kontener i router
weglarka apps stop stara-apka                # start = false: usuwa kontener, zostawia wolumeny i zakres UID
weglarka apps update stara-apka --no-start   # to samo co `apps stop`, przez update spec
weglarka apps update stara-apka --start      # to samo co `apps start`
```

- Apka z `start = false` jest **provisionowana**: przypięty digest obrazu, sieć apki, zakres UID i wolumeny —
  bez kontenera. `weglarka status` / `apps show` pokazują wtedy `not_started` i to jest stan poprawny (brak
  kontenera z założenia), a nie błąd ani „czeka na sekret”.
- `apps stop` **usuwa** kontener (nie tylko go zatrzymuje); wolumeny, zakres UID i sekrety zostają. Zakres i dane
  zwalnia dopiero `apps remove --purge-volumes`.
- Dopóki apka stoi, webhook/auto-update są wstrzymane: pakiet z GitHuba nie robi dla niej pullu ani deployu.
  `apps start` sam pobiera najnowszy tag, więc apka wstaje z aktualnym obrazem (stop nie zamraża wersji).
- Apka z `start = false` **nie dostaje routera** w nginx/Traefik — nie ma dokąd kierować ruchu. Jej domeny
  pozostają jednak zarezerwowane i walidowane: duplikat domeny (także z drugą, działającą apką) nadal jest
  błędem. Dzięki temu możesz trzymać domenę w Coolify i przygotować Węglarkę wcześniej, a przełączyć się bez
  kolizji routerów.
- `apps update --spec plik.toml` podmienia **całą** spec: jeśli w pliku nie ma `start`, obowiązuje domyślne `true`
  i apka wstanie. Zatrzymaną apkę opisuj w pliku z `start = false`.
- Uwaga przy rollbacku: `start` to nowe pole w `apps.toml` z `deny_unknown_fields`, więc **starszy** demon/CLI
  nie odczyta specu zatrzymanej apki (`start = false`). Wracając do poprzedniej wersji Węglarki usuń `start = false`
  z `apps.toml` (albo najpierw `weglarka apps start`) — inaczej daemon odmówi startu z błędem parsowania.
- Uwaga przy łączeniu wersji: `doctor` raportuje trwającą operację statusem `info` (`state.deploying`). Starsze CLI
  nie zna tego wariantu i gdy w chwili `weglarka doctor` trwa deploy/recreate, nie sparsuje odpowiedzi — aktualizuj
  CLI razem z demonem (nowe CLI czyta starszy demon bez zmian).

## 6c. Porty publikowane na hoście (`host_ports`)

Niektóre usługi muszą być widoczne na **stałym porcie TCP hosta**, obok swojej strony HTTPS w ingressie. Typowy
przypadek: serwer gita, którego SSH musi zostać pod znanym numerem (np. `2222` → port `22` w kontenerze), bo ten
numer siedzi w `git remote` i w przekierowaniu portów na routerze — a UI dalej idzie przez ingress po domenie.
Decyzja i odrzucone alternatywy: [0013](decisions/0013-host-ports.md).

```toml
# apps.toml / --spec: git.example.com po HTTPS przez ingress + SSH na porcie hosta
image = "ghcr.io/example/git-server:latest"
domains = ["git.example.com"]
port = 3000
# 127.0.0.1:2222 → 22 w kontenerze (bez `ip` = tylko loopback):
host_ports = [{ host = 2222, container = 22 }]
# publicznie, dopiero po regule UFW:
# host_ports = [{ host = 2222, container = 22, ip = "0.0.0.0" }]
```

Zastosowanie: `weglarka apps add git --spec git.toml` (albo `apps update git --spec git.toml`); gotowy plik:
[`docs/examples/host-ports.toml`](examples/host-ports.toml). To samo flagami `apps add` / `apps update`:
`--host-port 2222:22` (bez IP = loopback), `--host-port 0.0.0.0:2222:22`, `--host-port none` czyści listę.
Flaga, jak `--volume`, wyklucza się z `--spec`; reszta specu (obraz, domeny, limity) zostaje na dotychczasowych
flagach albo w pliku.

- `host` to port na hoście, `container` to port w kontenerze, `ip` — opcjonalny adres nasłuchu. **Bez `ip` port
  słucha tylko na `127.0.0.1`**: z hosta, przez tunel SSH albo lokalne proxy. Wystawienie na świat wymaga jawnego
  `ip = "0.0.0.0"` (albo `::`, albo adresu konkretnego interfejsu) — celowo, żeby nowe pole nie odsłaniało
  usługi przez przypadek.
- Tylko **TCP**. Nie ma UDP, TLS ani PROXY protocolu: to zwykłe mapowanie portu w Podmanie
  (`ContainerSpec.publish`), a nie proxy.
- **Ingress jest całkowicie pomijany:** żadnego routera nginx/Traefik, certyfikatu, logu dostępu ani routingu po
  domenie. Jedyne «drzwi» to firewall hosta — regułę UFW dodaje rola `weglarka_host` w Ansible, **Węglarka
  firewalla nie zmienia** (działa rootless). Port bez reguły jest nieosiągalny z zewnątrz, choć działa lokalnie:
  nie zakładaj, że «skoro `curl` z hosta działa, to działa też z internetu».
- `host_ports` **wchodzi do `spec-hash`**: zmiana `host`, `container` albo wystawionego adresu odtwarza kontener
  (krótka przerwa; bramka zdrowia i rollback jak przy każdym recreate). Pusta/nieustawiona lista haszuje się jak
  dotąd — aktualizacja Węglarki niczego nie odtwarza. Zapisanie `ip = "127.0.0.1"` zamiast pominięcia `ip` to ten
  sam hash (kolejność wpisów też nie ma znaczenia) — jawny loopback nie odtwarza kontenera.
- `apps update --spec` podmienia **całą** spec, więc plik bez `host_ports` po cichu usuwa wpisy — jak każde inne
  pole.
- Apka z `start = false` ([6b](#6b-zatrzymywanie-apek-start--false)) nie publikuje nic (nie ma kontenera, więc nikt
  nie słucha), ale wpisy zostają w specu i w walidacji konfliktów — zarezerwowane jak domeny.
- **Walidacja:** `host` i `container` ≠ 0, `ip` musi być literałem IP, żadnych dwóch wpisów tej samej apki na tym
  samym gnieździe; między apkami i względem `[ingress] bind` też nie może być kolizji (adres `0.0.0.0`/`::`
  koliduje z każdym innym adresem na tym porcie). Demon odrzuca taki spec przy `apps add`/`apps update` (HTTP 400,
  `invalid_request`), a `apps.toml` z kolizją nie wczyta się przy starcie — komunikat wskazuje apkę i port.
- **Porty < 1024** (np. samo `22`): rootless Podman zwiąże je tylko wtedy, gdy host ma ustawione
  `net.ipv4.ip_unprivileged_port_start=0`, a Węglarka dodatkowo wymaga
  `[runtime] allow_privileged_host_ports = true` ([2](#2-konfiguracja-hosta), domyślnie `false`). Bez tego spec
  jest odrzucany od razu, zamiast wywalać się przy starcie kontenera.
- Sprawdzenie przed dodaniem: `weglarka doctor --preflight` — `apps.host_ports_free` czyta lokalny `apps.toml`,
  waliduje deklarację (kolizje, porty < 1024 bez opt-inu) i pokazuje porty zajęte przez cudzy proces. Po
  deployu: `podman port <instancja>` albo `ss -lnt | grep 2222`.

**Uwaga bezpieczeństwa:** publikowany port omija cały ingress — nie ma tam TLS, logu dostępu, routingu po domenie
ani żadnej warstwy Węglarki. Autoryzację (klucze SSH, tokeny aplikacji) robi sama usługa, a dostęp ogranicza tylko
firewall hosta. Wystawiaj wyłącznie to, co naprawdę musi być publiczne, i zaczynaj od loopbacku, dopóki nie masz
reguły UFW.

Uwaga przy rollbacku: `host_ports` to nowe pole w `apps.toml`, a `[runtime] allow_privileged_host_ports` — w
`weglarka.toml`; oba pliki mają `deny_unknown_fields`, więc **starszy demon** ich nie odczyta. Wracając do
poprzedniej wersji Węglarki usuń wpisy `host_ports` z apek i tę flagę z configu — inaczej demon odmówi startu z
błędem parsowania.

## 6d. Zależności między apkami (`depends_on`)

Część apek potrzebuje, żeby inna apka już działała — usługa i jej baza, worker i kolejka. Bez deklaracji obie
startują w tym samym przebiegu reconcile, więc zależna apka może trafić na bramkę zdrowia, zanim zależność ma
kontener: deploy „raz działa, raz się cofa”. Decyzja i odrzucone alternatywy: [0015](decisions/0016-depends-on.md).

```toml
# apps.toml / --spec: `api` startuje dopiero, gdy `db` działa (i jest zdrowa, jeśli ma healthcheck)
depends_on = ["db"]
# kilka zależności naraz, kolejność na liście nie ma znaczenia:
# depends_on = ["db", "redis"]
```

Zastosowanie: `weglarka apps add api --depends-on db` (albo `apps update api --depends-on db`); `db` musi już być
w `apps.toml`. Gotowy plik: [`docs/examples/depends-on.toml`](examples/depends-on.toml) — fragment `apps.toml`
z dwiema apkami (nie `--spec`: plik specu opisuje jedną apkę). Flagi: `--depends-on` jest powtarzalna,
`--depends-on none` czyści listę, a `apps update api --remove-depends-on db` usuwa jedną pozycję (błąd użycia, gdy
jej nie ma); jak `--host-port`, wykluczają się z `--spec`.

- `depends_on` to **tylko kolejność startu i bramka zdrowia**, nie sieć: każda apka ma własną sieć `net-<instancja>`
  (0009), więc `api` nie rozwiąże nazwy `db` i nie połączy się z nią. Wspólna sieć / wspólny Postgres to pozostała,
  niezaimplementowana część #35.
- Kolejność obowiązuje tam, gdzie Węglarka **startuje** kontener: reconcile po starcie demona, pierwszy deploy,
  `apps start`, deploy z CLI i z webhooka oraz recreate, gdy kontenera nie ma. Nie dotyczy podmiany działającego
  kontenera przy zmianie spec-hash (apka już działa) ani provisioningu (`start = false` — nie ma kontenera).
- **Bramka:** kontener zależności musi **działać**, a jeśli zależność ma healthcheck (`health.command` albo
  `HEALTHCHECK` z obrazu), musi być **zdrowa**; `health.http` jest sprawdzane przez ingress, jak w bramce deployu
  (0010). Samo istnienie kontenera nie wystarcza.
- **Czekanie jest ograniczone:** gdy kontener zależności istnieje, ale nie jest jeszcze gotowy (np. właśnie trwa
  jego deploy), Węglarka czeka do 10 s, odpytując co 1 s. Potem — a także gdy czekanie nie ma sensu (brak
  kontenera, `start = false`) — admin API zwraca **409 Conflict** z listą niespełnionych zależności i powodów, a
  reconcile zgłasza „waiting for dependencies” i ponawia w następnym przebiegu, **bez oznaczania apki jako
  błędnej** (bez rollbacku i bez błędu w stanie).
- **Walidacja:** nieznana nazwa, odwołanie do samej siebie, duplikat i cykl są odrzucane przy zapisie specu
  (`apps add`/`apps update` → HTTP 400 `invalid_request`) i przy wczytywaniu `apps.toml` na starcie demona (demon
  odmawia startu, komunikat wskazuje apki). Dlatego `apps add api --depends-on db` wymaga, żeby `db` już było
  w `apps.toml`.
- **Usuwanie:** `apps remove db`, gdy inna apka ma `depends_on = ["db"]`, kończy się 409 Conflict z listą zależnych
  apek — nic nie jest usuwane, także z `--purge-volumes`. Najpierw usuń zależne apki albo ich wpisy `depends_on`.
- Zależność z `start = false` ([6b](#6b-zatrzymywanie-apek-start--false)) nie ma kontenera, więc zależna apka nie
  wystartuje: reconcile zgłasza oczekiwanie, a `doctor` ostrzega. Wystarczy `weglarka apps start db`.
- `depends_on` **nie wchodzi do `spec-hash`**: zmiana, przełożenie czy wyczyszczenie listy nie odtwarza kontenera,
  a `state.toml` się nie zmienia.
- `apps update --spec` podmienia **całą** spec, więc plik bez `depends_on` po cichu usuwa listę — jak każde inne
  pole.
- Sprawdzenie: `weglarka doctor` — nowy check `state.dependencies`: Warn, gdy zależność działającej apki nie
  istnieje, stoi albo jest niezdrowa, lub gdy zależność ma `start = false`; Info, gdy apka nie jest jeszcze wdrożona
  i czeka na zależności; Ok inaczej.

Uwaga przy rollbacku: `depends_on` to nowe pole w `apps.toml`, a ten plik ma `deny_unknown_fields`, więc **starszy
demon** go nie odczyta. Wracając do poprzedniej wersji Węglarki usuń wpisy `depends_on`
(`weglarka apps update <apka> --remove-depends-on <zależność>`) — inaczej demon odmówi startu z błędem parsowania.

## 6e. Streaming (SSE, long polling)

Aplikacje, które trzymają odpowiedź otwartą — SSE (np. `/<topic>/sse` w ntfy), strumień chunked albo long polling —
muszą ominąć dwa domyślne zachowania nginxa: `proxy_buffering on` (zdarzenia czekają w buforze proxy zamiast
iść do klienta) i `proxy_read_timeout 60s` (dłuższa cisza kończy strumień błędem 504). WebSocket działa już dziś
(nagłówki `Upgrade`/`Connection`), więc chodzi o klientów, którzy streamują po zwykłym HTTP. Decyzja i odrzucone
alternatywy: [0018](decisions/0018-ingress-streaming.md).

```toml
# apps.toml: strumieniowanie włączone tylko dla tej apki
[apps.ntfy.ingress]
streaming = true
# stream_timeout_secs = 180   # opcjonalne: domyślnie 180, dozwolone 1..=3600
```

Zastosowanie: `weglarka apps update ntfy --streaming` dla istniejącej apki, `weglarka apps add ntfy --streaming`
przy dodawaniu. W pliku `--spec` (jedna apka, nie cały `apps.toml`) ten sam blok to zwykła tabela `[ingress]`:

```toml
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
domains = ["ntfy.example.com"]
port = 8080
[ingress]
streaming = true
```

Gotowy plik: [`docs/examples/streaming.toml`](examples/streaming.toml).

- `streaming = true` dodaje w `location /` **tej jednej apki** cztery dyrektywy: `proxy_buffering off;`,
  `proxy_request_buffering off;`, `proxy_read_timeout <n>s;` i `proxy_send_timeout <n>s;`. Pozostałe apki, bloki
  webhooków i serwer domyślny zostają bez zmian — apka bez `ingress` dostaje `nginx.conf` dokładnie taki jak dziś.
- `stream_timeout_secs` to bezczynność w obie strony: **domyślnie 180**, dozwolone **1–3600**. Samo
  `streaming = true` wystarcza (domyślny timeout nie jest zapisywany). Ustawienie timeoutu przy
  `streaming = false` jest odrzucane przez walidację komunikatem „requires ingress.streaming = true” — timeout,
  który nigdy nie trafi do configu, to literówka, nie opcja. W v1 **nie ma flagi CLI** dla timeoutu: ustawiasz go
  w `apps.toml` albo przez `apps update --spec`.
- **Tylko ingress:** zmiana renderuje `nginx.conf`, sprawdza go `nginx -t` i robi SIGHUP — tak samo jak `--domain`.
  Kontener apki, jego digest i `spec-hash` zostają nietknięte, nie ma deployu ani przerwy w ruchu do apki. Zmiana
  działa na nowe połączenia; nginx domyka stare workery, więc otwarty strumień kończy się na starym.
- `--no-streaming` czyści **cały** blok `ingress` (razem z własnym timeoutem) i nic nie wysyła, gdy apka i tak nie
  streamuje. Flagi, jak `--domain`, wykluczają się z `--spec`.
- **Uwaga operacyjna:** `proxy_buffering off` to cel, ale ma koszt — wolny klient trzyma połączenie workera nginxa
  przez cały czas trwania strumienia (`worker_processes 1`, `worker_connections 1024`), a
  `proxy_request_buffering off` rozciąga to samo na wolno wysyłane ciało żądania. Włączaj streaming apkom, które
  naprawdę streamują, a nie wszystkim «na wszelki wypadek».
- Apka, która ma WebSocket i włączy streaming, dostaje przy okazji dłuższy idle timeout (180 s zamiast 60 s) —
  zwykle dokładnie to, czego chce, ale to zmiana zachowania, nie efekt uboczny.
- **Traefik (`behind`) się nie zmienia:** przekazuje odpowiedź na bieżąco i jej nie buforuje, a jego `idleTimeout`
  dotyczy bezczynności między żądaniami keep-alive, nie trwającego strumienia. (Tryb `edge` nie jest
  zaimplementowany; zanim powstanie, musi to sprawdzić osobno — [0005](decisions/0005-ingress-i-platforma.md).)
- **Bezpieczeństwo configu:** gdy nginx odrzuci wygenerowany config, `nginx -t` w demonie kończy się błędem,
  a poprzedni, działający config zostaje przywrócony — zły wpis nie zostawia ingressu bez ruchu.
- Rollback: `apps.toml` ma `deny_unknown_fields`, więc **starszy demon** nie odczyta bloku `[apps.X.ingress]`.
  Przed downgradem usuń go (`apps update --no-streaming` albo ręcznie) — patrz [7](#7-weryfikacja-i-rollback).

## 6f. Komenda i argumenty kontenera (`command`)

Obraz może definiować tylko `ENTRYPOINT` i oczekiwać podkomendy jako argumentu: `docker.io/binwiederhier/ntfy`
ma `ENTRYPOINT ["ntfy"]` i nie ma `CMD`, więc kontener startuje bez argumentów, wypisuje pomoc i kończy się
kodem 0 — a bramka zdrowia zgłasza „container not running (Stopped, exit code 0)”. To nie awaria obrazu ani
brakujący healthcheck: brakuje argumentu `serve`. Opcjonalne pole `command` podaje argv kontenera. Decyzja
i odrzucone alternatywy: [0019](decisions/0019-container-command.md).

```toml
# apps.toml / --spec: ntfy uruchamia się jako `ntfy serve`
[apps.ntfy]
image = "docker.io/binwiederhier/ntfy:latest"
domains = ["ntfy.example.com"]
port = 80
command = ["serve"]             # argv kontenera: ["ntfy", "serve"]
```

Zastosowanie: `weglarka apps add ntfy docker.io/binwiederhier/ntfy:latest --command serve` dla nowej apki,
`weglarka apps update ntfy --command serve` dla istniejącej; w pliku `--spec` `command` jest polem
najwyższego poziomu (jak `image`). Gotowy plik: [`docs/examples/command.toml`](examples/command.toml).

- **Exec form, bez shella:** każdy element listy to dokładnie jeden argument argv — nic nie jest cytowane,
  dzielone ani rozwijane. `command = ["serve", "-v"]` to dwa argumenty, `command = ["serve -v"]` to jeden
  argument ze spacją, a `$VAR`, `*`, `;` i `&&` są danymi, nie składnią shella (obraz bez shella, np.
  `scratch`, działa tak samo).
- **To nie jest nadpisanie entrypointu:** pole trafia do `Cmd` / `SpecGenerator.command` w libpodzie, czyli
  jest doklejane do `ENTRYPOINT` obrazu (dla ntfy: `["ntfy", "serve"]`). Osobne pole `entrypoint` jest poza
  zakresem tej zmiany — to inna decyzja o innym znaczeniu (podmiana `["ntfy"]`, nie dodanie argumentu).
- **Puste = `CMD` obrazu, ustawione zastępuje `CMD`** (nie dopisuje): obraz z `CMD ["serve"]` i
  `command = ["worker"]` uruchomi `worker`, a nie `serve worker`; obraz bez `ENTRYPOINT` dostaje całe argv
  z `command`. Puste `command` znaczy to samo co brak pola („bez argumentów” to dokładnie domyślny `CMD`).
- **`spec-hash`:** `command` wchodzi do hasha **tylko gdy jest ustawione** (dopisywane na końcu wejścia,
  format v1 bez zmian), więc upgrade Węglarki nie odtworzy żadnego istniejącego kontenera. Zmiana `command`
  — także kolejność argumentów — zmienia `spec-hash`, a kolejny reconcile odtwarza kontener z **przypiętego
  digestu** (bez pullu).
- **CLI:** `--command ARG` jest powtarzalna — jedno wystąpienie to jeden element argv; argument zaczynający
  się od myślnika wymaga formy z `=`: `apps update ntfy --command serve --command=-v`. Flagi **zastępują
  cały wektor** (nie dopisują do niego), a `--command none` (wielkość liter bez znaczenia) czyści pole do
  `CMD` obrazu — na obrazie z samym `ENTRYPOINT` to powrót do zepsutego domyślnego zachowania. Jak inne
  flagi specu, `--command` wyklucza się z `--spec`; `--dry-run` pokazuje diff i niczego nie wysyła.
- **Walidacja:** każdy argument musi być niepusty; pusty string kończy się HTTP 400 z komunikatem
  `command argument <i> must not be empty`. Pusta **lista** to nie błąd — to „nie ustawiono”, czyli `CMD`
  obrazu.
- **Uwaga operacyjna (rollback):** bramka zdrowia po nieudanym deployu przywraca tylko poprzedni **digest**,
  nie spec. Błędny `command` obleje więc deploy *i* rollback (stary digest, te same złe argumenty) i apka
  zostanie zatrzymana, dopóki spec nie zostanie poprawiony: `weglarka apps update <apka> --command ...`
  (kolejny reconcile odtworzy kontener z przypiętego digestu, bez pullu). Rozpoznanie objawu: deploy pada
  na bramce z kodem wyjścia 0 i pomocą obrazu — to brakujące lub złe `command`, nie zły obraz.
- **Downgrade:** `apps.toml` ma `deny_unknown_fields`, więc **starszy demon** nie odczyta `command`. Przed
  powrotem do starszej Węglarki usuń pole z apek (`apps update <apka> --command none` albo ręcznie) — patrz
  [7](#7-weryfikacja-i-rollback).
## 6g. Retencja obrazów i jednorazowe sprzątanie

Do tej pory każdy deploy zostawiał poprzedni obraz na zawsze (issue #40), więc dysk się zapełniał
(`niechybnie`: ~83 %). Teraz Węglarka sama pilnuje porządku i daje jednorazowe sprzątanie tego, co
zostało po starszych deployach.

- **Co zostaje:** po udanym deployu (także po rollbacku i przy `start = false`) trzymane są dwa obrazy
  repozytorium apki — bieżący (`current`) i poprzedni (`previous`, cel rollbacku). Starsze obrazy tego
  samego repozytorium są usuwane. Obraz, którego używa **jakikolwiek** kontener (także zatrzymany), obraz
  przypięty w `state.toml` dowolnej apki i obraz, którego tag nadal występuje w `apps.toml`, nigdy nie
  zostanie usunięty; `image remove` nie jest wołane z `force`, więc Podman odmawia usunięcia obrazu
  w użyciu. Deploy nie pada przez sprzątanie — problem z retencją jest tylko logowany.
- **Czego Węglarka nie rusza:** obrazów spoza repozytoriów wymienionych w `apps.toml` (ingress nginx,
  ręczne `podman pull`, warstwy pośrednie) oraz obrazów repozytorium, którego żadna apka już nie
  wymienia (usunięta apka albo zmieniony `image`) — te nie są przypisywalne, patrz
  [0020](decisions/0020-image-retention.md).
- **Jednorazowo po aktualizacji** (obrazy zostawione przez wcześniejsze deploye):

  ```sh
  weglarka images prune --dry-run   # lista: ID, tag/digest, rozmiar; nic nie usuwa
  weglarka images prune             # usuwa i podaje, ile miejsca zwolniono (górna granica)
  ```

  Sprzątanie jest **jawne**, nie automatyczne przy starcie demona: masowe kasowanie obrazów należy do
  decyzji operatora. Demon serializuje je z deployami (w trakcie deployu odpowiada `busy`, podobnie jak
  pozostałe mutacje).
- **Ostrzeżenie w `doctor`:** check `runtime.images` zgłasza `warn` z liczbą nieużywanych obrazów
  i rozmiarem („at most” — warstwy wspólne liczone są per obraz), a `hint` wskazuje
  `weglarka images prune`. W trakcie deployu check jest informacyjny (`info`): świeżo przyciągnięty obraz
  nie jest jeszcze w `state.toml`, więc wyglądałby na nieużywany.
- Brak zmian w `apps.toml`/`state.toml`, więc upgrade i rollback demona są bezpieczne.

## 6h. Powiadomienia (ntfy)

Nieudany deploy, rollback i zdarzenia z pętli reconcile trafiają do telefonu przez ntfy — wysyłanego przez
Węglarkę samą (apka `ntfy`), więc powiadomienia muszą przetrwać deploy ntfy. Decyzja i odrzucone alternatywy:
[0021](decisions/0021-notifications.md). Wycinek konfiguracji: [`docs/examples/notify.toml`](examples/notify.toml).

Co przychodzi: `deploy ok`, `deploy failed`, `rolled back`, `ROLLBACK FAILED` (krytyczne),
`provisioned`, `recreated`, `waiting for secrets` (info) oraz — gdy podniesiesz `min_severity` do `debug` —
`sprzątanie kontenera`, `oczekiwanie na zależności` i `duplikat webhooka`. Pętle restartów i failing
healthchecki opisuje [6i](#6i-wykrywanie-awarii-apek-crash-loop-unhealthy) i
[0022](decisions/0022-crash-loop-detection.md); fallback mailowy to #113.

**1. Temat i token w ntfy.** Utwórz temat (np. `weglarka`) i — jeśli serwer nie jest publiczny — token dostępu
w panelu ntfy. Token trzymaj w pliku 0600 obok konfiguracji; **nie wpisuj go do `weglarka.toml`**:

```sh
umask 077 && printf '%s\n' 'tk_…' | sudo -u weglarka tee /var/lib/weglarka/ntfy-token >/dev/null
sudo -u weglarka chmod 600 /var/lib/weglarka/ntfy-token
```

**2. Sekcja w `weglarka.toml`** (plik konfiguracyjny hosta, nie `apps.toml`):

```toml
[notify]
dedup_window_secs = 300          # okno łączenia powtórzeń; 0 = bez łączenia

[notify.ntfy]
url = "https://nz.example.com"   # musi być osiągalny Z KONTENERA Węglarki (patrz niżej)
topic = "weglarka"
token_file = "/var/lib/weglarka/ntfy-token"   # opcjonalny; bez niego temat jest publiczny
min_severity = "info"            # debug | info | warning | critical
```

- **Adres:** jeśli kontener Węglarki nie potrafi wyjść na publiczną domenę hosta (hairpin NAT / DNS w
  kontenerze), użyj trasy wewnętrznej przez ingress: `url = "http://weglarka-nginx:8080"` oraz
  `host = "nz.example.com"` (nagłówek `Host` i nazwa SNI; nginx routuje po `Host`, tak samo jak
  `health.http`). Wewnętrzna trasa jest po HTTP w sieci Podmana — token nie opuszcza hosta.
- **Walidacja przy starcie:** zły URL, temat albo nieczytelny/rozluźniony plik tokenu **zatrzymuje demona**
  (`notifications: …` w logu) — raz włączone powiadomienia nie mogą po cichu nie działać.
- **Test:** po restarcie `systemctl --user restart weglarka`:

```sh
weglarka notify test      # „test notification delivered” = URL, DNS, ingress i token działają
weglarka notify status    # kanały, kolejka, licznik odrzuconych, ostatni błąd i czas dostarczenia
```

`notify test` idzie **poza kolejką** (natychmiast, bez dedup), a przy odmowie kanału kończy się kodem 7.

**3. Co się dzieje, gdy ntfy nie odpowiada.** Każde powiadomienie najpierw trafia do trwałej kolejki
`/var/lib/weglarka/notifications.toml` (0600), a dopiero potem jest wysyłane. Nieudana próba zostaje w kolejce
i jest powtarzana z backoffem 30 s → 1 min → … → 30 min, maksymalnie 12 razy (≈3,5 h); kolejkę ograniczają też
200 pozycji i 7 dni (najstarsze wypadają, licznik `dropped` widać w `notify status`). Dzięki temu deploy ntfy —
czyli chwila, w której powiadomienia są najbardziej potrzebne — nie gubi powiadomień. Kolejka przeżywa restart
demona; okna dedup (poniżej) są tylko w pamięci.

**4. Powtórzenia (flapping).** Pierwsze zdarzenie danego rodzaju dla danej apki idzie od razu; kolejne w oknie
`dedup_window_secs` są liczone i po jego zamknięciu przychodzi jedno podsumowanie („3 more: deploy failed: ntfy”).
Sukces nie zeruje okna niepowodzeń — apka, która na przemian wstaje i pada, nadal daje jedno zgłoszenie na okno.

**5. Rollback.** `weglarka.toml` ma `deny_unknown_fields`, więc **starszy demon nie wystartuje** z sekcją
`[notify]`. Przed downgradem usuń ją z konfiguracji (albo zostaw w kopii) i zrestartuj usługę — powiadomienia
nie są częścią stanu apek, więc nic więcej nie trzeba czyścić.

## 6j. Configi z hosta (`config_root`) i `apps reload`

Infra-apki (Authelia #88, Prometheus, Grafana, Loki) potrzebują plików konfiguracyjnych. Zamiast wrzucać je do
obrazu, do sekretów albo importować do wolumenu, Węglarka montuje je **read-only** z jednego katalogu na hoście i
pozwala wskazać, jak apka ma je przeładować. Decyzja: [0023](decisions/0023-config-root-mounts.md); gotowy
przykład: [`docs/examples/configs.toml`](examples/configs.toml).

**1. Katalog.** W `weglarka.toml` dodaj `config_root` — absolutny albo względny do katalogu tego pliku:

```toml
# config_root = "/var/lib/weglarka/config"
```

Katalog należy do użytkownika runtime'u (zwykle trzyma się go jako repo git: commituj zmiany, `git checkout` to
rollback). Demon montuje ten katalog do **swojego** kontenera read-only (potrzebuje go do `apps show` i
`doctor`), a kontenery apek dostają własne bind-mounty read-only z libpoda. Bez `config_root` funkcja jest
wyłączona; apka z `configs` przy pustym `config_root` jest odrzucana przy zapisie. Sam `config_root`, jeśli
jest ustawiony, musi istnieć i być katalogiem — inaczej demon nie wystartuje.

Po aktualizacji Węglarki **uruchom ponownie `weglarka platform install`** (quadlet dostaje nowy mount) — bez tego
demon nie widzi katalogu i `doctor` to zgłosi.

**2. Spec apki.** `source` jest zawsze względny do `config_root`, `target` to ścieżka w kontenerze. Mount jest
zawsze read-only (nie ma flagi rw). Lista `configs` jest częścią `spec-hash` — zmiana **co** jest montowane
odtwarza kontener; zmiana **treści** plików już nie.

```toml
# apps.toml / --spec
configs = [
  { source = "prometheus/prometheus.yml", target = "/etc/prometheus/prometheus.yml" },
  { source = "prometheus/rules", target = "/etc/prometheus/rules" },   # katalog
]
reload_signal = "SIGHUP"   # opcjonalnie: bez niego `apps reload` restartuje kontener
```

Przez flagi CLI: `weglarka apps update prometheus --config prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
--reload-signal SIGHUP` (flaga zastępuje wpis o tym samym `source`; `--config none` czyści listę).

Bezpieczeństwo: `source` musi być względny, bez `.`/`..`, po rozwiązaniu symlinków musi zostać wewnątrz
`config_root`, a `target` podlega regułom wolumenów. Sekretów nie trzymaj w `config_root` — apka powinna czytać je
przez `*_FILE`/env. Walidacja jest dwuwarstwowa: reguły składniowe (`source` względny, bez `..`, unikalny `target`) przy
każdym `apps.toml`, a reguły systemu plików (symlinki, containment, plik/katalog) w reconcile, przed startem
kontenera i przy `apps reload`. Brakujący plik nie blokuje więc dodania apki ani startu demona — blokuje samą
apkę (`weglarka doctor` to pokaże).

**3. Zmiana i reload.** Treść plików nie jest częścią `spec-hash`, więc pętla reconcile niczego nie odtwarza.
Aplikuj zmianę jawnie:

```sh
vim /var/lib/weglarka/config/prometheus/prometheus.yml
weglarka apps reload prometheus        # SIGHUP (spec ma reload_signal) albo restart kontenera
git -C /var/lib/weglarka/config commit -am "scrape nowy cel"
```

`apps reload` bierze mutex silnika (serializuje się z deployem), nie zmienia `apps.toml`/`state.toml` i odmawia
(409), gdy kontener nie działa — wtedy `weglarka apps start`. Rollback configu to `git checkout` + `apps reload`;
rollback obrazu przywraca digest, nie pliki.

**4. Edytor, inode i `--recreate`.** Edytory zapisujące przez write-and-rename zostawiają single-file bind mount
na starym inodzie — apka nadal widzi poprzednią treść, mimo poprawnego `git status`. Rozwiązania: mountować
**katalog** (`source = "prometheus"`, `target = "/etc/prometheus"`) albo po takim zapisie:

```sh
weglarka apps reload prometheus --recreate   # odtworzenie kontenera z przypiętego digestu (bez pullu)
```

**5. Uprawnienia i widoczność.** Pliki użytkownika runtime'u są w zakresie UID apki widoczne jako `nobody`
([0009](decisions/0009-volume-ownership.md)), więc wystarczą `0644` dla plików i `0755` dla katalogów:

```sh
chmod -R u=rwX,go=rX /var/lib/weglarka/config
```

`weglarka apps show prometheus` wypisuje każdy mount z aktualnym fingerprintem treści, a `weglarka doctor`
ostrzega o brakującym źródle, ucieczce poza katalog, zbyt luźnych uprawnieniach oraz o tym, że sam katalog jest
group/world-writable.

**6. Rollback Węglarki.** `weglarka.toml` i `apps.toml` mają `deny_unknown_fields`: starszy demon nie wystartuje z
`config_root`, `configs` ani `reload_signal`. Przed downgradem usuń te pola (configi zostają na dysku, po prostu
nie są montowane).
## 6i. Wykrywanie awarii apek (crash loop, unhealthy)

Apka, która w kółko pada, nie jest dziś widoczna: każdy kontener chodzi z `restart = always`, więc Podman
podnosi go, zanim następne przejście reconcile zauważy cokolwiek złego — a bramka zdrowia sprawdza healthcheck
tylko przy deployu. Pętla reconcile wykrywa teraz dwie rzeczy i wysyła je jako **zdarzenia silnika**: przy
skonfigurowanych powiadomieniach trafiają do ntfy (patrz [6h](#6h-powiadomienia-ntfy)), a bez nich zostają
w logu demona. Decyzja i odrzucone alternatywy: [0022](decisions/0022-crash-loop-detection.md). Wycinek
konfiguracji: [`docs/examples/monitor.toml`](examples/monitor.toml).

**Co powstaje:**

- `crash loop: <apka>` (krytyczne) — liczba **nowych** restartów w oknie osiągnęła próg. Licznik to
  `RestartCount` z libpoda; odtworzenie kontenera (deploy, recreate, rollback) zaczyna liczyć od zera,
  więc nowa wersja nie dziedziczy alarmu po starej.
- `unhealthy: <apka>` (ostrzeżenie) — healthcheck kontenera nie przechodzi od `unhealthy_observations`
  kolejnych obserwacji. Kontener bez healthchecku nigdy nie jest tak zgłaszany.
- `running again: <apka>` (info) — apka wróciła do zdrowia: całe okno bez nowego restartu albo healthcheck
  znów przechodzi. Jedno zdarzenie na powrót, nie na każdą obserwację.

**Konfiguracja** (sekcja opcjonalna; domyślne wartości działają bez niej):

```toml
[monitor]
crash_loop_restarts = 3        # ile nowych restartów w oknie = pętla; 0 wyłącza detekcję
crash_loop_window_secs = 600   # okno licznika i okres ciszy, po którym uznajemy powrót do zdrowia
unhealthy_observations = 2     # ile kolejnych obserwacji z failing healthcheck = unhealthy; 0 wyłącza
```

- **Bez dodatkowego obciążenia:** detekcja korzysta z listy kontenerów, którą reconcile i tak pobiera
  (`container_list` robi inspect każdego kontenera), i nie zapisuje nic na dysk. Wszystko dzieje się w pamięci
  i pod mutexem silnika, więc obserwacja nie nakłada się na deploy.
- **Restart demona:** stan obserwacji jest pamięciowy. Pierwsza obserwacja po starcie tylko ustala punkt
  odniesienia, więc trwająca pętla zaalarmuje po kolejnych `crash_loop_restarts` restartach — nie od razu.
- **Appki `start = false`, czekające na sekrety i przed pierwszym deployem:** nie mają kontenera, więc nie
  generują zdarzeń. Kontenery spoza `apps.toml` (w trakcie sprzątania) też są pomijane.
- **Powtórzenia:** detektor wysyła jedno zdarzenie na pętlę, a nie na każdy restart; okna dedup powiadomień
  (sekcja 6h) nadal zbiorą ewentualne podsumowanie, gdy apka migocze między awarią a powrotem.
- **Rollback:** `[monitor]` to nowa sekcja w `weglarka.toml`, więc starszy demon jej nie odczyta — przed
  downgradem usuń ją razem z `[notify]` (patrz [7](#7-weryfikacja-i-rollback)).

## 7. Weryfikacja i rollback

```sh
weglarka status && weglarka apps show ntfy      # digest, generacja, ostatni deploy
curl -fsS https://nz.descriptortable.eu/        # z zewnątrz, przez Traefika
podman logs weglarka-nginx                      # access log JSON z polem app
podman inspect weglarka-nginx --format '{{.HostConfig.ReadonlyRootfs}} {{.EffectiveCaps}}'  # true [] (0014)
```

- **Automatyczny rollback:** deploy, który nie przejdzie bramki zdrowia, wraca do poprzedniego digestu
  (retencja 1); wynik w `weglarka deploy` (kod wyjścia 6 = `rolled_back`).
- **Ręczny rollback do wskazanej wersji:** `deploy --image` jest w MVP odrzucane przez demona (400, 0005), więc
  przypnij tag `sha-…` przez `apps update` (sekrety, wolumeny i reszta spec zostają):

  ```sh
  weglarka apps update ntfy ghcr.io/jpalczewski/ntfy.zig:sha-<poprzedni> --no-auto-update
  ```

  Zmiana obrazu przez `update` deployuje od razu (pull, bramka zdrowia; nieudana bramka = automatyczny rollback
  do poprzedniego digestu, kod wyjścia 6). Wróć na `:latest` tak samo, z `--auto-update`:
  `weglarka apps update ntfy ghcr.io/jpalczewski/ntfy.zig:latest --auto-update`.
- **Rollback Węglarki do starszej wersji:** pliki TOML mają `deny_unknown_fields`, więc starszy demon nie odczyta
  `apps.toml`/`weglarka.toml` z nowymi polami. Przed downgradem usuń z apek `start = false`
  ([6b](#6b-zatrzymywanie-apek-start--false)), wpisy `depends_on` ([6d](#6d-zależności-między-apkami-depends_on)),
  wpisy `shared_volumes` z apek, sekcję `[shared_volumes]` i sekcję `shared_volumes` ze `state.toml`
  ([6a](#wolumeny-współdzielone-grupa-uid-iteracja-2)), pole `command` w apkach
  ([6f](#6f-komenda-i-argumenty-kontenera-command)) oraz wpisy `host_ports` i `[runtime] allow_privileged_host_ports`
  ([6c](#6c-porty-publikowane-na-hoście-host_ports)), a także `config_root` w `weglarka.toml` i `configs`/
  `reload_signal` w apkach ([6i](#6j-configi-z-hosta-config_root-i-apps-reload)); inaczej daemon nie wystartuje z
  błędem parsowania.
  ([6b](#6b-zatrzymywanie-apek-start--false)), wpisy `host_ports` i `[runtime] allow_privileged_host_ports`
  ([6c](#6c-porty-publikowane-na-hoście-host_ports)) oraz bloki `[apps.X.ingress]` — `streaming`
  ([6e](#6e-streaming-sse-long-polling)); inaczej daemon nie wystartuje z błędem parsowania.

### `apps update`: co się dzieje po zmianie

Gdy demon jest zajęty innym deployem (bramka zdrowia trwa do kilkudziesięciu sekund), CLI nie zwraca od razu
błędu „busy”, tylko ponawia żądanie przez maks. 3 min (komunikat „daemon is busy … waiting…” na stderr).


`weglarka apps update <app> [flagi]` czyta obecną spec, nakłada flagi i wysyła **całą** spec (pełna podmiana;
`--spec plik.toml` podmienia ją w całości z pliku — brak `start` w pliku to `start = true`). `--dry-run` pokazuje
diff i niczego nie wysyła.

| Zmiana | Skutek |
|---|---|
| `--domain` / `--remove-domain` | tylko ingress (nginx reload, plik Traefika); kontener bez zmian |
| `--env`/`--unset-env`, `--port`/`--unset-port`, `--secret-env`/`--secret-mount`/`--unbind-secret`, wolumeny, limity, `health.command` | zmienia `spec-hash` → kolejny reconcile odtwarza kontener z przypiętego digestu (bez pullu) |
| `--shared-volume` (`shared_volumes` w `--spec`) | jak wolumeny: zmienia `spec-hash` → kolejny reconcile odtwarza kontener w zakresie wspólnej grupy UID (zmiana `target`/`read_only` też). Zmiana zakresu przy istniejących wolumenach prywatnych jest odrzucana — patrz [6a](#wolumeny-współdzielone-grupa-uid-iteracja-2). Pusta lista hashuje się jak dotąd |
| obraz (`apps update <app> <obraz>`) | deploy od razu: pull, bramka zdrowia, rollback przy porażce |
| `--auto-update` / `--no-auto-update` | tylko zapis; dotyczy kolejnych webhooków |
| `--start` / `--no-start` (`start` w `--spec`) | `start = false` usuwa kontener (wolumen i zakres UID zostają), `start = true` deployuje od razu: pull, bramka zdrowia, rollback przy porażce. `spec-hash` bez zmian |
| `--command` (`command` w `--spec`) | zmienia `spec-hash` → kolejny reconcile odtwarza kontener z przypiętego digestu (bez pullu); flagi zastępują cały wektor argumentów, a `--command none` przywraca `CMD` obrazu |
| `--host-port` (`host_ports` w `--spec`) | zmienia `spec-hash` → kolejny reconcile odtwarza kontener z przypiętego digestu (bez pullu); publikowany port odtwarza się razem z kontenerem |
| `--config` (`configs` w `--spec`), `--reload-signal` | lista `configs` zmienia `spec-hash` → kolejny reconcile odtwarza kontener z przypiętego digestu (bez pullu); **treść** plików nie jest w hashu, więc jej zmiany aplikuj przez `weglarka apps reload` ([6i](#6j-configi-z-hosta-config_root-i-apps-reload)). `reload_signal` jest poza hashem i dotyczy tylko reloadu |
  ([6b](#6b-zatrzymywanie-apek-start--false)), wpisy `depends_on`
  ([6d](#6d-zależności-między-apkami-depends_on)), wpisy `host_ports` i `[runtime] allow_privileged_host_ports`
  ([6c](#6c-porty-publikowane-na-hoście-host_ports)) oraz bloki `[apps.X.ingress]` — `streaming`
  ([6e](#6e-streaming-sse-long-polling)); inaczej daemon nie wystartuje z błędem parsowania.

Relacja z auto-update: webhook rozsyła deploy do apek, których `image` (repo + tag) zgadza się z paczką, które
mają `auto_update` i nie są zatrzymane (`start = false` — patrz 6b). Przypięcie tagu `sha-…` lub `--no-auto-update`
to więc ręczny „pin” — webhook jej nie ruszy, dopóki nie wrócisz na `:latest`. Rollback (retencja 1) działa jak przy
każdym deployu: wraca do poprzedniego digestu, a nieudany digest jest zapamiętany (ponowny deploy go pominie, dopóki
nie wymusisz `deploy`).
