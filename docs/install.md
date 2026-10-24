# Instalacja Węglarki

Węglarka działa jako **kontener rootless Podmana** (quadlet w systemd usera) obok własnego kontenera nginx;
CLI `weglarka` zostaje poza kontenerem — na hoście albo na laptopie przez tunel SSH do socketu admina.
Przykłady dotyczą hosta `niechybnie` (Ubuntu 24.04, tryb `behind`, Traefik z Coolify). Decyzje:
[0005](decisions/0005-ingress-i-platforma.md), [0006](decisions/0006-pakowanie-obrazy-i-release.md).

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
domeny z `apps.toml` na allowliście polityki, klucz `allowed_domains`). Reguły firewalla nie są sprawdzane. Kody wyjścia: 0 ok, 1 warn, 2 fail.

## 2. Konfiguracja hosta

`/etc/weglarka/weglarka.toml` (UID z `id -u weglarka`; ścieżki są montowane do kontenera pod tą samą nazwą,
więc ten sam plik działa dla demona i dla CLI na hoście):

```toml
[runtime]
user = "weglarka"

[ingress]
mode = "behind"
bind = "172.17.0.1:8088"                                   # docker0; 8080 zajmuje Traefik z Coolify
traefik_dynamic_file = "/var/lib/weglarka/traefik/weglarka.yml"  # root-owy path-unit waliduje i publikuje do dynamic/
# nginx przypięty po digeście (0006); podbijaj świadomie — zmiana odtwarza kontener nginx:
nginx_image = "docker.io/library/nginx:1.31.8-alpine@sha256:1ef7ca94d7879df82421428ce13bd1eaa412404953859cf7a5b6512c25e67a60"
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

Decyzja i pomiary: [0009](decisions/0009-volume-ownership.md).

**Każdy kontener Węglarki dostaje własny zakres UID** z puli subuid użytkownika runtime'u (`userns: private` +
jawne `UIDMap`/`GIDMap`): apka — 65 536 UID, nginx ingressu — 4 096. Zakres jest przydzielany raz (w `state.toml`:
`uid_range`, `ingress_uid_range`) i **nigdy nie zmienia się** dla istniejącej instancji, więc pliki w wolumenie mają
tego samego właściciela po każdym deployu i rollbacku. Pulę Węglarka pyta u Podmana (`GET /info`), nie czyta
`/etc/subuid` (demon w kontenerze go nie widzi). Pula 2 000 000 mieści zakres ingressu i 30 apek; brak miejsca =
instancja zablokowana z komunikatem w logu reconcile (powiększ `subuid` w Ansible, rozmiar zakresu się nie zmienia).
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

### Osłonienie kontenera (`security`)

Domyślnie kontener apki ma tylko izolację UID (osobny zakres per instancja) i ewentualne limity. Dla apek z
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

## 7. Weryfikacja i rollback

```sh
weglarka status && weglarka apps show ntfy      # digest, generacja, ostatni deploy
curl -fsS https://nz.descriptortable.eu/        # z zewnątrz, przez Traefika
podman logs weglarka-nginx                      # access log JSON z polem app
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
| obraz (`apps update <app> <obraz>`) | deploy od razu: pull, bramka zdrowia, rollback przy porażce |
| `--auto-update` / `--no-auto-update` | tylko zapis; dotyczy kolejnych webhooków |
| `--start` / `--no-start` (`start` w `--spec`) | `start = false` usuwa kontener (wolumen i zakres UID zostają), `start = true` deployuje od razu: pull, bramka zdrowia, rollback przy porażce. `spec-hash` bez zmian |

Relacja z auto-update: webhook rozsyła deploy do apek, których `image` (repo + tag) zgadza się z paczką, które
mają `auto_update` i nie są zatrzymane (`start = false` — patrz 6b). Przypięcie tagu `sha-…` lub `--no-auto-update`
to więc ręczny „pin” — webhook jej nie ruszy, dopóki nie wrócisz na `:latest`. Rollback (retencja 1) działa jak przy
każdym deployu: wraca do poprzedniego digestu, a nieudany digest jest zapamiętany (ponowny deploy go pominie, dopóki
nie wymusisz `deploy`).
