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
  jedyny backend `http://host.docker.internal:<port z bind>`, `tls.certResolver: letsencrypt`; bez middlewares,
  tcp/udp. Zwalidowany YAML jest kopiowany atomowo do `/data/coolify/proxy/dynamic/weglarka.yml`; przy błędzie
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
Skrypt dotyka tylko instancji `wg-canary` (domyślnie) oraz `wg-webhook`/`wg-rollback` i kontenera
`wg-accept-registry` z `--with-local-registry` — nigdy `ntfy`. Opcje: `--canary-image`, `--webhook-base`, `--keep`
(kanarek zostaje), `--skip-preflight`, `--strict` (warn z `doctor` = błąd), `--cert-timeout`, `--json` (raport
maszynowy na stdout), `--direct http://127.0.0.1:8088` (ruch prosto do nginx, bez Traefika/TLS — używa tego CI).
Kod wyjścia ≠ 0 przy jakimkolwiek FAIL; `ACCEPTANCE_VERBOSE=1` pokazuje log także udanych kroków.
Wymaga `weglarka`, `curl`, `openssl`, `jq`, `podman`. Opcjonalne `--with-volume` (też w CI; wymaga `tar`) dodaje krok
wolumenu na instancji `wg-volume`: import obcego tara, dane i zakres UID przeżywają `apps remove` + `apps add`,
eksport z właścicielem `uid_range.start + 1000`, `--purge-volumes`.

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

Kolejność ma znaczenie: `secrets set` wymaga istniejącej apki, a pierwszy deploy potrzebuje sekretu `config`
(brak sekretu = deploy zablokowany, ponowienie po jego ustawieniu).

```sh
weglarka apps add ntfy ghcr.io/jpalczewski/ntfy.zig:latest \
  --domain nz.descriptortable.eu --port 8085 \
  --env CONFIG_FILE=/config.json \
  --secret-mount config=/config.json

weglarka secrets set ntfy config --from-file ./config.json      # plik trafia pod /config.json
weglarka deploy ntfy                                            # pull, podmiana, bramka zdrowia
weglarka apps show ntfy
```

**Przełączenie z Coolify z minimalną przerwą** (domena nie może mieć jednocześnie dwóch routerów z tym samym
`Host()` — Coolify i Węglarki):

1. Dodaj apkę **bez `--domain`**, ustaw sekret, `deploy` — kontener przechodzi bramkę zdrowia, ruch nadal
   obsługuje Coolify.
2. Upewnij się, że domena jest na allowliście walidatora (`weglarka_allowed_domains` w Ansible).
3. Zatrzymaj stary kontener w Coolify (na niechybnie: `coolify-relay`) — znika jego router.
4. CLI nie ma `apps update`, a `apps add` na istniejącą nazwę zwraca 409 (kod 4): `weglarka apps remove ntfy`,
   potem `apps add` jak wyżej z `--domain`, i `weglarka deploy ntfy` (obraz już jest lokalnie; sekrety zostają
   w `secrets.toml` — sprawdź `weglarka secrets list ntfy`).
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
```

Wolumen `<instancja>.<nazwa>` (np. `szklana-pogoda.data`) powstaje przy deployu z etykietą `weglarka.instance`.
`weglarka volumes list <apka>` pokazuje deklarowane wolumeny. `apps remove` **nie usuwa danych** (wolumeny i zakres
UID zostają; ponowne `apps add` tej samej nazwy znajduje je z poprawnym właścicielem). Usunięcie danych:
`weglarka apps remove <apka> --purge-volumes` (kasuje kontener i wolumeny, zwalnia zakres UID — bez odwrotu).
Zakres UID jest też zwalniany, gdy usuniętą apkę zostawiono bez wolumenów.

### Import danych z Coolify (np. szklana.pogoda)

Tar z Coolify ma UID-y z obrazu (np. 1000). Importuj go trybem domyślnym (**obcy** tar): UID-y są mapowane przez
zakres apki, więc pliki należą do właściwego użytkownika w kontenerze.

```sh
# Na hoście Coolify: sam plik z wolumenu, nieskompresowany tar (rozpakuj .tar.gz przez gunzip)
tar -cf szklana-data.tar -C /var/lib/docker/volumes/<wolumen>/_data .

# Po stronie Węglarki: apka dodana ze spec z volumes i wdrożona RAZ (potrzebny obraz i zakres UID)
weglarka apps add szklana-pogoda --spec szklana.toml && weglarka deploy szklana-pogoda
weglarka volumes import szklana-pogoda data --from szklana-data.tar    # lub: < szklana-data.tar
```

Import zatrzymuje kontener apki, wypakowuje tar (robi to Podman w pomocniczym, niestartowanym kontenerze tego
samego obrazu — Węglarka niczego nie rozpakowuje) i uruchamia apkę z powrotem. Pliki o tej samej ścieżce są
nadpisywane, pozostałe zostają; przerwany import zostawia część plików. Limit jednego importu: 8 GiB.

**Własne kopie** (`volumes export`) wracają **tylko** z `--own` i tylko do apki o tym samym zakresie UID:

```sh
weglarka volumes export szklana-pogoda data --out backup.tar
weglarka volumes import szklana-pogoda data --from backup.tar --own
```

Nie myl trybów: obcy tar zaimportowany z `--own` ląduje **po cichu** na złych UID-ach; eksport Węglarki
zaimportowany bez `--own` kończy się błędem (UID-y spoza zakresu).

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

## 7. Weryfikacja i rollback

```sh
weglarka status && weglarka apps show ntfy      # digest, generacja, ostatni deploy
curl -fsS https://nz.descriptortable.eu/        # z zewnątrz, przez Traefika
podman logs weglarka-nginx                      # access log JSON z polem app
```

- **Automatyczny rollback:** deploy, który nie przejdzie bramki zdrowia, wraca do poprzedniego digestu
  (retencja 1); wynik w `weglarka deploy` (kod wyjścia 6 = `rolled_back`).
- **Ręczny rollback do wskazanej wersji:** `deploy --image` jest w MVP odrzucane przez demona (400, 0005), więc
  przypnij tag `sha-…` zastępując apkę (sekrety zostają w `secrets.toml`; sprawdź `weglarka secrets list ntfy`):

  ```sh
  weglarka apps remove ntfy
  weglarka apps add ntfy ghcr.io/jpalczewski/ntfy.zig:sha-<poprzedni> \
    --domain nz.descriptortable.eu --port 8085 --env CONFIG_FILE=/config.json \
    --secret-mount config=/config.json --no-auto-update
  ```

  Wróć na `:latest` tym samym sposobem (bez `--no-auto-update`).
