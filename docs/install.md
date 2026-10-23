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
- (tryb `behind`) plik dynamiczny Traefika `weglarka.yml` założony z góry i należący do `weglarka`, a sam
  użytkownik ma ACL `x` na katalogu `dynamic/` (jest `drwx------` innego uid) — Węglarka nadpisuje ten jeden plik w miejscu;
- DNS: rekord domeny webhooków (`[webhook] domain`) i domen apek wskazuje na host (Traefik terminuje TLS).

Sprawdzenie (jako użytkownik runtime'u, po zapisaniu `weglarka.toml`):

```sh
sudo -iu weglarka env XDG_RUNTIME_DIR=/run/user/$(id -u weglarka) \
  weglarka doctor --preflight --config /etc/weglarka/weglarka.toml
```

Każde `warn`/`fail` ma podpowiedź naprawy (`runtime.subuid`, `runtime.linger`, `runtime.podman_source`,
`ingress.traefik_file`, `state.secrets_file`, …). Kody wyjścia: 0 ok, 1 warn, 2 fail.

## 2. Konfiguracja hosta

`/etc/weglarka/weglarka.toml` (UID z `id -u weglarka`; ścieżki są montowane do kontenera pod tą samą nazwą,
więc ten sam plik działa dla demona i dla CLI na hoście):

```toml
[runtime]
user = "weglarka"

[ingress]
mode = "behind"
bind = "172.17.0.1:8080"                                   # docker0 — tu Traefik widzi nginx Węglarki
traefik_dynamic_file = "/data/coolify/proxy/dynamic/weglarka.yml"
# nginx przypięty po digeście (0006); podbijaj świadomie — zmiana odtwarza kontener nginx:
nginx_image = "docker.io/library/nginx:1.31.8-alpine@sha256:1ef7ca94d7879df82421428ce13bd1eaa412404953859cf7a5b6512c25e67a60"

[admin]
socket = "/var/lib/weglarka/run/admin.sock"

[webhook]
listen = "0.0.0.0:9180"                                    # wewnątrz kontenera, w sieci net-weglarka
domain = "weglarka.descriptortable.eu"                     # wystawiane są tylko ścieżki /webhook/

[state]
dir = "/var/lib/weglarka"                                  # apps.toml, state.toml, secrets.toml, nginx/
```

## 3. Binarki na hoście (`platform install`)

`platform install` używa `systemctl --user` i `/etc/passwd`, więc **nie działa w kontenerze** — potrzebny jest
`weglarka-daemon` z tarballa release'u (CLI i demon, `x86_64-unknown-linux-musl`):

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

Obraz `ghcr.io/jpalczewski/weglarka` jest po pierwszym wypchnięciu **prywatny** — ustaw pakiet jako publiczny
(GitHub → Packages → Package settings) albo wykonaj `podman login ghcr.io` jako `weglarka`.
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

Przed przełączeniem istniejącej instalacji z Coolify zatrzymaj `coolify-relay` i usuń jego router z Traefika,
żeby domena nie miała dwóch routerów (dane ntfy.zig: brak, więc `recreate` jest bezpieczne).

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
