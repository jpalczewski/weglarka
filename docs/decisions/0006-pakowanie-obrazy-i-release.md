# 0006 — Pakowanie: obraz Węglarki na `scratch`, oficjalny nginx, release na GHCR

Status: przyjęta (sesja pakowania, 2026-10-23).

**Obraz Węglarki** (`Containerfile`).
- Build wieloetapowy (lokalnie ze źródeł; w CI/release z gotowych binarek, 0008): `rust:1.99.1-alpine` (wersja = `rust-toolchain.toml`) → `scratch` z dwoma statycznymi
  binarkami (musl): `weglarka-daemon` (`ENTRYPOINT`, `CMD ["run"]`) i `weglarka` (CLI, do `podman exec … weglarka status`).
  Rozmiar ≈ 5 MB. Bez shella, bez libc.
- **Bez bundla CA**: demon rozmawia wyłącznie z socketem Podmana (obrazy ściąga Podman, nie my), a webhooki
  są przychodzące. `Cargo.lock` nie ma żadnego crate'a TLS. Jeśli kiedyś pojawi się HTTPS wychodzący — dodać wtedy.
- **Bez `USER`** (działamy jako root kontenera). W rootless Podmanie root kontenera to *użytkownik runtime'u z hosta*
  (np. `weglarka`), nie root hosta. Tylko on ma dostęp do zamontowanych 1:1 socketów, katalogu stanu i
  `secrets.toml` (0600). Nie-root w kontenerze mapowałby się na subuid i traciłby dostęp do wszystkich mountów
  (naprawa wymagałaby `UserNS=keep-id` w quadlecie — zmiana crate'a bez zysku bezpieczeństwa).
- Etykiety OCI: `source`, `revision`, `version` (z `--build-arg VERSION/REVISION`), `licenses`.
- `platform install` (systemctl + `/etc/passwd`) **nie działa w obrazie** — wymaga hosta. Dlatego `weglarka-daemon`
  jest też w tarballu release'u (linux-musl) obok CLI; `docs/install.md` używa go na hoście.

**nginx: oficjalny obraz `docker.io/library/nginx` (alpine), bez własnego.**
- Własny cienki obraz to kolejny artefakt do budowania, podpisywania i łatania CVE, a niczego nie dokłada:
  demon montuje cały `/etc/nginx` (ro) z jednym plikiem `nginx.conf`, który jest samowystarczalny (bez `mime.types`),
  pid i pliki tymczasowe idą do `/tmp`, logi na stdout/stderr, nasłuch na 8080 (bez uprawnień), reload przez `SIGHUP`.
  Skrypty `docker-entrypoint.d` oficjalnego obrazu nie mają co robić (brak `conf.d/default.conf` i `templates/`).
- Domyślna wartość `ingress.nginx_image` w kodzie zostaje tagiem (`nginx:1-alpine`); **na hoście przypinamy po digeście**
  w `weglarka.toml` (przykład w `docs/install.md`). Powód: `IngressManager::ensure_image` ciągnie obraz tylko
  gdy go brak lokalnie, więc ruchomy tag i tak nie aktualizuje się sam — aktualizacja nginxa to świadoma
  akcja operatora (zmiana `nginx_image` zmienia `weglarka.ingress-hash` → odtworzenie kontenera), a digest daje
  powtarzalność i audytowalność bez kosztu.
- CI waliduje wygenerowany config (`nginx -t`) na **tym samym obrazie, który demon uruchamia domyślnie**, a smoke test
  obrazu Węglarki uruchamia prawdziwy kontener nginx i wypisuje jego logi.

**Release** (`.github/workflows/release.yml`).
- `main` → `ghcr.io/jpalczewski/weglarka:main` + `:sha-<7>`; tag `v*` → `:<wersja>` + `:latest`. Tylko `linux/amd64`.
  Tag `v*` musi zgadzać się z `workspace.package.version`.
- Podpis keyless `cosign` (OIDC GitHub) po digeście obrazu; SBOM (SPDX JSON, syft) dołączony jako atestacja cosign
  (osobny artefakt w rejestrze — tag obrazu zostaje zwykłym manifestem, bez indeksu z atestacjami BuildKit).
- Assety GitHub Release (tylko dla `v*`): `weglarka-<wersja>-x86_64-unknown-linux-musl.tar.gz` (CLI + demon),
  `weglarka-<wersja>-aarch64-apple-darwin.tar.gz` (CLI), `SHA256SUMS` (+ podpis cosign `SHA256SUMS.sig`/`.pem`).
- Weryfikacja podpisu obrazu: `docs/install.md`.

**CI.** Obraz powstaje z gotowych binarek job-a `musl`, a smoke test (`.github/scripts/smoke-image.sh`) działa w
`integration-podman` — szczegóły i uzasadnienie: 0008.

**Poza MVP:** `linux/arm64` (Alpine/aarch64), `AutoUpdate=registry` w quadlecie (samoaktualizacja Węglarki),
automatyczne podbijanie digestu nginxa.
