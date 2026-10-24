# Węglarka — wskazówki dla agentów

Własny deploy-tool w Ruście (zastępca Coolify): demon zarządza rootless Podmanem 6 (libpod API v6
po unix sockecie), deklaratywny reconcile ze stanu w TOML, nginx w kontenerze za Traefikiem
(tryb `behind`), auto-update po webhooku GitHub (GHCR). MVP: `ntfy.zig` sam się aktualizuje.

**Zadania i plan rozwoju: [GitHub Issues](https://github.com/jpalczewski/weglarka/issues)** (etykieta `roadmap` =
funkcje zaplanowane, `bug` = błędy). Decyzje implementacyjne z uzasadnieniem: `docs/decisions/` (0001–0017).
Instrukcja wdrożenia i procedury migracji: `docs/install.md`. Repo jest **publiczne** — nie wpisuj tu (ani w PR-y,
issues, commity) odwołań do prywatnych notatek ani szczegółów prywatnej infrastruktury (nazwy kont, prywatnych
organizacji, tokenów).

Priorytety przy każdej decyzji: **bezpieczeństwo → elegancki, rozszerzalny kod (traity/adaptery) → oszczędność RAM.**

## Konwencje (obowiązują, nie do dyskusji w PR-ach)

- Rust: toolchain przypięty w `rust-toolchain.toml` (1.99.1), edition 2024. `unsafe_code = forbid` (workspace lints).
- Błędy: `thiserror` w bibliotekach, `anyhow` **tylko** w binarkach (`weglarka-daemon`, `weglarka-cli`).
- Runtime: `tokio`. Logi: `tracing` (JSON w demonie). Zależności tylko w `[workspace.dependencies]`.
- Serde: nasze TOML-e (`weglarka.toml`, `apps.toml`, `secrets.toml`, stan) → `#[serde(deny_unknown_fields)]`.
  Modele *zewnętrzne* (Podman, GitHub) → `#[serde(default)]`, nieznane pola ignorowane, tylko używane pola.
- Async w traitach: natywne `async fn`/`impl Future + Send` + generyki, bez `async-trait`
  (`docs/decisions/0001-async-traits.md`). Traity potrzebujące `dyn` (`WebhookSource`, `SecretStore`) są synchroniczne.
- Testy: snapshoty `insta` (pliki `.snap` commitujemy; aktualizacja: `INSTA_UPDATE=always cargo test`, potem przejrzyj diff).
- Przed commitem: `cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`.
- Sekrety nigdy w logach, `Debug` ani TOML-u apek (są tylko referencjami po nazwie).
- Git: PR do `main`, merge przez squash po zielonym CI; odwołuj się do issues (`#NN`), nie do prywatnych notatek.
- **Język: README, komentarze w kodzie i ADR-y po angielsku** (decyzja Jacka, 2026-10-23; ADR-y: 2026-10-24) —
  dotyczy wszystkich `README.md` (root i crate'ów), komentarzy `//`, doc-commentów `///`/`//!`, komentarzy
  w skryptach i workflowach oraz `docs/decisions/` (ADR-y i ich indeks). `docs/install.md` zostaje po polsku,
  a komunikaty runtime/CLI są w trakcie tłumaczenia (issue #32). Nowy i zmieniany kod piszesz od razu po angielsku;
  istniejące polskie komentarze w plikach, których nie dotykasz, tłumaczy osobne zadanie (nie mieszaj tłumaczeń
  z niezwiązanymi zmianami w PR).

## Commity i PR-y (Conventional Commits)

- Format: `<type>(<scope>): <summary>`. Po squashu tytuł PR **jest** tytułem commita na `main`, więc tytuł PR
  też musi być Conventional — pilnuje tego job CI `pr-title`.
- Typy: `feat`, `fix`, `docs`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`.
- Scope: obszar/crate — `core`, `podman`, `ingress`, `api`, `daemon`, `cli`, `ci`, `docs` (pomiń, gdy zmiana jest
  repo-wide).
- Breaking change: `feat(core)!: ...` i `BREAKING CHANGE:` w opisie; w PR opisz też rollback/kompatybilność.
- Changelogi i wersje są **per crate**, generowane przez release-plz z tytułów PR (ADR 0015): o tym, które crate'y
  dotyczy zmiana, decydują zmienione pliki, nie scope; wersje crate'ów bumpuje PR wydaniowy, nie ręczne edycje
  `version` ani `CHANGELOG.md`. Tag `vX.Y.Z` = wersja `weglarka-daemon` (uruchamia `release.yml`).
- Przykłady: `feat(core): provision apps without starting them`, `fix(podman): map libpod 500 to NotFound`,
  `docs: index the ADRs`. Stare commity (przed 2026-10-24) nie są Conventional — historii nie przepisujemy.

## Przed PR-em (checklista)

1. `git fetch origin && git rebase origin/main` — PR musi być na bieżącym `main`; inaczej GitHub pokaże konflikt
   i nie uruchomi CI.
2. `cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`.
3. Snapshoty: `INSTA_UPDATE=always cargo test`, przejrzyj diff `.snap` i commituj `.snap` (`.snap.new` jest ignorowany).
4. Nowe pole `AppSpec`/`ContainerSpec`: opcjonalne, poza `spec_hash` gdy nieustawione (`skip_serializing_if`
   w `HashInput`) — inaczej upgrade odtworzy wszystkie działające apki. Opisz też kompatybilność wstecz
   (`deny_unknown_fields` a rollback) w PR i w `docs/install.md`.
5. Decyzja implementacyjna → nowy ADR z [`docs/decisions/0000-template.md`](docs/decisions/0000-template.md);
   indeks wszystkich decyzji: [`docs/decisions/README.md`](docs/decisions/README.md).
6. Tytuł, commity i PR w Conventional Commits (`<type>(<scope>): <summary>`, patrz wyżej), po angielsku;
   `Closes #NN`; merge = squash po zielonym CI (`check`, `musl`, `integration-podman`; zmiana tylko w
   `docs/`/`*.md`/`.gitignore` nie buduje — job `changes`).

## Mapa crate'ów

Zależności: `api → core`; `podman → core`; `ingress → core`; `cli → api, core`; `daemon → wszystko`.

| Crate | Zawartość |
|---|---|
| `weglarka-core` | typy domenowe (`AppSpec`, `HostConfig`, stan), reconcile, deploy (bramka zdrowia, rollback), wolumeny i zakresy UID (w tym wolumeny współdzielone), sekrety, traity (`PodmanClient`, `Platform`, `WebhookSource`, `SecretStore`) + `FakePodman` (feature `testing`) |
| `weglarka-podman` | klient libpod v6 (hyper, unix socket) + testy integracyjne |
| `weglarka-ingress` | czyste generatory `nginx.conf` i pliku dynamicznego Traefika (snapshoty) |
| `weglarka-api` | kontrakt admin API (typy, endpointy, kody błędów) |
| `weglarka-daemon` | demon: admin API (unix socket), webhooki, zapis ingressu, `Platform` systemd (quadlet) |
| `weglarka-cli` | CLI `weglarka`, `doctor --preflight` |

Przy pracy równoległej kilku agentów: jeden crate/obszar na agenta, a zmiany w kontrakcie (`app.rs`, `podman.rs`,
`weglarka-api`) tylko addytywne i zawsze z aktualizacją `FakePodman`.
Nowa zależność zewnętrzna: dodaj do `[workspace.dependencies]` w root `Cargo.toml` i odwołaj się przez `.workspace = true`.

### Gdzie co leży (najczęstsze punkty wejścia)

| Obszar | Pliki |
|---|---|
| model i walidacja apki | `core/src/app.rs`, `core/src/state.rs` (`AppSpec`, `AppsFile`, `validate_app`) |
| pętla reconcile | `core/src/reconcile.rs` — czyste `plan()` (`Target`/`Action`) + `execute()` (jedyny pisarz stanu) |
| deploy | `core/src/deploy.rs` — `deploy_locked`: pull → stop → create+start → bramka → rollback; `provision_locked` |
| spec-hash | `core/src/hash.rs` — co odtwarza kontener (`HashInput`) |
| wolumeny i UID | `core/src/volumes.rs`, `core/src/uid_range.rs` (ADR 0009), wolumeny współdzielone: `core/src/shared_volumes.rs` + `core/src/volumes.rs` (ADR 0017) |
| sekrety | `core/src/secrets.rs`, `core/src/secret_store.rs` |
| kontrakt i trasy API | `api/src/types.rs` + `api/src/endpoints.rs` → `daemon/src/admin.rs` (nowy endpoint: najpierw `endpoints.rs`) |
| ingress | `ingress/src/plan.rs` (`Plan::build` waliduje) → `nginx.rs`/`traefik.rs` (render + snapshoty); reload: `daemon/src/ingress.rs` |
| CLI | `cli/src/update.rs` (read-modify-write specu: `apps update/start/stop`, `--dry-run`), `cli/src/commands.rs` |
| testy silnika | `core/src/engine_tests.rs` (scenariusze na `FakePodman`), testy modułu w `core/src/volumes.rs` |
| testy daemon/API | `daemon/tests/*.rs` (prawdziwy unix socket + `FakePodman`) |

## Wnioski z wdrożeń (obowiązują)

- **Nowe pola `AppSpec` / `ContainerSpec` są opcjonalne i nie zmieniają `spec_hash`, gdy nie są ustawione**
  (`skip_serializing_if` w `HashInput`) — inaczej aktualizacja Węglarki odtworzy wszystkie działające apki.
- **TOML-e mają `deny_unknown_fields`:** nowe pole w `state.toml`/`apps.toml` łamie rollback do starszego demona —
  opisz to w PR i w notatce do wdrożenia.
- **libpod zwraca czasem 500 zamiast 404** (np. `no such container` w trakcie usuwania) — klient mapuje je na
  `NotFound`; operacje sprzątające (disconnect, remove) są best effort i idempotentne.
- **Ingress:** każda zmiana generatorów przechodzi snapshoty, `nginx -t`, test nagłówków `X-Forwarded-*`
  (`.github/scripts/test-forwarded-headers.sh`) i `scripts/acceptance.sh`. Pamiętaj o obu entrypointach (http i https).
- **Import danych SQLite:** WAL — `volumes import --replace`, weryfikacja razem z `-wal`/`-shm`; kopia przez `.backup`.
- **Wolumen współdzielony (ADR 0017):** deklaracja `[shared_volumes.<nazwa>]` w `apps.toml`, montaż przez
  `shared_volumes = [...]` w spec apki; wolumen posiada **jeden zakres UID** dla wszystkich członków, a jego
  `wg-shared-<nazwa>` ma label `weglarka.shared-volume` i nigdy `weglarka.instance`. `apps remove
  --purge-volumes` członka przy innych członkach = 409 (nic nie usuwane), import wymaga zatrzymanych
  członków, a zmiana zakresu przy istniejących prywatnych danych jest odrzucana (`RangeChangeWithData`).
  Szczegóły: `docs/decisions/0017-shared-volumes.md` i `docs/install.md` §6a.
- **Testy uruchamiają się w CI tak jak na produkcji:** smoke test startuje demona z argumentów quadletu
  (bez `/etc/passwd`, bez `/etc/subuid` w obrazie `scratch`).

## Testy

- `cargo test --workspace` — jednostkowe + snapshoty, bez Podmana.
- Środowiska z sandboxem (agent / CI w kontenerze): jeśli cargo nie może pisać do globalnego `target-dir`
  (`Operation not permitted`), ustaw `CARGO_TARGET_DIR=$PWD/target` — katalog `target/` jest w `.gitignore`.
- Fake: `weglarka-core` z `features = ["testing"]` → `weglarka_core::testing::FakePodman`
  (skryptowalne digesty pulla, błędy w środku pulla, kolejka wyników healthchecka, log wywołań).
- Integracyjne z prawdziwym Podmanem 6.1 (`weglarka-podman/tests/`): wymagają `WEGLARKA_PODMAN_SOCKET`
  (CI ustawia je w jobie `integration-podman`); bez zmiennej testy się pomijają
  (`docs/decisions/0002-podman-in-ci.md`). Job podnosi pulę subuid do ~1 M (zakres instancji = 65 536 UID, ADR 0009);
  `engine_ranges_volumes_secrets_import_migration_and_purge` przechodzi przez cały silnik na prawdziwym Podmanie.
- Build statyczny: `cargo build --release --target x86_64-unknown-linux-musl` (CI: job `musl`).
- Odbiór na hoście / w CI: `scripts/acceptance.sh` (kanarek, ruch, webhook 202/401/204, sprzątanie;
  `--with-local-registry` dodaje deploy z webhooka i wymuszony rollback — tylko w CI). Smoke testy obrazu:
  `.github/scripts/smoke-image.sh` i `smoke-quadlet.sh` (argumenty z `platform install`).
- CI na PR buduje profilem `ci` (thin LTO), `main` i tagi — pełnym `release` (`docs/decisions/0008`).
  PR zmieniający wyłącznie dokumentację (`docs/**`, `*.md`, `.gitignore`) nie uruchamia buildów — job
  `changes` pomija `check`/`musl`/`integration-podman`; `changes` i `pr-title` biegną zawsze. Push na
  `main` z samą dokumentacją nie uruchamia CI ani Release (`paths-ignore`) — obraz nie jest wtedy
  przebudowywany; tagi `v*` budują zawsze.
