# Węglarka — wskazówki dla agentów

Własny deploy-tool w Ruście (zastępca Coolify): demon zarządza rootless Podmanem 6 (libpod API v6
po unix sockecie), deklaratywny reconcile ze stanu w TOML, nginx w kontenerze za Traefikiem
(tryb `behind`), auto-update po webhooku GitHub (GHCR). MVP: `ntfy.zig` sam się aktualizuje.

**Zadania i plan rozwoju: [GitHub Issues](https://github.com/jpalczewski/weglarka/issues)** (etykieta `roadmap` =
funkcje zaplanowane, `bug` = błędy). Decyzje implementacyjne z uzasadnieniem: `docs/decisions/` (0001–0010).
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
- **Język: README i komentarze w kodzie po angielsku** (decyzja Jacka, 2026-10-23) — dotyczy wszystkich `README.md`
  (root i crate'ów), komentarzy `//`, doc-commentów `///`/`//!` oraz komentarzy w skryptach i workflowach.
  Nowy i zmieniany kod piszesz od razu po angielsku; istniejące polskie komentarze w plikach, których nie dotykasz,
  tłumaczy osobne zadanie (nie mieszaj tłumaczeń z niezwiązanymi zmianami w PR).

## Mapa crate'ów

Zależności: `api → core`; `podman → core`; `ingress → core`; `cli → api, core`; `daemon → wszystko`.

| Crate | Zawartość |
|---|---|
| `weglarka-core` | typy domenowe (`AppSpec`, `HostConfig`, stan), reconcile, deploy (bramka zdrowia, rollback), wolumeny i zakresy UID, sekrety, traity (`PodmanClient`, `Platform`, `WebhookSource`, `SecretStore`) + `FakePodman` (feature `testing`) |
| `weglarka-podman` | klient libpod v6 (hyper, unix socket) + testy integracyjne |
| `weglarka-ingress` | czyste generatory `nginx.conf` i pliku dynamicznego Traefika (snapshoty) |
| `weglarka-api` | kontrakt admin API (typy, endpointy, kody błędów) |
| `weglarka-daemon` | demon: admin API (unix socket), webhooki, zapis ingressu, `Platform` systemd (quadlet) |
| `weglarka-cli` | CLI `weglarka`, `doctor --preflight` |

Przy pracy równoległej kilku agentów: jeden crate/obszar na agenta, a zmiany w kontrakcie (`app.rs`, `podman.rs`,
`weglarka-api`) tylko addytywne i zawsze z aktualizacją `FakePodman`.
Nowa zależność zewnętrzna: dodaj do `[workspace.dependencies]` w root `Cargo.toml` i odwołaj się przez `.workspace = true`.

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
- **Testy uruchamiają się w CI tak jak na produkcji:** smoke test startuje demona z argumentów quadletu
  (bez `/etc/passwd`, bez `/etc/subuid` w obrazie `scratch`).

## Testy

- `cargo test --workspace` — jednostkowe + snapshoty, bez Podmana.
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
