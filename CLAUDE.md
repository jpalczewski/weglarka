# Węglarka — wskazówki dla agentów

Własny deploy-tool w Ruście (zastępca Coolify): demon zarządza rootless Podmanem 6 (libpod API v6
po unix sockecie), deklaratywny reconcile ze stanu w TOML, nginx w kontenerze za Traefikiem
(tryb `behind`), auto-update po webhooku GitHub (GHCR). MVP: `ntfy.zig` sam się aktualizuje.

**Decyzje projektowe żyją w Kajecie** (MCP Kajet, workspace `Projekty`, folder `niechybnie/Węglarka`),
nie w repo. Przed zmianą zakresu czytaj; po nowej decyzji — zapisz tam, nie tutaj. W repo trzymamy
tylko decyzje implementacyjne w `docs/decisions/`.

| Notatka | note_id |
|---|---|
| MVP — zakres i decyzje (źródło prawdy) | `pF8HCwa` |
| Zasady architektury | `QlBT25G` |
| Runtime Podman | `IugYcG4` |
| Sieć i ingress | `d3xhzyZ` |
| Sekrety i env | `OJiFhA4` |
| Model apek i stan | `WVzILNR` |
| Deploy i źródła wersji | `megyqW6` |
| Host i platforma | `U0heZWo` |

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
- Git: commituj tylko pliki swojego crate'a (patrz niżej); nie ruszaj cudzych.

## Mapa crate'ów i własność plików

Zależności: `api → core`; `podman → core`; `ingress → core`; `cli → api, core`; `daemon → wszystko`.

| Crate | Zawartość | Właściciel |
|---|---|---|
| `weglarka-core` | typy domenowe, traity, fake | **sesja b** |
| ↳ `src/{reconcile,deploy,state,secrets}.rs` | logika (zalążki) | b |
| ↳ `src/{app,config,hash,labels,platform,webhook,secret_store}.rs` | kontrakt/typy domenowe z fundamentu | b (zmiany addytywne; łamiące — świadomie, z poprawką wszystkich konsumentów) |
| ↳ `src/podman.rs`, `src/testing/` | kontrakt `PodmanClient` + fake | współdzielone a/b: **a** może dodawać pola/metody potrzebne klientowi, **b** fake'a; zmiany tylko addytywne i zawsze z aktualizacją `FakePodman` |
| `weglarka-podman` | klient libpod v6 (hyper, unix socket) + testy integracyjne | **sesja a** |
| `weglarka-ingress` | generatory `nginx`, `traefik` (czyste, snapshoty) | **sesja c** |
| `weglarka-cli` | komendy, `doctor --preflight` | **sesja d** |
| `weglarka-api` | kontrakt admin API (typy, endpointy, `DoctorReport`) | fundament; zmiany tylko addytywne, uzgodnione z b/d |
| `weglarka-daemon` | szkielet `main` | krok 3 (składanie: axum, webhooki, `Platform` systemd) |
| `.github/`, `docs/`, `Cargo.toml` (workspace), `CLAUDE.md` | infra repo | krok 4 (pakowanie); inni dopisują tylko w swoim obszarze |

Nowa zależność zewnętrzna: dodaj do `[workspace.dependencies]` w root `Cargo.toml` (jedna linijka,
mała szansa na konflikt) i odwołaj się przez `.workspace = true`.

## Testy

- `cargo test --workspace` — jednostkowe + snapshoty, bez Podmana.
- Fake: `weglarka-core` z `features = ["testing"]` → `weglarka_core::testing::FakePodman`
  (skryptowalne digesty pulla, błędy w środku pulla, kolejka wyników healthchecka, log wywołań).
- Integracyjne z prawdziwym Podmanem 6.1 (`weglarka-podman/tests/`): wymagają `WEGLARKA_PODMAN_SOCKET`
  (CI ustawia je w jobie `integration-podman`); bez zmiennej testy się pomijają
  (`docs/decisions/0002-podman-in-ci.md`).
- Build statyczny: `cargo build --release --target x86_64-unknown-linux-musl` (CI: job `musl`).
