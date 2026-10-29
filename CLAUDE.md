# Węglarka — wskazówki dla agentów

Własny deploy-tool w Ruście (zastępca Coolify): demon zarządza rootless Podmanem 6 (libpod API v6
po unix sockecie), deklaratywny reconcile ze stanu w TOML, nginx w kontenerze za Traefikiem
(tryb `behind`), auto-update po webhooku GitHub (GHCR). MVP: `ntfy.zig` sam się aktualizuje.

**Zadania i plan rozwoju: [GitHub Issues](https://github.com/jpalczewski/weglarka/issues)** (etykieta `roadmap` =
funkcje zaplanowane, `bug` = błędy); widok roadmapy (tablica/oś czasu, pole `Area`) to
[projekt GitHub „Węglarka roadmap”](https://github.com/users/jpalczewski/projects/12) — tylko widok, źródłem prawdy są issues.
Decyzje implementacyjne z uzasadnieniem: `docs/decisions/` — indeks generowany z tytułów ADR-ów:
[`docs/decisions/README.md`](docs/decisions/README.md).
Instalacja: `docs/install.md`; przewodniki tematyczne (migracje, ingress, ACME, rollback…): [`docs/guides/`](docs/guides/README.md) — pliki nazwane tematem, nagłówki bez numerów (żadnego „6k”). Repo jest **publiczne** — nie wpisuj tu (ani w PR-y,
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
  w skryptach i workflowach oraz `docs/decisions/` (ADR-y i ich indeks). `docs/install.md` i `docs/guides/` są po angielsku (2026-10-25),
  a komunikaty runtime/CLI są w trakcie tłumaczenia (issue #32). Nowy i zmieniany kod piszesz od razu po angielsku;
  istniejące polskie komentarze w plikach, których nie dotykasz, tłumaczy osobne zadanie (nie mieszaj tłumaczeń
  z niezwiązanymi zmianami w PR).

## Dokumentacja dla operatora (`docs/install.md`, `docs/guides/`)

- Nowa funkcja z wpływem na operatora = nowy albo zmieniony przewodnik w `docs/guides/<temat>.md` (po angielsku) i wpis w
  `docs/guides/README.md`. Pliki nazywamy tematem, nagłówków **nie numerujemy**; linkujemy do pliku, nie do „sekcji 6k”.
- Linki między przewodnikami są plikowe (bez `#kotwicy` do cudzego pliku); `scripts/adr.sh lint` sprawdza linki, kotwice,
  unikalność nagłówków i obecność każdego przewodnika w indeksie.
- Repo jest publiczne: w przykładach tylko `example.com`/`example.org`, host `myhost`, żadnych prawdziwych domen, nazw hostów
  ani prywatnych projektów. Każdy przewodnik kończy się sekcją `## Rollback`, jeśli zmiana łamie downgrade
  (`deny_unknown_fields`, `schema_version`) — a pole trafia też do tabeli w `verify-and-rollback.md`.

## Commity i PR-y (Conventional Commits)

- Format: `<type>(<scope>): <summary>`. Po squashu tytuł PR **jest** tytułem commita na `main`, więc tytuł PR
  też musi być Conventional — pilnuje tego job CI `pr-title`.
- Typy: `feat`, `fix`, `docs`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`.
- Scope: obszar/crate — `model`, `engine`, `podman`, `ingress`, `api`, `daemon`, `cli`, `ci`, `docs` (pomiń, gdy zmiana jest
  repo-wide).
- Breaking change: `feat(model)!: ...` i `BREAKING CHANGE:` w opisie; w PR opisz też rollback/kompatybilność.
- Changelogi i wersje są **per crate**, generowane przez release-plz z tytułów PR (ADR 0015): o tym, które crate'y
  dotyczy zmiana, decydują zmienione pliki, nie scope; wersje crate'ów bumpuje PR wydaniowy, nie ręczne edycje
  `version` ani `CHANGELOG.md`. Wewnętrzne zależności w `[workspace.dependencies]` mają `version = "0.0"` (ADR 0015, aneks) —
  nie wpisuj tam bieżącej wersji, bo release-plz zbumpuje wtedy wszystkich zależnych razem z crate'em, który się zmienił.
  Wyjątek: `weglarka-api` (kontrakt CLI↔demon) ma dokładną wersję, więc jego wydanie wydaje też `weglarka-cli` i `weglarka-daemon`. Tag `vX.Y.Z` = wersja `weglarka-daemon` (uruchamia `release.yml`).
- Przykłady: `feat(engine): provision apps without starting them`, `fix(podman): map libpod 500 to NotFound`,
  `docs: index the ADRs`. Stare commity (przed 2026-10-24) nie są Conventional — historii nie przepisujemy.

## Przed PR-em (checklista)

1. `git fetch origin && git rebase origin/main` — PR musi być na bieżącym `main`; inaczej GitHub pokaże konflikt
   i nie uruchomi CI. W sesji agentskiej `git rebase --continue` czeka na edytor, więc wołaj je jako
   `GIT_EDITOR=true GIT_SEQUENCE_EDITOR=true git rebase --continue`; po rebase przejdź `scripts/adr.sh lint`
   (numer ADR-a i linki do sekcji mogły się zderzyć z upstreamem — patrz punkt 5).
2. `cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`.
3. Snapshoty: `INSTA_UPDATE=always cargo test`, przejrzyj diff `.snap` i commituj `.snap` (`.snap.new` jest ignorowany).
4. Nowe pole `AppSpec`/`ContainerSpec`: opcjonalne, poza `spec_hash` gdy nieustawione (`skip_serializing_if`
   w `HashInput`) — inaczej upgrade odtworzy wszystkie działające apki. Nowe pole `apps.toml`/`state.toml`
   (także `AppState`) → podbij `state::SCHEMA_VERSION` i dopisz krok w `SCHEMA_STEPS` (kompilacja tego pilnuje,
   ADR 0023); kompatybilność wstecz (`deny_unknown_fields` a rollback) opisz w PR i w odpowiednim przewodniku w `docs/guides/`
   — dla plików stanu to [wersja schematu](docs/guides/state-schema.md).
5. Decyzja implementacyjna → nowy ADR z [`docs/decisions/0000-template.md`](docs/decisions/0000-template.md).
   Tabelę indeksu generuje `scripts/adr.sh index` — nie edytuj jej ręcznie. Numer ADR to zasób wspólny
   dla równoległych gałęzi: zarezerwuj go wcześnie (push + draft PR ze stubem ADR-a) i scalaj szybko;
   jeśli rebase ujawni kolizję, przenumeruj jedną komendą: `scripts/adr.sh renumber OLD NEW`.
   Przed PR-em uruchom też `scripts/adr.sh lint` (to samo robi job `docs-lint`).
6. Tytuł, commity i PR w Conventional Commits (`<type>(<scope>): <summary>`, patrz wyżej), po angielsku;
   `Closes #NN`; merge = squash po zielonym CI (`check`, `musl`, `nginx-e2e`, `podman-tests`, `smoke-behind`, `smoke-edge`; zmiana tylko w
   `docs/`/`*.md`/`.gitignore` nie buduje — job `changes`).

## Worktrees (praca równoległa)

Jedno zadanie = jeden checkout: gałąź żyje we własnym worktree, więc dwie sesje nie edytują tych samych plików,
a nieudany eksperyment usuwa się razem z katalogiem. W DSH robi to bundle **Git Worktrees**: z **głównego
checkoutu** wołaj `create_worktree({ name })` — tworzy `.agents/worktrees/<name>` na nowej gałęzi o tej nazwie
od `HEAD`, wchodzi do niego i zwraca `path`/`branch`/`baseCommit`. Nie kopiuje niezacommitowanych plików i nie
robi `fetch`, więc worktree powstaje **przed** pierwszą edycją.

- **Startuj z głównego checkoutu, nie z wnętrza worktree.** Granica `workspace-write` to katalog, w którym sesja
  wystartowała, a nie ten, do którego później wchodzi (`create_worktree`, `working_directory`). Z głównego
  checkoutu `.agents/worktrees/*`, wspólne `.git` i `target/` są w granicach zapisu; sesja wystartowana
  w worktree ma główne `.git` i `target/` poza granicami (zapisy gita wymagają eskalacji).
- **Każdy checkout buduje we własnym `target/`** — nie dziel katalogu budowania między worktree (ani przez wspólny
  `CARGO_TARGET_DIR`, ani przez wspólny `build.build-dir`; zmierzone 2026-10-27, #223). Ścieżki crate'ów workspace są
  haszowane względem korzenia workspace, więc identyczne układy dają identyczne nazwy artefaktów, a świeżość to mtime:
  jeśli twoja edycja jest starsza niż build innego worktree, cargo nie przebuduje nic i zlinkuje **jego** kod. Zależności
  z crates.io i tak kompiluje raz sccache (`RUSTC_WRAPPER=sccache`), więc prywatny `target/` kosztuje dysk, nie czas.
  `~/.cargo/config.toml` bywa ustawiony na globalny `target-dir` — przypnij go: `export CARGO_TARGET_DIR="$(scripts/worktree.sh target)"`.
  Rozmiar: ok. 1,1 GB po `cargo build --workspace`, ≥2 GB z testami (`scripts/worktree.sh usage` pokazuje wszystkie + wolne miejsce).
- Wyjście: `cd` z powrotem do checkoutu (worktree i gałąź zostają). Po merge'u PR-a usuń worktree **razem z jego
  `target/`**: `scripts/worktree.sh remove .agents/worktrees/<name> --delete-branch` (to `rm -rf target`,
  `git worktree remove`, `git worktree prune`, `git branch -D`). Zalegające `target/` czyści też okresowo
  `scripts/worktree.sh sweep [dni]` (`cargo sweep --time 14` w każdym worktree; wymaga `cargo install cargo-sweep`).
  `.agents/worktrees/.gitignore` (`*`) trzyma pulę poza `git status`.
- Agent Teams: narzędzie zmienia katalog tylko wywołującej sesji. Jeden pisarz = jedno worktree: albo Lead
  tworzy je przed spawnem teammate'ów, albo każdy członek tworzy własne i wpisuje je w `write_scopes` zadania;
  teammate nigdy nie pracuje w checkoutcie Leada.
- Bez bundla (`create_worktree` niedostępne): `git worktree add .agents/worktrees/<name> -b <name> origin/main`
  i wejdź tam — pozostałe zasady bez zmian.
- Stare `.claude/worktrees/` (sesje Claude Code) są wykluczone z wyszukiwań; nie używaj ich do nowej pracy.

## Mapa crate'ów

Zależności: `api → model`; `podman → model`; `ingress → model`; `notify → model, http`; `registry → model, http`; `dns → model, http`; `acme → model`; `identity → model`; `http → (nic z Węglarki)`; `unix-http → (nic z Węglarki)`; `engine → model`; `acme → dns`;
`cli → api, model, engine, unix-http`; `panel → api, model, http, unix-http`; `daemon → wszystko` (poza `panel`). Liście (api, ingress, notify, acme, podman, dns, registry, panel) nie zależą od `engine` — nie dodawaj im jej (większość zależy **tylko od modelu**); od `panel` nie zależy żaden crate (ADR 0057).

| Crate | Zawartość |
|---|---|
| `weglarka-model` | model domenowy bez silnika: typy (`AppSpec`, `HostConfig`, stan i bramka schematu), walidacja `apps.toml`/`state.toml` (w tym czyste części `depends`, `shared_networks`, `shared_volumes`), `fsutil::write_atomic`, `hash`/`labels`/`uid_range`/`limits`, `identity`, `events`, stan samoaktualizacji (`self_update.rs`: plik stanu + czyste `decide()`/`supervise()`), plik dedupu webhooków (`delivery.rs`), `FileSecretStore`, traity (`PodmanClient` + typy, `WebhookSource`, `SecretStore`); bez wywołań Podmana i bez `tokio` (ADR 0053) |
| `weglarka-engine` | silnik: reconcile, deploy (bramka zdrowia, rollback), wolumeny i zakresy UID (w tym współdzielone), configi z hosta (`config_mounts.rs`), mounty hosta, wykrywanie awarii (`crash.rs`), sites/promote/push/run/forward, bramka `depends_on`, dostarczanie sekretów, trait `Platform` + `FakePodman` (feature `testing`) + testy silnika i testy integracyjne z prawdziwym Podmanem (`tests/`) |
| `weglarka-podman` | klient libpod v6 (hyper, unix socket) + testy integracyjne |
| `weglarka-ingress` | czyste generatory `nginx.conf` (`behind` i `edge`) i pliku dynamicznego Traefika (snapshoty) |
| `weglarka-http` | wspólny klient HTTP (#219): `client(Purpose)` buduje `reqwest::Client` (http1, `rustls` + `ring` jawnie, `webpki-roots`, bez aws-lc/OpenSSL; `rustls-platform-verifier` jest w grafie, ale nieużywany) z timeoutami i polityką redirectów per cel; **zależy tylko od zewnętrznych crate'ów** (nic z Węglarki), więc `reqwest` trafia wyłącznie do crate'ów sieciowych (nie do cli/api/ingress); guard `.github/scripts/check-deps.sh` w jobie `check` |
| `weglarka-panel` | panel admina (ADR 0057): serwer renderowany po stronie serwera (BFF), lib + bin `weglarka-panel`; `config.rs` (env: `OIDC_*` w tym `OIDC_CLIENT_SECRET_FILE`, `PANEL_PUBLIC_URL`, `PANEL_API_AUDIENCE`, `PANEL_SESSION_IDLE_SECS`/`_MAX_SECS`, `PANEL_LISTEN`, `WEGLARKA_PANEL_SOCKET`, `Secret` z redagowanym `Debug`; issuer `http://` tylko na loopbacku), `daemon.rs` (`DaemonClient` po `weglarka-unix-http`: `Call` = `Endpoint` + parametry, token tylko w `Authorization`, mapowanie 401/403/404/5xx na `DaemonError`, jawny deadline), `app.rs` (axum: `/healthz`, `/static/*`, `/auth/login`, `/auth/callback` publiczne, reszta za `auth::require_session` = default-deny), `oidc.rs` (klient OIDC: discovery, PKCE S256, wymiana kodu i refresh `client_secret_basic`, JWKS + `admin_auth::verify` dla id tokenu), `session.rs` (`SessionStore`, `PendingLogins`, `Session::ended()`, `Clock`), `auth.rs` (login/callback/logout, ciasteczka `__Host-`, odświeżanie tokenu), `csrf.rs` (token + `Sec-Fetch-Site` na żądaniach nie-GET), `secure.rs`, `headers.rs` (CSP i nagłówki na każdej odpowiedzi), `assets.rs` (`include_bytes!`), `pages.rs` + `templates/` (askama), `server.rs` (graceful shutdown); guard `check-deps.sh` pilnuje braku `engine` i C-crypto |
| `weglarka-unix-http` | klient HTTP/1 po unix sockecie (hyper, jedno połączenie na żądanie): `UnixClient` — `buffered` (cała odpowiedź), `open` (`StreamingResponse`, ciało ramkami), `connect`; `bearer()` buduje wrażliwy nagłówek `Authorization`; feature `testing`: `testing::mock` (mock serwera na krótkim gnieździe, zapisuje metodę, ścieżkę, query, nagłówki, ciało); **liść bez zależności od Węglarki i bez `reqwest`** (guard w `check-deps.sh`); używa go `cli` (później panel); `health_probe` w demonie celowo osobno (surowe bajty, HTTP/1.0, guardy wstrzyknięć); `podman/src/transport.rs` to ten sam kod hyper-po-unix-sockecie i **planowana migracja** pod #77 (jeszcze nie zrobiona) |
| `weglarka-notify` | powiadomienia: `Event` → `Severity` → komunikaty → dedup → trwała kolejka (outbox) → kanały (`ntfy`; mail = #113), klient HTTP z `weglarka-http`, `endpoint.rs` (parsowanie URL-a) |
| `weglarka-registry` | podpisy cosign z OCI (tag `.sig` + token GHCR) i weryfikacja kluczem statycznym ECDSA P-256 (`ring`); klient HTTP z `weglarka-http` (`Purpose::Registry`: ≤5 przekierowań, tylko https/loopback, bez tokena na obcy host), `FakeRegistry`/`TestSigner` (feature `testing`) |
| `weglarka-acme` | silnik ACME dla trybu `edge` (#96, ADR 0038): `CertSpec`/`CertId` (certyfikat = lista nazw, plik z id), trait `ChallengeSolver` (`Http01Solver`, `DnsSolver` nad `weglarka-dns` = #97), `AcmeClient`/`CertInspector`, `CertStore` (klucz 0600 przed certem 0644, atomowo), czyste `renewal::decide`, `Manager::pass`; `InstantAcme` (klient na `instant-acme`, `ring`, `webpki-roots`), `FakeAcme` (feature `testing`); test na staging Let's Encrypt jest opt-in (`WEGLARKA_ACME_STAGING_DOMAIN`/`_WEBROOT`); worker w demonie (`daemon/src/acme.rs`, `[acme]`, zdarzenia, `doctor acme.*`) |
| `weglarka-dns` | adaptery DNS dla ACME DNS-01: trait `DnsProvider` (`set_txt`/`remove_txt`, handle usuwa dokładnie swój rekord), adapter Cloudflare (API v4, klient HTTP z `weglarka-http` (`Purpose::Api`, bez przekierowań), token jako `SecretValue`), `FakeDns` (feature `testing`); ADR 0039 |
| `weglarka-identity` | czyste renderery configu providera tożsamości (Authelia, #42 P3): `render_oidc_clients` → `oidc-clients.yml` (klienci OIDC apek i zewnętrzni + `claims_policies`, sekret tylko jako digest, #91) i `render_access_control` → `access-control.yml` (zawsze `default_policy: deny` + stała reguła `bypass` dla hosta issuera, #90); JSON w pliku `.yml`, wyjście deterministyczne, snapshoty; bez I/O; `AutheliaGenerator` (impl `ConfigGenerator` z `model`) wpina oba renderery w pipeline, rejestruje go `daemon/src/generated.rs::registered` gdy jest `[identity]`; job CI `identity-config` waliduje fixtury `authelia config validate` na przypiętym obrazie |
| `weglarka-api` | kontrakt admin API (typy, endpointy, kody błędów) |
| `weglarka-daemon` | demon: admin API (unix socket, w tym `GET /v1/health`), webhooki, zapis ingressu, `Platform` systemd (quadlet + timery samoaktualizacji i watchdoga), worker powiadomień, host-side `self-update` i `supervise` |
| `weglarka-cli` | CLI `weglarka`, `doctor --preflight` |

Przy pracy równoległej kilku agentów: jeden crate/obszar na agenta, a zmiany w kontrakcie (`app.rs`, `podman.rs`,
`weglarka-api`) tylko addytywne i zawsze z aktualizacją `FakePodman`.
Nowa zależność zewnętrzna: dodaj do `[workspace.dependencies]` w root `Cargo.toml` i odwołaj się przez `.workspace = true`.

### Gdzie co leży (najczęstsze punkty wejścia)

| Obszar | Pliki |
|---|---|
| model i walidacja apki | `model/src/app.rs`, `model/src/state.rs` (`AppSpec`, `AppsFile`, `validate_app`, `SCHEMA_VERSION` + bramka schematu) |
| pętla reconcile | `engine/src/reconcile.rs` — czyste `plan()` (`Target`/`Action`) + `execute()` (jedyny pisarz stanu) |
| deploy | `engine/src/deploy.rs` — `deploy_locked`: pull → stop → create+start → bramka → rollback; `provision_locked` |
| spec-hash | `model/src/hash.rs` — co odtwarza kontener (`HashInput`) |
| wolumeny i UID | `engine/src/volumes.rs`, `model/src/uid_range.rs` (ADR 0009), wolumeny współdzielone: `model/src/shared_volumes.rs` + `engine/src/volumes.rs` (ADR 0017) |
| sekrety | `model/src/secrets.rs` (`FileSecretStore`) i `engine/src/secrets.rs` (dostarczanie do kontenerów), `model/src/secret_store.rs` |
| configi z hosta i reload | `engine/src/config_mounts.rs` (resolve/fingerprint/walidacja hosta), `engine/src/deploy.rs` (`launch` montuje `BindMount` ro, `reload_locked`/`reload`), pola `configs`/`reload_signal` w `model/src/app.rs`, hash w `model/src/hash.rs`, `daemon/src/settings.rs` (`Paths.config_root`) + mount w `daemon/src/service.rs` (`service_spec`), trasa `api/src/endpoints.rs` → `daemon/src/admin.rs`, check `configs.*` w `daemon/src/doctor.rs`, CLI `cli/src/commands.rs`/`spec_flags.rs` (ADR 0028) |
| mounty hosta i grupy (`host_mounts`, `group_add`) | `engine/src/host_mounts.rs` (allowlista `[runtime] host_mounts`, exact match + brak symlinków, `describe`), `HostMount`/`valid_host_source` w `model/src/app.rs`, walidacja w `model/src/state.rs`, hash w `model/src/hash.rs`, `Reconciler::resolve_mounts` w `engine/src/deploy.rs`, mount allowlisty do kontenera demona w `daemon/src/service.rs`, 400 w `daemon/src/admin.rs`, check `host_mounts.apps` w `daemon/src/doctor.rs`, `group_add` → `ContainerSpec::keep_groups` → adnotacja crun w `podman/src/wire.rs` (ADR 0045: keep-groups, nie gid), CLI `--host-mount`/`--group-add` w `cli/src/spec_flags.rs`, `docs/guides/host-mounts.md` (ADR 0045) |
| retencja obrazów | `engine/src/images.rs` (czysty `plan()` + `execute()`), wywołania po deployu w `engine/src/deploy.rs`, API `daemon/src/images.rs`, check `runtime.images` w `daemon/src/doctor.rs` (ADR 0020) |
| blue-green deploy (`strategy`) | `engine/src/deploy.rs` (`launch_blue_green`, `challenger_gate`, `launch_with_strategy`), `Strategy` w `model/src/app.rs` + `validate_strategy` w `model/src/state.rs`, nazwy `.next`/`.prev` i sieć staging w `model/src/labels.rs`, wyjątek dla nich w `plan()` (`engine/src/reconcile.rs`), `container_rename`/`network_connect_aliased` w `model/src/podman.rs` + `podman/src/{client,wire}.rs`, `resolver valid=1s` w `ingress/src/nginx.rs`, flaga `--strategy` w `cli/src/spec_flags.rs`, testy `engine/src/engine_tests.rs` (mod `blue_green`), `docs/guides/blue-green.md` (ADR 0046) |
| sites z środowiskami (`[sites]`, `weglarka promote`) | `model/src/environments.rs` (`SiteSpec`/`EnvSpec`, `expand`, kolizje nazw), `AppsFile`/`RawAppsFile` w `model/src/app.rs` (ekspansja przy odczycie, `origins` nie jest zapisywane), `engine/src/promote.rs` (`Reconciler::promote`, `declare_site`/`remove_site`, `ensure_unmanaged`), strażnik `PromoteOnly` w `engine/src/deploy.rs`/`push.rs`, pominięcie w `engine/src/reconcile.rs`, `NginxOptions::unreleased` → `return 503` w `ingress/src/nginx/location.rs`, trasy `daemon/src/sites.rs`, CLI `cli/src/sites.rs`, check `sites.unpromoted` w `daemon/src/doctor.rs`, testy `engine_tests.rs` (mod `environments`) i `daemon/tests/it/sites.rs`, `docs/guides/site-environments.md` (ADR 0050) |
| samoaktualizacja Węglarki | `model/src/self_update.rs` (stan + czyste `decide()`/`supervise()`), `registry/src/` (podpis cosign i weryfikacja kluczem), `daemon/src/self_update.rs` (host-side switcher + akcja fallbacku), `daemon/src/supervise.rs` (host-side watchdog: sonda `GET /v1/health`, blokada stanu), `daemon/src/service.rs` (spec współdzielony z `platform install`), `daemon/src/platform.rs` (timery, `install_user_units`, `restart_service`, `reset_failed`), sekcja `[self_update]` w `model/src/config.rs`, check `self_update` w `daemon/src/doctor.rs` (ADR 0027, ADR 0034) |
| sonda zdrowia (`health.http`, gniazdo sondy) | `daemon/src/health_probe.rs` (`NginxProber` po `UnixStream`), `daemon/src/ingress.rs` (`PROBE_SUBDIR`, `probe_socket_path`, mount tylko do nginx, hash v5), `ingress/src/nginx/common.rs` (`listen_probe`), `NginxOptions::probe_socket`, ADR 0054 |
| token admin API (`[admin.http]`, #43/#92) | `model/src/admin_auth.rs` (czysta walidacja JWT RS256/ES256, `JwkSet`, `Scope`/`Principal`, mapowanie grup; `testing::TestIssuer` pod feature `testing`), `AdminHttpConfig` w `model/src/config.rs`, `Endpoint.scope`/`lookup` w `api/src/endpoints.rs`, `daemon/src/admin_token.rs` (`JwksVerifier` + fetch JWKS przez gniazdo sondy, warstwa `authenticate`, `token_router`), `admin::api_routes` (jedna tabela tras dla obu listenerów), `bind_unix`/`spawn_server` w `daemon/src/lib.rs`, mount katalogu gniazda tylko dla `clients`: `engine/src/admin_token.rs` + `spec_hash_with_admin_token`, check `admin.http` w `daemon/src/doctor.rs`, testy `daemon/tests/it/token_api.rs`, `docs/guides/admin-api-tokens.md` (ADR 0056) |
| kontrakt i trasy API | `api/src/types.rs` + `api/src/endpoints.rs` → `daemon/src/admin.rs` (nowy endpoint: najpierw `endpoints.rs`) |
| ingress | `ingress/src/plan.rs` (`Plan::build` waliduje, w tym rozłączność `paths` na wspólnej domenie; `route_table()` dla `doctor`) → `nginx.rs`/`traefik.rs` (render + snapshoty); reload: `daemon/src/ingress.rs`; prefiksy ścieżek: ADR 0031, `paths`/`ingress.strip_prefix` w `model/src/app.rs`, składnia `check_path_prefix`, `docs/guides/path-routing.md`; tryb `edge` (dwa puby, TLS, webroot ACME, mapa uid ingressu): ADR 0036, `docs/guides/edge-mode.md` |
| certyfikaty ACME (edge) | `acme/src/{manager,store,solver,instant,renewal}.rs` (silnik, `FakeAcme` w `testing.rs`), `model/src/config.rs` (`AcmeConfig`, walidacja w `HostConfig::validate`), `model/src/events.rs` (`CertificateIssued`/`CertificateRenewalFailed`), `daemon/src/acme.rs` (worker, `AcmeStatus`) + wiring w `daemon/src/lib.rs`, checki `acme.*` w `daemon/src/doctor.rs`, `docs/guides/acme.md` (ADR 0038); wildcard przez DNS-01: `[acme.dns]` (`AcmeDnsConfig`, `token_file` 0600 jak ntfy), `DnsBackend` + drugi `Manager` w `daemon/src/acme.rs`, `DnsSolver` w `acme/src/dns.rs`, adaptery w `weglarka-dns`, checki `acme.dns`/`acme.wildcards`, `docs/guides/wildcard-certificates.md` (ADR 0039); serwowanie wildcardów: `model/src/config.rs` (`wildcard_covers`, `wildcard_cert_stem`), `ingress/src/nginx.rs` (`NginxOptions::certificate_stem`: własna para wygrywa, potem wildcard najdłuższego apexu), skan `_wildcard.<apex>` w `daemon/src/ingress.rs`, pominięcie HTTP-01 dla domen pokrytych w `AcmeWorker::specs` |
| powiadomienia | `notify/src/{message,dedup,outbox,worker,ntfy,endpoint,settings}.rs`; sekcja `[notify]`: `model/src/config.rs`; `Severity`: `model/src/events.rs`; wiring: `daemon/src/lib.rs` (`Notifier::build`, sink, worker), trasa: `api/src/endpoints.rs` → `daemon/src/admin.rs` |
| wykrywanie awarii | `engine/src/crash.rs` (polityka `Policy` + maszyna stanu `Watcher`), wywołanie w `engine/src/reconcile.rs` (`Reconciler::with_monitor`, raz na przejście), sekcja `[monitor]`: `model/src/config.rs`, zdarzenia: `model/src/events.rs`, testy: `engine/src/engine_tests.rs` (ADR 0022) |
| identity provider (#42, #88, #91) | `model/src/identity.rs` (`OidcClientSpec`, `ExternalClientSpec`, `IngressAuth`, walidacja leksykalna, **`effective_spec`** — jedyny overlay wstrzykiwanych env/sekretów/`depends_on` (hash, materialize, kontener, `weglarka run`), parser `--config` (`config_sources`), `validate_host_app`/`validate_provider`, `issuer_host`; `ingress.auth_policy`/`auth_groups` renderuje `weglarka-identity` do `access-control.yml` (#90), `daemon/tests/it/identity.rs`), `engine/src/identity.rs` (klienci zewnętrzni, rotacja), `engine/src/oidc_credentials.rs`, `daemon/src/identity.rs` (trasy `/v1/oidc-clients`, `/v1/apps/{name}/oidc/rotate`), CLI `cli/src/oidc.rs`, doctor `identity.provider`/`oidc.credentials`, `docs/guides/identity-provider.md`, `IdentityConfig` w `model/src/config.rs`, pola `oidc`/`ingress.auth*`/`[oidc_clients]` w `model/src/app.rs`, schema 14 (`identity_v14`), ADR 0051/0052 |
| wygenerowane configi (`apply_generated`, #212) | `model/src/generated.rs` (trait `ConfigGenerator`, `FileName`, `Fingerprint`), `model/src/generated_state.rs` (`generated.toml`: wynik ostatniego przebiegu per generator, tolerancyjny, 0600), zdarzenia `GeneratedConfig*` w `model/src/events.rs`, `engine/src/generated.rs` (`Reconciler::apply_generated`: render → wersja `v-<fp12>/` → walidacja jednorazowym kontenerem → swap symlinka `current` → reload + bramka zdrowia → rollback; `bootstrap_generated` przed pierwszym startem; mount `/weglarka/generated` w `prepare_instance`; `spec_hash_with_generated` tylko dla konsumenta), typowana blokada `EngineGuard` (`Reconciler::acquire`) w `engine/src/reconcile.rs`, worker z debounce 2 s w `daemon/src/generated.rs` (+ `Daemon::changed()`), check `generated.<id>` w `daemon/src/doctor.rs`, `docs/guides/generated-config.md` (ADR 0055); rejestr generatorów jest pusty do wpięcia renderera tożsamości (#42) |
| tymczasowy forward portu (`weglarka forward`) | `engine/src/forward.rs` (`prepare_forward`/`PendingForward::hold`, `remove_stale_forwards`), etykiety `weglarka.forward`/`forward-for` w `model/src/labels.rs`, `published_ports` w `ContainerInfo` (`model/src/podman.rs` + `podman/src/wire.rs`), strumień ramek `api/src/forward.rs`, trasa `daemon/src/forward.rs`, CLI `cli/src/forward.rs` + plik użytkownika `cli/src/user_config.rs` (`cli.toml`), `docs/guides/port-forward.md` (ADR 0041) |
| jednorazowe kontenery (`weglarka run`) | `engine/src/run.rs` (`prepare_run`/`PendingRun::drive`, `remove_stale_runs`; wspólne przygotowanie z deployem: `prepare_instance` w `engine/src/deploy.rs`), etykiety `weglarka.run`/`run-for` w `model/src/labels.rs`, `container_logs`/`container_wait`/`entrypoint` w `model/src/podman.rs` + `podman/src/{client,wire}.rs`, strumień ramek `api/src/run.rs`, trasa `daemon/src/admin.rs` (`run_app`), CLI `cli/src/run.rs`, `docs/guides/one-off-commands.md` (ADR 0040) |
| wdrożenie lokalnego obrazu (`weglarka push`) | `engine/src/push.rs` (`push_reference`/`push_archive`, jeden slot uploadu, tag `pushed`), źródło digestu `DigestSource` w `engine/src/deploy.rs` (`deploy_locked_from`/`provision_from`), `image_load`/`LoadedImage` w `model/src/podman.rs` + `podman/src/{client,wire}.rs`, trasa `PUT /v1/apps/{name}/image` w `api/src/endpoints.rs` → `daemon/src/push.rs`, `deploy` z `image_ref` w `daemon/src/admin.rs`, CLI `cli/src/push.rs`, testy `engine/src/engine_tests.rs` (mod `push`), `daemon/tests/it/push.rs`, `podman/tests/image_load.rs`, `docs/guides/push-local-images.md` (ADR 0042) |
| CLI | `cli/src/update.rs` (read-modify-write specu: `apps update/start/stop`, `--dry-run`), `cli/src/commands.rs` |
| testy silnika | `engine/src/engine_tests.rs` (scenariusze na `FakePodman`), testy modułu w `engine/src/volumes.rs` |
| testy daemon/API | `daemon/tests/it/*.rs` — jedna binarka testowa (`it/main.rs`, moduł na obszar, nowy plik = nowy `mod`), prawdziwy unix socket + `FakePodman` |

## Wnioski z wdrożeń (obowiązują)

- **Nowe pola `AppSpec` / `ContainerSpec` są opcjonalne i nie zmieniają `spec_hash`, gdy nie są ustawione**
  (`skip_serializing_if` w `HashInput`) — inaczej aktualizacja Węglarki odtworzy wszystkie działające apki.
- **Wersjonowanie schematu stanu (ADR 0023):** `apps.toml`/`state.toml` mogą nieść `schema_version`; plik bez
  znacznika to v1 (dzisiejszy kształt — demon celowo go nie dopisuje, żeby nie łamać najbliższego rollbacku),
  a każde nowe pole wymaga podbicia `state::SCHEMA_VERSION` i wpisu w `SCHEMA_STEPS` (pilnuje tego const-assert).
  Starszy demon odmawia startu z czytelnym komunikatem zamiast błędu parsowania; rollback przez granicę wersji
  schematu wymaga kopii plików sprzed aktualizacji. `secrets.toml` nie jest (jeszcze) wersjonowany, a `[notify]`
  w `weglarka.toml` nadal trzeba usunąć ręcznie przed downgradem.
- **Rollback przywraca digest, nie spec:** nieudany deploy wznawia poprzedni obraz *z nowym spec-em*, więc zmiana
  specu, która psuje start (`command`, `env`, mount), obleje deploy **i** rollback — apka leży do czasu poprawki
  specu. Nie opisuj nowego pola `AppSpec` jako „rollback-safe” (przykład: `command`, ADR 0019).
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
  Szczegóły: [`docs/decisions/0017-shared-volumes.md`](docs/decisions/0017-shared-volumes.md) i
  [`docs/guides/shared-volumes.md`](docs/guides/shared-volumes.md) i [`volumes.md`](docs/guides/volumes.md).
- **Powiadomienia (ADR 0021):** `EventSink::emit` jest wołane pod mutexem silnika, więc sink **tylko kolejkuje**
  (`try_send`, bez I/O) — całą robotę robi worker. Źródłem prawdy o wysyłce jest trwały outbox
  `<state dir>/notifications.toml` (tolerancyjny `serde`, 0600); sekcja `[notify]` w `weglarka.toml` łamie
  rollback do starszego demona (`deny_unknown_fields`). Nowy kanał = `Channel` + jego nazwa w outboxie.
- **Configi z hosta (ADR 0028):** jedno `config_root` w `weglarka.toml` (mountowane **read-only** do kontenera
  demona w `platform install` — po upgrade trzeba go przeinstalować), `configs = [{ source, target }]` w spec
  apki (source względny do rootu, walidacja składniowa w `validate_app`; start i zapis sprawdzają tylko sam
  `config_root`, a canonicalize/containment źródła — reconcile i moment tworzenia kontenera). **Treść plików jest poza `spec_hash`** (edycja nic nie odtwarza),
  **lista `configs` jest w hashu**; `reload_signal` poza hashem. Zmianę treści aplikuje `apps reload` (sygnał albo
  restart), a single-file bind mount po write-and-rename wymaga `--recreate`. Oba pliki TOML mają
  `deny_unknown_fields`, a `apps.toml` dostaje `schema_version = 2` (`state::SCHEMA_VERSION` + no-op
  `SCHEMA_STEPS`, ADR 0023) → przed downgradem usunąć `config_root`, `configs`, `reload_signal` i marker
  `schema_version` (albo przywrócić pliki z kopii). Pliki runtime usera
  widoczne w zakresie UID apki jako `nobody` → 0644/0755. Szczegóły:
  [`docs/decisions/0028-config-root-mounts.md`](docs/decisions/0028-config-root-mounts.md) i
  [`docs/guides/host-configs.md`](docs/guides/host-configs.md).
- **Detekcja awarii (ADR 0022):** watcher crash loopów działa w przejściu reconcile — `container_list` już
  robi inspect każdego kontenera, więc licznik restartów (`RestartCount` → `ContainerInfo.restarts`) nie
  kosztuje dodatkowego wywołania libpoda. Stan jest pamięciowy (po restarcie demona pierwsza obserwacja tylko
  ustala baseline), pod mutexem silnika, a granicą baseline'u jest etykieta `weglarka.generation`. Progi w
  `[monitor]` (nowa sekcja → kolejny caveat downgrade'u), zdarzenia idą tym samym `EventSink`-iem co deploye.
- **Tryb `edge` (ADR 0036, #95):** nginx Węglarki terminuje TLS i publikuje dwa porty — `bind` (HTTP: tylko
  301 na HTTPS + `/.well-known/acme-challenge/`) i `https_bind`; w kontenerze nadal 8080/8443, więc profil
  hardeningu (0014) się nie zmienia, a `health_probe` idzie gniazdem `<nginx_conf_dir>/probe/probe.sock` (ADR 0054). Certyfikaty: `<nginx_conf_dir>/tls/<domena>.crt|key`
  (0600/0700), webroot ACME `<nginx_conf_dir>/acme` (0644/0755); serwer TLS powstaje **tylko** dla domeny z
  parą plików (bez pary: redirect i odrzucony handshake — fail closed). Demon skanuje `tls/` przy każdym
  `apply`, a odcisk materiału w `nginx.conf` powoduje reload (`nginx -t` + SIGHUP) — **nigdy** odtworzenie
  kontenera; to jest ścieżka, którą idzie worker ACME (`[acme]`, ADR 0038, `docs/guides/acme.md`). W edge **nikt nie jest zaufany** w sprawie `X-Forwarded-*` (0007), a mapa
  uid ingressu jest dwuliniowa (uid 0 = użytkownik runtime, 1.. = zakres ingressu), żeby master czytał klucze
  0600 — dlatego **do nginx wolno montować tylko `<nginx_conf_dir>`** (jego podkatalogi `run/` i `probe/` dodatkowo, zapisywalnie). Porty publikuje kontener `weglarka-forwarder` (obraz demona, pasta, PROXY protocol po gnieździe `<nginx_conf_dir>/run`, `0700`; ADR 0043, #162), nie nginx — inaczej rootlessport gubi adres klienta; `weglarka.ingress-hash` = v5 w obu trybach (mount `probe/`, ADR 0054). Porty < 1024 wymagają sysctla i
  `[runtime] allow_privileged_host_ports`.
- **Sekrety są w zakresie per instancja (ADR 0024, `<apka>.<nazwa>` w `secrets.toml`)** — `apps remove`
  domyślnie **zachowuje** je (dane i poświadczenia to osobne decyzje), więc nowa apka pod starą nazwą
  dziedziczy stare wartości. Sprzątanie przy usuwaniu: `apps remove --purge-secrets` (cały zakres
  `<apka>.*`, także `webhook-hmac`, niezależnie od `--purge-volumes`, przed zapisem `apps.toml`).
  `secrets remove` działa **także po usunięciu apki** (sprząta pozostałości po zmianie nazwy instancji),
  a `doctor` ostrzega checkiem `state.orphan_secrets`. Szczegóły:
  [`docs/decisions/0024-secret-removal-and-purge.md`](docs/decisions/0024-secret-removal-and-purge.md) i
  [`docs/guides/secrets-cleanup.md`](docs/guides/secrets-cleanup.md).
- **Testy uruchamiają się w CI tak jak na produkcji:** smoke test startuje demona z argumentów quadletu
  (bez `/etc/passwd`, bez `/etc/subuid` w obrazie `scratch`).
- **Samoaktualizacja (ADR 0027):** demon siedzi w kontenerze `scratch` (brak `systemctl`, `/etc/passwd`,
  D-Bus) i nie ma prawa zapisu do własnego unitu, więc podmiana obrazu jest **host-side**:
  `weglarka-daemon self-update` + timer usera instalowany przez `platform install`. Kolejność: pull →
  weryfikacja podpisu (statyczny klucz cosign z `cosign.pub` w repo, `ring`, bez Rekor/TUF) → bramka
  schematu (label obrazu `io.weglarka.state-schema` kontra `schema_version` w `state.toml`) → pin
  `repo@sha256:…` w quadlecie → `pending` w `<state dir>/self-update.toml` (tolerancyjny, 0600) →
  restart; demon potwierdza na starcie i ustawia `current`/`previous`. Rejestr jest tylko publiczny
  (anonimowy token GHCR), a `[self_update]` w `weglarka.toml` łamie rollback do starszego demona.
  **Automatyczny powrót (ADR 0034, #100):** timer `weglarka-watchdog.timer` co minutę uruchamia
  `weglarka-daemon supervise`; gdy nowy demon nie odpowie na `GET /v1/health` w `[self_update]
  fallback_timeout_secs` (domyślnie 180 s), watchdog robi `reset-failed` + przypina `switch_from`
  w quadlecie i restartuje, a demon po starcie emituje `SelfUpdateFellBack` i zostawia zepsuty digest
  w `error` (bez ponownego pinu, dopóki tag się nie ruszy). Jedna próba: wyczerpany budżet to raport
  (`doctor`, journal, unit watchdoga „failed”), nie pętla restartów.
- **Dedup webhooków przeżywa restart (ADR 0035, #41):** identyfikatory dostaw trzyma
  `<katalog stanu>/webhook-deliveries.toml` (`model/src/delivery.rs`; 0600, 256 wpisów, najstarsze wypadają),
  zapisywany atomowo przez `fsutil::write_atomic` pod mutexem dedup, tylko na nowy id i **przed** fan-outem.
  Plik jest celowo poza `state.toml` (nowe pole łamie rollback przez `deny_unknown_fields`), nie ma znacznika
  schematu, a starszy demon go ignoruje. Odczyt jest tolerancyjny (brak = pusty zbiór, uszkodzony = warn +
  pusty i przepisany przy następnej dostawie), a błąd zapisu tylko ostrzega — księgowość nie może wywalić
  webhooka ani startu demona.
- **Właściciel zamontowanego sekretu (ADR 0037, #55):** `mode`/`uid`/`gid` w wiązaniu `kind = "mount"` są
  **kontenerowe** (ta sama przestrzeń co `USER` obrazu; Podman mapuje je przez zakres instancji, ADR 0009),
  `uid`/`gid` to liczby w `0..=65535` (nazwy użytkowników odrzuca parsowanie). Nieustawione pola nie wchodzą
  do `spec_hash` (aktualizacja nic nie odtwarza), ustawione/zmienione odtwarzają kontener, a `--secret-mount`
  wiąże od nowa i resetuje te opcje do domyślnych. Nowe pola `apps.toml` → `schema_version = 7` (no-op krok),
  więc przed downgradem usuń `uid`/`gid` z zamontowanych sekretów albo przywróć pliki stanu z kopii.

## Testy

- `cargo test --workspace` — jednostkowe + snapshoty, bez Podmana.
- Testy integracyjne demona to **jedna binarka** (`daemon/tests/it/main.rs`); nowy obszar = nowy `mod`, nie nowy
  `tests/*.rs` (każda binarka generuje od nowa `Daemon<FakePodman>`). Jeden obszar:
  `cargo test -p weglarka-daemon --test it -- sites::`.
- Środowiska z sandboxem (agent / CI w kontenerze): jeśli cargo nie może pisać do globalnego `target-dir`
  (`Operation not permitted`), ustaw `CARGO_TARGET_DIR` na katalog zapisywalny w sandboxie — dla worktree jego własny
  `target/` (`CARGO_TARGET_DIR="$(scripts/worktree.sh target)"`); nie wskazuj `target/` innego checkoutu (patrz „Worktrees").
- **Wspólny katalog budowania potrafi skłamać** (zmierzone 2026-10-24 i 2026-10-27): gdy dwa checkouty piszą do jednego
  `target/` (albo `build.build-dir`), cargo może zlinkować **stary albo cudzy** `libweglarka_{core,api}` — albo
  zgłosić błędy, których w kodzie nie ma (`unresolved import weglarka_core::images`, `no field repo_digests on type
  ImageInfo`, `ContainerSpec has no field command`), albo — gorzej — zbudować bez błędu i bez rekompilacji (0 crate'ów)
  binarkę z kodu drugiego worktree. Nie „naprawiaj" wtedy kodu: powtórz na prywatnym katalogu
  `CARGO_TARGET_DIR="$PWD/target" cargo test --workspace` (pełny rebuild, minuty, ale wiarygodny). Nie chowaj też
  werdyktu w potoku: `cargo test … > /tmp/log 2>&1; echo "EXIT: $?"` — `| tail` maskuje kod wyjścia.
- Fake: `weglarka-core` z `features = ["testing"]` → `weglarka_core::testing::FakePodman`
  (skryptowalne digesty pulla, błędy w środku pulla, kolejka wyników healthchecka, log wywołań).
- Integracyjne z prawdziwym Podmanem 6.1 (`weglarka-podman/tests/`): wymagają `WEGLARKA_PODMAN_SOCKET`
  (CI ustawia je w jobie `podman-tests`); bez zmiennej testy się pomijają
  (`docs/decisions/0002-podman-in-ci.md`). Job podnosi pulę subuid do ~1 M (zakres instancji = 65 536 UID, ADR 0009);
  `engine_ranges_volumes_secrets_import_migration_and_purge` przechodzi przez cały silnik na prawdziwym Podmanie.
- Build statyczny: `cargo build --release --target x86_64-unknown-linux-musl` (CI: job `musl`).
- Odbiór na hoście / w CI: `scripts/acceptance.sh` (kanarek, ruch, webhook 202/401/204, sprzątanie;
  `--with-local-registry` dodaje deploy z webhooka i wymuszony rollback — tylko w CI). Smoke testy obrazu:
  `.github/scripts/smoke-image.sh` i `smoke-quadlet.sh` (argumenty z `platform install`).
- CI na PR buduje profilem `ci` (thin LTO), `main` i tagi — pełnym `release` (`docs/decisions/0008`).
  PR zmieniający wyłącznie dokumentację (`docs/**`, `*.md`, `.gitignore`) nie uruchamia buildów — job
  `changes` pomija `check`/`nginx-e2e`/`musl`/`podman-tests`/`smoke-behind`/`smoke-edge`; `changes` i `pr-title` biegną zawsze. Push na
  `main` z samą dokumentacją nie uruchamia CI ani Release (`paths-ignore`) — obraz nie jest wtedy
  przebudowywany; tagi `v*` budują zawsze.
