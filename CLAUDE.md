# Węglarka — wskazówki dla agentów

Własny deploy-tool w Ruście (zastępca Coolify): demon zarządza rootless Podmanem 6 (libpod API v6
po unix sockecie), deklaratywny reconcile ze stanu w TOML, nginx w kontenerze za Traefikiem
(tryb `behind`), auto-update po webhooku GitHub (GHCR). MVP: `ntfy.zig` sam się aktualizuje.

**Zadania i plan rozwoju: [GitHub Issues](https://github.com/jpalczewski/weglarka/issues)** (etykieta `roadmap` =
funkcje zaplanowane, `bug` = błędy). Decyzje implementacyjne z uzasadnieniem: `docs/decisions/` — indeks generowany z tytułów ADR-ów:
[`docs/decisions/README.md`](docs/decisions/README.md).
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
  `version` ani `CHANGELOG.md`. Wewnętrzne zależności w `[workspace.dependencies]` mają `version = "0.0"` (ADR 0015, aneks) —
  nie wpisuj tam bieżącej wersji, bo release-plz zbumpuje wtedy wszystkich zależnych razem z crate'em, który się zmienił.
  Wyjątek: `weglarka-api` (kontrakt CLI↔demon) ma dokładną wersję, więc jego wydanie wydaje też `weglarka-cli` i `weglarka-daemon`. Tag `vX.Y.Z` = wersja `weglarka-daemon` (uruchamia `release.yml`).
- Przykłady: `feat(core): provision apps without starting them`, `fix(podman): map libpod 500 to NotFound`,
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
   ADR 0023); kompatybilność wstecz (`deny_unknown_fields` a rollback) opisz w PR i w `docs/install.md`
   — dla plików stanu to [wersja schematu](docs/install.md#wersja-schematu-plików-stanu-rollback-między-wersjami).
5. Decyzja implementacyjna → nowy ADR z [`docs/decisions/0000-template.md`](docs/decisions/0000-template.md).
   Tabelę indeksu generuje `scripts/adr.sh index` — nie edytuj jej ręcznie. Numer ADR to zasób wspólny
   dla równoległych gałęzi: zarezerwuj go wcześnie (push + draft PR ze stubem ADR-a) i scalaj szybko;
   jeśli rebase ujawni kolizję, przenumeruj jedną komendą: `scripts/adr.sh renumber OLD NEW`.
   Przed PR-em uruchom też `scripts/adr.sh lint` (to samo robi job `docs-lint`).
6. Tytuł, commity i PR w Conventional Commits (`<type>(<scope>): <summary>`, patrz wyżej), po angielsku;
   `Closes #NN`; merge = squash po zielonym CI (`check`, `musl`, `integration-podman`; zmiana tylko w
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
- Build z dowolnego checkoutu na jednym cache: `CARGO_TARGET_DIR="$(scripts/shared-target.sh)"`; sesja
  wystartowana w worktree używa `$PWD/target` (główny checkout jest wtedy poza sandboxem).
- Wyjście: `cd` z powrotem do checkoutu (worktree i gałąź zostają). Po merge'u PR-a:
  `git worktree remove .agents/worktrees/<name> && git branch -D <name>`, potem `git worktree prune`.
  `.agents/worktrees/.gitignore` (`*`) trzyma pulę poza `git status`.
- Agent Teams: narzędzie zmienia katalog tylko wywołującej sesji. Jeden pisarz = jedno worktree: albo Lead
  tworzy je przed spawnem teammate'ów, albo każdy członek tworzy własne i wpisuje je w `write_scopes` zadania;
  teammate nigdy nie pracuje w checkoutcie Leada.
- Bez bundla (`create_worktree` niedostępne): `git worktree add .agents/worktrees/<name> -b <name> origin/main`
  i wejdź tam — pozostałe zasady bez zmian.
- Stare `.claude/worktrees/` (sesje Claude Code) są wykluczone z wyszukiwań; nie używaj ich do nowej pracy.

## Mapa crate'ów

Zależności: `api → core`; `podman → core`; `ingress → core`; `notify → core`; `registry → core`; `acme → core`; `dns → core`; `acme → dns`;
`cli → api, core`; `daemon → wszystko`.

| Crate | Zawartość |
|---|---|
| `weglarka-core` | typy domenowe (`AppSpec`, `HostConfig`, stan), reconcile, deploy (bramka zdrowia, rollback), wolumeny i zakresy UID (w tym wolumeny współdzielone), configi z hosta (`config_root`, `config_mounts.rs`), sekrety, wykrywanie awarii (`crash.rs`), stan samoaktualizacji (`self_update.rs`: plik stanu + czyste `decide()`/`supervise()`), traity (`PodmanClient`, `Platform`, `WebhookSource`, `SecretStore`) + `FakePodman` (feature `testing`) |
| `weglarka-podman` | klient libpod v6 (hyper, unix socket) + testy integracyjne |
| `weglarka-ingress` | czyste generatory `nginx.conf` (`behind` i `edge`) i pliku dynamicznego Traefika (snapshoty) |
| `weglarka-notify` | powiadomienia: `Event` → `Severity` → komunikaty → dedup → trwała kolejka (outbox) → kanały (`ntfy`; mail = #113), własny klient HTTP/TLS (rustls + webpki-roots) |
| `weglarka-registry` | podpisy cosign z OCI (tag `.sig` + token GHCR) i weryfikacja kluczem statycznym ECDSA P-256 (`ring`); własny minimalny klient HTTP/TLS, `FakeRegistry`/`TestSigner` (feature `testing`) |
| `weglarka-acme` | silnik ACME dla trybu `edge` (#96, ADR 0038): `CertSpec`/`CertId` (certyfikat = lista nazw, plik z id), trait `ChallengeSolver` (`Http01Solver`, `DnsSolver` nad `weglarka-dns` = #97), `AcmeClient`/`CertInspector`, `CertStore` (klucz 0600 przed certem 0644, atomowo), czyste `renewal::decide`, `Manager::pass`; `InstantAcme` (klient na `instant-acme`, `ring`, `webpki-roots`), `FakeAcme` (feature `testing`); test na staging Let's Encrypt jest opt-in (`WEGLARKA_ACME_STAGING_DOMAIN`/`_WEBROOT`); worker w demonie (`daemon/src/acme.rs`, `[acme]`, zdarzenia, `doctor acme.*`) |
| `weglarka-dns` | adaptery DNS dla ACME DNS-01: trait `DnsProvider` (`set_txt`/`remove_txt`, handle usuwa dokładnie swój rekord), adapter Cloudflare (API v4, własny minimalny klient HTTP/TLS, token jako `SecretValue`), `FakeDns` (feature `testing`); ADR 0039 |
| `weglarka-api` | kontrakt admin API (typy, endpointy, kody błędów) |
| `weglarka-daemon` | demon: admin API (unix socket, w tym `GET /v1/health`), webhooki, zapis ingressu, `Platform` systemd (quadlet + timery samoaktualizacji i watchdoga), worker powiadomień, host-side `self-update` i `supervise` |
| `weglarka-cli` | CLI `weglarka`, `doctor --preflight` |

Przy pracy równoległej kilku agentów: jeden crate/obszar na agenta, a zmiany w kontrakcie (`app.rs`, `podman.rs`,
`weglarka-api`) tylko addytywne i zawsze z aktualizacją `FakePodman`.
Nowa zależność zewnętrzna: dodaj do `[workspace.dependencies]` w root `Cargo.toml` i odwołaj się przez `.workspace = true`.

### Gdzie co leży (najczęstsze punkty wejścia)

| Obszar | Pliki |
|---|---|
| model i walidacja apki | `core/src/app.rs`, `core/src/state.rs` (`AppSpec`, `AppsFile`, `validate_app`, `SCHEMA_VERSION` + bramka schematu) |
| pętla reconcile | `core/src/reconcile.rs` — czyste `plan()` (`Target`/`Action`) + `execute()` (jedyny pisarz stanu) |
| deploy | `core/src/deploy.rs` — `deploy_locked`: pull → stop → create+start → bramka → rollback; `provision_locked` |
| spec-hash | `core/src/hash.rs` — co odtwarza kontener (`HashInput`) |
| wolumeny i UID | `core/src/volumes.rs`, `core/src/uid_range.rs` (ADR 0009), wolumeny współdzielone: `core/src/shared_volumes.rs` + `core/src/volumes.rs` (ADR 0017) |
| sekrety | `core/src/secrets.rs`, `core/src/secret_store.rs` |
| configi z hosta i reload | `core/src/config_mounts.rs` (resolve/fingerprint/walidacja hosta), `core/src/deploy.rs` (`launch` montuje `BindMount` ro, `reload_locked`/`reload`), pola `configs`/`reload_signal` w `core/src/app.rs`, hash w `core/src/hash.rs`, `daemon/src/settings.rs` (`Paths.config_root`) + mount w `daemon/src/service.rs` (`service_spec`), trasa `api/src/endpoints.rs` → `daemon/src/admin.rs`, check `configs.*` w `daemon/src/doctor.rs`, CLI `cli/src/commands.rs`/`spec_flags.rs` (ADR 0028) |
| retencja obrazów | `core/src/images.rs` (czysty `plan()` + `execute()`), wywołania po deployu w `core/src/deploy.rs`, API `daemon/src/images.rs`, check `runtime.images` w `daemon/src/doctor.rs` (ADR 0020) |
| samoaktualizacja Węglarki | `core/src/self_update.rs` (stan + czyste `decide()`/`supervise()`), `registry/src/` (podpis cosign i weryfikacja kluczem), `daemon/src/self_update.rs` (host-side switcher + akcja fallbacku), `daemon/src/supervise.rs` (host-side watchdog: sonda `GET /v1/health`, blokada stanu), `daemon/src/service.rs` (spec współdzielony z `platform install`), `daemon/src/platform.rs` (timery, `install_user_units`, `restart_service`, `reset_failed`), sekcja `[self_update]` w `core/src/config.rs`, check `self_update` w `daemon/src/doctor.rs` (ADR 0027, ADR 0034) |
| kontrakt i trasy API | `api/src/types.rs` + `api/src/endpoints.rs` → `daemon/src/admin.rs` (nowy endpoint: najpierw `endpoints.rs`) |
| ingress | `ingress/src/plan.rs` (`Plan::build` waliduje, w tym rozłączność `paths` na wspólnej domenie; `route_table()` dla `doctor`) → `nginx.rs`/`traefik.rs` (render + snapshoty); reload: `daemon/src/ingress.rs`; prefiksy ścieżek: ADR 0031, `paths`/`ingress.strip_prefix` w `core/src/app.rs`, składnia `check_path_prefix`, `docs/install.md` 6n; tryb `edge` (dwa puby, TLS, webroot ACME, mapa uid ingressu): ADR 0036, `docs/install.md` 6p |
| certyfikaty ACME (edge) | `acme/src/{manager,store,solver,instant,renewal}.rs` (silnik, `FakeAcme` w `testing.rs`), `core/src/config.rs` (`AcmeConfig`, walidacja w `HostConfig::validate`), `core/src/events.rs` (`CertificateIssued`/`CertificateRenewalFailed`), `daemon/src/acme.rs` (worker, `AcmeStatus`) + wiring w `daemon/src/lib.rs`, checki `acme.*` w `daemon/src/doctor.rs`, `docs/install.md` 6q (ADR 0038); wildcard przez DNS-01: `[acme.dns]` (`AcmeDnsConfig`, `token_file` 0600 jak ntfy), `DnsBackend` + drugi `Manager` w `daemon/src/acme.rs`, `DnsSolver` w `acme/src/dns.rs`, adaptery w `weglarka-dns`, checki `acme.dns`/`acme.wildcards`, `docs/install.md` 6s (ADR 0039; ingress jeszcze nie serwuje wildcardów) |
| powiadomienia | `notify/src/{message,dedup,outbox,worker,ntfy,http,settings}.rs`; sekcja `[notify]`: `core/src/config.rs`; `Severity`: `core/src/events.rs`; wiring: `daemon/src/lib.rs` (`Notifier::build`, sink, worker), trasa: `api/src/endpoints.rs` → `daemon/src/admin.rs` |
| wykrywanie awarii | `core/src/crash.rs` (polityka `Policy` + maszyna stanu `Watcher`), wywołanie w `core/src/reconcile.rs` (`Reconciler::with_monitor`, raz na przejście), sekcja `[monitor]`: `core/src/config.rs`, zdarzenia: `core/src/events.rs`, testy: `core/src/engine_tests.rs` (ADR 0022) |
| jednorazowe kontenery (`weglarka run`) | `core/src/run.rs` (`prepare_run`/`PendingRun::drive`, `remove_stale_runs`; wspólne przygotowanie z deployem: `prepare_instance` w `core/src/deploy.rs`), etykiety `weglarka.run`/`run-for` w `core/src/labels.rs`, `container_logs`/`container_wait`/`entrypoint` w `core/src/podman.rs` + `podman/src/{client,wire}.rs`, strumień ramek `api/src/run.rs`, trasa `daemon/src/admin.rs` (`run_app`), CLI `cli/src/run.rs`, `docs/install.md` 6r (ADR 0040) |
| CLI | `cli/src/update.rs` (read-modify-write specu: `apps update/start/stop`, `--dry-run`), `cli/src/commands.rs` |
| testy silnika | `core/src/engine_tests.rs` (scenariusze na `FakePodman`), testy modułu w `core/src/volumes.rs` |
| testy daemon/API | `daemon/tests/*.rs` (prawdziwy unix socket + `FakePodman`) |

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
  [`docs/install.md` 6a](docs/install.md#6a-wolumeny-zakresy-uid-i-import-z-coolify-iteracja-2).
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
  [`docs/install.md` 6l](docs/install.md#6l-configi-z-hosta-config_root-i-apps-reload).
- **Detekcja awarii (ADR 0022):** watcher crash loopów działa w przejściu reconcile — `container_list` już
  robi inspect każdego kontenera, więc licznik restartów (`RestartCount` → `ContainerInfo.restarts`) nie
  kosztuje dodatkowego wywołania libpoda. Stan jest pamięciowy (po restarcie demona pierwsza obserwacja tylko
  ustala baseline), pod mutexem silnika, a granicą baseline'u jest etykieta `weglarka.generation`. Progi w
  `[monitor]` (nowa sekcja → kolejny caveat downgrade'u), zdarzenia idą tym samym `EventSink`-iem co deploye.
- **Tryb `edge` (ADR 0036, #95):** nginx Węglarki terminuje TLS i publikuje dwa porty — `bind` (HTTP: tylko
  301 na HTTPS + `/.well-known/acme-challenge/`) i `https_bind`; w kontenerze nadal 8080/8443, więc profil
  hardeningu (0014) i `health_probe` się nie zmieniają. Certyfikaty: `<nginx_conf_dir>/tls/<domena>.crt|key`
  (0600/0700), webroot ACME `<nginx_conf_dir>/acme` (0644/0755); serwer TLS powstaje **tylko** dla domeny z
  parą plików (bez pary: redirect i odrzucony handshake — fail closed). Demon skanuje `tls/` przy każdym
  `apply`, a odcisk materiału w `nginx.conf` powoduje reload (`nginx -t` + SIGHUP) — **nigdy** odtworzenie
  kontenera; to jest ścieżka, którą idzie worker ACME (`[acme]`, ADR 0038, `docs/install.md` 6q). W edge **nikt nie jest zaufany** w sprawie `X-Forwarded-*` (0007), a mapa
  uid ingressu jest dwuliniowa (uid 0 = użytkownik runtime, 1.. = zakres ingressu), żeby master czytał klucze
  0600 — dlatego **do nginx wolno montować tylko `<nginx_conf_dir>`**. Porty < 1024 wymagają sysctla i
  `[runtime] allow_privileged_host_ports`; `weglarka.ingress-hash` = v3 (tryb + oba puby).
- **Sekrety są w zakresie per instancja (ADR 0024, `<apka>.<nazwa>` w `secrets.toml`)** — `apps remove`
  domyślnie **zachowuje** je (dane i poświadczenia to osobne decyzje), więc nowa apka pod starą nazwą
  dziedziczy stare wartości. Sprzątanie przy usuwaniu: `apps remove --purge-secrets` (cały zakres
  `<apka>.*`, także `webhook-hmac`, niezależnie od `--purge-volumes`, przed zapisem `apps.toml`).
  `secrets remove` działa **także po usunięciu apki** (sprząta pozostałości po zmianie nazwy instancji),
  a `doctor` ostrzega checkiem `state.orphan_secrets`. Szczegóły:
  [`docs/decisions/0024-secret-removal-and-purge.md`](docs/decisions/0024-secret-removal-and-purge.md) i
  [`docs/install.md` 6j](docs/install.md#6j-sekrety-usuwanie-i-sprzątanie-po-apce).
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
  `<katalog stanu>/webhook-deliveries.toml` (`core/src/delivery.rs`; 0600, 256 wpisów, najstarsze wypadają),
  zapisywany atomowo przez `state::write_atomic` pod mutexem dedup, tylko na nowy id i **przed** fan-outem.
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
- Środowiska z sandboxem (agent / CI w kontenerze): jeśli cargo nie może pisać do globalnego `target-dir`
  (`Operation not permitted`), ustaw `CARGO_TARGET_DIR` na katalog zapisywalny w sandboxie. **Worktree nie buduje
  własnego `target/`:** wskaż wspólny katalog głównego checkoutu — `CARGO_TARGET_DIR="$(scripts/shared-target.sh)"` —
  żeby zależności z crates.io skompilowały się raz dla wszystkich worktree (skrypt zwraca ten sam katalog z głównego
  checkoutu i z `git worktree`). Przy sesji, której workspace *jest* worktree, główny checkout bywa poza sandboxem —
  wtedy zostaje `$PWD/target`.
- **Wspólny `target/` potrafi skłamać** (zmierzone 2026-10-24): gdy pisze do niego równolegle inny proces (druga
  sesja, świeży `git rebase`), cargo może zlinkować **stary** `libweglarka_{core,api}` i zgłosić błędy, których
  w kodzie nie ma — np. `unresolved import weglarka_core::images`, `no field repo_digests on type ImageInfo`,
  `ContainerSpec has no field command`. Nie „naprawiaj" wtedy kodu: powtórz na prywatnym katalogu
  `CARGO_TARGET_DIR="$PWD/target" cargo test --workspace` (pełny rebuild, minuty, ale wiarygodny). Nie chowaj też
  werdyktu w potoku: `cargo test … > /tmp/log 2>&1; echo "EXIT: $?"` — `| tail` maskuje kod wyjścia.
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
