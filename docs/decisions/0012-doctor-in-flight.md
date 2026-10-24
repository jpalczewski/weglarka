# 0012 — `doctor` a operacja w toku: status `info` zamiast fałszywego dryfu

Status: accepted (2026-10-24, issue #30).

## Problem

`state.toml` jest jedynym źródłem prawdy o stanie runtime, ale deploy/recreate/provision zapisują go
**dopiero po** utworzeniu, starcie i przejściu bramki zdrowia nowego kontenera (`launch()` → `save_state`).
Przez cały ten czas (ułamek sekundy przy prostym recreate, do `health.window_secs` przy bramce) żywy
kontener i `state.toml` mówią co innego, a `doctor` nie stoi za `Reconciler::lock` — porównuje właśnie te
dwa źródła:

- nowy kontener z nowym `spec-hash` vs stary `spec_hash` w stanie → „dryf spec-hash”,
- brak kontenera między `stop`/`remove` a `create` → „brak kontenera”,
- pierwszy deploy bez wpisu w `state.toml` → „jeszcze niewdrożona”.

Wszystkie trzy trafiają do `state.drift` jako `warn`, czyli `weglarka doctor` kończy się kodem 1 i alarmuje
w trakcie normalnej operacji (issue #30: kilka sekund po `apps update` lub zmianie sekretu). Po zapisie
stanu wszystko samo się zgadza, więc problem jest **fałszywym alarmem o przejściowym stanie**, a nie dryfem.

## Decision

**Rejestr operacji w toku po stronie silnika.** `Reconciler` trzyma
`activity: Mutex<Option<InFlight>>` (`InFlight { instance, kind }`, `ActivityKind` = `Deploy` / `Recreate` /
`Provision`). `begin_activity()` zwraca guard RAII, który czyści wpis w `Drop` — obejmuje to early-returny
`?` i panikę, więc nie da się „zawiesić” instancji w stanie „w toku”. Wpis ustawiają dokładnie trzy ścieżki,
w których `state.toml` chwilowo zostaje za kontenerem: `deploy_locked` (po gałęzi `start = false`),
`recreate_locked`, `provision_locked`. `Reconciler::in_flight()` jest publicznym, read-only odczytem dla
`doctor`; operacje i tak serializuje `lock`, więc w locie jest najwyżej jedna instancja.

**`doctor` pomija instancję w toku i raportuje ją osobno.** Per-instancyjne sprawdzenia (kontener istnieje,
działa, `spec-hash` zgodny) są pomijane dla tej jednej instancji; zamiast nich pojawia się nowa checka
`state.deploying` ze statusem `info` (`deploy w toku: <inst> (<kind>) — pominięto w ocenie dryfu`).
`state.drift` ocenia wtedy tylko pozostałe instancje, więc prawdziwy dryf nadal jest `warn`-em, a `doctor`
w trakcie deployu kończy się kodem 0. Checka istnieje wyłącznie wtedy, gdy coś jest w toku — w spoczynku
raport jest identyczny jak dotąd.

**Nowy wariant `CheckStatus::Info`.** Znajduje się między `Ok` i `Warn` w `Ord`, więc `worst()` nadal
podnosi realne ostrzeżenie/błąd ponad „w toku”, a `exit_code()` mapuje `info` → 0. CLI renderuje go jako
`[INFO]` i liczy w podsumowaniu (`N ok, N info, N warn, N fail`).

**Niezmienniki.** `state.toml`, `apps.toml`, `spec_hash` i schematy TOML pozostają bez zmian
(`deny_unknown_fields` bez nowych pól, brak migracji). Rejestr jest wyłącznie w pamięci procesu: po restarcie
demona jest pusty — to celowe, bo wtedy stan faktycznie jest chwilowo niespójny i pokazanie dryfu jest
poprawne (startowy reconcile go zaraz naprawia). Kompatybilność wstecz: nowe CLI czyta starszy demon bez
zmian; **starsze CLI nie zna wariantu `"info"`** (enum jest zamykany), więc przy trwającym deployu
`weglarka doctor` nie sparsuje odpowiedzi — CLI i demon aktualizuje się razem (ten sam obraz/release).
Odnotowane w `docs/install.md`.

**Testy.** `in_flight_is_visible_during_a_deploy` / `in_flight_is_cleared_when_the_deploy_fails` (core) pilnują
rejestru i RAII; `doctor_reports_a_recreate_in_progress_instead_of_state_drift` (daemon, prawdziwy unix socket
+ `FakePodman`) odtwarza okno recreate przez wolną bramkę zdrowia i sprawdza, że w trakcie jest
`state.deploying: info` i `state.drift: ok`, a po zakończeniu checka znika i stan jest zgodny.

## Consequences

- `weglarka doctor` w trakcie deployu/recreate/provision pokazuje `[INFO] state.deploying …` zamiast
  `[WARN] state.drift …`; exit code 0, więc monitoring przestaje alarmować o normalnej operacji.
- Operatory widzą, **która** instancja i **jaka** operacja trwa — czytelniej niż „dryf” bez kontekstu.
- `CheckStatus` zyskuje wariant; to jedyna zmiana kontraktu admin API. Rollback daemona do wersji bez
  `info` jest bezpieczny (starą odpowiedź czyta nowe CLI), ale rollback samego CLI przy nowym demonie psuje
  `doctor` w trakcie operacji — aktualizacja CLI+demona razem, jak dotąd.
- Restart demona w środku deployu nie pokazuje „w toku” (rejestr jest ulotny): `doctor` zaraportuje realny
  dryf, dopóki startowy reconcile nie doprowadzi instancji do porządku. To poprawne zachowanie, nie regresja.
- Nowy kod musi utrzymywać niezmiennik „guard założony tylko w ścieżkach opóźniających zapis `state.toml`”;
  dokładanie go do operacji, które stan zapisują przed zmianą kontenera, tylko wyciszyłoby prawdziwy dryf.

## Rejected alternatives

- **Komunikat „w toku” wewnątrz `state.drift` ze statusem `ok`**: bez nowej checki i bez zmiany kontraktu,
  ale `doctor` po samym `id` nie da się monitorować (trzeba parsować treść), a status `ok` myli — „OK” przy
  zmianie, która właśnie trwa. Wariant `info` oddaje intencję issue #30 i zostaje maszynowo rozpoznawalny.
- **Flaga „deploy w toku” w `state.toml`**: łamie rollback do starszego demona (`deny_unknown_fields`),
  a po crashu zostaje jako trwały „zawieszony” marker, który trzeba by sprzątać — czyli nowy tryb awarii
  w pliku, który ma być prosty.
- **Wnioskowanie z `apps.toml` (porównanie hasha z pożądanym spec-em)**: rozpoznaje tylko moment „kontener
  nowy, stan stary”; okna `stop`/`remove` (brak kontenera) i pierwszego deployu w ogóle nie odróżnia od
  prawdziwego problemu.
- **Globalne „silnik zajęty” (`try_lock` na `Reconciler::lock`)**: nie wskazuje instancji i wycisza
  `state.drift` dla **wszystkich** apek przez cały przebieg reconcile (włącznie z naprawdę zdryfowanymi),
  więc prawdziwy problem mógłby zniknąć z raportu.
- **Status `CheckStatus::Info` bez rejestru, tylko z porównania czasu zapisu pliku**: heurystyka oparta na
  mtime `state.toml` jest niedeterministyczna i myli się przy każdym wolnym zapisie; rejestr w silniku zna
  dokładną instancję i rodzaj operacji.
