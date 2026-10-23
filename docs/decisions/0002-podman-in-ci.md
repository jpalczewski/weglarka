# 0002 — Podman 6.1 w testach integracyjnych: instalacja z OBS na runnerze

Status: przyjęta (fundament, 2026-10-23); do potwierdzenia pierwszym zielonym przebiegiem joba.

**Opcje.** (A) `apt install` z OBS `home:alvistack` na `ubuntu-24.04` z pinningiem apt;
(B) Podman w kontenerze (`--privileged`, Podman-w-Podmanie / Docker).

**Decyzja: A.**
- Runner `ubuntu-24.04` to lustro hosta `niechybnie` (Ubuntu 24.04.4, cgroups v2, systemd 255) —
  test sprawdza też ten sam kanał dostarczania i pinning, który pójdzie na produkcję.
- Rootless Podman w kontenerze wymaga trybu uprzywilejowanego i zagnieżdżonych user namespace,
  co zmienia semantykę `userns=auto`/subuid — czyli właśnie to, co chcemy testować.
- Koszt: instalacja z zewnętrznego repo (kilkadziesiąt sekund) i zależność od dostępności OBS.
  Łagodzenie: job `integration-podman` jest osobny; w razie awarii OBS nie blokuje fmt/clippy/test.

**Kontrakt z testami (sesja a).** Job uruchamia `podman system service` i eksportuje
`WEGLARKA_PODMAN_SOCKET`. Testy integracyjne czytają tę zmienną i pomijają się, gdy jej brak
(lokalnie `cargo test` zostaje szybki i bez Podmana).
