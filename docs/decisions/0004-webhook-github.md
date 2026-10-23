# 0004 — Webhooki GitHub: zdarzenia, sekret per apka, 202 od razu

Status: przyjęta (sesja daemon, 2026-10-23). **Wybór zdarzenia do potwierdzenia na prawdziwym pushu.**

**Decyzja.**
- Endpoint: `POST /webhook/github/{instance}` (pod prefiksem `/webhook/`, który wystawia nginx).
  Instancja jest w ścieżce, bo HMAC jest **per apka**: sekret `<instancja>.webhook-hmac` w `secrets.toml`
  (ustawiany `weglarka secrets set <app> webhook-hmac`, ten sam ciąg trafia do ustawień webhooka na GitHubie).
- Obsługiwane zdarzenia: `registry_package` i `package`, `action == "published"`, `package_type`
  `CONTAINER` (lub brak pola). `image_ref` = `repo(package_url) + ":" + container_metadata.tag.name`
  (bez `package_url`: `ghcr.io/<namespace>/<name>`), małymi literami. Wersja bez tagu → ignorowana.
  Pozostałe zdarzenia (`ping`, `push`, `workflow_run`, …) → **204**.
- Kolejność: sekret → podpis (**401**, także dla nieznanej apki / braku sekretu — nieodróżnialne)
  → normalizacja (204 / **400** dla zepsutego ciała) → zdarzenie musi dotyczyć obrazu śledzonego przez
  tę apkę (inaczej 204) → **202** i `Reconciler::handle_webhook` w osobnym tasku (śledzonym na czas shutdownu).
- Podpis: `X-Hub-Signature-256`, HMAC-SHA256, porównanie w stałym czasie (`Mac::verify_slice`).
  Odrzucenia są logowane (instancja, delivery, powód) — bez ciała i bez sekretów.
- Dedup po `X-GitHub-Delivery` robi rdzeń; duplikat dostaje 202 (odpowiedź jest zanim wiadomo o duplikacie).
- Limit ciała: 1 MiB (zgodny z `webhook_max_body_bytes` nginxa) → 413.

**Do potwierdzenia na prawdziwym pushu.** Nie widzieliśmy jeszcze payloadu z GHCR dla ntfy.zig. Parser jest
tolerancyjny (`#[serde(default)]`), ale nazwy pól (`registry_package.package_version.container_metadata.tag.name`,
`package_url`) pochodzą z dokumentacji, nie z obserwacji. CI ntfy.zig pcha dwa tagi (`latest` i `sha-…`), więc
oczekujemy dwóch dostaw na push; `sha-…` nie pasuje do apki śledzącej `:latest` i kończy się 204.

**Fan-out (świadoma decyzja, Kajet „Model apek i stan”).** Webhook obrazu X aktualizuje *wszystkie* instancje
śledzące X z `auto_update = true` (`Reconciler::handle_webhook`). Trade-off: podpis jednej instancji może
wyzwolić deploy innych instancji tego samego obrazu. Ryzyko jest ograniczone: zdarzenie przechodzi tylko, gdy
`image_ref` z payloadu pasuje do obrazu/tagu **uwierzytelnionej** instancji (inaczej 204, nic się nie dzieje),
więc podpis instancji A nie uruchomi niczego poza tym, co A sama śledzi; inne instancje i tak śledzą ten sam
`image_ref`, a bramka zdrowia i rollback działają per instancja.

**Higiena logów i dedupu.** Identyfikator dostawy trafia do logów i zbioru dedup tylko, gdy ma ≤ 64 znaków
`[A-Za-z0-9-]`; niezaufane wartości w logach są formatowane przez `Debug`.
