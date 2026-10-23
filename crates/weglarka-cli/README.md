# weglarka-cli

Binarka `weglarka` — cienki klient admin API demona (HTTP/JSON po sockecie unix) oraz lokalny
`doctor --preflight`. Opisy komend po polsku (spójnie z README repo).

## Konfiguracja

Socket: `--socket` / `WEGLARKA_SOCKET`, w przeciwnym razie `admin.socket` z `weglarka.toml`
(`--config` / `WEGLARKA_CONFIG`, domyślnie `/etc/weglarka/weglarka.toml`).

## Konwencje dla agentów

- `--json`: na stdout dokładnie jeden dokument — typ z `weglarka-api` (`ListAppsResponse`,
  `ShowAppResponse`, `DeployResponse`, `StatusResponse`, `ListSecretsResponse`, `SecretInfo`,
  `DoctorReport`). Wyjątki CLI: `apps remove` → `{"removed","existed"}`, `--dry-run` →
  `{"dry_run":true,"method","path","body"}`.
- Błędy na stderr; z `--json`: `{"error":{"code","message","hint","exit_code"}}`.
- `--dry-run` (`apps add/remove`, `deploy`, `secrets set`): nic nie jest wysyłane do zmiany stanu;
  `remove`/`deploy` tylko sprawdzają istnienie apki (GET). Wartość sekretu jest zasłonięta.
- Idempotencja: `apps remove --ignore-missing`. `apps add --spec plik.toml` przyjmuje cały `AppSpec`.
- Sekret: `secrets set <app> <nazwa>` czyta stdin albo `--from-file`; wartość z argumentu jest
  niemożliwa. Domyślnie ucinany jest jeden końcowy `\n` (`--raw` zachowuje bajty).

## Kody wyjścia

| kod | znaczenie |
|---|---|
| 0 | sukces |
| 1 / 2 | `doctor`: najgorszy wynik `warn` / `fail` |
| 3 | nie znaleziono |
| 4 | już istnieje / konflikt |
| 5 | demon odrzucił żądanie (`invalid_request`) |
| 6 | `deploy`: `rolled_back` |
| 64 | błędne wywołanie / dane wejściowe |
| 69 | demon nieosiągalny |
| 70 | błąd wewnętrzny (I/O, protokół, 5xx) |
| 78 | brak / błędny `weglarka.toml` |

## `doctor --preflight`

Sprawdzenia (`id`): `config.file`, `runtime.user`, `runtime.subuid`/`subgid` (fail < 65 536,
warn < 1 000 000 — zapas pod `userns=auto`), `runtime.cgroups`, `runtime.linger` (tylko systemd),
`runtime.socket`, `runtime.podman_version` (libpod ≥ 6.0), `runtime.podman_source` (alvistack),
`runtime.netavark` (≥ 2, nftables), `runtime.pasta`, `runtime.apparmor_userns` (przy
`kernel.apparmor_restrict_unprivileged_userns=1` musi być załadowany profil `podman`; lista profili
jest czytelna tylko dla roota — jako zwykły user wynik to `warn`; brak AppArmor = ok),
`ingress.traefik_file` (tylko `behind`), `ingress.bind`, `ingress.bind_free` (port z `bind` nie jest
zajęty przez gniazdo innego uid niż user runtime'u; z `/proc/net/tcp*`), `ingress.traefik_sync`
(tylko `behind` + systemd: jeśli jest `/etc/weglarka/traefik-policy.json`, to unit
`weglarka-traefik-sync.path` jest `active`, a domeny z `apps.toml` — jeśli dostępny lokalnie —
są na allowliście polityki, klucz `allowed_domains`; ścieżki i nazwa unitu to stałe z konwencji roli
Ansible `weglarka_host`), `state.secrets_file` (0600).
Reguły firewalla (UFW) nie są sprawdzane — wymagają roota.
Nowe sprawdzenie = typ implementujący `Check` w `src/preflight/checks.rs` + wpis w `all_checks()`.
Dostęp do hosta wyłącznie przez trait `Host` (testy: `FakeHost`).
`secrets.toml` nie ma ścieżki w `weglarka.toml` — domyślnie obok pliku konfiguracji,
nadpisanie: `--secrets-file` / `WEGLARKA_SECRETS_FILE`.
