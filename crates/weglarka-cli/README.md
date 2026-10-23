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

Sprawdzenia (`id`): `config.file`, `runtime.user`, `runtime.subuid`/`subgid` (≥ 65536),
`runtime.cgroups`, `runtime.linger` (tylko systemd), `runtime.socket`, `runtime.podman_version`
(libpod ≥ 6.0), `runtime.podman_source` (alvistack), `runtime.netavark` (≥ 2, nftables),
`runtime.pasta`, `ingress.traefik_file` (tylko `behind`), `ingress.bind`, `state.secrets_file` (0600).
Nowe sprawdzenie = typ implementujący `Check` w `src/preflight/checks.rs` + wpis w `all_checks()`.
Dostęp do hosta wyłącznie przez trait `Host` (testy: `FakeHost`).
`secrets.toml` nie ma ścieżki w `weglarka.toml` — domyślnie obok pliku konfiguracji,
nadpisanie: `--secrets-file` / `WEGLARKA_SECRETS_FILE`.
