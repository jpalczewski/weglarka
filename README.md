# Węglarka

Lekki deploy-tool w Ruście zarządzający **rootless Podmanem 6**: deklaratywny stan w TOML,
pętla reconcile, nginx w kontenerze, auto-update po webhooku GitHub (GHCR), health gate z rollbackiem.
Alternatywa dla Coolify na małym VPS-ie (priorytety: bezpieczeństwo, rozszerzalny kod, mało RAM-u).

Status: **MVP** — demon, CLI, klient Podmana, ingress i pakowanie gotowe; wdrożenie na hoście w toku.

## Workspace

`weglarka-core` (domena, traity, reconcile) · `weglarka-api` (kontrakt admin API) ·
`weglarka-podman` (klient libpod v6) · `weglarka-ingress` (nginx/Traefik) ·
`weglarka-daemon` (demon) · `weglarka-cli` (binarka `weglarka`).

```sh
cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

Konwencje i podział pracy: [CLAUDE.md](CLAUDE.md). Decyzje implementacyjne: [docs/decisions](docs/decisions).

## Instalacja

Obraz `ghcr.io/jpalczewski/weglarka` (kontener rootless Podmana, quadlet systemd) + CLI `weglarka`
z assetów GitHub Release: wymagania hosta, `weglarka.toml`, start, CLI przez tunel SSH, pierwsza apka
(ntfy.zig), webhook GitHub, weryfikacja podpisu i rollback — [docs/install.md](docs/install.md).

## Licencja

`MIT OR Apache-2.0` — [LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE).
