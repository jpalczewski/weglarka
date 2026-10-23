//! Command definitions. The help text (the `///` docs below) is user-visible and stays in Polish.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::error::exit;

#[derive(Debug, Parser)]
#[command(
    name = "weglarka",
    version,
    about = "Węglarka — deploy-tool dla rootless Podmana (klient admin API demona)",
    after_long_help = exit::TABLE
)]
pub struct Cli {
    /// Wypisz wynik jako JSON (typy z weglarka-api); błędy jako {"error":{...}}.
    #[arg(long, global = true)]
    pub json: bool,

    /// Plik konfiguracji hosta.
    #[arg(long, global = true, env = "WEGLARKA_CONFIG", value_name = "PLIK")]
    pub config: Option<PathBuf>,

    /// Socket unix admin API (domyślnie `admin.socket` z weglarka.toml).
    #[arg(long, global = true, env = "WEGLARKA_SOCKET", value_name = "SOCKET")]
    pub socket: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Zarządzanie apkami (add/remove/list/show).
    #[command(subcommand)]
    Apps(AppsCommand),
    /// Wymuś deploy apki (pull, podmiana kontenera, bramka zdrowia, ewentualny rollback).
    Deploy(DeployArgs),
    /// Stan demona i apek.
    Status,
    /// Sekrety apek (set/list). Wartości nigdy nie wracają przez API.
    #[command(subcommand)]
    Secrets(SecretsCommand),
    /// Autodiagnoza; `--preflight` działa lokalnie, bez demona.
    Doctor(DoctorArgs),
}

#[derive(Debug, Subcommand)]
pub enum AppsCommand {
    /// Dodaj instancję apki.
    Add(AddArgs),
    /// Usuń instancję apki.
    Remove(RemoveArgs),
    /// Lista apek.
    List,
    /// Szczegóły apki: spec, stan, runtime.
    Show { name: String },
}

#[derive(Debug, Args)]
pub struct AddArgs {
    /// Nazwa instancji ([a-z0-9-], 1–63 znaki).
    pub name: String,
    /// Referencja obrazu, np. ghcr.io/jpalczewski/ntfy.zig:latest.
    #[arg(required_unless_present = "spec")]
    pub image: Option<String>,
    /// Domena kierowana do apki (można powtarzać).
    #[arg(long = "domain", conflicts_with = "spec")]
    pub domains: Vec<String>,
    /// Port HTTP w kontenerze.
    #[arg(long, conflicts_with = "spec")]
    pub port: Option<u16>,
    /// Zmienna środowiskowa KLUCZ=WARTOŚĆ (jawna, nie tajna; można powtarzać).
    #[arg(long = "env", value_name = "K=V", value_parser = parse_pair, conflicts_with = "spec")]
    pub env: Vec<(String, String)>,
    /// Sekret jako zmienna środowiskowa: SEKRET=ZMIENNA.
    #[arg(long = "secret-env", value_name = "SEKRET=ZMIENNA", value_parser = parse_pair, conflicts_with = "spec")]
    pub secret_env: Vec<(String, String)>,
    /// Sekret jako plik w kontenerze: SEKRET=ŚCIEŻKA.
    #[arg(long = "secret-mount", value_name = "SEKRET=ŚCIEŻKA", value_parser = parse_pair, conflicts_with = "spec")]
    pub secret_mount: Vec<(String, String)>,
    /// Wyłącz auto-update (webhook nie podmieni obrazu samoczynnie).
    #[arg(long, conflicts_with = "spec")]
    pub no_auto_update: bool,
    /// Cały AppSpec z pliku TOML (zamiast powyższych flag); `-` = stdin.
    #[arg(long, value_name = "PLIK")]
    pub spec: Option<PathBuf>,
    /// Nic nie wysyłaj; pokaż żądanie, które zostałoby wysłane.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct RemoveArgs {
    pub name: String,
    /// Brak apki nie jest błędem (idempotentne usuwanie).
    #[arg(long)]
    pub ignore_missing: bool,
    /// Nic nie usuwaj; sprawdź, że apka istnieje, i pokaż żądanie.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct DeployArgs {
    pub app: String,
    /// Jednorazowo nadpisz referencję obrazu (np. przypięty tag sha-…).
    #[arg(long, value_name = "REF")]
    pub image: Option<String>,
    /// Nic nie wdrażaj; sprawdź, że apka istnieje, i pokaż żądanie.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Subcommand)]
pub enum SecretsCommand {
    /// Ustaw (nadpisz) sekret. Wartość ze stdin albo z pliku — nigdy z argumentu.
    Set(SecretSetArgs),
    /// Lista sekretów apki (nazwa, odcisk, data) — bez wartości.
    List { app: String },
}

#[derive(Debug, Args)]
pub struct SecretSetArgs {
    pub app: String,
    /// Nazwa sekretu ([A-Za-z0-9_-], 1–64 znaki).
    pub name: String,
    /// Czytaj wartość z pliku zamiast ze stdin.
    #[arg(long, value_name = "PLIK")]
    pub from_file: Option<PathBuf>,
    /// Zachowaj wartość bajt w bajt (domyślnie usuwany jest jeden końcowy znak nowej linii).
    #[arg(long)]
    pub raw: bool,
    /// Nic nie wysyłaj; zwaliduj wejście i pokaż żądanie (wartość jest zasłonięta).
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Sprawdź host lokalnie, bez demona (user, subuid, cgroups, linger, Podman, ingress…).
    #[arg(long)]
    pub preflight: bool,
    /// Ścieżka secrets.toml do sprawdzenia praw (brak w weglarka.toml;
    /// domyślnie obok pliku konfiguracji).
    #[arg(
        long,
        value_name = "PLIK",
        env = "WEGLARKA_SECRETS_FILE",
        requires = "preflight"
    )]
    pub secrets_file: Option<PathBuf>,
}

fn parse_pair(s: &str) -> Result<(String, String), String> {
    match s.split_once('=') {
        Some((k, v)) if !k.is_empty() => Ok((k.to_owned(), v.to_owned())),
        _ => Err(format!("expected KEY=VALUE, got {s:?}")),
    }
}
