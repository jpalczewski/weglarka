//! Definicja komend (szkielet). Kody wyjścia i `--json` — do zaprojektowania w sesji d.

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "weglarka",
    version,
    about = "Węglarka — deploy-tool dla rootless Podmana"
)]
pub struct Cli {
    /// Wypisz wynik jako JSON.
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Zarządzanie apkami (add/remove/list/show).
    #[command(subcommand)]
    Apps(AppsCommand),
    /// Wymuś deploy apki.
    Deploy { app: String },
    /// Stan demona i apek.
    Status,
    /// Sekrety apek (set/list).
    #[command(subcommand)]
    Secrets(SecretsCommand),
    /// Autodiagnoza; `--preflight` działa lokalnie, bez demona.
    Doctor {
        #[arg(long)]
        preflight: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum AppsCommand {
    Add { name: String, image: String },
    Remove { name: String },
    List,
    Show { name: String },
}

#[derive(Debug, Subcommand)]
pub enum SecretsCommand {
    Set { app: String, name: String },
    List { app: String },
}
