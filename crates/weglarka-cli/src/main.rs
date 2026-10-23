//! CLI `weglarka`. **Własność: sesja d.** Cienki klient admin API; `doctor --preflight` lokalnie.

mod cli;

use anyhow::Result;
use clap::Parser;

fn main() -> Result<()> {
    let cli = cli::Cli::parse();
    anyhow::bail!("`weglarka {:?}` is not implemented yet", cli.command)
}
