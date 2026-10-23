//! CLI `weglarka`. Cienki klient admin API; `doctor --preflight` działa lokalnie, bez demona.

mod cli;
mod client;
mod commands;
mod error;
mod output;
mod preflight;
mod settings;

#[cfg(test)]
mod tests;

use std::process::ExitCode;

use clap::Parser;

use crate::error::exit;

fn main() -> ExitCode {
    let cli = match cli::Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            let _ = e.print();
            return code(if e.use_stderr() {
                exit::USAGE
            } else {
                exit::OK
            });
        }
    };
    let json = cli.json;
    // Jeden wątek: CLI nie potrzebuje puli (RAM).
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    match rt.block_on(commands::run(cli)) {
        Ok(c) => code(c),
        Err(e) => {
            output::emit_error(json, &e);
            code(e.exit_code())
        }
    }
}

fn code(c: i32) -> ExitCode {
    ExitCode::from(u8::try_from(c).unwrap_or(70))
}
