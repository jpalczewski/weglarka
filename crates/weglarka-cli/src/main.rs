//! The `weglarka` CLI. A thin admin API client; `doctor --preflight` runs locally, no daemon needed.

mod cli;
mod client;
mod commands;
mod error;
mod networks;
mod output;
mod preflight;
mod run;
mod settings;
mod spec_flags;
mod update;
mod volumes;

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
    // Single thread: the CLI doesn't need a pool (RAM).
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
