//! `weglarka-panel`: the admin panel server.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::net::TcpListener;
use tracing::level_filters::LevelFilter;
use weglarka_panel::config::{ENV_LISTEN, ENV_SOCKET};
use weglarka_panel::server::{Shutdown, serve};
use weglarka_panel::{AppState, PanelConfig, router};

#[derive(Parser)]
#[command(name = "weglarka-panel", version, about = "The Węglarka admin panel")]
struct Cli {
    /// The daemon's token socket (default `/run/weglarka-admin/api.sock`).
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Address to listen on (default `0.0.0.0:8080`).
    #[arg(long)]
    listen: Option<SocketAddr>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_max_level(LevelFilter::INFO)
        .init();

    let cli = Cli::parse();
    // A flag wins over the variable of the same setting; blank variables count as unset in `from_lookup`.
    let config = PanelConfig::from_lookup(|var| {
        let flag = match var {
            ENV_SOCKET => cli.socket.as_ref().map(|p| p.display().to_string()),
            ENV_LISTEN => cli.listen.map(|a| a.to_string()),
            _ => None,
        };
        flag.or_else(|| std::env::var(var).ok())
    })
    .context("invalid configuration")?;

    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("cannot listen on {}", config.listen))?;
    tracing::info!(listen = %config.listen, socket = %config.socket.display(), "panel started");

    let shutdown = Shutdown::install().context("cannot install signal handlers")?;
    let state = AppState::new(config).context("cannot build the HTTP client")?;
    state.sessions.spawn_sweeper();
    let app = router(state);
    serve(listener, app, shutdown.wait())
        .await
        .context("server failed")?;
    tracing::info!("panel stopped");
    Ok(())
}
