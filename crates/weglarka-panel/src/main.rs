//! `weglarka-panel`: the admin panel server.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::net::TcpListener;
use tracing::level_filters::LevelFilter;
use weglarka_panel::config::{ENV_LISTEN, ENV_SOCKET};
use weglarka_panel::server::{serve, shutdown_signal};
use weglarka_panel::{AppState, PanelConfig, router};

#[derive(Parser)]
#[command(name = "weglarka-panel", version, about = "The Węglarka admin panel")]
struct Cli {
    /// The daemon's token socket (default `/run/weglarka-admin/api.sock`).
    #[arg(long, env = ENV_SOCKET)]
    socket: Option<PathBuf>,
    /// Address to listen on (default `0.0.0.0:8080`).
    #[arg(long, env = ENV_LISTEN)]
    listen: Option<SocketAddr>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_max_level(LevelFilter::INFO)
        .init();

    let cli = Cli::parse();
    // Flags (and their env fallbacks, read by clap) win over the environment lookup below.
    let config = PanelConfig::from_lookup(|var| match var {
        ENV_SOCKET => cli.socket.as_ref().map(|p| p.display().to_string()),
        ENV_LISTEN => cli.listen.map(|a| a.to_string()),
        _ => std::env::var(var).ok(),
    })
    .context("invalid configuration")?;

    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("cannot listen on {}", config.listen))?;
    tracing::info!(listen = %config.listen, socket = %config.socket.display(), "panel started");

    let app = router(AppState::new(config));
    serve(listener, app, async {
        if let Err(e) = shutdown_signal().await {
            tracing::error!(error = %e, "cannot install signal handlers");
        }
    })
    .await
    .context("server failed")?;
    tracing::info!("panel stopped");
    Ok(())
}
