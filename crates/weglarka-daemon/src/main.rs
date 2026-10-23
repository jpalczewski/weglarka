//! Demon Węglarki. **Własność: sesja daemon (krok 3)**; do tego czasu tylko szkielet.

use anyhow::Result;
use tracing_subscriber::EnvFilter;

fn init_tracing() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    init_tracing();
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "weglarka-daemon: not implemented yet"
    );
    Ok(())
}
