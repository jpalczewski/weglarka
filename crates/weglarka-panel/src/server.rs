//! Serving, with graceful shutdown on SIGTERM and SIGINT.

use std::io;

use axum::Router;
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};

/// Resolves on the first SIGTERM or SIGINT.
pub async fn shutdown_signal() -> io::Result<()> {
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    tokio::select! {
        _ = term.recv() => tracing::info!("SIGTERM received, shutting down"),
        _ = int.recv() => tracing::info!("SIGINT received, shutting down"),
    }
    Ok(())
}

/// Serves `app` until `stop` resolves; in-flight requests finish first.
pub async fn serve(
    listener: TcpListener,
    app: Router,
    stop: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    axum::serve(listener, app)
        .with_graceful_shutdown(stop)
        .await
}
