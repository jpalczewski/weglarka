//! Serving, with graceful shutdown on SIGTERM and SIGINT.

use std::io;

use axum::Router;
use tokio::net::TcpListener;
use tokio::signal::unix::{Signal, SignalKind, signal};

/// SIGTERM and SIGINT handlers. Installing them is separate from waiting, so a failure to install
/// stops startup instead of looking like a shutdown request.
pub struct Shutdown {
    term: Signal,
    int: Signal,
}

impl Shutdown {
    pub fn install() -> io::Result<Self> {
        Ok(Self {
            term: signal(SignalKind::terminate())?,
            int: signal(SignalKind::interrupt())?,
        })
    }

    /// Resolves on the first SIGTERM or SIGINT.
    pub async fn wait(mut self) {
        tokio::select! {
            _ = self.term.recv() => tracing::info!("SIGTERM received, shutting down"),
            _ = self.int.recv() => tracing::info!("SIGINT received, shutting down"),
        }
    }
}

/// Serves `app` until `stop` resolves; in-flight requests finish first.
pub async fn serve(
    listener: TcpListener,
    app: Router,
    stop: impl Future<Output = ()> + Send + 'static,
) -> io::Result<()> {
    // The peer address feeds the callback limit.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(stop)
    .await
}
