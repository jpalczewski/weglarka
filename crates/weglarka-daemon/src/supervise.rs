//! `weglarka-daemon supervise` — the host-side watchdog of a self-update switch in flight
//! (issue #100, `docs/decisions/0034`).
//!
//! The switcher pins a new digest in the service definition and restarts the service; the daemon
//! inside the container cannot tell whether that image ever came up. This module runs from the user
//! timer `weglarka-watchdog.timer` (every minute, installed by `platform install`): it takes the
//! host-side state lock, asks the admin API for `GET /v1/health` over the unix socket, and hands the
//! observation to [`crate::self_update::watch`], which turns the pure decision of
//! `weglarka_model::self_update::supervise` into a pinned rollback — the previous digest restored in
//! the service definition and the service restarted.
//!
//! Everything that needs a decision is in `weglarka-model` (`self_update`; pure, injected clock); this module is the
//! thin host-side I/O around it: lock, probe and the two commands the fallback needs.

use std::path::Path;
use std::time::{Duration, SystemTime};

use weglarka_api::endpoints;
use weglarka_engine::platform::Platform;
use weglarka_model::podman::PodmanClient;

use crate::self_update::{self, WatchReport};
use crate::settings::Settings;

/// How long the probe waits for an answer before treating the daemon as "not healthy yet".
///
/// Short on purpose: the deadline, not the probe, is what decides the fallback, and the watchdog runs
/// once a minute.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// One watchdog run: skip when the feature is off or another run is active, probe, then supervise.
pub async fn run<P, Pl>(
    podman: &P,
    platform: &Pl,
    settings: &Settings,
    now: SystemTime,
) -> Result<WatchReport, self_update::Error>
where
    P: PodmanClient,
    Pl: Platform,
{
    let Some(config) = settings.host.self_update.as_ref() else {
        return Ok(WatchReport::Disabled);
    };
    if !config.enabled || !config.fallback {
        return Ok(WatchReport::Disabled);
    }
    // Held until the end of this function: a switch that lands mid-run must not interleave.
    let Some(_lock) = self_update::lock_state(&settings.paths.state_dir)? else {
        tracing::info!("another self-update run is active; skipping this watchdog wake-up");
        return Ok(WatchReport::Locked);
    };
    let healthy = probe_health(&settings.host.admin.socket, PROBE_TIMEOUT).await;
    tracing::debug!(
        healthy,
        socket = %settings.host.admin.socket.display(),
        "self-update watchdog probe"
    );
    self_update::watch(podman, platform, settings, healthy, now).await
}

/// Asks the admin API for `GET /v1/health` over its unix socket.
///
/// `true` only for a `200` answer within `timeout`: a refused connection, a stale socket file left by
/// a killed daemon, or a daemon that answers too late all mean "not healthy yet", which is exactly
/// what the fallback deadline is for. This is a readiness probe of the daemon's own API, never a
/// check of the apps.
pub async fn probe_health(socket: &Path, timeout: Duration) -> bool {
    match tokio::time::timeout(timeout, ask_health(socket)).await {
        Ok(healthy) => healthy,
        Err(_) => {
            tracing::debug!(socket = %socket.display(), "health probe timed out");
            false
        }
    }
}

async fn ask_health(socket: &Path) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let Ok(mut stream) = tokio::net::UnixStream::connect(socket).await else {
        return false;
    };
    // A minimal HTTP/1.1 request: the endpoint is our own and takes no body, so no client stack is
    // worth linking into the daemon binary for one line.
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        endpoints::HEALTH.path
    );
    if stream.write_all(request.as_bytes()).await.is_err() || stream.flush().await.is_err() {
        return false;
    }
    // Only the status line matters; the read is capped so a misbehaving server cannot make the
    // watchdog read forever.
    let mut buf = [0u8; 256];
    let mut filled = 0;
    while filled < buf.len() {
        match stream.read(&mut buf[filled..]).await {
            Ok(0) => break,
            Ok(n) => {
                filled += n;
                if buf[..filled].windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => return false,
        }
    }
    status_is_ok(&buf[..filled])
}

/// `HTTP/1.1 200 OK` → `true`; anything else (including a non-HTTP answer) → `false`.
fn status_is_ok(response: &[u8]) -> bool {
    String::from_utf8_lossy(response)
        .split_whitespace()
        .nth(1)
        .is_some_and(|code| code == "200")
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use crate::self_update::lock_state;

    async fn serve(dir: &Path, answer: &'static [u8]) -> std::path::PathBuf {
        use tokio::io::AsyncWriteExt;

        let socket = dir.join("admin.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let answer = answer.to_vec();
                tokio::spawn(async move {
                    let _ = stream.write_all(&answer).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        socket
    }

    #[tokio::test]
    async fn the_probe_accepts_a_200_answer_from_the_admin_socket() {
        let dir = tempfile::tempdir().unwrap();
        let socket = serve(
            dir.path(),
            b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{}",
        )
        .await;
        assert!(probe_health(&socket, Duration::from_secs(2)).await);
    }

    #[tokio::test]
    async fn the_probe_rejects_an_error_answer_a_stale_socket_and_a_silent_server() {
        let dir = tempfile::tempdir().unwrap();
        let socket = serve(
            dir.path(),
            b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n",
        )
        .await;
        assert!(!probe_health(&socket, Duration::from_secs(2)).await);

        // No listener at all: the file left by a killed daemon (connect refused).
        assert!(!probe_health(&dir.path().join("missing.sock"), Duration::from_secs(1)).await);

        // A server that never answers must not hang the watchdog.
        let silent = tokio::net::UnixListener::bind(dir.path().join("silent.sock")).unwrap();
        tokio::spawn(async move {
            let (stream, _) = silent.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(60)).await;
            drop(stream);
        });
        assert!(!probe_health(&dir.path().join("silent.sock"), Duration::from_millis(200)).await);
    }

    #[test]
    fn status_parsing_is_strict_about_the_code() {
        assert!(status_is_ok(b"HTTP/1.1 200 OK\r\n\r\n"));
        assert!(!status_is_ok(b"HTTP/1.1 204 No Content\r\n\r\n"));
        assert!(!status_is_ok(b"garbage"));
        assert!(!status_is_ok(b""));
    }

    #[tokio::test]
    async fn the_state_lock_keeps_two_host_side_runs_apart() {
        let dir = tempfile::tempdir().unwrap();
        let first = lock_state(dir.path()).unwrap();
        assert!(first.is_some(), "the first run takes the lock");
        assert!(
            lock_state(dir.path()).unwrap().is_none(),
            "a second run does not"
        );
        drop(first);
        assert!(
            lock_state(dir.path()).unwrap().is_some(),
            "the lock is released with the run"
        );
    }
}
