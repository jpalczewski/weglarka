//! `POST /v1/apps/{name}/forward` (issue #108, ADR 0041): a temporary relay to a port of an app.
//!
//! Like a run, everything that can be refused is refused with an ordinary JSON error *before* the
//! stream starts; afterwards the first frame names the host port and the stream stays open for as
//! long as the client wants the forward. Closing the connection removes the relay container.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use tokio::sync::mpsc;
use weglarka_api::{FORWARD_STREAM_CONTENT_TYPE, ForwardFrame, ForwardRequest};
use weglarka_core::forward::{ForwardOptions, ForwardOutcome};
use weglarka_core::podman::PodmanClient;

use crate::admin::{Fail, mutating, parse_json, parse_name};
use crate::app::Daemon;
use crate::ingress::nginx_security;

/// How often an idle forward stream carries a frame, so that a dead connection is noticed.
const KEEPALIVE: Duration = Duration::from_secs(15);

pub(crate) async fn forward_app<P: PodmanClient + 'static>(
    State(d): State<Arc<Daemon<P>>>,
    Path(raw): Path<String>,
    body: Bytes,
) -> Result<Response, Fail> {
    let name = parse_name(&raw)?;
    let req: ForwardRequest = parse_json(&body)?;
    let options = ForwardOptions {
        port: req.port,
        timeout: req.timeout_secs.map(|s| Duration::from_secs(s.into())),
        image: d.host.ingress.nginx_image.clone(),
        security: nginx_security(),
    };
    let pending = mutating(d.engine.prepare_forward(&name, &options)).await?;

    let (frames_tx, frames_rx) = mpsc::channel::<Bytes>(4);
    // The forward lives in its own task, so it ends the same way whether the client reads on or hangs
    // up: a dropped response body closes `frames_tx`, `closed` resolves and the relay is removed.
    tokio::spawn(async move {
        let ready = ForwardFrame::Ready {
            host_port: pending.host_port(),
        };
        if frames_tx.send(Bytes::from(ready.encode())).await.is_err() {
            pending.discard().await;
            return;
        }
        let closed = {
            let frames_tx = frames_tx.clone();
            async move {
                // The first tick is one period away: `Ready` has just gone out.
                let mut tick =
                    tokio::time::interval_at(tokio::time::Instant::now() + KEEPALIVE, KEEPALIVE);
                loop {
                    tokio::select! {
                        () = frames_tx.closed() => break,
                        _ = tick.tick() => {
                            let frame = Bytes::from(ForwardFrame::Keepalive.encode());
                            if frames_tx.send(frame).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        };
        let last = match pending.hold(closed).await {
            ForwardOutcome::Closed => None,
            ForwardOutcome::TimedOut => Some(ForwardFrame::TimedOut),
            ForwardOutcome::RelayExited(code) => Some(ForwardFrame::Error(format!(
                "the relay container exited with code {code}"
            ))),
        };
        if let Some(frame) = last {
            let _ = frames_tx.send(Bytes::from(frame.encode())).await;
        }
    });

    let stream = futures_util::stream::unfold(frames_rx, |mut rx| async move {
        rx.recv()
            .await
            .map(|frame| (Ok::<_, std::convert::Infallible>(frame), rx))
    });
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            FORWARD_STREAM_CONTENT_TYPE,
        )],
        axum::body::Body::from_stream(stream),
    )
        .into_response())
}
