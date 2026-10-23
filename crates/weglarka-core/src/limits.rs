//! Spec → container mapping of the configured healthcheck, and the health-probe seam.
//! **Owner: session 2 (iteration 2).**
//!
//! Resource limits need no mapping code here: [`crate::app::Resources`] already holds parsed,
//! validated values (`MemoryLimit`, `CpuLimit`, `pids_limit > 0`) and travels as-is in
//! [`crate::podman::ContainerSpec::resources`]; the libpod wire form lives in
//! `weglarka-podman/src/wire.rs`. The hash rules are in `hash.rs` (limits and `health.command`
//! recreate the container; `health.http` does not).

use std::future::Future;
use std::pin::Pin;

use crate::app::{HealthGate, HttpProbe};
use crate::podman::ContainerHealthcheck;

/// Defaults for the container's own periodic healthcheck. The deploy gate calls `healthcheck run`
/// itself, so these only matter for the running container (`podman healthcheck`, restart policies).
const DEFAULT_INTERVAL_SECS: u32 = 30;
const DEFAULT_TIMEOUT_SECS: u32 = 5;
const DEFAULT_RETRIES: u32 = 3;

/// Healthcheck for the container from the spec's `health.command`; `None` keeps the image's own.
pub fn container_healthcheck(gate: &HealthGate) -> Option<ContainerHealthcheck> {
    gate.command.as_ref().map(|command| ContainerHealthcheck {
        command: command.clone(),
        interval_secs: DEFAULT_INTERVAL_SECS,
        timeout_secs: DEFAULT_TIMEOUT_SECS,
        retries: DEFAULT_RETRIES,
    })
}

/// Future returned by [`HttpProber::probe`]. A boxed future (one small allocation per probe) because
/// the engine holds the prober as `dyn` — a deliberate, narrow exception to ADR 0001
/// (see docs/decisions/0010-health-http-probe.md).
pub type ProbeFuture<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

/// Performs a `health.http` probe for one app. Implemented by the daemon (requests go through the
/// ingress nginx); the engine only sees the verdict. `Err` carries a human-readable reason.
pub trait HttpProber: Send + Sync {
    /// `host` is the `Host` header (the app's first domain).
    fn probe<'a>(&'a self, host: &'a str, probe: &'a HttpProbe) -> ProbeFuture<'a>;
}

/// Verdict of one gate attempt: every configured probe must pass in the same attempt.
/// `None` — no probe was configured (the caller falls back to "running" semantics).
pub fn attempt_verdict(results: Vec<Result<(), String>>) -> Option<Result<(), String>> {
    if results.is_empty() {
        return None;
    }
    Some(results.into_iter().collect::<Result<(), String>>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthcheck_only_when_command_is_set() {
        assert_eq!(container_healthcheck(&HealthGate::default()), None);
        let gate = HealthGate {
            command: Some(vec!["/app".into(), "-health".into()]),
            ..Default::default()
        };
        let hc = container_healthcheck(&gate).unwrap();
        assert_eq!(hc.command, ["/app", "-health"]);
        assert_eq!((hc.interval_secs, hc.timeout_secs, hc.retries), (30, 5, 3));
    }

    #[test]
    fn verdict_needs_every_probe() {
        assert_eq!(attempt_verdict(vec![]), None);
        assert_eq!(attempt_verdict(vec![Ok(()), Ok(())]), Some(Ok(())));
        assert_eq!(
            attempt_verdict(vec![Ok(()), Err("http 503".into()), Err("later".into())]),
            Some(Err("http 503".into()))
        );
    }
}
