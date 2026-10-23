//! Spec → container mapping of resource limits and the configured healthcheck.
//! **Owner: session 2 (iteration 2).**
//!
//! Contract already in place: [`crate::app::Resources`], [`crate::app::HealthGate`]
//! (`command`, `http`), [`crate::podman::ContainerSpec`] (`resources`, `healthcheck`) and the hash
//! rules in `hash.rs` (limits and `health.command` recreate the container; `health.http` does not).
//! The libpod wire mapping (`resource_limits`, `healthconfig` in `weglarka-podman/src/wire.rs`) is
//! also session 2's.

use crate::app::HealthGate;
use crate::podman::ContainerHealthcheck;

/// Healthcheck for the container from the spec's `health.command`; `None` keeps the image's own.
pub fn container_healthcheck(_gate: &HealthGate) -> Option<ContainerHealthcheck> {
    todo!("session 2: health.command → ContainerHealthcheck (interval/timeout/retries defaults)")
}
