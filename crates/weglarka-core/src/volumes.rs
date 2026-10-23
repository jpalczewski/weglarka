//! Volume logic of the deploy engine. **Owner: session 1 (iteration 2).**
//!
//! Contract already in place: [`crate::app::VolumeMount`] (spec), [`crate::labels::volume_name`],
//! [`crate::podman::PodmanClient`] `volume_*`, [`crate::podman::VolumeAttachment`] (container mount),
//! [`crate::state::AppState::uid_range`] and [`crate::uid_range::allocate`] (ownership strategy:
//! docs/decisions/0009-volume-ownership.md).
//!
//! To do (session 1): before `container_create` in `deploy.rs` call [`ensure_volumes`], map
//! `spec.volumes` to `ContainerSpec::volumes`, apply the ownership strategy from the ADR, and purge
//! volumes on `apps remove --purge-volumes`. `deploy.rs` gets a single call site — keep the logic here.

use crate::app::{AppSpec, InstanceName};
use crate::podman::{PodmanClient, Result, VolumeAttachment};

/// Creates the instance's declared volumes (idempotent, labelled `weglarka.instance`).
pub async fn ensure_volumes<P: PodmanClient>(
    _podman: &P,
    _instance: &InstanceName,
    _spec: &AppSpec,
) -> Result<()> {
    todo!("session 1: volume_create for every spec.volumes entry")
}

/// Container-side mounts for the instance's declared volumes.
pub fn attachments(_instance: &InstanceName, _spec: &AppSpec) -> Vec<VolumeAttachment> {
    todo!("session 1: VolumeMount → VolumeAttachment (+ ownership options from the ADR)")
}
