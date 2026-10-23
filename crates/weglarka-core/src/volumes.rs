//! Volume logic of the deploy engine. **Owner: session 1 (iteration 2).**
//!
//! Contract already in place: [`crate::app::VolumeMount`] (spec), [`crate::labels::volume_name`],
//! [`crate::podman::PodmanClient`] `volume_*`, [`crate::podman::VolumeAttachment`] (container mount),
//! [`crate::state::AppState::uid_range`], [`crate::uid_range::allocate`] and
//! [`crate::podman::IdMapping`] (ownership: docs/decisions/0009-volume-ownership.md — a fixed uid range
//! per instance, explicit maps; plain `userns: auto` is a no-op rootless).
//!
//! To do (session 1): before `container_create` in `deploy.rs` call [`ensure_volumes`], map
//! `spec.volumes` to `ContainerSpec::volumes`, allocate/persist the instance's range on its first deploy
//! (pool size from `/etc/subuid`; the ingress nginx gets `StateFile::ingress_uid_range` the same way) and set `ContainerSpec::id_mapping`,
//! import foreign tars with `PodmanClient::container_archive_put` (not `volume_import`), and purge
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
