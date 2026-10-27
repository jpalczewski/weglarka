//! Węglarka engine: the reconcile loop, deploy flow, volumes and everything else that acts on the
//! host through [`weglarka_model::podman::PodmanClient`]. The domain model it works on lives in
//! `weglarka-model`; model-only consumers must not depend on this crate.

pub mod config_mounts;
pub mod crash;
pub mod depends;
pub mod deploy;
pub mod forward;
pub mod host_mounts;
pub mod images;
pub mod platform;
pub mod promote;
pub mod push;
pub mod reconcile;
pub mod run;
pub mod secrets;
pub mod shared_networks;
mod site_deploy;
pub mod sites;
pub mod volumes;
pub mod waiting;

#[cfg(feature = "testing")]
pub mod testing;

#[cfg(all(test, feature = "testing"))]
mod engine_tests;
