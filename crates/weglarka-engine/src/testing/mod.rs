//! Test fakes (feature `testing`).

mod fake_podman;

pub use fake_podman::{
    Call, DEAD_CONMON_MESSAGE, DEFAULT_IMAGE_SIZE_BYTES, DEFAULT_SUBUID_POOL, FAKE_STARTED_AT,
    FakePodman, LogScript, RunScript, StopFailure,
};

#[cfg(test)]
mod fake_podman_tests;
