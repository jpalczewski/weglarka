//! Test fakes (feature `testing`).

mod fake_podman;
#[cfg(test)]
mod harness;

pub use fake_podman::{
    Call, DEAD_CONMON_MESSAGE, DEFAULT_IMAGE_SIZE_BYTES, DEFAULT_SUBUID_POOL, FAKE_STARTED_AT,
    FakePodman, LogScript, RunScript, StopFailure,
};
#[cfg(test)]
pub(crate) use harness::Harness;

use weglarka_model::app::{Digest, InstanceName};

/// A valid digest made of one repeated hex character: `digest('a')` = `sha256:aaaa…`.
pub fn digest(c: char) -> Digest {
    Digest::new(format!("sha256:{}", c.to_string().repeat(64))).unwrap()
}

/// An instance name from a literal known to be valid.
pub fn name(s: &str) -> InstanceName {
    InstanceName::new(s).unwrap()
}

#[cfg(test)]
mod fake_podman_tests;
