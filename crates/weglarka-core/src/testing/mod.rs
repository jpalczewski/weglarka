//! Test fakes (feature `testing`).

mod fake_podman;

pub use fake_podman::{Call, DEFAULT_IMAGE_SIZE_BYTES, DEFAULT_SUBUID_POOL, FakePodman, RunScript};
