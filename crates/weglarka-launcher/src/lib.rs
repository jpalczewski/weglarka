//! The Węglarka host launcher library.
//!
//! The binary is a small static-musl executable with host protocol v1. This library holds the
//! host-only state it shares with the daemon adapters: the `host-tools.toml` selector, generation
//! directories, `platform-service.toml`, `runtime-jobs.toml`, the persisted attempt budgets and the
//! fixed-argv executor. It is deliberately independent of `apps.toml` and of the engine.
//!
//! See `docs/contracts/platform-update-v1/README.md` ("Host launcher and generation handoff" and
//! "OpenRC without privileged runtime operations") and ADR 0067.

pub mod bootstrap;
pub mod budget;
pub mod generation;
pub mod host;
pub mod lock;
pub mod run;
pub mod selection;
pub mod selector;
pub mod service;

pub use host::{
    DEFAULT_HOST_DIR, HOST_CLI_FILE, HOST_DAEMON_FILE, HOST_PROTOCOL_VERSION, HOST_TOOLS_FILE,
};
pub use selection::{Job, PlatformService, RuntimeJobs};
pub use selector::HostSelector;
