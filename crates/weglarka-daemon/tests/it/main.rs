//! The daemon's integration tests, deliberately one test binary. The engine and the admin router are
//! generic over `PodmanClient`, so every test binary re-generates and re-links `Daemon<FakePodman>`
//! and the HTTP stack: add new tests as a module here, never as a new `tests/*.rs` file.
//! Run one area with `cargo test -p weglarka-daemon --test it -- <module>::`.

mod common;

mod configs;
mod daemon;
mod depends_on;
mod events;
mod forgejo;
mod forward;
mod generated;
mod host_ports;
mod identity;
mod images;
mod ingress;
mod logs;
mod notify;
mod oidc_credentials;
mod push;
mod run;
mod secrets;
mod self_update;
mod shared_networks;
mod shared_volumes;
mod sites;
mod token_api;
mod update;
mod volumes;
