//! The daemon's integration tests as one test binary: each module was a `tests/*.rs` file of its
//! own, which compiled and linked the whole daemon once per file.

mod common;

mod configs;
mod daemon;
mod depends_on;
mod forgejo;
mod forward;
mod host_ports;
mod images;
mod ingress;
mod notify;
mod push;
mod run;
mod secrets;
mod self_update;
mod shared_networks;
mod shared_volumes;
mod sites;
mod update;
mod volumes;
