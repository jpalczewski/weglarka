//! `cargo run -p weglarka-identity --example render -- <dir>` writes `oidc-clients.yml`,
//! `oidc-clients-gated.yml` and `access-control.yml` for the sample inputs of the tests; CI feeds them to `authelia config validate`.

#[path = "../tests/fixtures.rs"]
mod fixtures;

use std::{env, fs, path::PathBuf};

use weglarka_identity::{render_access_control, render_oidc_clients};

fn main() {
    let dir = PathBuf::from(env::args().nth(1).expect("usage: render <dir>"));
    fs::create_dir_all(&dir).unwrap();
    let clients = fixtures::clients();
    let apps = fixtures::forward_apps();
    let forward: Vec<_> = apps.iter().map(fixtures::Forward::forward).collect();
    fs::write(
        dir.join("oidc-clients.yml"),
        render_oidc_clients(&clients.app_clients(), &clients.external).unwrap(),
    )
    .unwrap();
    // The group-gated clients get their own file: CI validates it next to the base config on its own.
    let gated = fixtures::gated_clients();
    fs::write(
        dir.join("oidc-clients-gated.yml"),
        render_oidc_clients(&gated.app_clients(), &gated.external).unwrap(),
    )
    .unwrap();
    // A public client with a loopback redirect (`weglarka login --browser`, ADR 0068), validated on its own.
    let mut loopback = std::collections::BTreeMap::new();
    loopback.insert(
        weglarka_model::identity::ClientId::new("cli").unwrap(),
        fixtures::external(
            r#"
            name = "weglarka CLI"
            redirect_uris = ["http://127.0.0.1/callback"]
            public = true
            device_flow = true
            scopes = ["openid", "profile", "groups", "offline_access"]
            "#,
        ),
    );
    fs::write(
        dir.join("oidc-clients-loopback.yml"),
        render_oidc_clients(&[], &loopback).unwrap(),
    )
    .unwrap();
    fs::write(
        dir.join("access-control.yml"),
        render_access_control(fixtures::ISSUER, &forward).unwrap(),
    )
    .unwrap();
}
