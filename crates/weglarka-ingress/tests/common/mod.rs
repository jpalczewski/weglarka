#![allow(dead_code)]
use std::collections::BTreeMap;

use weglarka_core::app::{AppSpec, AppsFile, InstanceName};
use weglarka_core::config::HostConfig;

pub const HOST: &str = r#"
[ingress]
mode = "behind"
bind = "172.17.0.1:8080"
traefik_dynamic_file = "/data/coolify/proxy/dynamic/weglarka.yml"

[admin]
socket = "/run/user/1001/weglarka/admin.sock"

[webhook]
listen = "0.0.0.0:9180"
domain = "weglarka.example.eu"
"#;

pub fn host() -> HostConfig {
    HostConfig::from_toml_str(HOST).unwrap()
}

pub fn apps(toml_src: &str) -> BTreeMap<InstanceName, AppSpec> {
    toml::from_str::<AppsFile>(toml_src).unwrap().apps
}

pub fn app_with(domains: &[&str], port: Option<u16>) -> BTreeMap<InstanceName, AppSpec> {
    let mut spec = AppSpec {
        image: "ghcr.io/x/y:latest".into(),
        domains: domains.iter().map(|d| (*d).to_owned()).collect(),
        port,
        env: Default::default(),
        secrets: vec![],
        health: Default::default(),
        volumes: vec![],
        shared_volumes: vec![],
        host_ports: vec![],
        depends_on: vec![],
        resources: Default::default(),
        security: Default::default(),
        auto_update: true,
        start: true,
    };
    spec.domains.shrink_to_fit();
    BTreeMap::from([(InstanceName::new("app").unwrap(), spec)])
}

pub const ONE_APP: &str = r#"
[apps.ntfy]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
domains = ["nz.example.eu"]
port = 8085
"#;

pub const MANY_APPS: &str = r#"
[apps.ntfy]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
domains = ["nz.example.eu"]
port = 8085

[apps.blog]
image = "ghcr.io/x/blog:latest"
domains = ["blog.example.eu", "www.blog.example.eu", "example.eu"]
port = 3000

[apps.worker]
image = "ghcr.io/x/worker:latest"
"#;
