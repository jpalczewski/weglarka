//! `cargo run -p weglarka-ingress --example dump -- nginx|traefik` — prints a sample config
//! (used in CI for `nginx -t`).

use std::collections::BTreeMap;

use weglarka_core::app::AppsFile;
use weglarka_core::config::HostConfig;
use weglarka_ingress::{nginx, traefik};

const HOST: &str = r#"
[ingress]
mode = "behind"
bind = "172.17.0.1:8080"

[admin]
socket = "/run/user/1001/weglarka/admin.sock"

[webhook]
listen = "0.0.0.0:9180"
domain = "weglarka.example.eu"
"#;

const APPS: &str = r#"
[apps.ntfy]
image = "ghcr.io/jpalczewski/ntfy.zig:latest"
domains = ["nz.example.eu"]
port = 8085

[apps.blog]
image = "ghcr.io/x/blog:latest"
domains = ["blog.example.eu", "www.blog.example.eu"]
port = 3000
"#;

fn main() {
    let host = HostConfig::from_toml_str(HOST).expect("host");
    let apps: BTreeMap<_, _> = toml::from_str::<AppsFile>(APPS).expect("apps").apps;
    let out = match std::env::args().nth(1).as_deref() {
        Some("nginx") => nginx::generate(
            &host,
            &apps,
            &nginx::NginxOptions::new(vec!["10.89.0.1".parse().unwrap()]),
        ),
        Some("traefik") => traefik::generate(&host, &apps, &traefik::TraefikOptions::default()),
        _ => {
            eprintln!("usage: dump nginx|traefik");
            std::process::exit(2);
        }
    };
    print!("{}", out.expect("generate"));
}
