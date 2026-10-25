//! `cargo run -p weglarka-ingress --example dump -- nginx [RESOLVER] [TRUSTED,...]|nginx-edge [CERT_DOMAIN,...] [WILDCARD_APEX,...]|traefik`
//! — prints a sample config (used in CI for `nginx -t`, the forwarded-header, streaming, body-size and
//! edge tests). `nginx-edge` (issue #95) renders the `edge` sample: the domains passed as a comma
//! list have a certificate under `/etc/nginx/tls`, the rest exercise the plain-HTTP-only branch; an
//! optional second list names apexes with a wildcard pair `_wildcard.<apex>.crt|key` (issue #97).
//!
//! `sse` is the only app with `ingress.streaming = true` (issue #64); `blog` deliberately keeps the
//! buffered defaults, so `.github/scripts/test-streaming.sh` can use it as the negative control.
//! `upload` (streamed, 256 MiB) and `capped` (not streamed, 8 MiB) carry `ingress.max_body_size`
//! (ADR 0033) for `.github/scripts/test-body-size.sh`; `blog` is again the default-limit control.

use std::collections::BTreeMap;

use weglarka_core::app::AppsFile;
use weglarka_core::config::HostConfig;
use weglarka_ingress::{Domain, nginx, traefik};

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

/// The `edge` sample (issue #95): two publishes, no Traefik and no trusted peer.
const EDGE_HOST: &str = r#"
[ingress]
mode = "edge"
bind = "0.0.0.0:8080"
https_bind = "0.0.0.0:8443"

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

[apps.sse]
image = "ghcr.io/x/sse:latest"
domains = ["sse.example.eu"]
port = 3000

[apps.sse.ingress]
streaming = true

[apps.upload]
image = "ghcr.io/x/upload:latest"
domains = ["upload.example.eu"]
port = 3000

[apps.upload.ingress]
streaming = true
max_body_size = "256m"

[apps.capped]
image = "ghcr.io/x/capped:latest"
domains = ["capped.example.eu"]
port = 3000

[apps.capped.ingress]
max_body_size = "8m"
"#;

fn main() {
    let host = HostConfig::from_toml_str(HOST).expect("host");
    let apps: BTreeMap<_, _> = toml::from_str::<AppsFile>(APPS).expect("apps").apps;
    let out = match std::env::args().nth(1).as_deref() {
        Some("nginx") => {
            let resolver = std::env::args()
                .nth(2)
                .unwrap_or_else(|| "10.89.0.1".into());
            let trusted: Vec<String> = std::env::args()
                .nth(3)
                .unwrap_or_else(|| "10.89.0.0/24".into())
                .split(',')
                .map(str::to_owned)
                .collect();
            let options = nginx::NginxOptions::new(vec![resolver.parse().expect("resolver")])
                .with_trusted_proxies(&trusted)
                .expect("trusted proxies");
            nginx::generate(&host, &apps, &options)
        }
        Some("nginx-edge") => {
            let host = HostConfig::from_toml_str(EDGE_HOST).expect("edge host");
            let certificates: Vec<Domain> = std::env::args()
                .nth(2)
                .unwrap_or_else(|| "weglarka.example.eu".to_owned())
                .split(',')
                .filter(|d| !d.is_empty())
                .map(|d| Domain::new(d).expect("cert domain"))
                .collect();
            let mut options =
                nginx::NginxOptions::new(vec!["10.89.0.1".parse().expect("resolver")]);
            options.certificates = certificates;
            // Optional third argument: apexes with a wildcard pair (`_wildcard.<apex>.crt|key`).
            options.wildcard_certificates = std::env::args()
                .nth(3)
                .unwrap_or_default()
                .split(',')
                .filter(|d| !d.is_empty())
                .map(|d| Domain::new(d).expect("wildcard apex"))
                .collect();
            options.tls_fingerprint = Some("1a2b3c4d".to_owned());
            // Optional: also listen on the port forwarder's unix sockets (issue #162).
            options.proxy_socket_dir = std::env::var("WEGLARKA_DUMP_PROXY_SOCKET_DIR").ok();
            nginx::generate(&host, &apps, &options)
        }
        Some("traefik") => traefik::generate(&host, &apps, &traefik::TraefikOptions::default()),
        _ => {
            eprintln!("usage: dump nginx|nginx-edge|traefik");
            std::process::exit(2);
        }
    };
    print!("{}", out.expect("generate"));
}
