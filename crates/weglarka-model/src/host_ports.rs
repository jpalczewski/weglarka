//! Cross-app validation of the ports published directly on the host (`host_ports`, issue #34).
//!
//! `state::validate_app` covers the rules an app can break on its own (zero ports, an IP that is not
//! an IP, two entries of one app on the same socket). The rules that need the host — privileged
//! ports, two apps on the same socket, a collision with the ingress publishes — live here and are
//! checked wherever the daemon writes or loads `apps.toml` (`docs/decisions/0013-host-ports.md`). In
//! `edge` mode the ingress publishes two sockets, so both are reserved (issue #95).

use std::net::{IpAddr, SocketAddr};

use crate::app::AppsFile;
use crate::config::HostConfig;

/// A `host_ports` configuration that cannot work on this host.
#[derive(Debug, thiserror::Error)]
pub enum HostPortError {
    #[error(
        "{app}: host port {port} is below 1024; rootless Podman cannot publish it without \
         `net.ipv4.ip_unprivileged_port_start=0` and `[runtime] allow_privileged_host_ports = true`"
    )]
    Privileged { app: String, port: u16 },
    #[error("{app}: host port {port} on {ip} is already published by {other}")]
    Conflict {
        app: String,
        other: String,
        port: u16,
        ip: String,
    },
    #[error("{app}: host port {port} on {ip} collides with the ingress bind {ingress}")]
    Ingress {
        app: String,
        port: u16,
        ip: String,
        ingress: SocketAddr,
    },
    #[error("{app}: host_ports bind address {ip:?} is not an IP literal")]
    InvalidIp { app: String, ip: String },
}

/// Whether two bind addresses can be held at the same time. Equal addresses and a wildcard
/// (`0.0.0.0`/`::`) overlap; two different specific addresses do not. Families are deliberately not
/// distinguished: a wildcard IPv4 bind blocks a specific IPv6 one on Linux, and treating any
/// wildcard as "everything" keeps the check conservative.
pub fn bind_overlaps(a: IpAddr, b: IpAddr) -> bool {
    a == b || a.is_unspecified() || b.is_unspecified()
}

/// Validates every app's `host_ports` against the host config and against each other.
///
/// `apps.toml` is a `BTreeMap`, so the report of the first conflict is deterministic.
pub fn validate(host: &HostConfig, apps: &AppsFile) -> Result<(), HostPortError> {
    let allow_privileged = host.runtime.allow_privileged_host_ports;
    // Both `edge` publishes (plain HTTP and TLS) and the single `behind` one; `https_bind` missing in
    // `edge` is `HostConfig::validate`'s error, not this module's.
    let ingress = host.ingress.publish_sockets();
    let mut published: Vec<(&str, u16, IpAddr)> = Vec::new();
    for (name, spec) in &apps.apps {
        let name = name.as_str();
        for entry in &spec.host_ports {
            let ip = entry
                .bind_ip()
                .parse::<IpAddr>()
                .map_err(|_| HostPortError::InvalidIp {
                    app: name.to_owned(),
                    ip: entry.bind_ip().to_owned(),
                })?;
            if entry.host < 1024 && !allow_privileged {
                return Err(HostPortError::Privileged {
                    app: name.to_owned(),
                    port: entry.host,
                });
            }
            if let Some(socket) = ingress
                .iter()
                .copied()
                .find(|socket| entry.host == socket.port() && bind_overlaps(ip, socket.ip()))
            {
                return Err(HostPortError::Ingress {
                    app: name.to_owned(),
                    port: entry.host,
                    ip: entry.bind_ip().to_owned(),
                    ingress: socket,
                });
            }
            if let Some((other, _, _)) = published
                .iter()
                .find(|(_, port, other_ip)| *port == entry.host && bind_overlaps(ip, *other_ip))
            {
                return Err(HostPortError::Conflict {
                    app: name.to_owned(),
                    other: (*other).to_owned(),
                    port: entry.host,
                    ip: entry.bind_ip().to_owned(),
                });
            }
            published.push((name, entry.host, ip));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn host() -> HostConfig {
        HostConfig::from_toml_str(HOST).unwrap()
    }

    fn apps(src: &str) -> AppsFile {
        toml::from_str(src).unwrap()
    }

    #[test]
    fn distinct_ports_anything_goes() {
        let parsed = apps(
            r#"
[apps.git]
image = "i"
host_ports = [{ host = 2222, container = 22 }]

[apps.other]
image = "j"
host_ports = [{ host = 2222, container = 22, ip = "10.0.0.5" }]
"#,
        );
        validate(&host(), &parsed).unwrap();
    }

    #[test]
    fn same_port_on_the_same_socket_is_a_conflict() {
        let parsed = apps(
            r#"
[apps.a]
image = "i"
host_ports = [{ host = 2222, container = 22 }]

[apps.b]
image = "j"
host_ports = [{ host = 2222, container = 22 }]
"#,
        );
        let err = validate(&host(), &parsed).unwrap_err();
        assert!(
            matches!(
                err,
                HostPortError::Conflict {
                    ref app,
                    ref other,
                    port: 2222,
                    ..
                } if app == "b" && other == "a"
            ),
            "{err}"
        );
    }

    #[test]
    fn a_wildcard_collides_with_a_specific_address() {
        let parsed = apps(
            r#"
[apps.a]
image = "i"
host_ports = [{ host = 2222, container = 22, ip = "0.0.0.0" }]

[apps.b]
image = "j"
host_ports = [{ host = 2222, container = 22, ip = "10.0.0.5" }]
"#,
        );
        assert!(matches!(
            validate(&host(), &parsed),
            Err(HostPortError::Conflict { .. })
        ));
    }

    #[test]
    fn privileged_ports_need_the_explicit_opt_in() {
        let parsed = apps(
            r#"
[apps.git]
image = "i"
host_ports = [{ host = 22, container = 22 }]
"#,
        );
        assert!(matches!(
            validate(&host(), &parsed),
            Err(HostPortError::Privileged { port: 22, .. })
        ));

        let mut allowed = host();
        allowed.runtime.allow_privileged_host_ports = true;
        validate(&allowed, &parsed).unwrap();
    }

    #[test]
    fn the_ingress_bind_is_reserved() {
        let parsed = apps(
            r#"
[apps.a]
image = "i"
host_ports = [{ host = 8080, container = 80, ip = "0.0.0.0" }]
"#,
        );
        assert!(matches!(
            validate(&host(), &parsed),
            Err(HostPortError::Ingress { port: 8080, .. })
        ));

        // A different, specific address on the same port is a different socket.
        let parsed = apps(
            r#"
[apps.a]
image = "i"
host_ports = [{ host = 8080, container = 80, ip = "10.0.0.5" }]
"#,
        );
        validate(&host(), &parsed).unwrap();
    }

    #[test]
    fn the_edge_tls_bind_is_reserved_too() {
        let edge = r#"
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
        let parsed = apps(
            r#"
[apps.a]
image = "i"
host_ports = [{ host = 8443, container = 443, ip = "0.0.0.0" }]
"#,
        );
        let err = validate(&HostConfig::from_toml_str(edge).unwrap(), &parsed).unwrap_err();
        assert!(
            matches!(
                err,
                HostPortError::Ingress {
                    port: 8443,
                    ref ingress,
                    ..
                } if ingress.port() == 8443
            ),
            "{err}"
        );
        // And the plain-HTTP one, exactly as in `behind`.
        let parsed = apps(
            r#"
[apps.a]
image = "i"
host_ports = [{ host = 8080, container = 80, ip = "0.0.0.0" }]
"#,
        );
        assert!(matches!(
            validate(&HostConfig::from_toml_str(edge).unwrap(), &parsed),
            Err(HostPortError::Ingress { port: 8080, .. })
        ));
    }

    #[test]
    fn a_bad_literal_is_reported() {
        let parsed = apps(
            r#"
[apps.a]
image = "i"
host_ports = [{ host = 2222, container = 22, ip = "not-an-ip" }]
"#,
        );
        assert!(matches!(
            validate(&host(), &parsed),
            Err(HostPortError::InvalidIp { .. })
        ));
    }
}
