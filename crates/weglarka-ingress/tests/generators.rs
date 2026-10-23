mod common;

use std::collections::BTreeMap;
use std::net::IpAddr;

use common::*;
use weglarka_core::app::{AppSpec, InstanceName};
use weglarka_ingress::nginx::{self, NginxOptions};
use weglarka_ingress::traefik::{self, TraefikOptions};
use weglarka_ingress::{Cidr, IngressError};

fn opts() -> NginxOptions {
    NginxOptions::new(vec!["10.89.0.1".parse().unwrap()])
        .with_trusted_proxies(&["10.89.0.0/24".into()])
        .unwrap()
}

fn layouts() -> Vec<(&'static str, BTreeMap<InstanceName, AppSpec>)> {
    vec![
        ("no_apps", BTreeMap::new()),
        ("one_app", apps(ONE_APP)),
        ("many_apps_multi_domain", apps(MANY_APPS)),
    ]
}

#[test]
fn nginx_snapshots() {
    for (name, apps) in layouts() {
        let conf = nginx::generate(&host(), &apps, &opts()).unwrap();
        insta::assert_snapshot!(format!("nginx_{name}"), conf);
    }
}

#[test]
fn traefik_snapshots() {
    for (name, apps) in layouts() {
        let yml = traefik::generate(&host(), &apps, &TraefikOptions::default()).unwrap();
        insta::assert_snapshot!(format!("traefik_{name}"), yml);
    }
}

#[test]
fn output_is_deterministic() {
    let a = apps(MANY_APPS);
    assert_eq!(
        nginx::generate(&host(), &a, &opts()).unwrap(),
        nginx::generate(&host(), &a, &opts()).unwrap()
    );
}

#[test]
fn traefik_without_cert_resolver() {
    let o = TraefikOptions {
        cert_resolver: None,
        ..Default::default()
    };
    insta::assert_snapshot!(traefik::generate(&host(), &apps(ONE_APP), &o).unwrap());
}

#[test]
fn nginx_ipv6_resolver_and_extra_trust() {
    let mut o = opts();
    o.resolvers = vec!["fd00::1".parse::<IpAddr>().unwrap()];
    o.trusted_proxies
        .push("10.0.0.0/8".parse::<Cidr>().unwrap());
    let conf = nginx::generate(&host(), &apps(ONE_APP), &o).unwrap();
    assert!(conf.contains("resolver [fd00::1] valid=5s ipv6=off;"));
    assert!(conf.contains("set_real_ip_from 10.0.0.0/8;"));
}

#[test]
fn rejects_malicious_domains() {
    let evil = [
        "a.com; return 200",
        "a.com\nserver {",
        "a.com{",
        "a b.com",
        "a.com`) || Host(`b.com",
        "*.example.com",
        "A.com",
        "a.com.",
        "localhost",
        "-a.com",
        "a..com",
        "a.com\"\n",
        "1.2.3.4",
        "ą.pl",
        "",
    ];
    for d in evil {
        let apps = app_with(&[d], Some(80));
        assert!(
            matches!(
                nginx::generate(&host(), &apps, &opts()),
                Err(IngressError::InvalidDomain { .. })
            ),
            "nginx accepted {d:?}"
        );
        assert!(
            traefik::generate(&host(), &apps, &TraefikOptions::default()).is_err(),
            "traefik accepted {d:?}"
        );
    }
}

#[test]
fn rejects_bad_webhook_domain() {
    let mut h = host();
    h.webhook.domain = "x.com; evil".into();
    assert!(nginx::generate(&h, &BTreeMap::new(), &opts()).is_err());
    assert!(traefik::generate(&h, &BTreeMap::new(), &TraefikOptions::default()).is_err());
}

#[test]
fn rejects_port_problems_and_duplicates() {
    let h = host();
    assert!(matches!(
        nginx::generate(&h, &app_with(&["a.example.eu"], None), &opts()),
        Err(IngressError::MissingPort(_))
    ));
    assert!(matches!(
        nginx::generate(&h, &app_with(&["a.example.eu"], Some(0)), &opts()),
        Err(IngressError::InvalidPort(_))
    ));
    assert!(matches!(
        nginx::generate(
            &h,
            &app_with(&["a.example.eu", "a.example.eu"], Some(80)),
            &opts()
        ),
        Err(IngressError::DuplicateDomain(_))
    ));
    assert!(matches!(
        nginx::generate(&h, &app_with(&["weglarka.example.eu"], Some(80)), &opts()),
        Err(IngressError::DuplicateDomain(_))
    ));
}

#[test]
fn rejects_instance_shadowing_webhook_upstream() {
    let mut a = apps(ONE_APP);
    let spec = a.remove(&"ntfy".to_owned().try_into().unwrap()).unwrap();
    a.insert("weglarka".to_owned().try_into().unwrap(), spec);
    assert!(matches!(
        nginx::generate(&host(), &a, &opts()),
        Err(IngressError::ReservedName(_))
    ));
}

#[test]
fn rejects_bad_options() {
    let h = host();
    let a = apps(ONE_APP);
    let mut o = opts();
    o.resolvers.clear();
    assert!(nginx::generate(&h, &a, &o).is_err());
    for p in [
        "/hook;", "/a/../b/", "webhook/", "/webhook", "/a//b/", "/a b/", "/x\n/",
    ] {
        let mut o = opts();
        o.webhook_paths = vec![p.into()];
        assert!(nginx::generate(&h, &a, &o).is_err(), "accepted path {p:?}");
    }
    for bad in ["x;y", "a b", "x\ny", "", "x`"] {
        let o = TraefikOptions {
            cert_resolver: Some(bad.into()),
            ..Default::default()
        };
        assert!(traefik::generate(&h, &a, &o).is_err(), "resolver {bad:?}");
        let o = TraefikOptions {
            entrypoint: bad.into(),
            ..Default::default()
        };
        assert!(traefik::generate(&h, &a, &o).is_err(), "entrypoint {bad:?}");
        let o = TraefikOptions {
            upstream_host: bad.into(),
            ..Default::default()
        };
        assert!(traefik::generate(&h, &a, &o).is_err(), "host {bad:?}");
    }
    assert!("1.2.3.4/33".parse::<Cidr>().is_err());
    assert!("1.2.3.4".parse::<Cidr>().is_ok(), "a bare address is a /32");
    assert!("1.2.3.4/x".parse::<Cidr>().is_err());
    assert!("1.2.3.4/8; deny".parse::<Cidr>().is_err());
}

#[test]
fn edge_mode_is_not_supported_yet() {
    let mut h = host();
    h.ingress.mode = weglarka_core::config::IngressMode::Edge;
    assert!(matches!(
        nginx::generate(&h, &BTreeMap::new(), &opts()),
        Err(IngressError::UnsupportedMode(_))
    ));
    assert!(matches!(
        traefik::generate(&h, &BTreeMap::new(), &TraefikOptions::default()),
        Err(IngressError::UnsupportedMode(_))
    ));
}

#[test]
fn trusted_proxies_from_config_replace_the_default() {
    let o = opts()
        .with_trusted_proxies(&["192.0.2.0/24".into(), "198.51.100.7".into()])
        .unwrap();
    let conf = nginx::generate(&host(), &apps(ONE_APP), &o).unwrap();
    assert!(conf.contains("set_real_ip_from 192.0.2.0/24;"));
    assert!(conf.contains("set_real_ip_from 198.51.100.7/32;"));
    // No implicit default: an empty list is refused.
    let empty = opts().with_trusted_proxies(&[]).unwrap();
    assert!(nginx::generate(&host(), &apps(ONE_APP), &empty).is_err());
    assert!(
        opts()
            .with_trusted_proxies(&["10.0.0.0/8; deny".into()])
            .is_err()
    );
}

/// The publishing validator (docs/install.md) only lets through routers/services named `weglarka`
/// or `weglarka-*`, `Host()` rules, entryPoints `http`/`https`, a router-level `tls` of `{}` or
/// `certResolver: letsencrypt`, and no middlewares. The generated file must stay inside that policy.
#[test]
fn traefik_output_satisfies_publish_policy() {
    for resolver in [Some("letsencrypt".to_owned()), None] {
        let o = TraefikOptions {
            cert_resolver: resolver,
            ..Default::default()
        };
        for (_, apps) in layouts() {
            let yml = traefik::generate(&host(), &apps, &o).unwrap();
            assert!(!yml.contains("middlewares"), "{yml}");
            let (mut routers, mut http, mut https) = (0, 0, 0);
            let mut name = String::new();
            let mut entrypoint = String::new();
            let mut has_tls = false;
            let mut check = |name: &str, entrypoint: &str, has_tls: bool| {
                if name.is_empty() {
                    return;
                }
                assert!(
                    name == "weglarka" || name.starts_with("weglarka-"),
                    "{name}"
                );
                match entrypoint {
                    "http" => {
                        assert!(!has_tls, "{name}: http router must not have tls");
                        assert!(name.starts_with("weglarka-http-"), "{name}");
                        http += 1;
                    }
                    "https" => {
                        assert!(has_tls, "{name}: https router needs tls");
                        https += 1;
                    }
                    other => panic!("{name}: entrypoint {other}"),
                }
                routers += 1;
            };
            let mut in_routers = false;
            for line in yml.lines() {
                if line == "  routers:" {
                    in_routers = true;
                } else if line == "  services:" {
                    check(&name, &entrypoint, has_tls);
                    in_routers = false;
                } else if in_routers && line.starts_with("    ") && !line.starts_with("     ") {
                    check(&name, &entrypoint, has_tls);
                    name = line.trim().trim_end_matches(':').to_owned();
                    entrypoint.clear();
                    has_tls = false;
                } else if in_routers {
                    let t = line.trim();
                    if let Some(rule) = t.strip_prefix("rule: ") {
                        assert!(rule.starts_with("\"Host(`"), "{rule}");
                        assert!(
                            !rule.contains("PathPrefix") && !rule.contains("&&"),
                            "{rule}"
                        );
                    } else if let Some(ep) = t.strip_prefix("- ") {
                        entrypoint = ep.to_owned();
                    } else if t == "service: weglarka" {
                    } else if t == "tls: {}" || t == "certResolver: letsencrypt" || t == "tls:" {
                        has_tls = true;
                    } else if !matches!(t, "entryPoints:") {
                        panic!("unexpected router line {t:?}");
                    }
                }
            }
            assert_eq!(http, https, "every router has an http twin");
            assert_eq!(routers, http + https);
        }
    }
}

#[test]
fn nginx_redirects_only_on_explicit_forwarded_http() {
    let conf = nginx::generate(&host(), &apps(ONE_APP), &opts()).unwrap();
    // Webhook server + one app; not the default server.
    assert_eq!(
        conf.matches("return 301 https://$host$request_uri;")
            .count(),
        2
    );
    // A trusted peer with no header (the daemon's health probe) must not be redirected.
    assert!(conf.contains("\"1:http\" 1;") && conf.contains("default 0;"));
}

#[test]
fn rejects_bad_http_entrypoint() {
    let o = TraefikOptions {
        http_entrypoint: "a b".into(),
        ..Default::default()
    };
    assert!(traefik::generate(&host(), &apps(ONE_APP), &o).is_err());
}

#[test]
fn traefik_router_names_never_collide() {
    let mut a = apps(ONE_APP);
    let spec = a.values().next().unwrap().clone();
    for n in ["ntfy-http", "http-ntfy"] {
        a.insert(n.to_owned().try_into().unwrap(), spec.clone());
    }
    let mut a2 = a.clone();
    for (i, spec) in a2.values_mut().enumerate() {
        spec.domains = vec![format!("d{i}.example.eu")];
    }
    let yml = traefik::generate(&host(), &a2, &TraefikOptions::default()).unwrap();
    let names: Vec<&str> = yml
        .lines()
        .filter(|l| l.starts_with("    weglarka-"))
        .collect();
    let unique: std::collections::BTreeSet<_> = names.iter().collect();
    assert_eq!(names.len(), unique.len(), "{yml}");
}
