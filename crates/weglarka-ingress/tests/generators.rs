mod common;

use std::collections::BTreeMap;
use std::net::IpAddr;

use common::*;
use weglarka_core::app::{AppSpec, InstanceName};
use weglarka_ingress::nginx::{self, NginxOptions};
use weglarka_ingress::traefik::{self, TraefikOptions};
use weglarka_ingress::{Cidr, Domain, IngressError, Plan};

fn opts() -> NginxOptions {
    NginxOptions::new(vec!["10.89.0.1".parse().unwrap()])
        .with_trusted_proxies(&["10.89.0.0/24".into()])
        .unwrap()
}

/// The `start = false` (provision-only) form of [`app_with`].
fn stopped(mut apps: BTreeMap<InstanceName, AppSpec>) -> BTreeMap<InstanceName, AppSpec> {
    for spec in apps.values_mut() {
        spec.start = false;
    }
    apps
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

/// Hardening assumption (docs/decisions/0014): the nginx container has a read-only root, and the only
/// writable filesystem it gets is libpod's tmpfs on `/tmp` (`/var/tmp`, `/run`). Every path nginx writes
/// at startup — its pid and the request-body/proxy temp directories — therefore has to live under `/tmp`;
/// a directive writing elsewhere would break the hardened container, not just this test.
#[test]
fn writable_nginx_paths_stay_under_tmp() {
    for (name, apps) in layouts() {
        let conf = nginx::generate(&host(), &apps, &opts()).unwrap();
        let mut checked = 0;
        for line in conf.lines() {
            let Some((directive, value)) = line.trim().split_once(' ') else {
                continue;
            };
            if directive != "pid" && !directive.ends_with("_temp_path") {
                continue;
            }
            let path = value.trim_end_matches(';');
            assert!(
                path.starts_with("/tmp/"),
                "{name}: {directive} points outside the writable tmpfs: {path}"
            );
            checked += 1;
        }
        assert_eq!(checked, 6, "{name}: pid plus five *_temp_path directives");
    }
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

/// One streaming app with a custom timeout and one ordinary app: the directives must not leak.
const STREAMING_APPS: &str = r#"
[apps.sse]
image = "ghcr.io/x/sse:latest"
domains = ["sse.example.eu"]
port = 3000

[apps.sse.ingress]
streaming = true
stream_timeout_secs = 600

[apps.buffered]
image = "ghcr.io/x/buffered:latest"
domains = ["buffered.example.eu"]
port = 3001
"#;

#[test]
fn streaming_apps_get_an_unbuffered_location() {
    let conf = nginx::generate(&host(), &apps(STREAMING_APPS), &opts()).unwrap();

    let sse = server_block(&conf, "sse.example.eu");
    for directive in [
        "proxy_buffering off;",
        "proxy_request_buffering off;",
        "proxy_read_timeout 600s;",
        "proxy_send_timeout 600s;",
    ] {
        assert!(sse.contains(directive), "{directive} missing from\n{sse}");
    }
    // They sit inside `location /`, after `proxy_pass`.
    let location = sse.find("location / {").expect("location block");
    assert!(location < sse.find("proxy_buffering off;").unwrap());

    // An app without the option keeps the nginx defaults (the negative control in CI).
    let buffered = server_block(&conf, "buffered.example.eu");
    assert!(!buffered.contains("proxy_buffering"), "{buffered}");
    assert!(!buffered.contains("proxy_read_timeout"), "{buffered}");

    // Neither does the webhook server.
    let webhook = server_block(&conf, "weglarka.example.eu");
    assert!(!webhook.contains("proxy_buffering"), "{webhook}");
}

#[test]
fn streaming_timeout_defaults_to_three_minutes() {
    let conf = nginx::generate(
        &host(),
        &apps(
            r#"
[apps.sse]
image = "i"
domains = ["sse.example.eu"]
port = 3000
ingress = { streaming = true }
"#,
        ),
        &opts(),
    )
    .unwrap();
    assert!(conf.contains("proxy_read_timeout 180s;"), "{conf}");
    assert!(conf.contains("proxy_send_timeout 180s;"), "{conf}");
}

#[test]
fn traefik_ignores_streaming() {
    let mut streamed = apps(STREAMING_APPS);
    let with = traefik::generate(&host(), &streamed, &TraefikOptions::default()).unwrap();
    for spec in streamed.values_mut() {
        spec.ingress = Default::default();
    }
    let without = traefik::generate(&host(), &streamed, &TraefikOptions::default()).unwrap();
    assert_eq!(with, without, "ingress options are an nginx-only concern");
}

#[test]
fn nginx_streaming_snapshot() {
    let conf = nginx::generate(&host(), &apps(STREAMING_APPS), &opts()).unwrap();
    insta::assert_snapshot!("nginx_streaming", conf);
}

/// A git/registry-shaped app (big body, streamed), a capped app and an ordinary one on separate
/// domains, plus two apps sharing a domain under different prefixes (ADR 0031) with different limits.
const BODY_LIMIT_APPS: &str = r#"
[apps.git]
image = "ghcr.io/x/git:latest"
domains = ["git.example.eu"]
port = 3000
ingress = { streaming = true, max_body_size = "4g" }

[apps.capped]
image = "ghcr.io/x/capped:latest"
domains = ["capped.example.eu"]
port = 3001
ingress = { max_body_size = "8m" }

[apps.open]
image = "ghcr.io/x/open:latest"
domains = ["open.example.eu"]
port = 3002
ingress = { max_body_size = "0" }

[apps.plain]
image = "ghcr.io/x/plain:latest"
domains = ["plain.example.eu"]
port = 3003

[apps.up]
image = "ghcr.io/x/up:latest"
domains = ["shared.example.eu"]
paths = ["/upload"]
port = 3004
ingress = { max_body_size = "1g" }

[apps.web]
image = "ghcr.io/x/web:latest"
domains = ["shared.example.eu"]
paths = ["/"]
port = 3005
"#;

#[test]
fn max_body_size_is_a_location_directive_with_unbuffered_requests() {
    let conf = nginx::generate(&host(), &apps(BODY_LIMIT_APPS), &opts()).unwrap();
    let location = |server: &str| {
        let block = server_block(&conf, server);
        let at = block.find("location").expect("location");
        block[at..].to_owned()
    };

    let git = location("git.example.eu");
    assert!(git.contains("client_max_body_size 4294967296;"), "{git}");
    // `streaming` already switches request buffering off: the directive appears once.
    assert_eq!(
        git.matches("proxy_request_buffering off;").count(),
        1,
        "{git}"
    );

    // Without `streaming` the limit alone must not leave the body spooled on the ingress tmpfs.
    let capped = location("capped.example.eu");
    assert!(capped.contains("client_max_body_size 8388608;"), "{capped}");
    assert!(capped.contains("proxy_request_buffering off;"), "{capped}");
    assert!(
        !capped.contains("proxy_buffering off;"),
        "response stays buffered: {capped}"
    );
    assert!(!capped.contains("proxy_read_timeout"), "{capped}");

    assert!(location("open.example.eu").contains("client_max_body_size 0;"));

    // An app without the field keeps the server-level default and nothing in its location.
    let plain = location("plain.example.eu");
    assert!(!plain.contains("client_max_body_size"), "{plain}");
    assert!(!plain.contains("proxy_request_buffering"), "{plain}");
    assert!(server_block(&conf, "plain.example.eu").contains("client_max_body_size 67108864;"));

    // Two apps in one `server`: only the `/upload` locations carry the larger limit.
    let shared = server_block(&conf, "shared.example.eu");
    let (web, upload) = shared
        .split_once("location = /upload")
        .expect("upload location");
    assert!(
        upload.contains("client_max_body_size 1073741824;"),
        "{shared}"
    );
    assert!(!web.contains("1073741824"), "{shared}");
}

#[test]
fn nginx_max_body_size_snapshot() {
    let conf = nginx::generate(&host(), &apps(BODY_LIMIT_APPS), &opts()).unwrap();
    insta::assert_snapshot!("nginx_max_body_size", conf);
}

#[test]
fn traefik_ignores_max_body_size() {
    let mut limited = apps(BODY_LIMIT_APPS);
    let with = traefik::generate(&host(), &limited, &TraefikOptions::default()).unwrap();
    for spec in limited.values_mut() {
        spec.ingress = Default::default();
    }
    let without = traefik::generate(&host(), &limited, &TraefikOptions::default()).unwrap();
    assert_eq!(
        with, without,
        "Traefik has no body limit; nginx is the only one"
    );
}

/// The `server { … }` block whose `server_name` names the given host (output nests 4 spaces per level).
fn server_block(conf: &str, server_name: &str) -> String {
    let block = conf
        .split("    server {\n")
        .skip(1)
        .find(|b| {
            b.lines()
                .any(|l| l.trim_start().starts_with("server_name ") && l.contains(server_name))
        })
        .unwrap_or_else(|| panic!("no server block for {server_name} in\n{conf}"));
    // A server block closes at the `http` level (4 spaces) before any `location` does (8 spaces).
    block.split("\n    }").next().unwrap_or(block).to_owned()
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
fn start_false_apps_are_validated_and_reserve_domains_but_are_not_rendered() {
    let h = host();
    let a = stopped(app_with(&["off.example.eu"], Some(80)));

    // The plan still carries the route: the domain is reserved even though the app does not run.
    let plan = Plan::build(&h, &a).unwrap();
    assert_eq!(plan.apps.len(), 1);
    assert!(
        !plan.apps[0].active,
        "start = false must map to active = false"
    );
    assert_eq!(
        plan.apps[0]
            .domains
            .iter()
            .map(Domain::as_str)
            .collect::<Vec<_>>(),
        ["off.example.eu"]
    );

    // No route may reach a container that does not exist.
    let conf = nginx::generate(&h, &a, &opts()).unwrap();
    assert!(
        !conf.contains("off.example.eu"),
        "nginx rendered a server block for a start = false app"
    );
    assert!(
        !conf.contains("set $app \"app\";"),
        "nginx rendered the app access-log name"
    );
    assert!(conf.contains("server_name _;"), "default server must stay");

    let yml = traefik::generate(&h, &a, &TraefikOptions::default()).unwrap();
    assert!(
        !yml.contains("off.example.eu"),
        "traefik rendered a router for a start = false app"
    );
    assert!(!yml.contains("weglarka-app-app"), "app router name leaked");
    assert!(
        yml.contains("weglarka-webhooks"),
        "webhook router must stay"
    );
}

#[test]
fn start_false_apps_still_take_part_in_validation() {
    let h = host();
    // A duplicate domain of an inactive app is still a duplicate: starting it later would hijack
    // the other app's traffic.
    let dup = apps(
        r#"
[apps.a]
image = "ghcr.io/x/a:latest"
domains = ["dup.example.eu"]
port = 80

[apps.b]
image = "ghcr.io/x/b:latest"
domains = ["dup.example.eu"]
port = 80
start = false
"#,
    );
    assert!(matches!(
        Plan::build(&h, &dup),
        Err(IngressError::DuplicateDomain(_))
    ));
    assert!(matches!(
        nginx::generate(&h, &dup, &opts()),
        Err(IngressError::DuplicateDomain(_))
    ));

    // Domains and ports are validated exactly like for a running app.
    assert!(matches!(
        Plan::build(&h, &stopped(app_with(&["a.com; return 200"], Some(80)))),
        Err(IngressError::InvalidDomain { .. })
    ));
    assert!(matches!(
        Plan::build(&h, &stopped(app_with(&["off.example.eu"], None))),
        Err(IngressError::MissingPort(_))
    ));
    assert!(matches!(
        Plan::build(&h, &stopped(app_with(&["off.example.eu"], Some(0)))),
        Err(IngressError::InvalidPort(_))
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
    assert!(conf.contains("\"~^1:.+\" 1;") && conf.contains("\"1:https\" 0;"));
    assert!(conf.contains("\"1:wss\" 0;") && conf.contains("default 0;"));
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

/// Two instances split one domain by path (ADR 0031), a third owns its own domain and a fourth keeps
/// a catch-all next to a prefix.
const PATH_APPS: &str = r#"
[apps.api]
image = "ghcr.io/x/api:latest"
domains = ["app.example.eu"]
paths = ["/api", "/healthz"]
port = 3000

[apps.mcp]
image = "ghcr.io/x/mcp:latest"
domains = ["app.example.eu"]
paths = ["/mcp", "/.well-known"]
port = 3001

[apps.mcp.ingress]
streaming = true
strip_prefix = true

[apps.spa]
image = "ghcr.io/x/spa:latest"
domains = ["app.example.eu"]
port = 3002

[apps.solo]
image = "ghcr.io/x/solo:latest"
domains = ["solo.example.eu"]
port = 3003
"#;

#[test]
fn path_routes_share_one_server_and_render_per_prefix() {
    let a = apps(PATH_APPS);
    let conf = nginx::generate(&host(), &a, &opts()).unwrap();
    insta::assert_snapshot!("nginx_paths", conf);
    insta::assert_snapshot!(
        "traefik_paths",
        traefik::generate(&host(), &a, &TraefikOptions::default()).unwrap()
    );

    let shared = server_block(&conf, "app.example.eu");
    assert!(shared.contains("location = /api {"), "{shared}");
    assert!(shared.contains("location ^~ /api/ {"), "{shared}");
    assert!(shared.contains("location / {"), "{shared}");
    // The app name for the log comes from the location, not the (shared) server.
    assert!(shared.contains("set $app \"api\";"), "{shared}");
    // Streaming and strip are per instance: they must not leak into the neighbour.
    assert!(
        shared.contains("rewrite ^/mcp/(.*)$ /$1 break;"),
        "{shared}"
    );
    assert!(
        shared.contains(r"rewrite ^/\.well-known/(.*)$ /$1 break;"),
        "{shared}"
    );
    assert_eq!(
        shared.matches("proxy_buffering off;").count(),
        4,
        "{shared}"
    );
    assert_eq!(shared.matches("rewrite ").count(), 4, "{shared}");
    // An unshared domain keeps its single-app server.
    let solo = server_block(&conf, "solo.example.eu");
    assert!(
        solo.contains("set $app \"solo\";") && solo.contains("location / {"),
        "{solo}"
    );
    assert!(!solo.contains("location ^~"), "{solo}");
}

#[test]
fn path_route_table_lists_every_domain_and_prefix() {
    let a = apps(PATH_APPS);
    let h = host();
    let plan = Plan::build(&h, &a).unwrap();
    let rows: Vec<String> = plan
        .route_table()
        .iter()
        .map(|r| format!("{}{} -> {}:{}", r.domain, r.path, r.instance, r.port))
        .collect();
    assert_eq!(
        rows,
        [
            "app.example.eu/ -> spa:3002",
            "app.example.eu/.well-known -> mcp:3001",
            "app.example.eu/api -> api:3000",
            "app.example.eu/healthz -> api:3000",
            "app.example.eu/mcp -> mcp:3001",
            "solo.example.eu/ -> solo:3003",
        ]
    );
}

#[test]
fn overlapping_paths_on_a_shared_domain_are_rejected() {
    let build = |a_paths: &str, b_paths: &str| {
        let a = apps(&format!(
            r#"
[apps.a]
image = "ghcr.io/x/a:latest"
domains = ["app.example.eu"]
port = 80
{a_paths}

[apps.b]
image = "ghcr.io/x/b:latest"
domains = ["app.example.eu"]
port = 81
{b_paths}
"#
        ));
        Plan::build(&host(), &a).map(|_| ())
    };
    assert_eq!(build("paths = [\"/a\"]", "paths = [\"/b\"]"), Ok(()));
    // A prefix on a segment boundary only: `/api` and `/apiary` are different routes.
    assert_eq!(build("paths = [\"/api\"]", "paths = [\"/apiary\"]"), Ok(()));
    // `/` is the catch-all and coexists with prefixes.
    assert_eq!(build("", "paths = [\"/b\"]"), Ok(()));
    for (a, b) in [
        ("paths = [\"/a\"]", "paths = [\"/a\"]"),
        ("paths = [\"/a\"]", "paths = [\"/a/b\"]"),
        ("paths = [\"/a/b\"]", "paths = [\"/a\"]"),
    ] {
        let err = build(a, b).unwrap_err();
        assert!(matches!(err, IngressError::PathConflict { .. }), "{err:?}");
        assert!(err.to_string().contains("overlap"), "{err}");
    }
    // Two catch-alls are the old "domain already taken" error.
    assert!(matches!(
        build("", ""),
        Err(IngressError::DuplicateDomain(_))
    ));
    assert!(matches!(
        build("paths = [\"/\"]", ""),
        Err(IngressError::DuplicateDomain(_))
    ));
}

#[test]
fn the_webhook_domain_stays_exclusive_even_with_paths() {
    let a = apps(
        r#"
[apps.a]
image = "ghcr.io/x/a:latest"
domains = ["weglarka.example.eu"]
paths = ["/a"]
port = 80
"#,
    );
    assert!(matches!(
        Plan::build(&host(), &a),
        Err(IngressError::DuplicateDomain(_))
    ));
}

#[test]
fn invalid_paths_never_reach_the_generator() {
    let a = apps(
        r#"
[apps.a]
image = "ghcr.io/x/a:latest"
domains = ["app.example.eu"]
paths = ["/a;b"]
port = 80
"#,
    );
    assert!(matches!(
        nginx::generate(&host(), &a, &opts()),
        Err(IngressError::InvalidPath { .. })
    ));
}
