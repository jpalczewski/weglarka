mod common;

use std::collections::BTreeMap;
use std::net::IpAddr;

use common::*;
use weglarka_ingress::nginx::{self, NginxOptions};
use weglarka_ingress::traefik::{self, TraefikOptions};
use weglarka_ingress::{Cidr, Domain, IngressError, Plan};
use weglarka_model::app::{AppSpec, InstanceName};
use weglarka_model::config::IngressMode;

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
/// a directive writing elsewhere would break the hardened container, not just this test. Holds for both
/// ingress modes (issue #95).
#[test]
fn writable_nginx_paths_stay_under_tmp() {
    let mut cases: Vec<(String, String)> = Vec::new();
    for (name, apps) in layouts() {
        cases.push((
            format!("behind_{name}"),
            nginx::generate(&host(), &apps, &opts()).unwrap(),
        ));
        cases.push((
            format!("edge_{name}"),
            nginx::generate(
                &edge_host(),
                &apps,
                &edge_opts(&["nz.example.eu", "blog.example.eu", "weglarka.example.eu"]),
            )
            .unwrap(),
        ));
    }
    for (name, conf) in cases {
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
    assert!(conf.contains("resolver [fd00::1] valid=1s ipv6=off;"));
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

/// A chatty poller (exact and prefix entries) next to an ordinary app, a shared domain, and an app with
/// an entry that needs regex escaping (issue #181).
const ACCESS_LOG_SKIP_APPS: &str = r#"
[apps.forgejo]
image = "ghcr.io/x/forgejo:latest"
domains = ["git.example.eu"]
port = 3000
ingress = { access_log_skip_paths = ["/api/actions/runner.v1.RunnerService/", "/healthz"] }

[apps.plain]
image = "ghcr.io/x/plain:latest"
domains = ["plain.example.eu"]
port = 3001

[apps.v1]
image = "ghcr.io/x/v1:latest"
domains = ["shared.example.eu"]
paths = ["/v1"]
port = 3002
ingress = { access_log_skip_paths = ["/v1/poll/"] }

[apps.web]
image = "ghcr.io/x/web:latest"
domains = ["shared.example.eu"]
paths = ["/"]
port = 3003
"#;

#[test]
fn access_log_skip_paths_render_maps_and_a_conditional_log() {
    let conf = nginx::generate(&host(), &apps(ACCESS_LOG_SKIP_APPS), &opts()).unwrap();
    assert!(
        conf.contains("access_log /dev/stdout weglarka if=$weglarka_loggable;"),
        "{conf}"
    );
    // A trailing slash is a prefix, anything else is anchored; the dots are escaped.
    assert!(
        conf.contains(r#""~^forgejo /api/actions/runner\.v1\.RunnerService/" 1;"#),
        "{conf}"
    );
    assert!(conf.contains(r#""~^forgejo /healthz$" 1;"#), "{conf}");
    assert!(conf.contains(r#""~^v1 /v1/poll/" 1;"#), "{conf}");
    // Only successes and redirects are dropped; errors stay in the log.
    assert!(conf.contains(r#""~^1:[123][0-9][0-9]$" 0;"#), "{conf}");
    assert!(
        !conf.contains("plain /"),
        "apps without entries add nothing: {conf}"
    );
}

#[test]
fn empty_access_log_skip_paths_leave_the_config_untouched() {
    let conf = nginx::generate(&host(), &apps(BODY_LIMIT_APPS), &opts()).unwrap();
    assert!(conf.contains("access_log /dev/stdout weglarka;"), "{conf}");
    assert!(!conf.contains("weglarka_loggable"), "{conf}");
    assert!(!conf.contains("weglarka_skip_path"), "{conf}");
}

#[test]
fn stopped_apps_contribute_no_access_log_rules() {
    let conf = nginx::generate(&host(), &stopped(apps(ACCESS_LOG_SKIP_APPS)), &opts()).unwrap();
    assert!(!conf.contains("weglarka_loggable"), "{conf}");
}

#[test]
fn nginx_access_log_skip_snapshot() {
    let conf = nginx::generate(&host(), &apps(ACCESS_LOG_SKIP_APPS), &opts()).unwrap();
    insta::assert_snapshot!("nginx_access_log_skip", conf);
}

#[test]
fn nginx_edge_access_log_skip_snapshot() {
    let conf = nginx::generate(
        &edge_host(),
        &apps(ACCESS_LOG_SKIP_APPS),
        &edge_opts(&["git.example.eu"]),
    )
    .unwrap();
    insta::assert_snapshot!("nginx_edge_access_log_skip", conf);
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
fn edge_mode_renders_without_traefik_and_rejects_it() {
    // Traefik has no part in `edge`: the generator refuses that mode, so a stale
    // `traefik_dynamic_file` cannot publish a second, unmanaged entrypoint.
    assert!(matches!(
        traefik::generate(&edge_host(), &BTreeMap::new(), &TraefikOptions::default()),
        Err(IngressError::UnsupportedMode(IngressMode::Edge))
    ));
}

/// `edge` options: no trusted peer, one fixed TLS fingerprint, the given domains have certificates.
fn edge_opts(certificates: &[&str]) -> NginxOptions {
    let mut o = NginxOptions::new(vec!["10.89.0.1".parse().unwrap()]);
    o.certificates = certificates
        .iter()
        .map(|d| Domain::new(*d).unwrap())
        .collect();
    o.tls_fingerprint = Some("1a2b3c4d".to_owned());
    o
}

#[test]
fn nginx_edge_snapshots() {
    let h = edge_host();
    for (name, apps) in layouts() {
        // The webhook domain always has a certificate; the many-app layout leaves some app domains
        // without one on purpose, so both the TLS and the plain-HTTP-only branches are pinned.
        let certs: &[&str] = match name {
            "no_apps" => &["weglarka.example.eu"],
            "one_app" => &["nz.example.eu", "weglarka.example.eu"],
            _ => &["blog.example.eu", "example.eu", "weglarka.example.eu"],
        };
        let conf = nginx::generate(&h, &apps, &edge_opts(certs)).unwrap();
        insta::assert_snapshot!(format!("nginx_edge_{name}"), conf);
    }
}

#[test]
fn nginx_edge_paths_snapshot() {
    let conf = nginx::generate(
        &edge_host(),
        &apps(PATH_APPS),
        &edge_opts(&["app.example.eu", "weglarka.example.eu"]),
    )
    .unwrap();
    insta::assert_snapshot!("nginx_edge_paths", conf);
}

/// `edge` options with wildcard pairs (`_wildcard.<apex>.crt|key`) next to the per-domain ones.
fn edge_wildcard_opts(certificates: &[&str], wildcards: &[&str]) -> NginxOptions {
    let mut o = edge_opts(certificates);
    o.wildcard_certificates = wildcards.iter().map(|d| Domain::new(*d).unwrap()).collect();
    o
}

#[test]
fn nginx_edge_wildcard_snapshot() {
    // `example.eu` wildcard + the own pair of `blog.example.eu` (which must win over it).
    let conf = nginx::generate(
        &edge_host(),
        &apps(MANY_APPS),
        &edge_wildcard_opts(&["blog.example.eu"], &["example.eu"]),
    )
    .unwrap();
    insta::assert_snapshot!("nginx_edge_wildcard", conf);
}

#[test]
fn edge_serves_a_covered_domain_with_the_wildcard_and_prefers_its_own_pair() {
    let conf = nginx::generate(
        &edge_host(),
        &apps(MANY_APPS),
        &edge_wildcard_opts(&["blog.example.eu"], &["example.eu"]),
    )
    .unwrap();
    // The apex and one label below are covered; the webhook domain too.
    for domain in ["example.eu", "nz.example.eu", "weglarka.example.eu"] {
        let tls = tls_server(&conf, domain);
        assert!(
            tls.contains("ssl_certificate /etc/nginx/tls/_wildcard.example.eu.crt;"),
            "{domain}: {tls}"
        );
        assert!(
            tls.contains("ssl_certificate_key /etc/nginx/tls/_wildcard.example.eu.key;"),
            "{domain}: {tls}"
        );
    }
    // An own pair always wins over a wildcard.
    let own = tls_server(&conf, "blog.example.eu");
    assert!(own.contains("/etc/nginx/tls/blog.example.eu.crt;"), "{own}");
    assert!(!own.contains("_wildcard"), "{own}");
    // Two labels below the apex are not covered: no TLS server, plain HTTP still redirects.
    assert!(
        !conf.contains("ssl_certificate /etc/nginx/tls/www.blog.example.eu.crt"),
        "{conf}"
    );
    assert!(
        !conf
            .split("    server {\n")
            .skip(1)
            .any(|b| b.contains(" ssl;") && b.contains("server_name www.blog.example.eu;")),
        "www.blog.example.eu is two labels below the apex"
    );
    assert!(
        server_block(&conf, "www.blog.example.eu")
            .contains("return 301 https://$host$request_uri;")
    );
}

#[test]
fn certificate_stem_picks_own_pair_then_the_longest_covering_wildcard() {
    let o = edge_wildcard_opts(&["own.example.eu"], &["example.eu", "dev.example.eu"]);
    let stem = |d: &str| o.certificate_stem(&Domain::new(d).unwrap());
    assert_eq!(stem("own.example.eu").as_deref(), Some("own.example.eu"));
    assert_eq!(
        stem("a.example.eu").as_deref(),
        Some("_wildcard.example.eu")
    );
    assert_eq!(stem("example.eu").as_deref(), Some("_wildcard.example.eu"));
    // `dev.example.eu` is covered by both: the more specific apex wins.
    assert_eq!(
        stem("dev.example.eu").as_deref(),
        Some("_wildcard.dev.example.eu")
    );
    assert_eq!(
        stem("x.dev.example.eu").as_deref(),
        Some("_wildcard.dev.example.eu")
    );
    assert_eq!(stem("a.b.example.eu"), None);
    assert_eq!(stem("example.org"), None);
}

/// The `server { … }` block of `domain` that listens on TLS.
fn tls_server(conf: &str, domain: &str) -> String {
    let block = conf
        .split("    server {\n")
        .skip(1)
        .find(|b| {
            b.contains(" ssl;")
                && b.lines()
                    .any(|l| l.trim_start().starts_with("server_name ") && l.contains(domain))
        })
        .unwrap_or_else(|| panic!("no TLS server block for {domain} in\n{conf}"));
    block.split("\n    }").next().unwrap_or(block).to_owned()
}

#[test]
fn edge_plain_http_serves_acme_and_redirects_everything_else() {
    let conf =
        nginx::generate(&edge_host(), &apps(ONE_APP), &edge_opts(&["nz.example.eu"])).unwrap();
    let plain = server_block(&conf, "nz.example.eu");
    assert!(plain.contains("listen 8080;"), "{plain}");
    assert!(
        plain.contains("return 301 https://$host$request_uri;"),
        "{plain}"
    );
    assert!(
        !plain.contains("proxy_pass"),
        "plain HTTP must not proxy the app: {plain}"
    );
    // The ACME prefix is served from the webroot, before the catch-all redirect.
    assert!(
        plain.contains("location ^~ /.well-known/acme-challenge/ {"),
        "{plain}"
    );
    assert!(plain.contains("alias /etc/nginx/acme/;"), "{plain}");
    assert!(plain.contains("limit_except GET"), "{plain}");
    assert!(
        plain.find("acme-challenge").unwrap() < plain.find("location / {").unwrap(),
        "the ACME location must win over the redirect: {plain}"
    );
    // The TLS server of the same domain proxies it.
    let tls = tls_server(&conf, "nz.example.eu");
    assert!(
        tls.contains("ssl_certificate /etc/nginx/tls/nz.example.eu.crt;"),
        "{tls}"
    );
    assert!(
        tls.contains("ssl_certificate_key /etc/nginx/tls/nz.example.eu.key;"),
        "{tls}"
    );
    assert!(tls.contains("http2 on;"), "{tls}");
    assert!(tls.contains("proxy_pass $upstream;"), "{tls}");
}

/// The server for `domain` that listens on the probe socket.
fn probe_server(conf: &str, domain: &str) -> String {
    let block = conf
        .split("    server {\n")
        .skip(1)
        .find(|b| {
            b.contains("listen unix:/run/weglarka-probe/probe.sock")
                && b.lines()
                    .any(|l| l.trim_start().starts_with("server_name ") && l.contains(domain))
        })
        .unwrap_or_else(|| panic!("no probe-socket server for {domain} in\n{conf}"));
    block.split("\n    }").next().unwrap_or(block).to_owned()
}

#[test]
fn edge_serves_tls_only_for_domains_with_a_certificate() {
    let conf = nginx::generate(
        &edge_host(),
        &apps(MANY_APPS),
        &edge_opts(&["blog.example.eu"]),
    )
    .unwrap();
    assert!(
        tls_server(&conf, "blog.example.eu").contains("proxy_pass"),
        "a certified domain is served over TLS"
    );
    // Every other routed domain (app or webhook) keeps the redirect but has no certificate.
    for domain in [
        "www.blog.example.eu",
        "example.eu",
        "nz.example.eu",
        "weglarka.example.eu",
    ] {
        assert!(
            !conf.contains(&format!("ssl_certificate /etc/nginx/tls/{domain}.crt")),
            "{domain} must not have a TLS server"
        );
        assert!(
            server_block(&conf, domain).contains("return 301 https://$host$request_uri;"),
            "{domain}: plain HTTP must still redirect"
        );
    }
    // Nothing silently proxies over plain HTTP: a server that proxies listens on TCP or the forwarder's
    // sockets only with TLS; its one plain listener is the daemon's probe socket.
    let mut proxying = 0;
    for block in conf.split("    server {\n").skip(1) {
        let block = block.split("\n    }").next().unwrap_or(block);
        if !block.contains("proxy_pass") {
            continue;
        }
        proxying += 1;
        for listen in block
            .lines()
            .filter(|l| l.trim_start().starts_with("listen "))
        {
            assert!(
                listen.contains(" ssl") || listen.contains("unix:/run/weglarka-probe/probe.sock;"),
                "plain-HTTP listener on a proxying server: {listen}\n{block}"
            );
        }
    }
    // blog.example.eu, www.blog.example.eu, example.eu (all `blog`) and nz.example.eu (`ntfy`).
    assert_eq!(
        proxying, 4,
        "every routed app domain has one proxying server"
    );
}

#[test]
fn edge_probe_socket_serves_domains_without_a_certificate() {
    let conf = nginx::generate(&edge_host(), &apps(ONE_APP), &edge_opts(&[])).unwrap();
    let block = probe_server(&conf, "nz.example.eu");
    assert!(block.contains("proxy_pass"), "{block}");
    assert!(
        !block.contains("ssl"),
        "no certificate, no TLS listener: {block}"
    );
    // The redirect server stays: the probe's listener is the only plain path to the app.
    assert!(server_block(&conf, "nz.example.eu").contains("return 301"));
}

/// Issue #321: the identity provider refuses OIDC requests that claim plain HTTP, so the daemon's
/// `X-Forwarded-Proto: https` must reach it — from the probe socket only, in both modes.
#[test]
fn probe_socket_may_announce_https_and_nobody_else_can() {
    let edge = nginx::generate(&edge_host(), &apps(ONE_APP), &edge_opts(&[])).unwrap();
    let behind = nginx::generate(
        &host(),
        &apps(ONE_APP),
        &NginxOptions::new(vec!["10.89.0.1".parse().unwrap()])
            .with_trusted_proxies(&["10.89.0.2".to_owned()])
            .unwrap(),
    )
    .unwrap();
    for (mode, conf) in [("edge", edge), ("behind", behind)] {
        // The key starts with the literal peer address `unix:`, which only the probe socket has.
        assert!(
            conf.contains("map \"$remote_addr:$http_x_forwarded_proto\" $weglarka_proto {"),
            "{mode}: {conf}"
        );
        assert!(conf.contains("\"unix::https\" https;"), "{mode}");
        assert_eq!(
            conf.matches("\"unix::").count(),
            1,
            "{mode}: only https, only unix:"
        );
        assert!(
            conf.contains("proxy_set_header X-Forwarded-Proto $weglarka_proto;"),
            "{mode}"
        );
    }
}

#[test]
fn probe_socket_is_a_plain_listener_without_proxy_protocol_on_every_app_server() {
    let mut behind = NginxOptions::new(vec!["10.89.0.1".parse().unwrap()])
        .with_trusted_proxies(&["10.89.0.2".to_owned()])
        .unwrap();
    behind.probe_socket = "/run/probe/p.sock".to_owned();
    let conf = nginx::generate(&host(), &apps(MANY_APPS), &behind).unwrap();
    assert!(conf.contains("listen unix:/run/probe/p.sock default_server;"));
    // Every server on the app port but the webhook one also listens on the socket.
    for block in conf.split("    server {\n").skip(1) {
        let block = block.split("\n    }").next().unwrap_or(block);
        if block.contains("listen 8080") && !block.contains("weglarka.example.eu") {
            assert!(block.contains("listen unix:/run/probe/p.sock"), "{block}");
        }
    }
    assert!(!conf.contains("p.sock proxy_protocol"));
    assert!(!conf.contains("p.sock ssl"));
    assert!(
        !server_block(&conf, "weglarka.example.eu").contains("p.sock"),
        "the webhook server is not probed"
    );
}

#[test]
fn the_probe_socket_must_stay_out_of_the_forwarder_directory() {
    let mut o = edge_opts(&[]);
    o.proxy_socket_dir = Some("/run/weglarka-ingress".to_owned());
    o.probe_socket = "/run/weglarka-ingress/probe.sock".to_owned();
    assert!(nginx::generate(&edge_host(), &BTreeMap::new(), &o).is_err());
    o.probe_socket = "relative.sock".to_owned();
    assert!(nginx::generate(&edge_host(), &BTreeMap::new(), &o).is_err());
}

#[test]
fn edge_rejects_an_unknown_sni_without_a_certificate() {
    let conf =
        nginx::generate(&edge_host(), &apps(ONE_APP), &edge_opts(&["nz.example.eu"])).unwrap();
    assert!(conf.contains("listen 8443 ssl default_server;"), "{conf}");
    assert!(conf.contains("ssl_reject_handshake on;"), "{conf}");
    // The default TLS server must not borrow any app certificate.
    let default = conf
        .split("    server {\n")
        .skip(1)
        .find(|b| b.contains("ssl_reject_handshake"))
        .expect("default TLS server");
    assert!(!default.contains("ssl_certificate"), "{default}");
}

#[test]
fn edge_never_trusts_forwarded_headers() {
    let conf =
        nginx::generate(&edge_host(), &apps(ONE_APP), &edge_opts(&["nz.example.eu"])).unwrap();
    assert!(!conf.contains("set_real_ip_from"), "{conf}");
    assert!(!conf.contains("$weglarka_trusted"), "{conf}");
    // The one reader of the header is keyed on the probe socket's literal peer address (#321).
    assert_eq!(conf.matches("$http_x_forwarded_proto").count(), 1, "{conf}");
    assert!(
        conf.contains("map \"$remote_addr:$http_x_forwarded_proto\""),
        "{conf}"
    );
    // The headers are nginx's own: a direct client cannot choose them.
    assert!(
        conf.contains("proxy_set_header X-Forwarded-For $remote_addr;"),
        "{conf}"
    );
    assert!(
        conf.contains("proxy_set_header X-Forwarded-Proto $weglarka_proto;"),
        "{conf}"
    );
    assert!(
        conf.contains("proxy_set_header X-Forwarded-Host $host;"),
        "{conf}"
    );
}

#[test]
fn edge_options_reject_behind_settings_and_bad_paths() {
    let h = edge_host();
    let a = apps(ONE_APP);
    let mut o = edge_opts(&["nz.example.eu"]);
    o.trusted_proxies = vec!["10.89.0.0/24".parse().unwrap()];
    assert!(matches!(
        nginx::generate(&h, &a, &o),
        Err(IngressError::InvalidOption {
            name: "trusted_proxies",
            ..
        })
    ));

    let mut o = edge_opts(&["nz.example.eu"]);
    o.tls_fingerprint = None;
    assert!(matches!(
        nginx::generate(&h, &a, &o),
        Err(IngressError::InvalidOption {
            name: "tls_fingerprint",
            ..
        })
    ));
    let mut o = edge_opts(&["nz.example.eu"]);
    o.tls_fingerprint = Some("../../etc".to_owned());
    assert!(nginx::generate(&h, &a, &o).is_err());

    // The certificate and webroot paths land verbatim in the config: only safe container paths.
    for bad in [
        "relative/tls",
        "/etc/nginx/tls/",
        "/etc/nginx/../x",
        "/etc/nginx/t ls",
    ] {
        let mut o = edge_opts(&["nz.example.eu"]);
        o.cert_dir = bad.into();
        assert!(nginx::generate(&h, &a, &o).is_err(), "accepted {bad:?}");
    }
}

#[test]
fn edge_output_is_independent_of_the_certificate_order() {
    let h = edge_host();
    let a = apps(MANY_APPS);
    let first = nginx::generate(&h, &a, &edge_opts(&["blog.example.eu", "nz.example.eu"])).unwrap();
    let second =
        nginx::generate(&h, &a, &edge_opts(&["nz.example.eu", "blog.example.eu"])).unwrap();
    assert_eq!(
        first, second,
        "the certificate list must not drive ordering"
    );
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
        .map(|r| format!("{}{} -> {}:{}", r.domain, r.path, r.instance, r.backend))
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

#[test]
fn nginx_edge_proxy_sockets_snapshot() {
    let mut o = edge_opts(&["app.example.eu", "weglarka.example.eu"]);
    o.proxy_socket_dir = Some("/run/weglarka-ingress".to_owned());
    let conf = nginx::generate(&edge_host(), &BTreeMap::new(), &o).unwrap();
    insta::assert_snapshot!("nginx_edge_proxy_sockets", conf);
}

#[test]
fn proxy_sockets_are_an_edge_only_option() {
    let mut o = NginxOptions::new(vec!["10.89.0.1".parse().unwrap()])
        .with_trusted_proxies(&["10.89.0.2".to_owned()])
        .unwrap();
    o.proxy_socket_dir = Some("/run/weglarka-ingress".to_owned());
    assert!(nginx::generate(&host(), &BTreeMap::new(), &o).is_err());
}

fn edge_cdn_opts(pinned: &[&str]) -> NginxOptions {
    let mut o = edge_opts(&["app.example.eu", "weglarka.example.eu"]);
    o.proxy_socket_dir = Some("/run/weglarka-ingress".to_owned());
    let pinned: Vec<String> = pinned.iter().map(|r| (*r).to_owned()).collect();
    o.cdn = Some(
        weglarka_ingress::CdnTrust::from_config(
            weglarka_model::config::CdnProvider::Cloudflare,
            &pinned,
        )
        .unwrap(),
    );
    o
}

#[test]
fn nginx_edge_cdn_snapshot() {
    let o = edge_cdn_opts(&[]);
    let conf = nginx::generate(&edge_host(), &apps(ONE_APP), &o).unwrap();
    insta::assert_snapshot!("nginx_edge_cdn", conf);
}

#[test]
fn edge_cdn_trusts_only_the_ranges_and_never_x_forwarded_for() {
    let o = edge_cdn_opts(&["203.0.113.0/24"]);
    let conf = nginx::generate(&edge_host(), &apps(ONE_APP), &o).unwrap();
    // Trust is decided on the PROXY-header address, which is also set on requests rejected early.
    assert!(conf.contains("geo $weglarka_peer $weglarka_cdn {"));
    assert!(conf.contains("203.0.113.0/24 1;"));
    assert!(
        !conf.contains("173.245.48.0/20"),
        "a pin replaces the bundled list"
    );
    assert!(conf.contains("proxy_set_header X-Forwarded-For $weglarka_client;"));
    assert!(conf.contains("proxy_set_header X-Real-IP $weglarka_client;"));
    assert!(conf.contains("proxy_set_header X-Forwarded-Proto $weglarka_proto;"));
    assert!(!conf.contains("$http_x_forwarded_for"));
    assert!(conf.contains("\"peer\":\"$weglarka_peer\""));
    // A fallback to the peer for a CDN peer without a usable header, and for any non-CDN peer: a
    // spoofed `CF-Connecting-IP` is never read (the `geo` default is 0).
    assert!(conf.contains("default 0;"));
    assert!(conf.contains("default $weglarka_peer;"));
    assert!(!conf.contains("default $remote_addr;\n        \"~^1:"));
}

#[test]
fn edge_without_a_cdn_is_unchanged() {
    let mut o = edge_opts(&["app.example.eu", "weglarka.example.eu"]);
    o.proxy_socket_dir = Some("/run/weglarka-ingress".to_owned());
    let conf = nginx::generate(&edge_host(), &apps(ONE_APP), &o).unwrap();
    assert!(!conf.contains("weglarka_cdn") && !conf.contains("weglarka_client"));
    assert!(!conf.contains("\"peer\""));
}

#[test]
fn the_cdn_option_needs_the_forwarder_and_edge_mode() {
    // Invariant: without the forwarder `$remote_addr` is nginx's own address.
    let mut o = edge_cdn_opts(&[]);
    o.proxy_socket_dir = None;
    assert!(nginx::generate(&edge_host(), &BTreeMap::new(), &o).is_err());
    // `behind` rejects it like `https_bind`.
    let mut b = NginxOptions::new(vec!["10.89.0.1".parse().unwrap()])
        .with_trusted_proxies(&["10.89.0.2".to_owned()])
        .unwrap();
    b.cdn = edge_cdn_opts(&[]).cdn;
    assert!(nginx::generate(&host(), &BTreeMap::new(), &b).is_err());
}

#[test]
fn every_mode_defaults_app_for_requests_that_reach_no_app_server() {
    let mut edge = edge_opts(&["app.example.eu", "weglarka.example.eu"]);
    edge.proxy_socket_dir = Some("/run/weglarka-ingress".to_owned());
    for conf in [
        nginx::generate(&edge_host(), &apps(ONE_APP), &edge).unwrap(),
        nginx::generate(&edge_host(), &apps(ONE_APP), &edge_opts(&[])).unwrap(),
    ] {
        assert!(conf.contains("map \"\" $app {\n"), "{conf}");
        assert!(conf.contains("default \"-\";"));
    }
}

#[test]
fn edge_logs_the_proxy_protocol_address_for_requests_rejected_before_realip() {
    let mut o = edge_opts(&["app.example.eu", "weglarka.example.eu"]);
    o.proxy_socket_dir = Some("/run/weglarka-ingress".to_owned());
    let conf = nginx::generate(&edge_host(), &apps(ONE_APP), &o).unwrap();
    assert!(conf.contains("map \"$remote_addr|$proxy_protocol_addr\" $weglarka_peer {"));
    // The probe socket has no PROXY header: its peer is the literal `unix:`, never empty.
    assert!(conf.contains("\"unix:|\" \"unix:\";"));
    assert!(conf.contains("\"~^unix:\\|(?<announced>.+)$\" $announced;"));
    assert!(conf.contains("\"remote_addr\":\"$weglarka_peer\""));
    // Without the forwarder socket there is nothing to fall back to.
    let conf = nginx::generate(&edge_host(), &apps(ONE_APP), &edge_opts(&[])).unwrap();
    assert!(!conf.contains("weglarka_peer"));
}

/// Issue #180: `streaming_paths` carve long-lived locations out of the catch-all; the rest of the app
/// keeps nginx's default timeout, and an app without the list renders exactly as before.
const STREAMING_PATHS_APPS: &str = r#"
[apps.forge]
image = "ghcr.io/x/forge:latest"
domains = ["git.example.eu"]
port = 3000

[apps.forge.ingress]
streaming_paths = ["/user/events"]
max_body_size = "4g"

[apps.plain]
image = "ghcr.io/x/plain:latest"
domains = ["plain.example.eu"]
port = 3001
"#;

#[test]
fn streaming_paths_get_their_own_long_timeout_location() {
    let conf = nginx::generate(&host(), &apps(STREAMING_PATHS_APPS), &opts()).unwrap();
    insta::assert_snapshot!("nginx_streaming_paths", conf);

    let forge = server_block(&conf, "git.example.eu");
    assert!(forge.contains("location = /user/events {"), "{forge}");
    assert!(forge.contains("location ^~ /user/events/ {"), "{forge}");
    assert_eq!(
        forge.matches("proxy_read_timeout 3600s;").count(),
        2,
        "{forge}"
    );
    // The catch-all keeps the default: its block ends before the first streaming location.
    let root =
        &forge[forge.find("location / {").unwrap()..forge.find("location = /user/events").unwrap()];
    assert!(!root.contains("proxy_read_timeout"), "{root}");
    assert!(!conf.contains("proxy_read_timeout 180s"), "{conf}");
    let plain = server_block(&conf, "plain.example.eu");
    assert!(!plain.contains("proxy_read_timeout"), "{plain}");
}

#[test]
fn streaming_paths_render_in_edge_mode_too() {
    let conf = nginx::generate(
        &edge_host(),
        &apps(STREAMING_PATHS_APPS),
        &edge_opts(&["git.example.eu"]),
    )
    .unwrap();
    assert!(conf.contains("location = /user/events {"), "{conf}");
    assert!(conf.contains("proxy_read_timeout 3600s;"), "{conf}");
}

#[test]
fn streaming_paths_must_not_shadow_another_apps_prefix() {
    let a = apps(
        r#"
[apps.forge]
image = "i"
domains = ["git.example.eu"]
port = 3000
ingress = { streaming_paths = ["/user/events"] }

[apps.other]
image = "i"
domains = ["git.example.eu"]
paths = ["/user"]
port = 3001
"#,
    );
    assert!(matches!(
        nginx::generate(&host(), &a, &opts()),
        Err(IngressError::PathConflict { .. })
    ));
}

// --- Static sites (ADR 0049): a directory backend instead of an upstream ---------------------------

/// A root site, a prefixed site and a container app on one domain (disjoint paths), plus a lone
/// root site. None of the sites has a port.
const SITE_APPS: &str = r#"
[apps.api]
image = "ghcr.io/x/api:latest"
domains = ["app.example.eu"]
paths = ["/api"]
port = 3000

[apps.docs]
kind = "static"
image = "ghcr.io/x/docs:latest"
domains = ["app.example.eu"]
paths = ["/docs.v2"]

[apps.landing]
kind = "static"
image = "ghcr.io/x/landing:latest"
domains = ["www.example.eu"]
"#;

#[test]
fn static_site_needs_no_port_and_has_a_directory_backend() {
    let a = apps(SITE_APPS);
    let h = host();
    let plan = Plan::build(&h, &a).unwrap();
    let rows: Vec<String> = plan
        .route_table()
        .iter()
        .map(|r| format!("{}{} -> {}:{}", r.domain, r.path, r.instance, r.backend))
        .collect();
    assert_eq!(
        rows,
        [
            "app.example.eu/api -> api:3000",
            "app.example.eu/docs.v2 -> docs:static:/etc/nginx/sites/docs/current",
            "www.example.eu/ -> landing:static:/etc/nginx/sites/landing/current",
        ]
    );
}

#[test]
fn static_site_shares_the_domain_rules_of_apps() {
    let h = host();
    let site = |paths: &str| {
        format!(
            r#"
[apps.a]
image = "ghcr.io/x/a:latest"
domains = ["app.example.eu"]
port = 80
paths = ["/api"]

[apps.s]
kind = "static"
image = "ghcr.io/x/s:latest"
domains = ["app.example.eu"]
{paths}
"#
        )
    };
    // Disjoint prefix next to a container app, and the catch-all next to a prefixed app: accepted.
    assert!(Plan::build(&h, &apps(&site("paths = [\"/docs\"]"))).is_ok());
    assert!(Plan::build(&h, &apps(&site(""))).is_ok());
    // Overlap and an identical prefix are refused like for two containers.
    assert!(matches!(
        Plan::build(&h, &apps(&site("paths = [\"/api/v2\"]"))),
        Err(IngressError::PathConflict { .. })
    ));
    assert!(matches!(
        Plan::build(&h, &apps(&site("paths = [\"/api\"]"))),
        Err(IngressError::PathConflict { .. })
    ));
    // Two catch-alls, one of them a site.
    let both = apps(
        r#"
[apps.a]
image = "ghcr.io/x/a:latest"
domains = ["app.example.eu"]
port = 80

[apps.s]
kind = "static"
image = "ghcr.io/x/s:latest"
domains = ["app.example.eu"]
"#,
    );
    assert!(matches!(
        Plan::build(&h, &both),
        Err(IngressError::DuplicateDomain(_))
    ));
    // The webhook domain stays exclusive; the reserved instance name too.
    let webhook = apps(
        r#"
[apps.s]
kind = "static"
image = "ghcr.io/x/s:latest"
domains = ["weglarka.example.eu"]
"#,
    );
    assert!(matches!(
        Plan::build(&h, &webhook),
        Err(IngressError::DuplicateDomain(_))
    ));
    let reserved = apps(
        r#"
[apps.weglarka]
kind = "static"
image = "ghcr.io/x/s:latest"
domains = ["s.example.eu"]
"#,
    );
    assert!(matches!(
        Plan::build(&h, &reserved),
        Err(IngressError::ReservedName(_))
    ));
}

#[test]
fn nginx_static_site_snapshots() {
    let a = apps(SITE_APPS);
    let behind = nginx::generate(&host(), &a, &opts()).unwrap();
    insta::assert_snapshot!("nginx_sites", behind);
    let edge = nginx::generate(
        &edge_host(),
        &a,
        &edge_opts(&["app.example.eu", "www.example.eu", "weglarka.example.eu"]),
    )
    .unwrap();
    insta::assert_snapshot!("nginx_edge_sites", edge);

    for conf in [&behind, &edge] {
        // Only the container location proxies; the sites never do.
        assert_eq!(conf.matches("proxy_pass $upstream;").count(), 3, "{conf}"); // api (exact + below) + webhook
        let www = server_block(conf, "www.example.eu");
        assert!(
            !www.contains("proxy_pass") && !www.contains("$upstream"),
            "{www}"
        );
        // (`edge` has a plain-HTTP and a TLS server per domain; `server_block` finds the first.)
        assert!(
            conf.contains("root /etc/nginx/sites/landing/current;"),
            "{conf}"
        );
        // The prefix is stripped before `try_files` (`/docs.v2/x` -> `<root>/x`), `.` escaped.
        assert!(
            conf.contains("rewrite ^/docs\\.v2/(.*)$ /$1 break;"),
            "{conf}"
        );
        assert!(conf.contains("rewrite ^ /index.html break;"), "{conf}");
        assert!(conf.contains("try_files $uri $uri/index.html =404;"));
        assert!(conf.contains("limit_except GET HEAD {"));
    }
}

#[test]
fn stopped_static_site_reserves_its_domain_but_renders_nothing() {
    let a = stopped(apps(SITE_APPS));
    let conf = nginx::generate(&host(), &a, &opts()).unwrap();
    assert!(!conf.contains("/etc/nginx/sites"), "{conf}");
    let yml = traefik::generate(&host(), &a, &TraefikOptions::default()).unwrap();
    assert!(!yml.contains("weglarka-app-"), "{yml}");
}

#[test]
fn traefik_routes_a_static_site_to_the_nginx_like_any_app() {
    let yml = traefik::generate(&host(), &apps(SITE_APPS), &TraefikOptions::default()).unwrap();
    insta::assert_snapshot!("traefik_sites", yml);
    assert!(yml.contains("Host(`www.example.eu`)"));
}

#[test]
fn a_static_site_without_a_release_answers_503() {
    let a = apps(SITE_APPS);
    let mut o = opts();
    o.unreleased.insert(InstanceName::new("landing").unwrap());
    let conf = nginx::generate(&host(), &a, &o).unwrap();
    insta::assert_snapshot!("nginx_unreleased_site", conf);
    let www = server_block(&conf, "www.example.eu");
    assert!(
        www.contains("return 503;") && !www.contains("try_files"),
        "{www}"
    );
    // The sibling site that has a release keeps serving files.
    assert!(
        conf.contains("root /etc/nginx/sites/docs/current;"),
        "{conf}"
    );
}

// --- Forward auth (#89, ADR 0052): nginx `auth_request` in both modes -------------------------------

const IDENTITY: &str = r#"
[identity]
provider = "authelia"
instance = "authelia"
issuer = "https://auth.example.eu"
"#;

fn identity_host(base: &str) -> weglarka_model::config::HostConfig {
    weglarka_model::config::HostConfig::from_toml_str(&format!("{base}{IDENTITY}")).unwrap()
}

/// The provider, a forward app with an exempt `/mcp/` that shares its domain with an unprotected
/// prefix app, a forward prefix app with `strip_prefix`, and an app without forward auth.
const FORWARD_APPS: &str = r#"
[apps.authelia]
image = "ghcr.io/authelia/authelia:latest"
domains = ["auth.example.eu"]
port = 9091

[apps.panel]
image = "ghcr.io/x/panel:latest"
domains = ["panel.example.eu"]
port = 3000
ingress = { auth = "forward", auth_exempt_paths = ["/mcp/", "/.well-known/oauth", "/health"], max_body_size = "8m" }

[apps.docs]
image = "ghcr.io/x/docs:latest"
domains = ["panel.example.eu"]
paths = ["/docs"]
port = 3001

[apps.wiki]
image = "ghcr.io/x/wiki:latest"
domains = ["wiki.example.eu"]
paths = ["/wiki"]
port = 3002
ingress = { auth = "forward", strip_prefix = true }

[apps.plain]
image = "ghcr.io/x/plain:latest"
domains = ["plain.example.eu"]
port = 3003
"#;

const FORWARD_DOMAINS: &[&str] = &[
    "auth.example.eu",
    "panel.example.eu",
    "wiki.example.eu",
    "plain.example.eu",
    "weglarka.example.eu",
];

#[test]
fn forward_auth_snapshots_in_both_modes() {
    let a = apps(FORWARD_APPS);
    let behind = nginx::generate(&identity_host(HOST), &a, &opts()).unwrap();
    insta::assert_snapshot!("nginx_forward_auth", behind);
    let edge = nginx::generate(&identity_host(EDGE_HOST), &a, &edge_opts(FORWARD_DOMAINS)).unwrap();
    insta::assert_snapshot!("nginx_edge_forward_auth", edge);
}

/// Cuts the `location` block that starts with `header` out of a server block.
fn location_block<'a>(server: &'a str, header: &str) -> &'a str {
    let start = server
        .find(header)
        .unwrap_or_else(|| panic!("{header}: {server}"));
    let rest = &server[start..];
    &rest[..rest.find("\n        }").expect("location end") + 10]
}

#[test]
fn forward_auth_protects_by_location_and_exempts_structurally() {
    let a = apps(FORWARD_APPS);
    let behind = nginx::generate(&identity_host(HOST), &a, &opts()).unwrap();
    let edge = nginx::generate(&identity_host(EDGE_HOST), &a, &edge_opts(FORWARD_DOMAINS)).unwrap();
    for (conf, edge) in [(behind, false), (edge, true)] {
        // `edge` has a plain-HTTP redirect server per domain next to the app server.
        let server_block = |conf: &str, domain: &str| {
            if edge {
                tls_server(conf, domain)
            } else {
                server_block(conf, domain)
            }
        };
        // The identity headers are stripped for everyone at `http {}` level.
        for header in ["User", "Groups", "Name", "Email"] {
            assert!(
                conf.contains(&format!("proxy_set_header Remote-{header} \"\";")),
                "{conf}"
            );
        }
        let panel = server_block(&conf, "panel.example.eu");
        assert_eq!(
            panel
                .matches("location = /internal/weglarka/authz {")
                .count(),
            1
        );
        let root = location_block(&panel, "location / {");
        assert!(
            root.contains("auth_request /internal/weglarka/authz;"),
            "{root}"
        );
        // A protected location re-emits the whole header set with the authz result.
        assert!(
            root.contains("proxy_set_header Remote-User $wg_user;"),
            "{root}"
        );
        assert!(root.contains("proxy_set_header Host $host;"), "{root}");
        assert!(
            root.contains("proxy_set_header X-Forwarded-Proto"),
            "{root}"
        );
        assert!(
            root.contains("proxy_set_header Upgrade $http_upgrade;"),
            "{root}"
        );
        assert!(
            root.contains("error_page 401 =302 $wg_redirect_or_portal;"),
            "{root}"
        );
        // The exempt paths are the app's own locations minus `auth_request` (and without `Remote-*`
        // values), exact + prefix for an entry ending in `/`.
        for header in [
            "location = /mcp {",
            "location ^~ /mcp/ {",
            "location = /.well-known/oauth {",
            "location = /health {",
        ] {
            let exempt = location_block(&panel, header);
            assert!(!exempt.contains("auth_request"), "{exempt}");
            assert!(!exempt.contains("$wg_"), "{exempt}");
            assert!(exempt.contains("proxy_pass $upstream;"), "{exempt}");
            assert!(exempt.contains("client_max_body_size 8388608;"), "{exempt}");
        }
        assert!(!panel.contains("location ^~ /health/"), "{panel}");
        assert!(
            !panel.contains("location ^~ /.well-known/oauth/"),
            "{panel}"
        );
        // The unprotected app on the same server carries none of it.
        let docs = location_block(&panel, "location ^~ /docs/ {");
        assert!(!docs.contains("auth_request"), "{docs}");
        let plain = server_block(&conf, "plain.example.eu");
        assert!(!plain.contains("auth_request"), "{plain}");
        assert!(!plain.contains("internal/weglarka"), "{plain}");
        // A prefix app protects both of its locations and keeps its rewrite.
        let wiki = server_block(&conf, "wiki.example.eu");
        assert_eq!(
            wiki.matches("auth_request /internal/weglarka/authz;")
                .count(),
            2,
            "{wiki}"
        );
        assert!(wiki.contains("rewrite ^/wiki/(.*)$ /$1 break;"), "{wiki}");
        // The provider's own server is plain.
        let idp = server_block(&conf, "auth.example.eu");
        assert!(!idp.contains("auth_request"), "{idp}");
    }
}

#[test]
fn the_authz_subrequest_names_the_scheme_the_client_used() {
    let a = apps(FORWARD_APPS);
    let behind = nginx::generate(&identity_host(HOST), &a, &opts()).unwrap();
    let panel = server_block(&behind, "panel.example.eu");
    // `$scheme` would be `http` behind Traefik, and the provider answers 400 to that.
    assert!(
        panel.contains("proxy_set_header X-Original-URL $weglarka_proto://$host$request_uri;"),
        "{panel}"
    );
    assert!(
        panel.contains("proxy_set_header X-Forwarded-For $weglarka_xff;"),
        "{panel}"
    );
    assert!(!panel.contains("X-Original-URL $scheme"), "{panel}");
    assert!(
        panel.contains("set $wg_idp \"http://authelia:9091\";"),
        "{panel}"
    );
    assert!(
        panel.contains("proxy_pass $wg_idp/api/authz/auth-request;"),
        "{panel}"
    );
    assert!(
        behind.contains("\"\" \"https://auth.example.eu/\";"),
        "{behind}"
    );
    assert!(behind.contains("\"unix:\" 1;"), "{behind}");

    let edge = nginx::generate(&identity_host(EDGE_HOST), &a, &edge_opts(FORWARD_DOMAINS)).unwrap();
    let panel = tls_server(&edge, "panel.example.eu");
    assert!(
        panel.contains("proxy_set_header X-Original-URL https://$host$request_uri;"),
        "{panel}"
    );
    assert!(
        panel.contains("proxy_set_header X-Forwarded-For $remote_addr;"),
        "{panel}"
    );
}

#[test]
fn the_probe_socket_listens_on_the_forward_app_and_the_authz_location_lets_it_through() {
    let a = apps(FORWARD_APPS);
    let conf = nginx::generate(&identity_host(HOST), &a, &opts()).unwrap();
    let panel = server_block(&conf, "panel.example.eu");
    assert!(
        panel.contains("listen unix:/run/weglarka-probe/probe.sock;"),
        "{panel}"
    );
    let authz = location_block(&panel, "location = /internal/weglarka/authz {");
    let skip = authz
        .find("if ($weglarka_probe) {")
        .expect("probe exemption");
    // The exemption comes before the upstream is even chosen.
    assert!(skip < authz.find("proxy_pass").unwrap(), "{authz}");
}

#[test]
fn without_a_forward_app_only_the_four_strip_lines_appear() {
    let plain = apps(MANY_APPS);
    let without = nginx::generate(&host(), &plain, &opts()).unwrap();
    // `[identity]` alone changes nothing: the machinery is rendered for forward apps only.
    let with = nginx::generate(&identity_host(HOST), &plain, &opts()).unwrap();
    assert_eq!(without, with);
    for noise in ["auth_request", "weglarka_probe", "wg_", "internal/weglarka"] {
        assert!(!without.contains(noise), "{noise}");
    }
    assert_eq!(without.matches("Remote-").count(), 4);
    // A forward app that is not started renders no route and therefore no machinery either.
    let mut stopped_forward = apps(FORWARD_APPS);
    for spec in stopped_forward.values_mut() {
        spec.start = false;
    }
    let conf = nginx::generate(&identity_host(HOST), &stopped_forward, &opts()).unwrap();
    assert!(
        !conf.contains("auth_request") && !conf.contains("wg_"),
        "{conf}"
    );
}

#[test]
fn forward_auth_fails_closed_without_a_usable_provider() {
    let a = apps(FORWARD_APPS);
    // No `[identity]`: refuse the plan instead of serving the app open.
    assert!(matches!(
        nginx::generate(&host(), &a, &opts()),
        Err(IngressError::ForwardWithoutIdentity(_))
    ));
    // The provider behind its own forward auth would redirect to itself.
    let mut looped = apps(FORWARD_APPS);
    looped
        .get_mut(&InstanceName::new("authelia").unwrap())
        .unwrap()
        .ingress
        .auth = weglarka_model::identity::IngressAuth::Forward;
    assert!(matches!(
        nginx::generate(&identity_host(HOST), &looped, &opts()),
        Err(IngressError::ForwardProvider(_))
    ));
    // No port to default the upstream to, and none configured.
    let mut no_port = apps(FORWARD_APPS);
    let provider = no_port
        .get_mut(&InstanceName::new("authelia").unwrap())
        .unwrap();
    // Without domains the provider is not routed, so only the upstream default can notice.
    provider.port = None;
    provider.domains.clear();
    assert!(matches!(
        nginx::generate(&identity_host(HOST), &no_port, &opts()),
        Err(IngressError::InvalidOption {
            name: "identity.upstream",
            ..
        })
    ));
    // An explicit upstream wins and is validated.
    let explicit = format!("{IDENTITY}upstream = \"idp.internal:9091\"\n");
    let host_with =
        weglarka_model::config::HostConfig::from_toml_str(&format!("{HOST}{explicit}")).unwrap();
    let conf = nginx::generate(&host_with, &no_port, &opts()).unwrap();
    assert!(
        conf.contains("set $wg_idp \"http://idp.internal:9091\";"),
        "{conf}"
    );
}

#[test]
fn exempt_paths_must_not_collide_with_streaming_paths_or_other_apps() {
    let with = |ingress: &str, extra: &str| {
        apps(&format!(
            "[apps.panel]\nimage = \"i\"\ndomains = [\"panel.example.eu\"]\nport = 3000\n\
             ingress = {{ auth = \"forward\", {ingress} }}\n{extra}\n\
             [apps.authelia]\nimage = \"i\"\ndomains = [\"auth.example.eu\"]\nport = 9091\n"
        ))
    };
    let gen_ =
        |a: &BTreeMap<InstanceName, AppSpec>| nginx::generate(&identity_host(HOST), a, &opts());
    // `/mcp` and `/mcp/` are one entry, not two duplicate locations.
    let conf = gen_(&with("auth_exempt_paths = [\"/mcp\", \"/mcp/\"]", "")).unwrap();
    assert_eq!(conf.matches("location = /mcp {").count(), 1, "{conf}");
    assert_eq!(conf.matches("location ^~ /mcp/ {").count(), 1, "{conf}");
    // Same path, or an ancestor/descendant, as a streaming path.
    for (exempt, streaming) in [
        ("/mcp/", "/mcp"),
        ("/mcp", "/mcp/events"),
        ("/mcp/events/", "/mcp"),
    ] {
        let a = with(
            &format!("auth_exempt_paths = [\"{exempt}\"], streaming_paths = [\"{streaming}\"]"),
            "",
        );
        assert!(
            matches!(gen_(&a), Err(IngressError::ExemptOverlap { .. })),
            "{exempt} vs {streaming}"
        );
    }
    // Another app already owns that prefix on the domain.
    let a = with(
        "auth_exempt_paths = [\"/api/\"]",
        "[apps.api]\nimage = \"i\"\ndomains = [\"panel.example.eu\"]\npaths = [\"/api\"]\nport = 3001\n",
    );
    assert!(matches!(gen_(&a), Err(IngressError::PathConflict { .. })));
}

#[test]
fn the_authz_path_is_reserved_and_the_authz_subrequest_drops_client_identity() {
    let a = apps(
        r#"
[apps.panel]
image = "i"
domains = ["panel.example.eu"]
port = 3000
ingress = { auth = "forward", auth_exempt_paths = ["/internal/weglarka/authz"] }
[apps.authelia]
image = "i"
domains = ["auth.example.eu"]
port = 9091
"#,
    );
    assert!(matches!(
        nginx::generate(&identity_host(HOST), &a, &opts()),
        Err(IngressError::InvalidPath { .. })
    ));
    let conf = nginx::generate(&identity_host(HOST), &apps(FORWARD_APPS), &opts()).unwrap();
    let panel = server_block(&conf, "panel.example.eu");
    let authz = location_block(&panel, "location = /internal/weglarka/authz {");
    assert!(
        authz.contains("proxy_set_header Remote-User \"\";"),
        "{authz}"
    );
}
