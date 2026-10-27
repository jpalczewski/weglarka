//! `behind` mode (ADR 0005/0007): one `server` per host group on the single published port.

use std::collections::BTreeMap;

use weglarka_model::app::InstanceName;

use super::NginxOptions;
use super::common::*;
use super::conf::Conf;
use super::location::write_app_locations;
use crate::plan::{AppRoute, Domain, Plan, WEBHOOK_UPSTREAM_HOST};

pub(super) const BEHIND_FORWARDED: Forwarded = Forwarded {
    real_ip: "$remote_addr",
    xff: "$weglarka_xff",
    proto: "$weglarka_proto",
    fwd_host: "$weglarka_fwd_host",
    original_proto: "$weglarka_proto",
};

fn behind_redirect(c: &mut Conf) {
    c.block("if ($weglarka_redirect_https)", |c| {
        c.line("return 301 https://$host$request_uri;");
    });
}

/// `behind` (ADR 0005/0007): one `server` per host group on the single published port. A trusted
/// peer's forwarded plain scheme triggers the redirect; the daemon's health probe (no header) never
/// does.
pub(super) fn render_behind(plan: &Plan<'_>, o: &NginxOptions) -> String {
    let mut c = Conf::default();
    write_preamble(&mut c, None);
    c.block("http", |c| {
        write_http_scaffolding(c, o);
        behind_prelude(c, o);
        c.blank();
        write_upgrade_map(c);
        c.blank();
        write_log(c, ClientAddr::Direct, plan);
        c.blank();
        write_proxy_headers(c, &BEHIND_FORWARDED, None);
        c.blank();
        write_auth_maps(c, plan);

        write_default_server(c, o);

        c.blank();
        c.block("server", |c| {
            listen(c, o.listen_port, false);
            c.line(&format!("server_name {};", plan.webhook.domain));
            // `set` before the redirect: rewrite directives run in order, and the access log needs
            // `$app` also for the 301.
            set_app(c, WEBHOOK_UPSTREAM_HOST);
            behind_redirect(c);
            write_webhook_body(c, plan, o);
        });

        // Apps with `start = false` are provisioned only: they reserve their domains (see plan), but
        // have no container, so there is nothing to proxy to and no `server` block for them.
        // Domains whose set of serving apps is identical share one `server`: an app whose domains
        // are not shared with anyone renders exactly as before path routing existed (ADR 0031).
        let mut by_domain: BTreeMap<&Domain, Vec<&AppRoute<'_>>> = BTreeMap::new();
        for app in plan.apps.iter().filter(|app| app.active) {
            for domain in &app.domains {
                by_domain.entry(domain).or_default().push(app);
            }
        }
        let mut groups: BTreeMap<Vec<&InstanceName>, (Vec<Domain>, Vec<&AppRoute<'_>>)> =
            BTreeMap::new();
        for (domain, apps) in by_domain {
            let key: Vec<&InstanceName> = apps.iter().map(|a| a.instance).collect();
            let group = groups.entry(key).or_insert_with(|| (Vec::new(), apps));
            group.0.push(domain.clone());
        }
        for (domains, apps) in groups.values() {
            c.blank();
            c.block("server", |c| {
                listen(c, o.listen_port, false);
                listen_probe(c, o, false);
                c.line(&format!("server_name {};", join_domains(domains)));
                // One app: known up front, so the redirect is attributed too. Several: each
                // `location` sets its own and the redirect logs `-`.
                let shared = apps.len() > 1;
                set_app(
                    c,
                    if shared {
                        NO_APP
                    } else {
                        apps[0].instance.as_str()
                    },
                );
                behind_redirect(c);
                write_app_locations(c, plan, o, &BEHIND_FORWARDED, apps, shared);
            });
        }
    });
    c.finish()
}

/// The `http {}` prelude of `behind`: `real_ip` and the trust maps of ADR 0007/0032.
fn behind_prelude(c: &mut Conf, o: &NginxOptions) {
    for net in &o.trusted_proxies {
        c.line(&format!("set_real_ip_from {net};"));
    }
    c.line("real_ip_header X-Forwarded-For;");
    c.line("real_ip_recursive on;");
    c.blank();
    // We honor `X-Forwarded-Proto` only from a trusted peer (Traefik terminates TLS).
    write_trusted_peers(
        c,
        "$realip_remote_addr",
        "$weglarka_trusted",
        &o.trusted_proxies,
    );
    c.block(
        "map \"$weglarka_trusted:$http_x_forwarded_proto\" $weglarka_proto",
        |c| {
            c.line("default $scheme;");
            c.line("\"1:https\" https;");
            c.line("\"1:http\" http;");
        },
    );
    // Redirect only on an explicit non-secure scheme from a trusted peer. A trusted peer that sends no
    // header (the daemon's health probe) falls back to `$scheme` in `$weglarka_proto` — which is
    // `http` too — so `$weglarka_proto` alone cannot drive the redirect.
    c.block(
        "map \"$weglarka_trusted:$http_x_forwarded_proto\" $weglarka_redirect_https",
        |c| {
            c.line("default 0;");
            // Fail closed: any value a trusted proxy reports other than a secure scheme (`http`,
            // `ws`, garbage) redirects. Exact entries win over the regex.
            c.line("\"~^1:.+\" 1;");
            c.line("\"1:https\" 0;");
            c.line("\"1:wss\" 0;");
        },
    );
    // Same rule for the forwarded chain and host: a trusted peer's values are passed on,
    // anyone else gets our own (a client cannot forge `X-Forwarded-*`).
    c.block(
        "map \"$weglarka_trusted:$http_x_forwarded_for\" $weglarka_xff",
        |c| {
            c.line("default $remote_addr;");
            c.line("\"~^1:(?<chain>.+)$\" $chain;");
        },
    );
    c.block(
        "map \"$weglarka_trusted:$http_x_forwarded_host\" $weglarka_fwd_host",
        |c| {
            c.line("default $host;");
            c.line("\"~^1:(?<fhost>.+)$\" $fhost;");
        },
    );
}
