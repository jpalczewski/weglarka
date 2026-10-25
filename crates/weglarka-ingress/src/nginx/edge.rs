//! `edge` mode (issue #95): nginx terminates TLS.

use std::collections::BTreeMap;

use super::ACME_CHALLENGE_PREFIX;
use super::NginxOptions;
use super::common::*;
use super::conf::Conf;
use super::location::write_app_locations;
use crate::cdn::CdnTrust;
use crate::plan::{AppRoute, Domain, Plan, WEBHOOK_UPSTREAM_HOST};

pub(super) const EDGE_FORWARDED: Forwarded = Forwarded {
    real_ip: "$remote_addr",
    xff: "$remote_addr",
    proto: "$scheme",
    fwd_host: "$host",
};

/// `edge` behind a CDN: the client address is the one `$weglarka_client` resolves (see
/// [`write_cdn_client`]); proto and host stay nginx's own.
pub(super) const EDGE_CDN_FORWARDED: Forwarded = Forwarded {
    real_ip: "$weglarka_client",
    xff: "$weglarka_client",
    proto: "$scheme",
    fwd_host: "$host",
};

/// The visitor's address behind a CDN (issue #159): the CDN header for a peer inside the ranges,
/// `$remote_addr` for everyone else, and also for a CDN peer whose header is missing or not an IP
/// literal (the edge address, never empty). `X-Forwarded-For` is never read: a CDN appends to it,
/// so its prefix is client-controlled. The regex runs only for CDN peers.
fn write_cdn_client(c: &mut Conf, cdn: &CdnTrust) {
    c.line(&format!(
        "# CDN peers ({}): only they may announce the visitor.",
        cdn.source_label()
    ));
    write_trusted_peers(c, "$remote_addr", "$weglarka_cdn", &cdn.ranges);
    c.block(
        &format!(
            "map \"$weglarka_cdn:{}\" $weglarka_client",
            cdn.header_variable
        ),
        |c| {
            c.line("default $remote_addr;");
            c.line("\"~^1:(?<ip>[0-9A-Fa-f.:]{3,45})$\" $ip;");
        },
    );
}

/// `edge` (issue #95, docs/decisions/0036): nginx terminates TLS. The plain-HTTP listener only
/// redirects (ACME token requests excepted); the TLS listener has one `server` per domain, because
/// nginx picks the server — and therefore the certificate — by SNI.
pub(super) fn render_edge(plan: &Plan<'_>, o: &NginxOptions) -> String {
    let mut c = Conf::default();
    write_preamble(&mut c, o.tls_fingerprint.as_deref());
    c.block("http", |c| {
        write_http_scaffolding(c, o);
        // TLS defaults for every TLS server. `ssl_reject_handshake` on the default server needs no
        // certificate (nginx >= 1.19.4) and `http2 on` needs nginx >= 1.25.1 — the pinned image is
        // newer; a custom `nginx_image` must satisfy this (docs/install.md).
        c.line("ssl_protocols TLSv1.2 TLSv1.3;");
        c.line("ssl_session_cache shared:SSL:10m;");
        c.line("ssl_session_timeout 1d;");
        c.line("ssl_session_tickets off;");
        c.line("ssl_prefer_server_ciphers off;");
        c.blank();
        write_upgrade_map(c);
        c.blank();
        write_log(c, o.cdn.is_some(), plan);
        c.blank();
        // No `real_ip` and no trust maps: a direct client is never trusted for `X-Forwarded-*`
        // (ADR 0007). The headers are rebuilt from nginx's own `$remote_addr`/`$scheme`/`$host`.
        if o.proxy_socket_dir.is_some() {
            // Only the forwarder's unix socket carries a PROXY header; TCP peers are never replaced.
            c.line("set_real_ip_from unix:;");
            c.line("real_ip_header proxy_protocol;");
            c.blank();
        }
        let forwarded = if let Some(cdn) = &o.cdn {
            write_cdn_client(c, cdn);
            c.blank();
            &EDGE_CDN_FORWARDED
        } else {
            &EDGE_FORWARDED
        };
        write_proxy_headers(c, forwarded);
        c.blank();

        write_default_server(c, o);

        // The TLS default server: no certificate at all, every unknown SNI is refused.
        c.blank();
        c.block("server", |c| {
            listen_edge_tls(c, o, true);
            c.line("ssl_reject_handshake on;");
            c.line("server_name _;");
            c.line("return 444;");
        });

        // The webhook domain: plain HTTP redirect + ACME, TLS only when its certificate exists.
        c.blank();
        c.block("server", |c| {
            listen_edge_plain(c, o, false);
            c.line(&format!("server_name {};", plan.webhook.domain));
            c.line(&format!("set $app \"{WEBHOOK_UPSTREAM_HOST}\";"));
            write_plain_http_body(c, o);
        });
        if let Some(stem) = o.certificate_stem(&plan.webhook.domain) {
            c.blank();
            c.block("server", |c| {
                write_tls_listener(c, o, &stem);
                c.line(&format!("server_name {};", plan.webhook.domain));
                c.line(&format!("set $app \"{WEBHOOK_UPSTREAM_HOST}\";"));
                write_webhook_body(c, plan, o);
            });
        }

        // One pair of servers per routed domain: plain HTTP (redirect + ACME) and, when the domain
        // has a certificate, TLS. `start = false` apps are not routed at all here.
        let mut by_domain: BTreeMap<&Domain, Vec<&AppRoute<'_>>> = BTreeMap::new();
        for app in plan.apps.iter().filter(|app| app.active) {
            for domain in &app.domains {
                by_domain.entry(domain).or_default().push(app);
            }
        }
        for (domain, apps) in by_domain {
            let shared = apps.len() > 1;
            let app_name = if shared {
                "-"
            } else {
                apps[0].instance.as_str()
            };
            c.blank();
            c.block("server", |c| {
                listen_edge_plain(c, o, false);
                c.line(&format!("server_name {domain};"));
                c.line(&format!("set $app \"{app_name}\";"));
                write_plain_http_body(c, o);
            });
            let Some(stem) = o.certificate_stem(domain) else {
                continue;
            };
            c.blank();
            c.block("server", |c| {
                write_tls_listener(c, o, &stem);
                c.line(&format!("server_name {domain};"));
                c.line(&format!("set $app \"{app_name}\";"));
                write_app_locations(c, o, &apps, shared);
            });
        }
    });
    c.finish()
}

/// The plain-HTTP server body of `edge`: the ACME HTTP-01 webroot (never redirected) and the
/// redirect to HTTPS for everything else. The `^~` prefix wins over `location /`, so no `if` or map
/// is needed and no request can slip past the exception.
fn write_plain_http_body(c: &mut Conf, o: &NginxOptions) {
    c.block(&format!("location ^~ {ACME_CHALLENGE_PREFIX}"), |c| {
        // `alias` maps the prefix straight onto the webroot: the token file is `<webroot>/<token>`.
        c.line(&format!("alias {}/;", o.acme_webroot));
        c.line("default_type text/plain;");
        c.block("limit_except GET", |c| c.line("deny all;"));
    });
    c.block("location /", |c| {
        c.line("return 301 https://$host$request_uri;");
    });
}

/// `stem` is the certificate file stem from [`NginxOptions::certificate_stem`].
fn write_tls_listener(c: &mut Conf, o: &NginxOptions, stem: &str) {
    listen_edge_tls(c, o, false);
    c.line("http2 on;");
    c.line(&format!("ssl_certificate {}/{stem}.crt;", o.cert_dir));
    c.line(&format!("ssl_certificate_key {}/{stem}.key;", o.cert_dir));
}
