//! nginx config: one server per app, `proxy_pass` by name on the app network, JSON access log with `app`;
//! **Owner: session c.**
//!
//! Per-app ingress options ([`AppIngress`], issue #64) are rendered inside that app's `location` only:
//! `streaming = true` turns response/request buffering off and raises both proxy timeouts, so other
//! apps keep the nginx defaults. `max_body_size` (ADR 0033) overrides the server-level
//! `client_max_body_size` in that app's locations and, since a large body must not be spooled to the
//! ingress container's tmpfs, also turns request buffering off there.
//!
//! Two ingress modes (`docs/decisions/0005`, `docs/decisions/0036`):
//!
//! * `behind` (ADR 0005/0007) — one published port; Traefik terminates TLS and forwards
//!   `X-Forwarded-*` from a trusted peer. The generated config trusts exactly `[ingress]
//!   trusted_proxies` (or nginx's own addresses, ADR 0032) and redirects to HTTPS on a forwarded
//!   plain scheme.
//! * `edge` (issue #95) — nginx terminates TLS itself and publishes two ports: the plain-HTTP one
//!   ([`NginxOptions::listen_port`]) redirects every request to HTTPS except the ACME HTTP-01 prefix
//!   [`ACME_CHALLENGE_PREFIX`], and the TLS one ([`NginxOptions::https_listen_port`]) serves one
//!   `server` per domain with the certificate at [`NginxOptions::cert_dir`]. No client is trusted for
//!   `X-Forwarded-*` (ADR 0007): the headers are rebuilt from nginx's own `$remote_addr`/`$scheme`/
//!   `$host`. A domain without a certificate gets no TLS server and its TLS handshake is rejected —
//!   fail closed.
//!
//! Extension points: [`Backend`] (today only a proxy to a container; static sites would be another
//! variant) and the two renderers, which share the location/log/scaffolding helpers, so a third mode
//! only has to write its own `server` blocks.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::net::IpAddr;

use weglarka_core::app::{AppIngress, AppSpec, InstanceName};
use weglarka_core::config::{HostConfig, IngressMode, wildcard_cert_stem, wildcard_covers};

use crate::cdn::CdnTrust;
use crate::plan::{AppRoute, Cidr, Domain, IngressError, PathPrefix, Plan, WEBHOOK_UPSTREAM_HOST};

/// Container directory with the TLS material (`<nginx_conf_dir>/tls`): `<domain>.crt` (PEM chain,
/// leaf first) and `<domain>.key` (PEM). Read by the nginx **master** at start and at every reload.
pub const CERT_CONTAINER_DIR: &str = "/etc/nginx/tls";
/// Container directory with ACME HTTP-01 tokens (`<nginx_conf_dir>/acme`): the file `<token>` is
/// served at [`ACME_CHALLENGE_PREFIX`]`<token>`. Read by the **worker** on request.
pub const ACME_CONTAINER_DIR: &str = "/etc/nginx/acme";
/// Socket files (in [`NginxOptions::proxy_socket_dir`]) the port forwarder connects to: plain HTTP and TLS.
pub const PLAIN_SOCKET: &str = "http.sock";
pub const TLS_SOCKET: &str = "https.sock";
/// ACME HTTP-01 prefix, reserved on the plain-HTTP listener and exempt from the HTTPS redirect.
pub const ACME_CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

/// Generator settings that belong to neither `HostConfig` nor `AppSpec`.
#[derive(Debug, Clone)]
pub struct NginxOptions {
    /// Resolver addresses (aardvark-dns of the Podman network); at least one is required.
    pub resolvers: Vec<IpAddr>,
    /// Port nginx listens on *inside* the container for plain HTTP (published on `ingress.bind`).
    pub listen_port: u16,
    /// Port nginx listens on *inside* the container for TLS (`edge` only; published on
    /// `ingress.https_bind`).
    pub https_listen_port: u16,
    /// Peers we trust for `X-Forwarded-*` and `real_ip` (`behind` mode only: whoever connects to the
    /// published port — with rootless Podman that is the port forwarder, not Traefik itself, and it
    /// dials from one of nginx's own addresses, `docs/decisions/0032`).
    pub trusted_proxies: Vec<Cidr>,
    /// Webhook path prefixes (start and end with `/`); the rest of the domain → 404.
    pub webhook_paths: Vec<String>,
    /// Webhook request body limit.
    pub webhook_max_body_bytes: u32,
    /// App request body limit.
    pub app_max_body_bytes: u64,
    /// `edge`: domains with a certificate pair in [`Self::cert_dir`]. A routed domain missing here
    /// gets a plain-HTTP server (redirect + ACME) but no TLS server.
    pub certificates: Vec<Domain>,
    /// `edge`: apex domains with a wildcard pair (`_wildcard.<apex>.crt|key`, issue #97). A routed
    /// domain without a pair of its own is served with the wildcard of the apex that covers it (the
    /// apex itself or one label below, [`wildcard_covers`]); a domain's own pair always wins.
    pub wildcard_certificates: Vec<Domain>,
    /// `edge`: container path of the TLS material, mounted read-only (default [`CERT_CONTAINER_DIR`]).
    pub cert_dir: String,
    /// `edge`: container path of the ACME webroot (default [`ACME_CONTAINER_DIR`]).
    pub acme_webroot: String,
    /// `edge`: stable fingerprint of the TLS material on the host. It is rendered as a comment, so a
    /// renewed certificate changes `nginx.conf` (and therefore triggers `nginx -t` + reload) even
    /// though no route changed. The generator does not interpret it beyond its alphabet.
    pub tls_fingerprint: Option<String>,
    /// `edge`: container directory with the two unix sockets ([`PLAIN_SOCKET`], [`TLS_SOCKET`]) on
    /// which nginx also listens, with `proxy_protocol`, for the port forwarder (issue #162,
    /// docs/decisions/0043). The forwarder is the only peer on them; the client address it announces
    /// in the PROXY header becomes `$remote_addr`. `None` = TCP listeners only (nginx's own address is
    /// then what a published port shows as the client).
    pub proxy_socket_dir: Option<String>,
    /// `edge`: the peers that are a CDN and announce the visitor in a header (issue #159,
    /// docs/decisions/0044). Requires [`Self::proxy_socket_dir`]: only then `$remote_addr` is the
    /// real peer the ranges can be compared with.
    pub cdn: Option<CdnTrust>,
}

impl NginxOptions {
    /// File stem (`<domain>` or `_wildcard.<apex>`) of the certificate pair `domain` is served with
    /// in `edge`: its own pair first, else the wildcard of the longest covering apex. `None` = no
    /// TLS server for the domain (its handshake is refused, fail closed).
    pub fn certificate_stem(&self, domain: &Domain) -> Option<String> {
        if self.certificates.contains(domain) {
            return Some(domain.to_string());
        }
        self.wildcard_certificates
            .iter()
            .filter(|apex| wildcard_covers(apex.as_str(), domain.as_str()))
            .max_by_key(|apex| apex.as_str().len())
            .map(|apex| wildcard_cert_stem(apex.as_str()))
    }

    pub fn new(resolvers: Vec<IpAddr>) -> Self {
        Self {
            resolvers,
            listen_port: 8080,
            https_listen_port: 8443,
            trusted_proxies: Vec::new(),
            webhook_paths: vec!["/webhook/".to_owned()],
            webhook_max_body_bytes: 1024 * 1024,
            app_max_body_bytes: 64 * 1024 * 1024,
            certificates: Vec::new(),
            wildcard_certificates: Vec::new(),
            cert_dir: CERT_CONTAINER_DIR.to_owned(),
            acme_webroot: ACME_CONTAINER_DIR.to_owned(),
            tls_fingerprint: None,
            proxy_socket_dir: None,
            cdn: None,
        }
    }

    /// Sets the trusted peers (CIDRs or bare addresses). There is deliberately no default: trusting
    /// a whole Podman address range would let any app container forge `X-Forwarded-*`
    /// (`docs/decisions/0007`); callers pass nginx's own addresses or the configured list.
    pub fn with_trusted_proxies(mut self, entries: &[String]) -> Result<Self, IngressError> {
        self.trusted_proxies = entries
            .iter()
            .map(|e| e.parse())
            .collect::<Result<_, _>>()?;
        Ok(self)
    }

    fn validate(&self, mode: IngressMode) -> Result<(), IngressError> {
        let bad = |name, reason: &str| IngressError::InvalidOption {
            name,
            reason: reason.to_owned(),
        };
        if self.resolvers.is_empty() {
            return Err(bad("resolvers", "at least one resolver required"));
        }
        if self.listen_port == 0 {
            return Err(bad("listen_port", "must not be 0"));
        }
        if self.https_listen_port == 0 {
            return Err(bad("https_listen_port", "must not be 0"));
        }
        if self.webhook_paths.is_empty() {
            return Err(bad("webhook_paths", "at least one path required"));
        }
        for p in &self.webhook_paths {
            let ok = p.len() <= 128
                && p.starts_with('/')
                && p.ends_with('/')
                && !p.contains("//")
                && !p.split('/').any(|seg| seg == "." || seg == "..")
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.'));
            if !ok {
                return Err(bad(
                    "webhook_paths",
                    "expected '/'-delimited prefix of [A-Za-z0-9_.-]",
                ));
            }
        }
        match mode {
            IngressMode::Behind => {
                if self.proxy_socket_dir.is_some() {
                    return Err(bad(
                        "proxy_socket_dir",
                        "is an `edge`-mode option (Traefik is the client-facing hop in `behind`)",
                    ));
                }
                if self.cdn.is_some() {
                    return Err(bad(
                        "cdn",
                        "is an `edge`-mode option (Traefik is the client-facing hop in `behind`)",
                    ));
                }
                if self.trusted_proxies.is_empty() {
                    return Err(bad(
                        "trusted_proxies",
                        "at least one peer required (set [ingress] trusted_proxies)",
                    ));
                }
            }
            IngressMode::Edge => {
                // `behind` only: in `edge` nginx terminates TLS and no direct client may be trusted.
                if !self.trusted_proxies.is_empty() {
                    return Err(bad(
                        "trusted_proxies",
                        "is a `behind`-mode option; in `edge` no client is trusted (docs/decisions/0007)",
                    ));
                }
                check_container_dir("cert_dir", &self.cert_dir)?;
                check_container_dir("acme_webroot", &self.acme_webroot)?;
                if let Some(dir) = &self.proxy_socket_dir {
                    check_container_dir("proxy_socket_dir", dir)?;
                }
                if self.cdn.is_some() && self.proxy_socket_dir.is_none() {
                    // Without the forwarder `$remote_addr` is nginx's own address, so the CDN ranges
                    // would be compared with the wrong peer (an invariant: `edge` always sets it).
                    return Err(bad(
                        "cdn",
                        "requires proxy_socket_dir (the real peer address)",
                    ));
                }
                if self.cert_dir == self.acme_webroot {
                    return Err(bad("cert_dir", "must differ from acme_webroot"));
                }
                if self.listen_port == self.https_listen_port {
                    return Err(bad("https_listen_port", "must differ from listen_port"));
                }
                match self.tls_fingerprint.as_deref() {
                    Some(fingerprint) if is_tls_fingerprint(fingerprint) => {}
                    Some(fingerprint) => {
                        return Err(IngressError::InvalidOption {
                            name: "tls_fingerprint",
                            reason: format!("{fingerprint:?}: expected 8 lowercase hex characters"),
                        });
                    }
                    None => return Err(bad("tls_fingerprint", "required in `edge`")),
                }
            }
        }
        Ok(())
    }
}

/// An absolute container path made of the characters a config token can carry safely: it lands
/// verbatim in `alias`/`ssl_certificate`, so no whitespace, quotes or `;` (defence in depth — the
/// daemon passes its own constants).
fn check_container_dir(name: &'static str, path: &str) -> Result<(), IngressError> {
    let ok = path.starts_with('/')
        && path.len() > 1
        && !path.ends_with('/')
        && !path.contains("//")
        && !path.split('/').any(|seg| seg == "." || seg == "..")
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.'));
    if ok {
        Ok(())
    } else {
        Err(IngressError::InvalidOption {
            name,
            reason: format!(
                "{path:?}: expected an absolute container directory of [A-Za-z0-9/_.-]"
            ),
        })
    }
}

/// 8 lowercase hex characters: the daemon's truncated sha256 of the TLS material.
fn is_tls_fingerprint(value: &str) -> bool {
    value.len() == 8
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}

/// The three expressions the shared proxy headers are built from. `behind` reuses the trust maps
/// (ADR 0007/0032); `edge` has no trusted peer, so the values are nginx's own.
struct Forwarded {
    real_ip: &'static str,
    xff: &'static str,
    proto: &'static str,
    fwd_host: &'static str,
}

const BEHIND_FORWARDED: Forwarded = Forwarded {
    real_ip: "$remote_addr",
    xff: "$weglarka_xff",
    proto: "$weglarka_proto",
    fwd_host: "$weglarka_fwd_host",
};

const EDGE_FORWARDED: Forwarded = Forwarded {
    real_ip: "$remote_addr",
    xff: "$remote_addr",
    proto: "$scheme",
    fwd_host: "$host",
};

/// `edge` behind a CDN: the client address is the one `$weglarka_client` resolves (see
/// [`write_cdn_client`]); proto and host stay nginx's own.
const EDGE_CDN_FORWARDED: Forwarded = Forwarded {
    real_ip: "$weglarka_client",
    xff: "$weglarka_client",
    proto: "$scheme",
    fwd_host: "$host",
};

/// Where nginx forwards traffic. Today only a container; static sites will come as another variant.
enum Backend<'a> {
    Container { host: &'a str, port: u16 },
}

impl Backend<'_> {
    /// Renders the `location`(s) of one `(app, path)`. The root prefix is a plain `location /`; any
    /// other prefix `/p` becomes `location = /p` plus `location ^~ /p/` — a bare `location /p` would
    /// also match `/pxyz` (ADR 0031). `set_app` names the app for the access log when the server
    /// hosts several apps and the server-level `$app` is therefore unknown.
    fn write_locations(
        &self,
        c: &mut Conf,
        ingress: &AppIngress,
        path: &PathPrefix,
        set_app: Option<&str>,
    ) {
        if path.is_root() {
            self.write_location(c, "location /", ingress, None, set_app);
            return;
        }
        let p = path.as_str();
        // `Some((regex, replacement))` of the rewrite that removes the prefix (`.` is the only regex
        // metacharacter the path alphabet allows).
        let escaped = p.replace('.', "\\.");
        let exact = ingress
            .strip_prefix
            .then(|| ("^".to_owned(), "/".to_owned()));
        let below = ingress
            .strip_prefix
            .then(|| (format!("^{escaped}/(.*)$"), "/$1".to_owned()));
        self.write_location(c, &format!("location = {p}"), ingress, exact, set_app);
        self.write_location(c, &format!("location ^~ {p}/"), ingress, below, set_app);
    }

    fn write_location(
        &self,
        c: &mut Conf,
        header: &str,
        ingress: &AppIngress,
        strip: Option<(String, String)>,
        set_app: Option<&str>,
    ) {
        match self {
            Backend::Container { host, port } => {
                // A variable in `proxy_pass` forces runtime resolution (via `resolver`): a missing
                // container yields 502 instead of a startup error; a new IP after recreate is picked up after the TTL.
                c.block(header, |c| {
                    if let Some(app) = set_app {
                        c.line(&format!("set $app \"{app}\";"));
                    }
                    c.line(&format!("set $upstream \"http://{host}:{port}\";"));
                    // `strip_prefix`: with a variable `proxy_pass` carries no URI of its own, so the
                    // rewritten one is what the upstream sees (query string is kept by `rewrite`).
                    if let Some((regex, replacement)) = strip {
                        c.line(&format!("rewrite {regex} {replacement} break;"));
                    }
                    c.line("proxy_pass $upstream;");
                    // Per-app body limit (ADR 0033). It is a *location* directive so that apps
                    // sharing a `server` (path routing) keep their own limits, and the server-level
                    // default stays for everyone else. nginx would otherwise buffer the body in
                    // `client_body_temp_path` — on the read-only root's small tmpfs, i.e. in RAM —
                    // before the upstream sees the first byte; `streaming` below already says this.
                    if let Some(limit) = ingress.max_body_size {
                        c.line(&format!("client_max_body_size {};", limit.bytes()));
                        if !ingress.streaming {
                            c.line("proxy_request_buffering off;");
                        }
                    }
                    // Streaming is opt-in per app (issue #64, docs/decisions/0018): buffering is the
                    // right default everywhere else. Both timeouts change together — nginx would
                    // otherwise cut an idle stream at its 60 s default. The `Connection`/`Upgrade`
                    // headers stay global on purpose: a streaming app may still use WebSocket.
                    if ingress.streaming {
                        c.line("proxy_buffering off;");
                        c.line("proxy_request_buffering off;");
                        c.line(&format!(
                            "proxy_read_timeout {}s;",
                            ingress.stream_timeout_secs
                        ));
                        c.line(&format!(
                            "proxy_send_timeout {}s;",
                            ingress.stream_timeout_secs
                        ));
                    }
                });
            }
        }
    }
}

/// Generates the full `nginx.conf` for Węglarka's nginx container.
pub fn generate(
    host: &HostConfig,
    apps: &BTreeMap<InstanceName, AppSpec>,
    options: &NginxOptions,
) -> Result<String, IngressError> {
    let plan = Plan::build(host, apps)?;
    options.validate(plan.mode)?;
    match plan.mode {
        IngressMode::Behind => Ok(render_behind(&plan, options)),
        IngressMode::Edge => Ok(render_edge(&plan, options)),
    }
}

/// JSON access log format. `path` is `$uri` (no query string, so tokens in URLs do not
/// end up in logs); `upstream_response_time` is a string (`-` or a list on retry).
const LOG_FORMAT: &str = concat!(
    "{\"time\":\"$time_iso8601\",\"app\":\"$app\",\"host\":\"$host\",",
    "\"remote_addr\":\"$remote_addr\",\"method\":\"$request_method\",\"path\":\"$uri\",",
    "\"status\":$status,\"bytes_sent\":$body_bytes_sent,\"request_time\":$request_time,",
    "\"upstream_response_time\":\"$upstream_response_time\",\"request_id\":\"$request_id\",",
    "\"user_agent\":\"$http_user_agent\"}"
);

/// The fixed part of every mode: the process preamble and the `events` block.
fn write_preamble(c: &mut Conf, tls_fingerprint: Option<&str>) {
    c.line("# Generated by weglarka — do not edit.");
    if let Some(fingerprint) = tls_fingerprint {
        c.line(&format!("# tls material: fingerprint {fingerprint}"));
    }
    c.line("worker_processes 1;");
    c.line("pid /tmp/nginx.pid;");
    c.line("error_log /dev/stderr warn;");
    c.blank();
    c.block("events", |c| c.line("worker_connections 1024;"));
    c.blank();
}

/// Directives at the top of `http {}` that do not depend on the mode: the read-only-root writable
/// paths (ADR 0014), the resolver used by the variable `proxy_pass`, and the access-log format.
fn write_http_scaffolding(c: &mut Conf, o: &NginxOptions) {
    c.line("server_tokens off;");
    c.line("client_body_temp_path /tmp/client_body;");
    c.line("proxy_temp_path /tmp/proxy;");
    c.line("fastcgi_temp_path /tmp/fastcgi;");
    c.line("uwsgi_temp_path /tmp/uwsgi;");
    c.line("scgi_temp_path /tmp/scgi;");
    c.blank();
    let resolvers: Vec<String> = o
        .resolvers
        .iter()
        .map(|ip| match ip {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => format!("[{v6}]"),
        })
        .collect();
    // `valid=1s`: a blue-green switch (ADR 0046) moves the instance alias to a new container, and
    // nginx must not keep the old address longer than the drain that follows. aardvark is local, so
    // the extra lookups cost nothing.
    c.line(&format!(
        "resolver {} valid=1s ipv6=off;",
        resolvers.join(" ")
    ));
    c.line("resolver_timeout 2s;");
    c.blank();
}

fn write_upgrade_map(c: &mut Conf) {
    c.block("map $http_upgrade $connection_upgrade", |c| {
        c.line("default upgrade;");
        c.line("'' close;");
    });
}

fn write_log(c: &mut Conf, cdn: bool) {
    c.line("# App name for the access log; set in each `server`.");
    c.line("log_format weglarka escape=json");
    // Behind a CDN `remote_addr` is the visitor and the CDN's edge address is kept as `peer`.
    let format = if cdn {
        LOG_FORMAT.replace(
            "\"remote_addr\":\"$remote_addr\"",
            "\"remote_addr\":\"$weglarka_client\",\"peer\":\"$remote_addr\"",
        )
    } else {
        LOG_FORMAT.to_owned()
    };
    c.line(&format!("    '{format}';"));
    c.line("access_log /dev/stdout weglarka;");
}

fn write_proxy_headers(c: &mut Conf, forwarded: &Forwarded) {
    c.line("proxy_http_version 1.1;");
    c.line("proxy_set_header Host $host;");
    c.line(&format!(
        "proxy_set_header X-Real-IP {};",
        forwarded.real_ip
    ));
    c.line(&format!(
        "proxy_set_header X-Forwarded-For {};",
        forwarded.xff
    ));
    c.line(&format!(
        "proxy_set_header X-Forwarded-Proto {};",
        forwarded.proto
    ));
    c.line(&format!(
        "proxy_set_header X-Forwarded-Host {};",
        forwarded.fwd_host
    ));
    c.line("proxy_set_header X-Request-Id $request_id;");
    c.line("proxy_set_header Upgrade $http_upgrade;");
    c.line("proxy_set_header Connection $connection_upgrade;");
    c.line("add_header X-Request-Id $request_id always;");
}

fn listen(c: &mut Conf, port: u16, default_server: bool) {
    let suffix = if default_server {
        " default_server"
    } else {
        ""
    };
    c.line(&format!("listen {port}{suffix};"));
}

/// `listen` of an `edge` plain-HTTP server: the TCP port (the daemon's health probe, nothing is
/// published on it any more) plus the forwarder's unix socket with `proxy_protocol`.
fn listen_edge_plain(c: &mut Conf, o: &NginxOptions, default_server: bool) {
    listen(c, o.listen_port, default_server);
    if let Some(dir) = &o.proxy_socket_dir {
        let suffix = if default_server {
            " default_server"
        } else {
            ""
        };
        c.line(&format!(
            "listen unix:{dir}/{PLAIN_SOCKET}{suffix} proxy_protocol;"
        ));
    }
}

/// `listen` of an `edge` TLS server (`default_server` for the certificate-less one); see
/// [`listen_edge_plain`].
fn listen_edge_tls(c: &mut Conf, o: &NginxOptions, default_server: bool) {
    let suffix = if default_server {
        " default_server"
    } else {
        ""
    };
    c.line(&format!("listen {} ssl{suffix};", o.https_listen_port));
    if let Some(dir) = &o.proxy_socket_dir {
        c.line(&format!(
            "listen unix:{dir}/{TLS_SOCKET} ssl{suffix} proxy_protocol;"
        ));
    }
}

/// The default server: a foreign `Host` gets nothing.
fn write_default_server(c: &mut Conf, o: &NginxOptions) {
    c.block("server", |c| {
        listen_edge_plain(c, o, true);
        c.line("server_name _;");
        c.line("set $app \"-\";");
        c.line("return 444;");
    });
}

/// Webhook locations: only the listed prefixes, POST, small body limit.
fn write_webhook_body(c: &mut Conf, plan: &Plan<'_>, o: &NginxOptions) {
    c.line(&format!(
        "client_max_body_size {};",
        o.webhook_max_body_bytes
    ));
    for path in &o.webhook_paths {
        c.block(&format!("location ^~ {path}"), |c| {
            c.block("limit_except POST", |c| c.line("deny all;"));
            c.line(&format!(
                "set $upstream \"http://{WEBHOOK_UPSTREAM_HOST}:{}\";",
                plan.webhook.upstream_port
            ));
            c.line("proxy_pass $upstream;");
        });
    }
    c.block("location /", |c| c.line("return 404;"));
}

/// Locations of a `server` hosting `apps`: the body limit first (ADR 0033), then every `(path, app)`
/// sorted by path. `shared` names the app per location (several apps in one server) or at the
/// server level (one app, set by the caller).
fn write_app_locations(c: &mut Conf, o: &NginxOptions, apps: &[&AppRoute<'_>], shared: bool) {
    c.line(&format!("client_max_body_size {};", o.app_max_body_bytes));
    let mut locations: Vec<(&PathPrefix, &AppRoute<'_>)> = apps
        .iter()
        .flat_map(|app| app.paths.iter().map(move |p| (p, *app)))
        .collect();
    locations.sort_by(|a, b| a.0.cmp(b.0));
    for (path, app) in locations {
        Backend::Container {
            host: app.instance.as_str(),
            port: app.port,
        }
        .write_locations(c, &app.ingress, path, shared.then(|| app.instance.as_str()));
    }
}

fn behind_redirect(c: &mut Conf) {
    c.block("if ($weglarka_redirect_https)", |c| {
        c.line("return 301 https://$host$request_uri;");
    });
}

/// `behind` (ADR 0005/0007): one `server` per host group on the single published port. A trusted
/// peer's forwarded plain scheme triggers the redirect; the daemon's health probe (no header) never
/// does.
fn render_behind(plan: &Plan<'_>, o: &NginxOptions) -> String {
    let mut c = Conf::default();
    write_preamble(&mut c, None);
    c.block("http", |c| {
        write_http_scaffolding(c, o);
        behind_prelude(c, o);
        c.blank();
        write_upgrade_map(c);
        c.blank();
        write_log(c, false);
        c.blank();
        write_proxy_headers(c, &BEHIND_FORWARDED);
        c.blank();

        write_default_server(c, o);

        c.blank();
        c.block("server", |c| {
            listen(c, o.listen_port, false);
            c.line(&format!("server_name {};", plan.webhook.domain));
            // `set` before the redirect: rewrite directives run in order, and the access log needs
            // `$app` also for the 301.
            c.line(&format!("set $app \"{WEBHOOK_UPSTREAM_HOST}\";"));
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
                c.line(&format!("server_name {};", join_domains(domains)));
                // One app: known up front, so the redirect is attributed too. Several: each
                // `location` sets its own and the redirect logs `-`.
                let shared = apps.len() > 1;
                c.line(&format!(
                    "set $app \"{}\";",
                    if shared {
                        "-"
                    } else {
                        apps[0].instance.as_str()
                    }
                ));
                behind_redirect(c);
                write_app_locations(c, o, apps, shared);
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

/// `geo <address> <variable>` that is `1` for an address inside `peers` and `0` otherwise: the
/// trust decision of `behind` (`$realip_remote_addr`) and of `edge` behind a CDN (`$remote_addr`).
fn write_trusted_peers(c: &mut Conf, address: &str, variable: &str, peers: &[Cidr]) {
    c.block(&format!("geo {address} {variable}"), |c| {
        c.line("default 0;");
        for net in peers {
            c.line(&format!("{net} 1;"));
        }
    });
}

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
fn render_edge(plan: &Plan<'_>, o: &NginxOptions) -> String {
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
        write_log(c, o.cdn.is_some());
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

fn join_domains(domains: &[Domain]) -> String {
    let mut s = String::new();
    for (i, d) in domains.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        let _ = write!(s, "{d}");
    }
    s
}

/// Small builder with indentation (4 spaces).
#[derive(Default)]
struct Conf {
    buf: String,
    depth: usize,
}

impl Conf {
    fn line(&mut self, text: &str) {
        for _ in 0..self.depth {
            self.buf.push_str("    ");
        }
        self.buf.push_str(text);
        self.buf.push('\n');
    }

    fn blank(&mut self) {
        self.buf.push('\n');
    }

    fn block(&mut self, header: &str, body: impl FnOnce(&mut Self)) {
        self.line(&format!("{header} {{"));
        self.depth += 1;
        body(self);
        self.depth -= 1;
        self.line("}");
    }

    fn finish(self) -> String {
        self.buf
    }
}
