//! nginx config: one server per app, `proxy_pass` by name on the app network, JSON access log with `app`;
//! **Owner: session c.**
//!
//! Per-app ingress options ([`AppIngress`], issue #64) are rendered inside that app's `location` only:
//! `streaming = true` turns response/request buffering off and raises both proxy timeouts, so other
//! apps keep the nginx defaults.
//!
//! Extension points: [`ModeProfile`] (what differs between the `behind`/`edge` modes: trust headers,
//! `listen`, TLS/ACME) and [`Backend`] (today only a proxy to a container; static sites would be
//! another variant). The `edge` mode currently returns [`IngressError::UnsupportedMode`].

use std::fmt::Write as _;
use std::net::IpAddr;

use weglarka_core::app::{AppIngress, AppSpec, InstanceName};
use weglarka_core::config::{HostConfig, IngressMode};

use crate::plan::{AppRoute, Cidr, Domain, IngressError, PathPrefix, Plan, WEBHOOK_UPSTREAM_HOST};
use std::collections::BTreeMap;

/// Generator settings that belong to neither `HostConfig` nor `AppSpec`.
#[derive(Debug, Clone)]
pub struct NginxOptions {
    /// Resolver addresses (aardvark-dns of the Podman network); at least one is required.
    pub resolvers: Vec<IpAddr>,
    /// Port nginx listens on *inside* the container (published on `ingress.bind`).
    pub listen_port: u16,
    /// Peers we trust for `X-Forwarded-*` and `real_ip` (`behind` mode: whoever connects to the
    /// published port — with rootless Podman that is the port forwarder, not Traefik itself).
    pub trusted_proxies: Vec<Cidr>,
    /// Webhook path prefixes (start and end with `/`); the rest of the domain → 404.
    pub webhook_paths: Vec<String>,
    /// Webhook request body limit.
    pub webhook_max_body_bytes: u32,
    /// App request body limit.
    pub app_max_body_bytes: u64,
}

impl NginxOptions {
    pub fn new(resolvers: Vec<IpAddr>) -> Self {
        Self {
            resolvers,
            listen_port: 8080,
            trusted_proxies: Vec::new(),
            webhook_paths: vec!["/webhook/".to_owned()],
            webhook_max_body_bytes: 1024 * 1024,
            app_max_body_bytes: 64 * 1024 * 1024,
        }
    }

    /// Sets the trusted peers (CIDRs or bare addresses). There is deliberately no default: trusting
    /// a whole Podman address range would let any app container forge `X-Forwarded-*`
    /// (`docs/decisions/0007`); callers pass the forwarder's network or the configured list.
    pub fn with_trusted_proxies(mut self, entries: &[String]) -> Result<Self, IngressError> {
        self.trusted_proxies = entries
            .iter()
            .map(|e| e.parse())
            .collect::<Result<_, _>>()?;
        Ok(self)
    }

    fn validate(&self) -> Result<(), IngressError> {
        let bad = |name, reason: &str| IngressError::InvalidOption {
            name,
            reason: reason.to_owned(),
        };
        if self.resolvers.is_empty() {
            return Err(bad("resolvers", "at least one resolver required"));
        }
        if self.trusted_proxies.is_empty() {
            return Err(bad(
                "trusted_proxies",
                "at least one peer required (set [ingress] trusted_proxies)",
            ));
        }
        if self.listen_port == 0 {
            return Err(bad("listen_port", "must not be 0"));
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
        Ok(())
    }
}

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

/// What differs between ingress modes. `behind` is implemented; `edge` (TLS, ACME
/// `/.well-known/acme-challenge/`, `listen 80/443`) will come as a second implementation.
trait ModeProfile {
    /// Directives at the `http {}` level: proxy trust, the `$weglarka_proto` variable.
    fn http_prelude(&self, c: &mut Conf);
    /// Inside a (non-default) `server`: redirect plain-HTTP requests to HTTPS. Must never fire for
    /// requests whose scheme is unknown (the daemon's health probes carry no forwarded headers).
    fn https_redirect(&self, c: &mut Conf);
    /// The server's `listen`.
    fn listen(&self, c: &mut Conf, default_server: bool);
}

struct Behind<'a>(&'a NginxOptions);

impl ModeProfile for Behind<'_> {
    fn http_prelude(&self, c: &mut Conf) {
        for net in &self.0.trusted_proxies {
            c.line(&format!("set_real_ip_from {net};"));
        }
        c.line("real_ip_header X-Forwarded-For;");
        c.line("real_ip_recursive on;");
        c.blank();
        // We honor `X-Forwarded-Proto` only from a trusted peer (Traefik terminates TLS).
        c.block("geo $realip_remote_addr $weglarka_trusted", |c| {
            c.line("default 0;");
            for net in &self.0.trusted_proxies {
                c.line(&format!("{net} 1;"));
            }
        });
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

    fn https_redirect(&self, c: &mut Conf) {
        // An `edge` profile would key this on `$scheme` instead (and exempt the ACME challenge path).
        c.block("if ($weglarka_redirect_https)", |c| {
            c.line("return 301 https://$host$request_uri;");
        });
    }

    fn listen(&self, c: &mut Conf, default_server: bool) {
        let suffix = if default_server {
            " default_server"
        } else {
            ""
        };
        c.line(&format!("listen {}{suffix};", self.0.listen_port));
    }
}

/// Generates the full `nginx.conf` for Węglarka's nginx container.
pub fn generate(
    host: &HostConfig,
    apps: &BTreeMap<InstanceName, AppSpec>,
    options: &NginxOptions,
) -> Result<String, IngressError> {
    options.validate()?;
    let plan = Plan::build(host, apps)?;
    match plan.mode {
        IngressMode::Behind => Ok(render(&plan, options, &Behind(options))),
        mode @ IngressMode::Edge => Err(IngressError::UnsupportedMode(mode)),
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

fn render(plan: &Plan<'_>, o: &NginxOptions, mode: &dyn ModeProfile) -> String {
    let mut c = Conf::default();
    c.line("# Generated by weglarka — do not edit.");
    c.line("worker_processes 1;");
    c.line("pid /tmp/nginx.pid;");
    c.line("error_log /dev/stderr warn;");
    c.blank();
    c.block("events", |c| c.line("worker_connections 1024;"));
    c.blank();

    c.block("http", |c| {
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
        c.line(&format!(
            "resolver {} valid=5s ipv6=off;",
            resolvers.join(" ")
        ));
        c.line("resolver_timeout 2s;");
        c.blank();

        mode.http_prelude(c);
        c.blank();

        c.block("map $http_upgrade $connection_upgrade", |c| {
            c.line("default upgrade;");
            c.line("'' close;");
        });
        c.blank();
        c.line("# App name for the access log; set in each `server`.");
        c.line("log_format weglarka escape=json");
        c.line(&format!("    '{LOG_FORMAT}';"));
        c.line("access_log /dev/stdout weglarka;");
        c.blank();

        c.line("proxy_http_version 1.1;");
        c.line("proxy_set_header Host $host;");
        c.line("proxy_set_header X-Real-IP $remote_addr;");
        c.line("proxy_set_header X-Forwarded-For $weglarka_xff;");
        c.line("proxy_set_header X-Forwarded-Proto $weglarka_proto;");
        c.line("proxy_set_header X-Forwarded-Host $weglarka_fwd_host;");
        c.line("proxy_set_header X-Request-Id $request_id;");
        c.line("proxy_set_header Upgrade $http_upgrade;");
        c.line("proxy_set_header Connection $connection_upgrade;");
        c.line("add_header X-Request-Id $request_id always;");
        c.blank();

        // Default server: a foreign Host gets nothing.
        c.block("server", |c| {
            mode.listen(c, true);
            c.line("server_name _;");
            c.line("set $app \"-\";");
            c.line("return 444;");
        });

        // Webhooks: only the listed prefixes, POST, small body limit.
        c.blank();
        c.block("server", |c| {
            mode.listen(c, false);
            c.line(&format!("server_name {};", plan.webhook.domain));
            // `set` before the redirect: rewrite directives run in order, and the access log needs
            // `$app` also for the 301.
            c.line(&format!("set $app \"{WEBHOOK_UPSTREAM_HOST}\";"));
            mode.https_redirect(c);
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
                mode.listen(c, false);
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
                mode.https_redirect(c);
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
                    .write_locations(
                        c,
                        &app.ingress,
                        path,
                        shared.then(|| app.instance.as_str()),
                    );
                }
            });
        }
    });
    c.finish()
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
