//! nginx config: one server per app, `proxy_pass` by name on the app network, JSON access log with `app`;
//! **Owner: session c.**
//!
//! Extension points: [`ModeProfile`] (what differs between the `behind`/`edge` modes: trust headers,
//! `listen`, TLS/ACME) and [`Backend`] (today only a proxy to a container; static sites would be
//! another variant). The `edge` mode currently returns [`IngressError::UnsupportedMode`].

use std::fmt::Write as _;
use std::net::IpAddr;

use weglarka_core::app::{AppSpec, InstanceName};
use weglarka_core::config::{HostConfig, IngressMode};

use crate::plan::{Cidr, Domain, IngressError, Plan, WEBHOOK_UPSTREAM_HOST};
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
    fn write_location(&self, c: &mut Conf) {
        match self {
            Backend::Container { host, port } => {
                // A variable in `proxy_pass` forces runtime resolution (via `resolver`): a missing
                // container yields 502 instead of a startup error; a new IP after recreate is picked up after the TTL.
                c.block("location /", |c| {
                    c.line(&format!("set $upstream \"http://{host}:{port}\";"));
                    c.line("proxy_pass $upstream;");
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
        c.line("# Nazwa apki dla access logu; ustawiana w każdym `server`.");
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
            c.line(&format!("set $app \"{WEBHOOK_UPSTREAM_HOST}\";"));
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

        for app in &plan.apps {
            c.blank();
            c.block("server", |c| {
                mode.listen(c, false);
                c.line(&format!("server_name {};", join_domains(&app.domains)));
                c.line(&format!("set $app \"{}\";", app.instance));
                c.line(&format!("client_max_body_size {};", o.app_max_body_bytes));
                Backend::Container {
                    host: app.instance.as_str(),
                    port: app.port,
                }
                .write_location(c);
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
