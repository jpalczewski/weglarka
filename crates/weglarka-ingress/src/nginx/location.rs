//! Backends and the `location`s rendered for them.

use weglarka_core::app::AppIngress;

use super::NginxOptions;
use super::conf::Conf;
use crate::plan::{AppRoute, PathPrefix};

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

/// Locations of a `server` hosting `apps`: the body limit first (ADR 0033), then every `(path, app)`
/// sorted by path. `shared` names the app per location (several apps in one server) or at the
/// server level (one app, set by the caller).
pub(super) fn write_app_locations(
    c: &mut Conf,
    o: &NginxOptions,
    apps: &[&AppRoute<'_>],
    shared: bool,
) {
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
