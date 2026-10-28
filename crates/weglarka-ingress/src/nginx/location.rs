//! Backends and the `location`s rendered for them.

use weglarka_model::app::AppIngress;

use super::NginxOptions;
use super::common::{
    AuthVars, Forwarded, set_app, write_auth_request, write_authz_location, write_proxy_headers,
};
use super::conf::Conf;
use crate::plan::{AppRoute, ExemptPath, PathPrefix, Plan, RouteBackend};

/// Where nginx sends traffic: a container (`proxy_pass`) or a static site's directory (ADR 0049).
enum Backend<'a> {
    Container {
        host: &'a str,
        port: u16,
    },
    /// Files below `root`; never a `proxy_pass`, so none of the proxy headers apply.
    Directory {
        root: &'a str,
    },
    /// A static site that has no release yet: the route is reserved but answers 503.
    Unreleased,
}

/// One `location` block of an app, before its directives are rendered. Extra locations of an app
/// (several paths, a streaming sub-path) are more entries of the list [`path_locations`] builds.
struct Location<'a> {
    /// The whole header, e.g. `location ^~ /p/`.
    header: String,
    /// `(regex, replacement)` of the `rewrite` that removes the path prefix.
    strip: Option<(String, String)>,
    /// App name set for the access log when the server hosts several apps and the server-level
    /// `$app` is therefore unknown.
    app: Option<&'a str>,
    /// A `streaming_paths` entry (issue #180): rendered with the long-lived stream directives.
    long_lived: bool,
    /// Forward auth (#89): the location asks the identity provider first. `false` for an app
    /// without forward auth and for its `auth_exempt_paths` — those locations are the app's own
    /// minus the `auth_request`, so the exemption is structural, never a rule that could be misread.
    auth: bool,
    /// An `auth_exempt_paths` location: nginx matches on the normalized path while the upstream
    /// gets the raw request URI, so a request that only an upstream treating `;` or `\` as path
    /// syntax would resolve elsewhere (`/mcp/..;/admin`) is refused instead of passed on unguarded.
    exempt: bool,
}

/// The `location`(s) of one `(app, path)`. The root prefix is a plain `location /`; any other prefix
/// `/p` becomes `location = /p` plus `location ^~ /p/` — a bare `location /p` would also match
/// `/pxyz` (ADR 0031).
fn path_locations<'a>(
    route: &AppRoute<'_>,
    path: &PathPrefix,
    app: Option<&'a str>,
    directory: bool,
) -> Vec<Location<'a>> {
    let ingress = &route.ingress;
    let auth = route.forward_auth();
    if path.is_root() {
        return vec![Location {
            header: "location /".to_owned(),
            strip: None,
            app,
            long_lived: false,
            auth,
            exempt: false,
        }]
        .into_iter()
        .chain(streaming_locations(ingress, app, auth))
        .chain(exempt_locations(&route.auth_exempt, app))
        .collect();
    }
    let p = path.as_str();
    // The rewrite that removes the prefix (`.` is the only regex metacharacter the path alphabet
    // allows).
    let escaped = p.replace('.', "\\.");
    // The files of a site live at its root, so its prefix is always removed; `/p` itself is the
    // site's index.
    let strip = ingress.strip_prefix || directory;
    let exact = strip.then(|| {
        (
            "^".to_owned(),
            if directory { "/index.html" } else { "/" }.to_owned(),
        )
    });
    let below = strip.then(|| (format!("^{escaped}/(.*)$"), "/$1".to_owned()));
    vec![
        Location {
            header: format!("location = {p}"),
            strip: exact,
            app,
            long_lived: false,
            auth,
            exempt: false,
        },
        Location {
            header: format!("location ^~ {p}/"),
            strip: below,
            app,
            long_lived: false,
            auth,
            exempt: false,
        },
    ]
}

/// Issue #180: the long-lived endpoints carved out of the catch-all, each matching itself and
/// everything below it. Validation only allows them on apps routed at `/`.
fn streaming_locations<'a>(
    ingress: &AppIngress,
    app: Option<&'a str>,
    auth: bool,
) -> impl Iterator<Item = Location<'a>> {
    ingress.streaming_paths.iter().flat_map(move |p| {
        [format!("location = {p}"), format!("location ^~ {p}/")]
            .into_iter()
            .map(move |header| Location {
                header,
                strip: None,
                app,
                long_lived: true,
                auth,
                exempt: false,
            })
    })
}

/// `auth_exempt_paths` (#89): the exact path, and for an entry ending in `/` everything below it as
/// well. Like the streaming carve-outs they are validated only on apps routed at `/` (the model
/// refuses them next to `paths`, the plan refuses overlaps), and they never carry `auth_request`.
fn exempt_locations<'a>(
    exempt: &[ExemptPath],
    app: Option<&'a str>,
) -> impl Iterator<Item = Location<'a>> {
    exempt.iter().flat_map(move |e| {
        let exact = format!("location = {}", e.path);
        let below = e.prefix.then(|| format!("location ^~ {}/", e.path));
        std::iter::once(exact)
            .chain(below)
            .map(move |header| Location {
                header,
                strip: None,
                app,
                long_lived: false,
                auth: false,
                exempt: true,
            })
    })
}

impl Backend<'_> {
    fn write_location(
        &self,
        c: &mut Conf,
        location: &Location<'_>,
        ingress: &AppIngress,
        forwarded: &Forwarded,
    ) {
        // Issue #180: a streaming-path location is the app's own settings with the long-lived
        // stream directives on (long timeout, buffering off); the body limit is inherited.
        let long_lived = AppIngress {
            streaming: true,
            stream_timeout_secs: AppIngress::STREAMING_PATH_TIMEOUT_SECS,
            ..ingress.clone()
        };
        let ingress = if location.long_lived {
            &long_lived
        } else {
            ingress
        };
        c.block(&location.header, |c| {
            if let Some(app) = location.app {
                set_app(c, app);
            }
            // `return 503` runs in the rewrite phase, before any access check, so a route that only
            // reserves a name needs none.
            if location.exempt {
                c.block(
                    "if ($request_uri ~* \"^[^?]*(;|%3b|\\\\\\\\|%5c|%25)\")",
                    |c| c.line("return 400;"),
                );
            }
            if location.auth && !matches!(self, Backend::Unreleased) {
                // The provider matches its access rules against the raw `X-Original-URL`, while nginx
                // routes on the normalized path: `/open/../admin` would be judged as `/open/...` but
                // served by the `/admin` location. Refuse the ways of writing a path differently.
                c.block(
                    "if ($request_uri ~* \"^[^?]*(;|%3b|\\\\\\\\|%5c|%25|%2e|%2f|/\\.\\.?(/|\\?|$))\")",
                    |c| c.line("return 400;"),
                );
                write_auth_request(c);
            }
            match self {
                Backend::Directory { root } => {
                    write_directory(c, root, location.strip.as_ref());
                    return;
                }
                Backend::Unreleased => {
                    c.line("return 503;");
                    return;
                }
                Backend::Container { .. } => {}
            }
            self.write_upstream(c, location.strip.as_ref());
            write_body_limit(c, ingress);
            write_streaming(c, ingress);
            if location.auth {
                // The first `proxy_set_header` of a level drops every inherited one: repeat the
                // whole set, this time with `Remote-*` from the authz answer.
                write_proxy_headers(c, forwarded, Some(AuthVars));
            }
        });
    }

    /// `set $upstream` + optional prefix rewrite + `proxy_pass`.
    fn write_upstream(&self, c: &mut Conf, strip: Option<&(String, String)>) {
        match self {
            Backend::Container { host, port } => {
                // A variable in `proxy_pass` forces runtime resolution (via `resolver`): a missing
                // container yields 502 instead of a startup error; a new IP after recreate is picked up after the TTL.
                c.line(&format!("set $upstream \"http://{host}:{port}\";"));
                // `strip_prefix`: with a variable `proxy_pass` carries no URI of its own, so the
                // rewritten one is what the upstream sees (query string is kept by `rewrite`).
                if let Some((regex, replacement)) = strip {
                    c.line(&format!("rewrite {regex} {replacement} break;"));
                }
                c.line("proxy_pass $upstream;");
            }
            Backend::Directory { .. } | Backend::Unreleased => {
                unreachable!("a static site is rendered by write_location")
            }
        }
    }
}

/// A static site's `location` body. `rewrite ... break` runs before `try_files`, which then sees the URI
/// relative to the site root; nginx has normalized `$uri` (no `..`) before this point. Only GET and HEAD
/// are allowed, and nothing is listed.
fn write_directory(c: &mut Conf, root: &str, strip: Option<&(String, String)>) {
    if let Some((regex, replacement)) = strip {
        c.line(&format!("rewrite {regex} {replacement} break;"));
    }
    c.line(&format!("root {root};"));
    c.line("index index.html;");
    c.line("autoindex off;");
    c.line("try_files $uri $uri/index.html =404;");
    c.block("limit_except GET HEAD", |c| c.line("deny all;"));
}

/// Per-app body limit (ADR 0033). It is a *location* directive so that apps sharing a `server`
/// (path routing) keep their own limits, and the server-level default stays for everyone else.
/// nginx would otherwise buffer the body in `client_body_temp_path` — on the read-only root's small
/// tmpfs, i.e. in RAM — before the upstream sees the first byte; `streaming` already says this.
fn write_body_limit(c: &mut Conf, ingress: &AppIngress) {
    if let Some(limit) = ingress.max_body_size {
        c.line(&format!("client_max_body_size {};", limit.bytes()));
        if !ingress.streaming {
            c.line("proxy_request_buffering off;");
        }
    }
}

/// Streaming is opt-in per app (issue #64, docs/decisions/0018): buffering is the right default
/// everywhere else. Both timeouts change together — nginx would otherwise cut an idle stream at its
/// 60 s default. The `Connection`/`Upgrade` headers stay global on purpose: a streaming app may
/// still use WebSocket.
fn write_streaming(c: &mut Conf, ingress: &AppIngress) {
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
}

/// Locations of a `server` hosting `apps`: the body limit first (ADR 0033), then every `(path, app)`
/// sorted by path. `shared` names the app per location (several apps in one server) or at the
/// server level (one app, set by the caller).
pub(super) fn write_app_locations(
    c: &mut Conf,
    plan: &Plan<'_>,
    o: &NginxOptions,
    forwarded: &Forwarded,
    apps: &[&AppRoute<'_>],
    shared: bool,
) {
    c.line(&format!("client_max_body_size {};", o.app_max_body_bytes));
    if let Some(identity) = plan.forward_auth()
        && apps.iter().any(|app| app.forward_auth())
    {
        write_authz_location(c, identity, forwarded);
    }
    let mut locations: Vec<(&PathPrefix, &AppRoute<'_>)> = apps
        .iter()
        .flat_map(|app| app.paths.iter().map(move |p| (p, *app)))
        .collect();
    locations.sort_by(|a, b| a.0.cmp(b.0));
    for (path, app) in locations {
        let backend = match &app.backend {
            RouteBackend::Upstream { port } => Backend::Container {
                host: app.instance.as_str(),
                port: *port,
            },
            RouteBackend::Directory { .. } if o.unreleased.contains(app.instance) => {
                Backend::Unreleased
            }
            RouteBackend::Directory { root } => Backend::Directory { root },
        };
        let directory = matches!(backend, Backend::Directory { .. } | Backend::Unreleased);
        let name = shared.then(|| app.instance.as_str());
        for location in path_locations(app, path, name, directory) {
            backend.write_location(c, &location, &app.ingress, forwarded);
        }
    }
}
