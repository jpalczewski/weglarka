//! Backends and the `location`s rendered for them.

use weglarka_model::admin_auth::{RELAY_MAX_BODY_BYTES, RELAY_PREFIX};
use weglarka_model::app::{
    AppIngress, BodySizeLimit, SecurityHeaders, SecurityHeadersPreset, StaticIngress,
};

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
    /// The admin API relay of an `[admin.http] clients` app (docs/decisions/0060): no `auth_request`
    /// (the daemon checks the bearer token), the long-lived stream directives, and the upload body limit.
    relay: bool,
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
            relay: false,
        }]
        .into_iter()
        .chain(streaming_locations(ingress, app, auth))
        .chain(exempt_locations(&route.auth_exempt, app))
        .chain(
            route
                .admin_relay
                .then(|| relay_locations(app))
                .into_iter()
                .flatten(),
        )
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
            relay: false,
        },
        Location {
            header: format!("location ^~ {p}/"),
            strip: below,
            app,
            long_lived: false,
            auth,
            exempt: false,
            relay: false,
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
                relay: false,
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
                relay: false,
            })
    })
}

/// The relay prefix: the exact path and everything below it, never guarded by forward auth. The same
/// `;`/`\\`/`%25` guard as an exempt path refuses the ways of writing a path differently.
fn relay_locations(app: Option<&str>) -> Vec<Location<'_>> {
    [
        format!("location = {RELAY_PREFIX}"),
        format!("location ^~ {RELAY_PREFIX}/"),
    ]
    .into_iter()
    .map(|header| Location {
        header,
        strip: None,
        app,
        long_lived: false,
        auth: false,
        exempt: true,
        relay: true,
    })
    .collect()
}

impl Backend<'_> {
    fn write_location(
        &self,
        c: &mut Conf,
        location: &Location<'_>,
        ingress: &AppIngress,
        forwarded: &Forwarded,
        site_prefix: &str,
    ) {
        // Issue #180: a streaming-path location is the app's own settings with the long-lived
        // stream directives on (long timeout, buffering off); the body limit is inherited.
        let long_lived = AppIngress {
            streaming: true,
            stream_timeout_secs: AppIngress::STREAMING_PATH_TIMEOUT_SECS,
            ..ingress.clone()
        };
        // The relay streams uploads and answers that are silent until a deploy ends: long-lived
        // directives and the largest body the daemon accepts.
        let relay = AppIngress {
            max_body_size: BodySizeLimit::from_bytes(RELAY_MAX_BODY_BYTES).ok(),
            ..long_lived.clone()
        };
        let ingress = if location.relay {
            &relay
        } else if location.long_lived {
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
                // routes on the normalized path: `/open/../admin` or `//admin` would be judged as written but
                // served by the `/admin` location. Refuse the ways of writing a path differently.
                c.block(
                    "if ($request_uri ~* \"^[^?]*(;|%3b|\\\\\\\\|%5c|%25|%2e|%2f|//|/\\.\\.?(/|\\?|$))\")",
                    |c| c.line("return 400;"),
                );
                write_auth_request(c);
            }
            match self {
                Backend::Directory { root } => {
                    write_directory(c, root, location.strip.as_ref(), site_prefix, ingress.static_.as_ref());
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

/// MIME types for a static site (issue #498). The generated config is self-contained on purpose (ADR
/// 0005/0006: no `include mime.types` from the image), and nginx's compiled-in table only knows
/// `html`/`gif`/`jpg` — everything else falls back to `default_type` and is served as `text/plain`,
/// which browsers reject as a stylesheet and refuse to load as an ES module. This table covers the file
/// types a built static site (Astro, Hugo, plain HTML) actually ships; an unmatched extension gets the
/// explicit, inert `application/octet-stream` instead of `text/plain`.
const STATIC_SITE_TYPES: &[(&str, &[&str])] = &[
    ("text/html", &["html", "htm"]),
    ("text/css", &["css"]),
    ("application/javascript", &["js", "mjs"]),
    ("application/json", &["json", "webmanifest"]),
    ("image/svg+xml", &["svg"]),
    ("font/woff", &["woff"]),
    ("font/woff2", &["woff2"]),
    ("application/wasm", &["wasm"]),
    ("application/xml", &["xml"]),
    ("text/plain", &["txt"]),
    ("image/png", &["png"]),
    ("image/jpeg", &["jpg", "jpeg"]),
    ("image/gif", &["gif"]),
    ("image/x-icon", &["ico"]),
];

/// A static site's `location` body. `rewrite ... break` runs before `try_files`, which then sees the URI
/// relative to the site root; nginx has normalized `$uri` (no `..`) before this point. Only GET and HEAD
/// are allowed, and nothing is listed. `opts` are the site's per-site rendering options (#104, ADR
/// 0069: `clean_urls`, `not_found_page`, `cache_revalidate`, `security_headers` — `cache_immutable_paths`,
/// `redirects` and `feeds` add sibling `location`s instead, see [`write_cache_immutable_locations`] and
/// [`write_redirects_and_feeds`], since nginx cannot define the same `location` twice and a site may be
/// reached through two locations (an exact `/p` and a prefix `/p/`, ADR 0031)); `site_prefix` is the
/// public path this site is mounted at ("" for the root), needed to turn `not_found_page` — a path
/// relative to the release root, like `index.html` — back into a client-facing URI `error_page` can
/// route through this same location.
fn write_directory(
    c: &mut Conf,
    root: &str,
    strip: Option<&(String, String)>,
    site_prefix: &str,
    opts: Option<&StaticIngress>,
) {
    if let Some((regex, replacement)) = strip {
        c.line(&format!("rewrite {regex} {replacement} break;"));
    }
    c.line(&format!("root {root};"));
    c.block("types", |c| {
        for (mime, extensions) in STATIC_SITE_TYPES {
            c.line(&format!("{mime} {};", extensions.join(" ")));
        }
    });
    c.line("default_type application/octet-stream;");
    c.line("index index.html;");
    c.line("autoindex off;");
    if let Some(opts) = opts {
        if let Some(page) = &opts.not_found_page {
            c.line(&format!("error_page 404 {site_prefix}{page};"));
        }
        if opts.cache_revalidate {
            c.line("add_header Cache-Control \"no-cache\" always;");
        }
        if opts.cache_revalidate || opts.security_headers.is_some() {
            write_security_headers(c, opts.security_headers.as_ref());
        }
    }
    write_try_files(c, opts.is_some_and(|o| o.clean_urls));
    c.block("limit_except GET HEAD", |c| c.line("deny all;"));
}

/// `try_files` fallback chain: `clean_urls` (#104) also tries `$uri.html`, so `/about` is served from
/// `about.html` without a redirect.
fn write_try_files(c: &mut Conf, clean_urls: bool) {
    if clean_urls {
        c.line("try_files $uri $uri.html $uri/index.html =404;");
    } else {
        c.line("try_files $uri $uri/index.html =404;");
    }
}

/// The preset content of [`SecurityHeadersPreset`] (#104, ADR 0069's "Rendering"; the exact header set
/// is this PR's own decision — the ADR fixes the mechanism, not the values): conservative defaults a
/// static site has no app framework of its own to set. `Content-Security-Policy` stays an explicit
/// opt-in (`csp`) because it is specific to each site's own markup and a wrong default would break pages.
fn write_security_preset(c: &mut Conf, preset: SecurityHeadersPreset) {
    match preset {
        SecurityHeadersPreset::Baseline => {
            c.line("add_header X-Content-Type-Options nosniff always;");
            c.line("add_header X-Frame-Options DENY always;");
            c.line("add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;");
        }
    }
}

/// `security_headers`' directives, ending with a restated `X-Request-Id` (ADR 0069): the first
/// `add_header` on a `location` drops every header `server`/`http` would otherwise have set, so a
/// location that adds any header of its own must repeat the whole set. A no-op when `headers` is
/// `None` — callers that already emit an unconditional `add_header` of their own (cache locations)
/// restate `X-Request-Id` themselves instead of going through this function.
fn write_security_headers(c: &mut Conf, headers: Option<&SecurityHeaders>) {
    let Some(headers) = headers else { return };
    write_security_preset(c, headers.preset);
    if let Some(age) = headers.hsts_max_age_secs {
        c.line(&format!(
            "add_header Strict-Transport-Security \"max-age={age}; includeSubDomains\" always;"
        ));
    }
    if let Some(csp) = &headers.csp {
        c.line(&format!(
            "add_header Content-Security-Policy \"{csp}\" always;"
        ));
    }
    c.line("add_header X-Request-Id $request_id always;");
}

/// `cache_immutable_paths` and `feeds` (#104): both name a file of the release, relative to the site's
/// own root like `not_found_page`, so both need `site_prefix` and get a sibling `location
/// ^~ <site_prefix><p>` (cache) or `location = <site_prefix><path>` (feed) with its own copy of
/// `root` — never nested inside the main location, since nginx resolves `location`s by specificity
/// regardless of nesting, and a sibling avoids ever defining the same `location` twice when a prefixed
/// site also renders an exact `location = <site_prefix>` (ADR 0031). `^~` wins over the shorter main
/// location by nginx's own longest-prefix rule, so textual order does not matter. Rendered once per
/// `(path, app)` pair, like `not_found_page`, so a multi-`paths` site gets one block per path prefix.
fn write_site_relative_locations(
    c: &mut Conf,
    root: &str,
    site_prefix: &str,
    opts: &StaticIngress,
    app: Option<&str>,
) {
    for p in &opts.cache_immutable_paths {
        c.block(&format!("location ^~ {site_prefix}{p}"), |c| {
            if let Some(app) = app {
                set_app(c, app);
            }
            c.line(&format!("root {root};"));
            c.line("add_header Cache-Control \"public, max-age=31536000, immutable\" always;");
            write_security_preset_only(c, opts.security_headers.as_ref());
            // Cache-Control is unconditional here, so `X-Request-Id` always needs restating
            // (`write_security_headers` would skip it when `security_headers` is unset).
            c.line("add_header X-Request-Id $request_id always;");
            write_try_files(c, opts.clean_urls);
            c.block("limit_except GET HEAD", |c| c.line("deny all;"));
        });
    }
    for f in &opts.feeds {
        c.block(&format!("location = {site_prefix}{}", f.path), |c| {
            if let Some(app) = app {
                set_app(c, app);
            }
            c.line(&format!("root {root};"));
            // An empty `types {}` turns off extension sniffing for this one location, so the forced
            // `default_type` always wins (issue #498's table would otherwise still match `.xml`).
            c.line("types { }");
            c.line(&format!("default_type {};", f.format.content_type()));
            c.line("charset utf-8;");
            write_security_preset_only(c, opts.security_headers.as_ref());
            c.line("add_header X-Request-Id $request_id always;");
            c.block("limit_except GET HEAD", |c| c.line("deny all;"));
        });
    }
}

/// The preset's directives alone, without the trailing `X-Request-Id` (the caller already restates it
/// unconditionally because it always emits an `add_header` of its own). A no-op when unset.
fn write_security_preset_only(c: &mut Conf, headers: Option<&SecurityHeaders>) {
    let Some(headers) = headers else { return };
    write_security_preset(c, headers.preset);
    if let Some(age) = headers.hsts_max_age_secs {
        c.line(&format!(
            "add_header Strict-Transport-Security \"max-age={age}; includeSubDomains\" always;"
        ));
    }
    if let Some(csp) = &headers.csp {
        c.line(&format!(
            "add_header Content-Security-Policy \"{csp}\" always;"
        ));
    }
}

/// `redirects` (#104): already-absolute client paths, validated against the site's own `paths` in
/// `weglarka-model` (unlike `cache_immutable_paths`/`feeds`, which are release-relative). Rendered once
/// per app rather than once per `(path, app)` pair — a multi-`paths` site would otherwise define the
/// same `location` twice.
fn write_redirects(c: &mut Conf, opts: &StaticIngress, app: Option<&str>) {
    for r in &opts.redirects {
        if r.prefix {
            // `.` is the only regex metacharacter the path alphabet allows (`check_path_prefix`).
            let escaped = r.from.replace('.', "\\.");
            c.block(&format!("location ^~ {}", r.from), |c| {
                if let Some(app) = app {
                    set_app(c, app);
                }
                write_security_headers(c, opts.security_headers.as_ref());
                c.line(&format!("rewrite ^{escaped}(.*)$ {}$1 permanent;", r.to));
            });
        } else {
            c.block(&format!("location = {}", r.from), |c| {
                if let Some(app) = app {
                    set_app(c, app);
                }
                write_security_headers(c, opts.security_headers.as_ref());
                c.line(&format!("return 301 {}$is_args$args;", r.to));
            });
        }
    }
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
    for (path, app) in &locations {
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
        // The public path this site answers under ("" for the root): `StaticIngress` options that
        // name a file of the release (`not_found_page`, `cache_immutable_paths`, `feeds`) need it to
        // turn their release-relative path back into a client-facing URI (#104, ADR 0069).
        let site_prefix = if path.is_root() {
            String::new()
        } else {
            path.as_str().to_owned()
        };
        for location in path_locations(app, path, name, directory) {
            backend.write_location(c, &location, &app.ingress, forwarded, &site_prefix);
        }
        if let Backend::Directory { root } = &backend
            && let Some(opts) = app.ingress.static_.as_ref()
        {
            write_site_relative_locations(c, root, &site_prefix, opts, name);
        }
    }
    // `redirects` are already-absolute client paths, independent of path-prefix routing, so they are
    // emitted once per app rather than once per `(path, app)` pair (#104, ADR 0069).
    let mut redirects_done = std::collections::BTreeSet::new();
    for (_, app) in &locations {
        if !redirects_done.insert(app.instance) {
            continue;
        }
        if o.unreleased.contains(app.instance) {
            continue;
        }
        let Some(opts) = app.ingress.static_.as_ref() else {
            continue;
        };
        if opts.redirects.is_empty() {
            continue;
        }
        let name = shared.then(|| app.instance.as_str());
        write_redirects(c, opts, name);
    }
}
