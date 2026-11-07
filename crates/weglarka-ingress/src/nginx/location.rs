//! Backends and the `location`s rendered for them.

use weglarka_model::admin_auth::{RELAY_MAX_BODY_BYTES, RELAY_PREFIX};
use weglarka_model::app::{
    AppIngress, BodySizeLimit, Robots, SecurityHeaders, SecurityHeadersPreset, StaticIngress,
};

use super::NginxOptions;
use super::common::{
    AuthVars, Forwarded, assert_no_escaping_needed, set_app, write_auth_request,
    write_authz_location, write_basic_auth_guard, write_proxy_headers,
};
use super::conf::Conf;
use super::security;
use crate::plan::{
    AppRoute, ExemptPath, OAUTH_AUTHORIZATION_SERVER_PATH, OAUTH_PROTECTED_RESOURCE_PREFIX,
    PathPrefix, Plan, RouteBackend,
};

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
    /// HTTP basic auth (ADR 0081): `Some(n)` when this location is protected by the credential `map`
    /// of the instance at index `n` in the plan. `None` for an app without basic auth and for its
    /// `auth_exempt_paths` and admin relay locations, which are structurally unguarded like `auth`'s.
    basic: Option<usize>,
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
    basic: Option<usize>,
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
            basic,
            exempt: false,
            relay: false,
        }]
        .into_iter()
        .chain(streaming_locations(ingress, app, auth, basic))
        .chain(exempt_locations(
            owned_exempt(route, path).collect(),
            app,
            None,
        ))
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
    // `auth_exempt_paths` entries (#612): one equal to the prefix switches `auth_request` off on the
    // prefix's own locations (`/p/` both, `/p` only the exact one); the rest lie below it and get
    // top-level locations of their own, carrying the same rewrite as the prefix.
    let owned: Vec<&ExemptPath> = owned_exempt(route, path).collect();
    let own = owned.iter().find(|e| e.path == *path);
    let exact_open = own.is_some();
    let below_open = own.is_some_and(|e| e.prefix);
    let nested: Vec<&ExemptPath> = owned.iter().copied().filter(|e| e.path != *path).collect();
    let mut locations = vec![
        Location {
            header: format!("location = {p}"),
            strip: exact,
            app,
            long_lived: false,
            auth: auth && !exact_open,
            basic: basic.filter(|_| !exact_open),
            exempt: exact_open,
            relay: false,
        },
        Location {
            header: format!("location ^~ {p}/"),
            strip: below.clone(),
            app,
            long_lived: false,
            auth: auth && !below_open,
            basic: basic.filter(|_| !below_open),
            exempt: below_open,
            relay: false,
        },
    ];
    locations.extend(exempt_locations(nested, app, below));
    locations
}

/// The `auth_exempt_paths` entries rendered next to `path`: those lying in it that no longer prefix
/// of the same app contains (nginx picks the longest match, so the entry belongs to the most specific
/// location that can hold it).
fn owned_exempt<'r, 'p>(
    route: &'r AppRoute<'_>,
    path: &'p PathPrefix,
) -> impl Iterator<Item = &'r ExemptPath> + use<'r, 'p> {
    let deeper: Vec<PathPrefix> = route
        .paths
        .iter()
        .filter(|q| *q != path && path.contains(q))
        .cloned()
        .collect();
    let path = path.clone();
    route
        .auth_exempt
        .iter()
        .filter(move |e| path.contains(&e.path) && !deeper.iter().any(|q| q.contains(&e.path)))
}

/// Issue #180: the long-lived endpoints carved out of the catch-all, each matching itself and
/// everything below it. Validation only allows them on apps routed at `/`.
fn streaming_locations<'a>(
    ingress: &AppIngress,
    app: Option<&'a str>,
    auth: bool,
    basic: Option<usize>,
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
                basic,
                exempt: false,
                relay: false,
            })
    })
}

/// `auth_exempt_paths` (#89): the exact path, and for an entry ending in `/` everything below it as
/// well. They carve out of the location of the prefix they lie in (the catch-all, or since #612 a
/// prefix of a `paths` app; `strip` is that prefix's rewrite for everything below it) and never carry
/// `auth_request`.
fn exempt_locations<'a>(
    exempt: Vec<&ExemptPath>,
    app: Option<&'a str>,
    strip: Option<(String, String)>,
) -> impl Iterator<Item = Location<'a>> {
    exempt
        .into_iter()
        .flat_map(|e| {
            let exact = format!("location = {}", e.path);
            let below = e.prefix.then(|| format!("location ^~ {}/", e.path));
            std::iter::once(exact).chain(below)
        })
        .map(move |header| Location {
            header,
            strip: strip.clone(),
            app,
            long_lived: false,
            auth: false,
            basic: None,
            exempt: true,
            relay: false,
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
        basic: None,
        exempt: true,
        relay: true,
    })
    .collect()
}

/// `oauth_resources` (#215, ADR 0078): for each `/p` the exact path and everything below it, rendered with
/// the long-lived stream directives and **without** `auth_request` — the app checks the tokens itself. In a
/// forward app they also carry the `;`/`\\`/`%25` guard of an exempt path: nginx routes on the normalized
/// path while the upstream gets the raw URI, so `/mcp/..;/admin` must not slip into a guarded location.
/// A resource path is a public path, so this does not depend on the app's `paths`.
fn oauth_locations<'a>(
    route: &AppRoute<'_>,
    app: Option<&'a str>,
) -> impl Iterator<Item = Location<'a>> {
    let exempt = route.forward_auth();
    route.oauth_resources.iter().flat_map(move |p| {
        [format!("location = {p}"), format!("location ^~ {p}/")]
            .into_iter()
            .map(move |header| Location {
                header,
                strip: None,
                app,
                long_lived: true,
                auth: false,
                // `oauth_resources` and `auth = "basic"` exclude each other (ADR 0081), so a
                // resource location never carries the credential check.
                basic: None,
                exempt,
                relay: false,
            })
    })
}

/// The protected resource metadata of `/p` (RFC 9728, #215, ADR 0078), rendered once per server. The
/// document names `$wg_oauth_origin` (an http-level `map $host`, see [`write_oauth_maps`]) instead of
/// `$host`, so a client cannot put a byte of its own request into it; a `Host` without an origin in the
/// map gets `404` instead of a document about somebody else's resource. The scheme is always `https`, in
/// `behind` too: TLS ends at the edge either way.
fn write_oauth_metadata(c: &mut Conf, resource: &PathPrefix, issuer: &str) {
    let path = format!("{OAUTH_PROTECTED_RESOURCE_PREFIX}{resource}");
    assert_no_escaping_needed(&path);
    assert_no_escaping_needed(issuer);
    c.block(&format!("location = {path}"), |c| {
        c.line("if ($wg_oauth_origin = \"\") { return 404; }");
        c.line("default_type application/json;");
        c.line("add_header Cache-Control \"public, max-age=300\" always;");
        c.line("add_header Access-Control-Allow-Origin \"*\" always;");
        c.line("add_header Access-Control-Allow-Methods \"GET, OPTIONS\" always;");
        c.line("add_header Access-Control-Allow-Headers \"*\" always;");
        c.line("if ($request_method = OPTIONS) { return 204; }");
        c.line(&format!(
            "return 200 '{{\"resource\":\"$wg_oauth_origin{resource}\",\"authorization_servers\":[\"{issuer}\"],\"bearer_methods_supported\":[\"header\"]}}';"
        ));
    });
}

/// The legacy authorization server discovery of a server that serves at least one resource (#215, ADR
/// 0078): a redirect to the issuer, never a proxy — the app host does not relay the provider's document,
/// so this needs no second upstream and no `Host`/`X-Forwarded-*` rewriting.
fn write_oauth_authorization_server(c: &mut Conf, issuer: &str) {
    c.block(
        &format!("location = {OAUTH_AUTHORIZATION_SERVER_PATH}"),
        |c| {
            c.line(&format!(
                "return 302 {issuer}{OAUTH_AUTHORIZATION_SERVER_PATH};"
            ));
        },
    );
}

impl Backend<'_> {
    fn write_location(
        &self,
        c: &mut Conf,
        location: &Location<'_>,
        ingress: &AppIngress,
        instance: &weglarka_model::app::InstanceName,
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
            // ADR 0081: the basic auth check of this location, in the same place forward auth puts
            // its `auth_request`. It refuses with 401 before nginx chooses a content handler.
            if let Some(index) = location.basic
                && !matches!(self, Backend::Unreleased)
            {
                write_basic_auth_guard(c, index);
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
                write_proxy_headers(c, forwarded, Some(AuthVars), false);
            } else if location.basic.is_some() {
                // Same rule, and the upstream never sees the shared password: `Authorization` is
                // cleared here, while an exempt location inherits the http-level set unchanged.
                write_proxy_headers(c, forwarded, None, true);
            }
            // Security headers (#497, ADR 0076) go next to `X-Request-Id` so an `add_header` of
            // this location cannot drop either; the `authz` subrequest location is a different
            // function and never carries them. A location with neither forward nor basic auth has no
            // `add_header` of its own yet, so the variable set restates `X-Request-Id` for it.
            if let (Backend::Container { .. }, Some(headers)) =
                (self, ingress.security_headers.as_ref())
            {
                security::write_headers(
                    c,
                    instance,
                    headers,
                    location.auth || location.basic.is_some(),
                );
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
/// 0069: `clean_urls`, `not_found_page`, `cache_revalidate`, `security_headers`; `robots`, ADR 0075).
/// `cache_immutable_paths`, `redirects` and `feeds` add sibling `location`s instead, see
/// [`write_site_relative_locations`] and [`write_redirects`], since nginx cannot define the same
/// `location` twice and a site may be reached through two locations (an exact `/p` and a prefix
/// `/p/`, ADR 0031); `site_prefix` is the public path this site is mounted at ("" for the root),
/// needed to turn `not_found_page` — a path relative to the release root, like `index.html` — back
/// into a client-facing URI `error_page` can route through this same location.
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
        // `cache_revalidate` alone (no `security_headers`) still emits an unconditional `add_header`
        // above, so `X-Request-Id` must be restated here too — `write_security_headers` only restates
        // it when the site adds a header of its own, which would otherwise silently drop the header.
        if opts.cache_revalidate || opts.security_headers.is_some() || opts.robots.is_some() {
            write_security_preset_only(c, opts.security_headers.as_ref());
            write_robots(c, opts);
            c.line("add_header X-Request-Id $request_id always;");
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

/// `security_headers`, `robots` and a restated `X-Request-Id` (ADR 0069, ADR 0075): the first
/// `add_header` on a `location` drops every header `server`/`http` would otherwise have set, so a
/// location that adds any header of its own must repeat the whole set — including `robots`, which is
/// why this takes the whole [`StaticIngress`] rather than just `security_headers`. A no-op when the
/// site adds nothing (callers that already emit an unconditional `add_header` of their own — cache
/// and feed locations — restate `X-Request-Id` themselves instead of going through this function).
/// Delegates the preset/HSTS/CSP body to [`write_security_preset_only`] instead of duplicating it, so
/// the two never drift apart.
fn write_security_headers(c: &mut Conf, opts: &StaticIngress) {
    write_security_preset_only(c, opts.security_headers.as_ref());
    write_robots(c, opts);
    if opts.security_headers.is_some() || opts.robots.is_some() {
        c.line("add_header X-Request-Id $request_id always;");
    }
}

/// `robots` (#545, ADR 0075): an enumerated preset instead of a free-form header, so nothing here is
/// a channel to inject `nginx.conf` directives. A no-op when unset.
fn write_robots(c: &mut Conf, opts: &StaticIngress) {
    if let Some(Robots::Noindex) = opts.robots {
        c.line("add_header X-Robots-Tag \"noindex, nofollow\" always;");
    }
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
    basic: Option<usize>,
) {
    for p in &opts.cache_immutable_paths {
        // The trailing `/` is a segment boundary (ADR 0031's own convention): without it, `^~` would
        // also match a sibling path that merely starts with the same string (e.g. `/assets-backup`
        // for `/assets`).
        c.block(&format!("location ^~ {site_prefix}{p}/"), |c| {
            if let Some(app) = app {
                set_app(c, app);
            }
            // A protected site guards these locations too (ADR 0081: every location of the app,
            // except its exempt paths and the admin relay).
            if let Some(index) = basic {
                write_basic_auth_guard(c, index);
            }
            c.line(&format!("root {root};"));
            c.line("add_header Cache-Control \"public, max-age=31536000, immutable\" always;");
            write_security_preset_only(c, opts.security_headers.as_ref());
            write_robots(c, opts);
            // Cache-Control is unconditional here, so `X-Request-Id` always needs restating
            // (`write_security_headers` would skip it when the site adds nothing else).
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
            if let Some(index) = basic {
                write_basic_auth_guard(c, index);
            }
            c.line(&format!("root {root};"));
            // An empty `types {}` turns off extension sniffing for this one location, so the forced
            // `default_type` always wins (issue #498's table would otherwise still match `.xml`).
            c.line("types { }");
            c.line(&format!("default_type {};", f.format.content_type()));
            c.line("charset utf-8;");
            write_security_preset_only(c, opts.security_headers.as_ref());
            write_robots(c, opts);
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
        // No `includeSubDomains`/`preload` in v1 — see `write_security_headers`.
        c.line(&format!(
            "add_header Strict-Transport-Security \"max-age={age}\" always;"
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
/// same `location` twice. A redirect is a location of the app like any other, so a protected site
/// answers a request without credentials with 401 before the redirect (ADR 0081).
fn write_redirects(c: &mut Conf, opts: &StaticIngress, app: Option<&str>, basic: Option<usize>) {
    for r in &opts.redirects {
        if r.prefix {
            // `.` is the only regex metacharacter the path alphabet allows (`check_path_prefix`).
            let escaped = r.from.replace('.', "\\.");
            // Segment boundary (same convention as `exempt_locations`/ADR 0031): without the
            // trailing `/` on the prefix match, `^~ {from}` would also match a sibling path that
            // merely starts with the same string (e.g. `/blogging` for `/blog`). The bare `from`
            // itself still redirects, via its own exact match below.
            c.block(&format!("location ^~ {}/", r.from), |c| {
                if let Some(app) = app {
                    set_app(c, app);
                }
                if let Some(index) = basic {
                    write_basic_auth_guard(c, index);
                }
                write_security_headers(c, opts);
                c.line(&format!("rewrite ^{escaped}/(.*)$ {}/$1 permanent;", r.to));
            });
            c.block(&format!("location = {}", r.from), |c| {
                if let Some(app) = app {
                    set_app(c, app);
                }
                if let Some(index) = basic {
                    write_basic_auth_guard(c, index);
                }
                write_security_headers(c, opts);
                c.line(&format!("return 301 {}$is_args$args;", r.to));
            });
        } else {
            c.block(&format!("location = {}", r.from), |c| {
                if let Some(app) = app {
                    set_app(c, app);
                }
                if let Some(index) = basic {
                    write_basic_auth_guard(c, index);
                }
                write_security_headers(c, opts);
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
    // ADR 0081: a protected instance whose credential `map` file the daemon did not write answers 503
    // in every location, exactly like an unreleased site (fail closed). Nothing of that instance
    // renders a real location, so no config ever names an undefined `$weglarka_basic_ok_<n>` — which
    // `nginx -t` would reject for the whole host, taking every other app down with it.
    let fails_closed = |app: &AppRoute<'_>| {
        o.unreleased.contains(app.instance)
            || (app.basic_auth() && !o.basic_auth.contains_key(app.instance))
    };
    for (path, app) in &locations {
        let basic = if app.basic_auth() && !fails_closed(app) {
            plan.index_of(app.instance)
        } else {
            None
        };
        let backend = if fails_closed(app) {
            Backend::Unreleased
        } else {
            match &app.backend {
                RouteBackend::Upstream { port } => Backend::Container {
                    host: app.instance.as_str(),
                    port: *port,
                },
                RouteBackend::Directory { root } => Backend::Directory { root },
            }
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
        for location in path_locations(app, path, name, directory, basic) {
            backend.write_location(
                c,
                &location,
                &app.ingress,
                app.instance,
                forwarded,
                &site_prefix,
            );
        }
        if let Backend::Directory { root } = &backend
            && let Some(opts) = app.ingress.static_.as_ref()
        {
            write_site_relative_locations(c, root, &site_prefix, opts, name, basic);
        }
    }
    // `redirects` are already-absolute client paths, independent of path-prefix routing, so they are
    // emitted once per app rather than once per `(path, app)` pair (#104, ADR 0069).
    let mut redirects_done = std::collections::BTreeSet::new();
    for (_, app) in &locations {
        if !redirects_done.insert(app.instance) {
            continue;
        }
        // An app that answers 503 renders none of them: its own catch-all already fails closed, and a
        // redirect location would answer without the credential check otherwise.
        if fails_closed(app) {
            continue;
        }
        let Some(opts) = app.ingress.static_.as_ref() else {
            continue;
        };
        if opts.redirects.is_empty() {
            continue;
        }
        let name = shared.then(|| app.instance.as_str());
        let basic = if app.basic_auth() {
            plan.index_of(app.instance)
        } else {
            None
        };
        write_redirects(c, opts, name, basic);
    }
    write_oauth_server(c, plan, forwarded, apps, shared);
}

/// OAuth-protected resources of a `server` (#215, ADR 0078): first the app's own locations for each `/p`
/// (a resource is a public path, so this is once per app, not once per `(path, app)` pair), then the
/// generated discovery documents — one metadata location per resource and the legacy authorization
/// server redirect once, both naming the provider's issuer. Renders nothing for a server without
/// resources, so such a config stays byte for byte as before.
fn write_oauth_server(
    c: &mut Conf,
    plan: &Plan<'_>,
    forwarded: &Forwarded,
    apps: &[&AppRoute<'_>],
    shared: bool,
) {
    let Some(identity) = plan.oauth_resources() else {
        return;
    };
    let serving: Vec<&AppRoute<'_>> = apps
        .iter()
        .copied()
        .filter(|app| app.has_oauth_resources())
        .collect();
    if serving.is_empty() {
        return;
    }
    for app in &serving {
        let name = shared.then(|| app.instance.as_str());
        for location in oauth_locations(app, name) {
            let backend = match &app.backend {
                RouteBackend::Upstream { port } => Backend::Container {
                    host: app.instance.as_str(),
                    port: *port,
                },
                RouteBackend::Directory { root } => Backend::Directory { root },
            };
            backend.write_location(c, &location, &app.ingress, app.instance, forwarded, "");
        }
    }
    for app in &serving {
        for resource in &app.oauth_resources {
            write_oauth_metadata(c, resource, &identity.issuer);
        }
    }
    write_oauth_authorization_server(c, &identity.issuer);
}
