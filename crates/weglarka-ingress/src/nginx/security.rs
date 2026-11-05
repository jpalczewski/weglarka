//! Security headers for ordinary container apps (#497, docs/decisions/0076).
//!
//! A static site's headers are unconditional ([`super::location`]): there is no upstream that could
//! have set its own. A proxied app may answer with any of them already, so the ingress adds a header
//! only when the upstream response does not carry it — the app wins, because only the app knows what
//! its markup needs (a CSP with a per-request nonce, `X-Frame-Options: SAMEORIGIN` for a preview
//! embed). nginx cannot test a response header inside `add_header`, so every configured header gets
//! an `http {}`-level `map` from `$upstream_http_<header>` to either the configured value (upstream
//! sent nothing) or the empty string (nginx omits an `add_header` whose value is empty).

use weglarka_model::app::{InstanceName, SecurityHeaders, SecurityHeadersPreset};

use super::conf::Conf;
use crate::plan::Plan;

/// One configured header: what the location adds, and which `map` variable decides whether it does.
struct SecurityHeader {
    /// The header name of the `add_header` (`X-Frame-Options`).
    name: &'static str,
    /// The header name lower-cased, as the `$upstream_http_*` variable and the per-app variable's
    /// suffix (`x_frame_options` → `$upstream_http_x_frame_options`, `$wg_api_x_frame_options`).
    suffix: &'static str,
    /// The value added when the upstream sent nothing (`DENY`).
    value: String,
}

/// The headers a [`SecurityHeaders`] table asks for, in a stable order. The preset always
/// contributes its three headers (ADR 0069: the `preset` field is not optional, an existing
/// `security_headers` table defaults to `baseline`), `hsts_max_age_secs` and `csp` add theirs.
fn headers_of(headers: &SecurityHeaders) -> Vec<SecurityHeader> {
    let mut list = Vec::new();
    match headers.preset {
        SecurityHeadersPreset::Baseline => {
            for (name, suffix, value) in [
                (
                    "X-Content-Type-Options",
                    "x_content_type_options",
                    "nosniff",
                ),
                ("X-Frame-Options", "x_frame_options", "DENY"),
                (
                    "Referrer-Policy",
                    "referrer_policy",
                    "strict-origin-when-cross-origin",
                ),
            ] {
                list.push(SecurityHeader {
                    name,
                    suffix,
                    value: value.to_owned(),
                });
            }
        }
    }
    if let Some(age) = headers.hsts_max_age_secs {
        list.push(SecurityHeader {
            name: "Strict-Transport-Security",
            suffix: "strict_transport_security",
            // No `includeSubDomains`/`preload` in v1 — see `SecurityHeaders::hsts_max_age_secs`.
            value: format!("max-age={age}"),
        });
    }
    if let Some(csp) = &headers.csp {
        list.push(SecurityHeader {
            name: "Content-Security-Policy",
            suffix: "content_security_policy",
            value: csp.clone(),
        });
    }
    list
}

/// Name of the `map` variable for one header of one app. A container instance name is
/// `[a-z0-9-]` only (`InstanceName`), so `-` → `_` is injective and two apps can never share a
/// variable (nor a `map` target, which nginx would refuse).
fn variable(instance: &InstanceName, suffix: &str) -> String {
    format!("wg_{}_{suffix}", instance.as_str().replace('-', "_"))
}

/// The `map`s for every active app with `ingress.security_headers`, at `http {}` level. A no-op (not
/// even a blank line) when no app configures any.
pub(super) fn write_maps(c: &mut Conf, plan: &Plan<'_>) {
    let apps: Vec<_> = plan
        .apps
        .iter()
        .filter(|app| app.active)
        .filter_map(|app| Some((app.instance, app.ingress.security_headers.as_ref()?)))
        .collect();
    if apps.is_empty() {
        return;
    }
    c.blank();
    c.line(
        "# Security headers of a container app, added only when the app did not send them (#497).",
    );
    for (instance, headers) in apps {
        for header in headers_of(headers) {
            c.block(
                &format!(
                    "map $upstream_http_{} ${}",
                    header.suffix,
                    variable(instance, header.suffix)
                ),
                |c| {
                    c.line(&format!("\"\" \"{}\";", header.value));
                    c.line("default \"\";");
                },
            );
        }
    }
}

/// The headers of one app inside one of its proxy locations (never in the `authz` subrequest
/// location, which has no app of its own). `restates_request_id` says the caller has already emitted
/// `add_header X-Request-Id` at this level — the first `add_header` of a level drops every inherited
/// one, so a location that adds any header of its own must restate it.
pub(super) fn write_headers(
    c: &mut Conf,
    instance: &InstanceName,
    headers: &SecurityHeaders,
    restates_request_id: bool,
) {
    if !restates_request_id {
        c.line("add_header X-Request-Id $request_id always;");
    }
    for header in headers_of(headers) {
        c.line(&format!(
            "add_header {} ${} always;",
            header.name,
            variable(instance, header.suffix)
        ));
    }
}
