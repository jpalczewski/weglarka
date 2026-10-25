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
//! Extension points: [`Backend`] (a proxy to a container or a directory served by nginx itself, ADR 0049)
//! and the two renderers, which share the location/log/scaffolding helpers, so a third mode
//! only has to write its own `server` blocks.

mod behind;
mod common;
mod conf;
mod edge;
mod location;
mod options;

use std::collections::BTreeMap;

use weglarka_core::app::{AppSpec, InstanceName};
use weglarka_core::config::{HostConfig, IngressMode};

use crate::plan::{IngressError, Plan};

pub use options::NginxOptions;

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

/// Generates the full `nginx.conf` for Węglarka's nginx container.
pub fn generate(
    host: &HostConfig,
    apps: &BTreeMap<InstanceName, AppSpec>,
    options: &NginxOptions,
) -> Result<String, IngressError> {
    let plan = Plan::build(host, apps)?;
    options.validate(plan.mode)?;
    match plan.mode {
        IngressMode::Behind => Ok(behind::render_behind(&plan, options)),
        IngressMode::Edge => Ok(edge::render_edge(&plan, options)),
    }
}
