//! Compile-time templates (askama: checked at build time, HTML auto-escaped). A page extends
//! `templates/base.html`, which links only same-origin assets: no inline script or style, and no
//! inline event handler, because the Content-Security-Policy forbids them (docs/decisions/0057).

use askama::Template;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::session::SessionView;
use crate::views::{
    AppDetail, AppRow, Badge, CertRow, CheckGroup, ConfigSection, EventRow, Field, NotifyView,
    SiteRow, StatsView,
};

/// The navigation: key (for `aria-current`), path, label.
pub const NAV: &[(&str, &str, &str)] = &[
    ("dashboard", "/", "Dashboard"),
    ("apps", "/apps", "Applications"),
    ("doctor", "/doctor", "Doctor"),
    ("volumes", "/volumes", "Volumes"),
    ("networks", "/networks", "Networks"),
    ("sites", "/sites", "Sites"),
    ("certificates", "/certificates", "Certificates"),
    ("events", "/events", "Events"),
    ("notifications", "/notifications", "Notifications"),
    ("config", "/config", "Config"),
];

/// What every signed-in page needs from the session: who is shown, the logout form's CSRF token and
/// which navigation entry is current.
#[derive(Debug, Clone)]
pub struct Shell {
    pub user: String,
    pub csrf: String,
    pub active: &'static str,
    pub nav: &'static [(&'static str, &'static str, &'static str)],
}

impl Shell {
    pub fn new(view: &SessionView, active: &'static str) -> Self {
        Self {
            user: view.user.name.clone(),
            csrf: view.csrf.clone(),
            active,
            nav: NAV,
        }
    }
}

/// Renders a template into an HTML response with `status`; a template failure degrades to a bare 500.
pub fn respond<T: Template>(page: &T, status: StatusCode) -> Response {
    match page.render() {
        Ok(html) => (status, axum::response::Html(html)).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "rendering a page failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Renders a fragment (an SSE payload) to a string.
pub fn fragment<T: Template>(page: &T) -> Option<String> {
    match page.render() {
        Ok(html) => Some(html),
        Err(e) => {
            tracing::error!(error = %e, "rendering a fragment failed");
            None
        }
    }
}

/// A signed-in page that says something went wrong (403, 404, 5xx) without losing the navigation.
#[derive(Template)]
#[template(path = "problem.html")]
pub struct ProblemPage {
    pub shell: Shell,
    pub title: &'static str,
    pub message: String,
    pub retry: Option<String>,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardPage {
    pub shell: Shell,
    pub host: Vec<Field>,
    pub doctor: Badge,
    pub doctor_text: String,
    pub apps_total: usize,
    pub apps_running: usize,
    pub apps_attention: usize,
    pub certs: Vec<CertRow>,
    pub events: Vec<EventRow>,
}

#[derive(Template)]
#[template(path = "apps.html")]
pub struct AppsPage {
    pub shell: Shell,
    pub apps: Vec<AppRow>,
}

#[derive(Template)]
#[template(path = "app.html")]
pub struct AppPage {
    pub shell: Shell,
    pub app: AppDetail,
    /// Whether the log and access-log sections are offered: the daemon let this user open the
    /// (admin-only) streams. Both start on demand, so the page itself opens none.
    pub logs: bool,
}

#[derive(Template)]
#[template(path = "doctor.html")]
pub struct DoctorPage {
    pub shell: Shell,
    pub groups: Vec<CheckGroup>,
}

pub struct SharedVolumeRow {
    pub name: String,
    pub podman_name: String,
    pub group: String,
    pub members: String,
    pub uid_range: String,
    pub exists: &'static str,
}

pub struct AppVolumeRow {
    pub app: String,
    pub name: String,
    pub target: String,
    pub podman_name: String,
    pub exists: &'static str,
    pub shared: bool,
}

#[derive(Template)]
#[template(path = "volumes.html")]
pub struct VolumesPage {
    pub shell: Shell,
    pub shared: Vec<SharedVolumeRow>,
    pub app_volumes: Vec<AppVolumeRow>,
}

pub struct NetworkRow {
    pub name: String,
    pub podman_name: String,
    pub members: String,
    pub exists: &'static str,
}

#[derive(Template)]
#[template(path = "networks.html")]
pub struct NetworksPage {
    pub shell: Shell,
    pub networks: Vec<NetworkRow>,
}

#[derive(Template)]
#[template(path = "sites.html")]
pub struct SitesPage {
    pub shell: Shell,
    pub sites: Vec<SiteRow>,
}

#[derive(Template)]
#[template(path = "notifications.html")]
pub struct NotificationsPage {
    pub shell: Shell,
    pub notify: NotifyView,
}

#[derive(Template)]
#[template(path = "certificates.html")]
pub struct CertificatesPage {
    pub shell: Shell,
    pub acme_enabled: bool,
    pub summary: Vec<Field>,
    pub certs: Vec<CertRow>,
}

#[derive(Template)]
#[template(path = "events.html")]
pub struct EventsPage {
    pub shell: Shell,
    pub events: Vec<EventRow>,
    /// The SSE URL, already carrying the cursor of the rows above.
    pub stream: String,
}

#[derive(Template)]
#[template(path = "config.html")]
pub struct ConfigPage {
    pub shell: Shell,
    pub sections: Vec<ConfigSection>,
}

/// One event as a list item: the page renders the same fragment the SSE stream pushes.
#[derive(Template)]
#[template(path = "event_item.html")]
pub struct EventItem<'a> {
    pub e: &'a EventRow,
}

pub struct LogLine {
    pub stderr: bool,
    pub text: String,
}

/// A batch of log lines as `<div>`s. The text is escaped by the template like any other value.
#[derive(Template)]
#[template(path = "log_lines.html")]
pub struct LogLines<'a> {
    pub lines: &'a [LogLine],
}

/// What the log "Start" button loads: the element that opens the stream.
#[derive(Template)]
#[template(path = "logs_live.html")]
pub struct LogsLive {
    /// The same-origin stream URL.
    pub stream: String,
}

/// What the access-log filter form loads: the element that opens the (filtered) stream.
#[derive(Template)]
#[template(path = "access_live.html")]
pub struct AccessLive {
    /// The same-origin stream URL, carrying the re-encoded filter.
    pub stream: String,
}

/// One access-log entry; every text field is untrusted and already cut and cleaned, the template
/// escapes it.
pub struct AccessRow {
    pub time: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    /// Badge class: `ok`, `info`, `warn`, `fail` or `muted`.
    pub class: &'static str,
    pub bytes: u64,
    pub request_time: String,
    pub remote: String,
    pub user_agent: String,
}

#[derive(Template)]
#[template(path = "access_rows.html")]
pub struct AccessRows<'a> {
    pub rows: &'a [AccessRow],
}

/// The answer to a filter the panel refuses (400). Fixed text: the input is never echoed.
#[derive(Template)]
#[template(path = "filter_error.html")]
pub struct FilterError;

/// A bare page for a status: sign-in required, not found, daemon trouble.
#[derive(Template)]
#[template(path = "error.html")]
pub struct ErrorPage<'a> {
    pub title: &'a str,
    pub message: &'a str,
    /// Where the "Sign in" link goes, if the page offers one.
    pub sign_in: Option<&'a str>,
}

impl ErrorPage<'_> {
    /// Renders the page with `status`. A template failure degrades to the bare status.
    pub fn respond(&self, status: StatusCode) -> Response {
        match self.render() {
            Ok(html) => (status, axum::response::Html(html)).into_response(),
            Err(e) => {
                tracing::error!(error = %e, "rendering the error page failed");
                status.into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_escaped() {
        let html = ErrorPage {
            title: "<script>alert(1)</script>",
            message: "a & b",
            sign_in: None,
        }
        .render()
        .unwrap();
        assert!(!html.contains("<script>alert"), "{html}");
        assert!(html.contains("a &#38; b"), "{html}");
    }

    /// The CSP contract in advance of any real page: templates carry no inline script, style or
    /// event handler (htmx `hx-on` included, ADR 0057 decision 2).
    #[test]
    fn templates_have_no_inline_script_style_or_handlers() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/templates");
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let text = std::fs::read_to_string(&path).unwrap().to_ascii_lowercase();
            for banned in [
                "<style",
                " style=",
                "javascript:",
                "hx-on",
                "<iframe",
                "|safe",
                "|escape(\"none\")",
                "{% filter",
            ] {
                assert!(!text.contains(banned), "{path:?} contains {banned}");
            }
            for tag in text.split("<script").skip(1) {
                let open = tag.split('>').next().unwrap();
                assert!(open.contains(" src="), "{path:?} has an inline <script>");
            }
            let bytes = text.as_bytes();
            for (i, _) in text.match_indices(" on") {
                let rest = &text[i + 3..];
                let name: String = rest.chars().take_while(char::is_ascii_lowercase).collect();
                let after = bytes.get(i + 3 + name.len());
                assert!(
                    !(name.len() > 2 && after == Some(&b'=')),
                    "{path:?} has an inline event handler on{name}"
                );
            }
        }
    }
}

/// The "Resources" section's body, polled by the app page (docs/decisions/0065, decision 5).
#[derive(Template)]
#[template(path = "stats.html")]
pub struct StatsFragment {
    pub stats: Option<StatsView>,
}
