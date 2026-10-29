//! Compile-time templates (askama: checked at build time, HTML auto-escaped). A page extends
//! `templates/base.html`, which links only same-origin assets: no inline script or style, and no
//! inline event handler, because the Content-Security-Policy forbids them (docs/decisions/0057).

use askama::Template;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// A bare page for a status: sign-in required, not found, daemon trouble.
#[derive(Template)]
#[template(path = "error.html")]
pub struct ErrorPage<'a> {
    pub title: &'a str,
    pub message: &'a str,
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
            for banned in ["<style", " style=", "javascript:", "hx-on", "<iframe"] {
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
